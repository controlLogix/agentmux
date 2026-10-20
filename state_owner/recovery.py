"""Bounded owner checkpoints. Recovery never executes effects or grants writes.

The backup directory is trusted administrator-owned storage. Files are private,
but not encrypted: protected off-volume backup and key custody remain deployment
responsibilities. A digest from a trusted inventory detects substituted backups;
an embedded digest alone only detects corruption. No source history is removed.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import os
from pathlib import Path
import secrets
import stat

from agentmux_contracts.wire import ContractError, canonical_bytes, strict_loads
from .ledger import OwnerBinding, Snapshot, StoredRecord, validate_history

MAX_CHECKPOINT_BYTES = 64 * 1024 * 1024
MAX_FRAME_BYTES = 128 * 1024
MAX_RECORDS = 100_000


@dataclass(frozen=True)
class FencedRecovery:
    snapshot: Snapshot = field(repr=False)
    digest: str
    reconciliation_required: bool = field(default=True, init=False)


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _binding(binding):
    return {'hubId': binding.hub_id, 'ownerDomain': binding.owner_domain,
            'entityId': binding.entity_id, 'entityKind': binding.entity_kind,
            'scope': strict_loads(binding.scope)}


def _frame(value):
    result = canonical_bytes(value) + b'\n'
    if len(result) > MAX_FRAME_BYTES:
        raise ContractError('checkpoint_limit')
    return result


def build_checkpoint(snapshot: Snapshot, binding: OwnerBinding) -> bytes:
    """Preserve all validated records, including outcomes, reservations and intent."""
    try:
        if not snapshot.records or len(snapshot.records) > MAX_RECORDS:
            raise ContractError('checkpoint_invalid')
        if sum(len(item.record) for item in snapshot.records) > MAX_CHECKPOINT_BYTES:
            raise ContractError('checkpoint_limit')
        checked = validate_history(snapshot.records, binding)
        if checked.sequence != snapshot.sequence:
            raise ContractError('checkpoint_invalid')
        frames = [_frame({'format': 'amx-owner-checkpoint-v1', 'binding': _binding(binding),
                          'recordCount': len(checked.records), 'cursor': checked.sequence})]
        total = len(frames[0])
        for item in checked.records:
            frame = _frame({'sequence': item.sequence,
                            'record': base64.b64encode(item.record).decode('ascii')})
            total += len(frame)
            if total > MAX_CHECKPOINT_BYTES - 128:
                raise ContractError('checkpoint_limit')
            frames.append(frame)
        body = b''.join(frames)
        return body + _frame({'digest': _digest(body)})
    except Exception:
        raise ContractError('checkpoint_invalid') from None


def read_checkpoint(raw: bytes, binding: OwnerBinding, *, expected_digest=None) -> FencedRecovery:
    """Check integrity and exact owner scope; never establish execution authority."""
    try:
        if type(raw) is not bytes or not raw or len(raw) > MAX_CHECKPOINT_BYTES or not raw.endswith(b'\n'):
            raise ValueError
        if expected_digest is not None and _digest(raw) != expected_digest:
            raise ValueError
        frames = raw.splitlines(keepends=True)
        if not 3 <= len(frames) <= MAX_RECORDS + 2 or any(len(x) > MAX_FRAME_BYTES for x in frames):
            raise ValueError
        values = [strict_loads(x) for x in frames]
        if any(_frame(value) != frame for value, frame in zip(values, frames)):
            raise ValueError
        head, tail = values[0], values[-1]
        if set(head) != {'format', 'binding', 'recordCount', 'cursor'} or head['format'] != 'amx-owner-checkpoint-v1':
            raise ValueError
        if head['binding'] != _binding(binding) or type(head['recordCount']) is not int or head['recordCount'] != len(values) - 2:
            raise ValueError
        if type(head['cursor']) is not int or tail != {'digest': _digest(b''.join(frames[:-1]))}:
            raise ValueError
        records = []
        for item in values[1:-1]:
            if set(item) != {'record', 'sequence'} or type(item['sequence']) is not int:
                raise ValueError
            record = base64.b64decode(item['record'], validate=True)
            if base64.b64encode(record).decode('ascii') != item['record']:
                raise ValueError
            records.append(StoredRecord(record=record, sequence=item['sequence']))
        snapshot = validate_history(tuple(records), binding)
        if snapshot.sequence != head['cursor']:
            raise ValueError
        return FencedRecovery(snapshot, _digest(raw))
    except Exception:
        raise ContractError('checkpoint_invalid') from None


def _directory(path):
    path = Path(path)
    if path.name in ('', '.', '..'):
        raise OSError
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    metadata = os.fstat(fd)
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
        os.close(fd)
        raise OSError
    return fd, path.name


def write_backup(path, checkpoint: bytes, binding: OwnerBinding) -> str:
    """Publish a complete private backup without replacing any existing name.

    An error after publication retains the destination and reports uncertainty.
    Read it back before retrying. Only this call's exact temporary inode is removed.
    """
    restored = read_checkpoint(checkpoint, binding)
    directory = descriptor = None
    temporary = identity = None
    published = False
    try:
        directory, name = _directory(path)
        temporary = '.amx-checkpoint-' + secrets.token_hex(16)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        os.fchmod(descriptor, 0o600)
        view = memoryview(checkpoint)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError
            view = view[count:]
        os.fsync(descriptor)
        os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        published = True
        os.fsync(directory)
        return restored.digest
    except FileExistsError:
        raise ContractError('backup_exists') from None
    except Exception:
        raise ContractError('backup_publication_uncertain' if published else 'backup_write_failed') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            try:
                if identity is not None:
                    metadata = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
                    if (metadata.st_dev, metadata.st_ino) == identity:
                        os.unlink(temporary, dir_fd=directory)
                        os.fsync(directory)
            except OSError:
                pass
            finally:
                os.close(directory)


def restore_backup(path, binding: OwnerBinding, *, expected_digest: str) -> FencedRecovery:
    """Read a trusted-inventory backup into fenced data, not a running owner."""
    directory = descriptor = None
    try:
        if type(expected_digest) is not str or len(expected_digest) != 71 or not expected_digest.startswith('sha256:'):
            raise ValueError
        directory, name = _directory(path)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o077 or before.st_size > MAX_CHECKPOINT_BYTES:
            raise ValueError
        chunks, total = [], 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_CHECKPOINT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CHECKPOINT_BYTES:
                raise ValueError
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError
        return read_checkpoint(b''.join(chunks), binding, expected_digest=expected_digest)
    except Exception:
        raise ContractError('backup_restore_failed') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)
