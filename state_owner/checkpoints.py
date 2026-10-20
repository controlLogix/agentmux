"""Multipart owner checkpoints with bounded memory and fenced restore.

Files are private, not encrypted. A trusted external manifest digest is required.
All retained outcomes and effects are copied; no effect runs and no source is
pruned. Off-volume protection and application-wide backup remain host duties.
"""
import base64
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from .history import OwnerHistory
from .ledger import StoredRecord, StreamIdentity, validate_record
from .recovery import _binding

DEFAULT_SHARD_BYTES = 8 * 1024 * 1024
MAX_SHARD_BYTES = 64 * 1024 * 1024
MAX_FRAME_BYTES = 128 * 1024
MAX_MANIFEST_BYTES = 512 * 1024
MAX_RECORDS = 1_000_000
DEFAULT_HISTORY_BYTES = 1_073_741_824
MAX_HISTORY_BYTES = 1_099_511_627_776
_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
_NAME = re.compile(r'part-[a-f0-9]{32}-[0-9]{6}\.jsonl\Z')


@dataclass(frozen=True, repr=False)
class CheckpointReceipt:
    manifest_path: str
    digest: str
    cursor: int


@dataclass(frozen=True, repr=False)
class FencedHistory:
    history: OwnerHistory = field(repr=False)
    digest: str
    cursor: int
    reconciliation_required: bool = field(default=True, init=False)

    def __repr__(self):
        return '<FencedHistory reconciliation-required>'


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _source(identity):
    return {'created': identity.created.isoformat(), 'minimumSequence': identity.minimum_sequence}


def _directory(path):
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parent.parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        meta = os.fstat(fd)
        if meta.st_uid != os.getuid() or meta.st_mode & 0o077:
            raise ValueError()
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def _publish(directory, name, raw, *, admit=None):
    temporary = '.checkpoint-' + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    metadata = None
    try:
        metadata = os.fstat(fd)
        if admit is not None:
            admit(fd)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError()
            view = view[count:]
        os.fsync(fd)
        if admit is not None:
            admit(fd)
        os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.fsync(directory)
    finally:
        os.close(fd)
        # Without an initial inode identity, retain the empty temporary file
        # rather than remove a path that could now refer to another object.
        if metadata is not None:
            current = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino):
                os.unlink(temporary, dir_fd=directory)
                os.fsync(directory)


def _read(directory, name, limit, *, admit=None):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or not 0 < before.st_size <= limit):
            raise ValueError()
        if admit is not None:
            admit(fd)
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        if admit is not None:
            admit(fd)
        if (len(raw) > limit or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError()
        return bytes(raw)
    finally:
        os.close(fd)


def _shard_size(source_bytes, record_count, requested):
    if not 1 <= source_bytes <= MAX_HISTORY_BYTES:
        raise ValueError()
    estimated_bytes = (source_bytes * 4 + 2) // 3 + record_count * 100
    max_parts = (MAX_MANIFEST_BYTES - 4096) // 256
    required = MAX_FRAME_BYTES + (estimated_bytes + max_parts - 1) // max_parts
    size = max(requested, required)
    if size > MAX_SHARD_BYTES:
        raise ValueError()
    return size


def export_checkpoint(manifest_path, history, binding, stream_identity, *, through=None,
                      shard_bytes=DEFAULT_SHARD_BYTES):
    """Publish shards, then the manifest; retain published files on any error."""
    directory = None
    try:
        if type(shard_bytes) is not int or not MAX_FRAME_BYTES <= shard_bytes <= MAX_SHARD_BYTES:
            raise ValueError()
        if history.source_identity.created != stream_identity.created:
            raise ValueError()
        retained_identity = StreamIdentity(stream_identity.created, max(
            stream_identity.minimum_sequence, history.source_identity.minimum_sequence))
        cursor = history.verified_cursor if through is None else through
        records = history.records(cursor)
        if not 1 <= len(records) <= MAX_RECORDS or cursor < retained_identity.minimum_sequence:
            raise ValueError()
        # Reserve manifest space before publishing any shards. Base64 and frame
        # overhead are bounded; the current cache total safely overestimates a
        # shorter prefix. Larger histories need larger shards, never more RAM
        # than the declared maximum. Reject unsupported manifests before writes.
        shard_bytes = _shard_size(history.total_bytes, len(records), shard_bytes)
        directory, name = _directory(manifest_path)
        token = secrets.token_hex(16)
        parts, buffer = [], bytearray()
        total = previous = 0
        def flush():
            part_name = f'part-{token}-{len(parts):06d}.jsonl'
            raw = buffer
            _publish(directory, part_name, raw)
            parts.append({'name': part_name, 'bytes': len(raw), 'digest': _digest(raw)})
            buffer.clear()
        for position, stored in enumerate(records, 1):
            value = validate_record(stored.record, binding)
            if value['previousRevision'] != previous or value['entityVersion'] != position:
                raise ValueError()
            previous = stored.sequence
            total += len(stored.record)
            if total > MAX_HISTORY_BYTES:
                raise ValueError()
            frame = canonical_bytes({'sequence': stored.sequence,
                                     'record': base64.b64encode(stored.record).decode('ascii')}) + b'\n'
            if len(frame) > MAX_FRAME_BYTES:
                raise ValueError()
            if len(buffer) + len(frame) > shard_bytes:
                flush()
            buffer.extend(frame)
        if buffer:
            flush()
        manifest = canonical_bytes({'format': 'amx-owner-checkpoint-parts-v1',
            'binding': _binding(binding), 'source': _source(retained_identity), 'cursor': cursor,
            'recordCount': len(records), 'recordBytes': total, 'shards': parts})
        if len(manifest) > MAX_MANIFEST_BYTES or previous != cursor:
            raise ValueError()
        _publish(directory, name, manifest)
        return _digest(manifest)
    except Exception:
        raise ContractError('checkpoint_export_uncertain') from None
    finally:
        if directory is not None:
            os.close(directory)


async def export_checkpoint_async(manifest_path, history, binding, stream_identity, *, through=None,
                                  shard_bytes=DEFAULT_SHARD_BYTES):
    """Publish from bounded owner-thread pages and join the original file worker.

    Returns the manifest digest after publication. The host supplies a fresh
    generation path and durably inventories that path, digest, cursor and source
    binding before advancing checkpoint cadence. Keep history open until return,
    including while cancellation waits for worker and callback cleanup.
    """
    from ._history_worker import run_history_worker
    def write(view, call_on_owner):
        return export_checkpoint(manifest_path, view, binding, stream_identity,
                                 through=view.verified_cursor, shard_bytes=shard_bytes)
    try:
        return await run_history_worker(history, write, through=through)
    except Exception:
        raise ContractError('checkpoint_export_uncertain') from None


def load_checkpoint(manifest_path, *, expected_digest, binding, stream_identity,
                    history_path, max_records=MAX_RECORDS, max_bytes=DEFAULT_HISTORY_BYTES,
                    _source_directory=None, _admit=None):
    """Restore to a fresh cache; errors close it and never return partial data.

    The enrolled host must verify the checkpoint head against its live leader
    before adopting this prefix. A restored owner remains fenced until recovery
    authority and external execution history have been reconciled.
    """
    directory = cache_directory = None
    history = None
    completed = False
    try:
        if not isinstance(expected_digest, str) or not _DIGEST.fullmatch(expected_digest):
            raise ValueError()
        if _source_directory is None:
            directory, name = _directory(manifest_path)
        else:
            directory, name = os.dup(_source_directory), Path(manifest_path).name
        raw = _read(directory, name, MAX_MANIFEST_BYTES, admit=_admit)
        if _digest(raw) != expected_digest:
            raise ValueError()
        manifest = strict_loads(raw)
        if (canonical_bytes(manifest) != raw
                or set(manifest) != {'format', 'binding', 'source', 'cursor', 'recordCount', 'recordBytes', 'shards'}
                or manifest['format'] != 'amx-owner-checkpoint-parts-v1'
                or manifest['binding'] != _binding(binding)
                or type(manifest['source']) is not dict
                or set(manifest['source']) != {'created', 'minimumSequence'}
                or manifest['source']['created'] != stream_identity.created.isoformat()
                or type(manifest['source']['minimumSequence']) is not int
                or not 0 <= manifest['source']['minimumSequence'] <= manifest['cursor']
                or type(manifest['recordCount']) is not int or not 1 <= manifest['recordCount'] <= max_records
                or type(manifest['recordBytes']) is not int or not 1 <= manifest['recordBytes'] <= max_bytes
                or type(manifest['cursor']) is not int or manifest['cursor'] < stream_identity.minimum_sequence
                or type(manifest['shards']) is not list or not 1 <= len(manifest['shards']) <= MAX_RECORDS):
            raise ValueError()
        names = set()
        for part in manifest['shards']:
            if (type(part) is not dict or set(part) != {'name', 'bytes', 'digest'}
                    or not isinstance(part['name'], str) or not _NAME.fullmatch(part['name'])
                    or part['name'] in names or type(part['bytes']) is not int
                    or not 1 <= part['bytes'] <= MAX_SHARD_BYTES
                    or not isinstance(part['digest'], str) or not _DIGEST.fullmatch(part['digest'])):
                raise ValueError()
            names.add(part['name'])
        cache_directory, cache_name = _directory(history_path)
        fd = os.open(cache_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=cache_directory)
        os.close(fd)
        retained_identity = StreamIdentity(stream_identity.created, max(
            stream_identity.minimum_sequence, manifest['source']['minimumSequence']))
        history = OwnerHistory(history_path, binding, stream_identity=retained_identity,
                               max_records=max_records, max_bytes=max_bytes)
        count = total = 0
        for part in manifest['shards']:
            shard = _read(directory, part['name'], MAX_SHARD_BYTES, admit=_admit)
            if len(shard) != part['bytes'] or _digest(shard) != part['digest'] or not shard.endswith(b'\n'):
                raise ValueError()
            offset = 0
            while offset < len(shard):
                end = shard.find(b'\n', offset, offset + MAX_FRAME_BYTES)
                if end < 0:
                    raise ValueError()
                frame = shard[offset:end + 1]
                offset = end + 1
                if len(frame) > MAX_FRAME_BYTES:
                    raise ValueError()
                value = strict_loads(frame)
                if set(value) != {'sequence', 'record'} or canonical_bytes(value) + b'\n' != frame:
                    raise ValueError()
                record = base64.b64decode(value['record'], validate=True)
                if base64.b64encode(record).decode('ascii') != value['record']:
                    raise ValueError()
                history.verify_source(StoredRecord(record, value['sequence']))
                count += 1
                total += len(record)
                if count > manifest['recordCount'] or total > manifest['recordBytes']:
                    raise ValueError()
        if (count != manifest['recordCount'] or total != manifest['recordBytes']
                or history.verified_cursor != manifest['cursor']):
            raise ValueError()
        completed = True
        return FencedHistory(history, expected_digest, manifest['cursor'])
    except Exception:
        raise ContractError('checkpoint_restore_failed') from None
    finally:
        cleanup_error = None
        for descriptor in (directory, cache_directory):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    cleanup_error = cleanup_error or error
        if history is not None and (not completed or cleanup_error is not None):
            try:
                history.close()
            except BaseException as error:
                cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            if isinstance(cleanup_error, Exception):
                raise ContractError('checkpoint_restore_failed') from None
            raise cleanup_error


class CheckpointCadence:
    """Host-driven checkpoint policy; no timers, background work or authority.

    Call due on each owner observation and a host timer. Supply monotonic seconds
    and the dedicated owner cursor. Sequence gaps may request a checkpoint early.
    Call completed only after durable manifest publication has succeeded.
    """
    def __init__(self, *, cursor=0, now=0):
        self._cursor = self._observed = cursor
        self._now = now
        self._dirty_since = None
        self._validate(cursor, now)

    def __repr__(self):
        return '<CheckpointCadence private>'

    def _validate(self, cursor, now):
        import math
        if (type(cursor) is not int or not 0 <= cursor <= 9_007_199_254_740_991
                or type(now) not in (int, float) or not math.isfinite(now) or now < 0
                or cursor < self._cursor or now < self._now):
            raise ContractError('checkpoint_cadence_invalid')

    def due(self, cursor, now):
        self._validate(cursor, now)
        if cursor < self._observed:
            raise ContractError('checkpoint_cadence_invalid')
        self._observed, self._now = cursor, now
        if cursor > self._cursor and self._dirty_since is None:
            self._dirty_since = now
        return (cursor - self._cursor >= 10_000 or
                (self._dirty_since is not None and now - self._dirty_since >= 900))

    def completed(self, cursor, now):
        self._validate(cursor, now)
        self._cursor, self._now = cursor, now
        self._observed = max(self._observed, cursor)
        # Completion of an older prefix must not hide newer observed changes.
        if cursor == self._observed:
            self._dirty_since = None
