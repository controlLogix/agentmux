"""Encrypted single-owner backups; never run effects or activate restored writes.

The host supplies keys and current artifact authorization. It also owns protected
storage, key custody and scheduling. Total ciphertext and artifact counts are
explicitly bounded; local plaintext staging also needs its own disk budget. Plaintext checkpoint staging is temporary
local storage, never the backup destination. Published orphan ciphertext is kept
on failure. These helpers do not establish multi-owner consistency or RPO/RTO.
"""
import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import tempfile

from nacl.secret import SecretBox
from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from .checkpoints import (_directory, _publish, _read, _digest,
                          export_checkpoint, load_checkpoint, MAX_SHARD_BYTES)
from .recovery import _binding
from .ledger import validate_record

MAX_MANIFEST = 512 * 1024
MAX_ARTIFACTS = 4096
MAX_TOTAL = 1_099_511_627_776
OVERHEAD = SecretBox.NONCE_SIZE + SecretBox.MACBYTES
_NAME = re.compile(r'backup-[a-f0-9]{32}\.box\Z')
_PART = re.compile(r'part-[a-f0-9]{32}-[0-9]{6}\.jsonl\Z')
_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')


@dataclass(frozen=True)
class BackupReceipt:
    manifest_name: str
    digest: str
    cursor: int


def _config(key, max_total_bytes, max_artifacts):
    if (type(key) is not bytes or len(key) != SecretBox.KEY_SIZE
            or type(max_total_bytes) is not int or not 1 <= max_total_bytes <= MAX_TOTAL
            or type(max_artifacts) is not int or not 0 <= max_artifacts <= MAX_ARTIFACTS):
        raise ValueError()
    return SecretBox(key)


def _refs(records, binding, max_artifacts, max_total_bytes):
    identities, references = {}, {}
    total = 0
    for stored in records:
        value = validate_record(stored.record, binding)
        total += len(stored.record)
        if total > max_total_bytes:
            raise ValueError()
        for reference in value['artifacts']:
            full = canonical_bytes(reference)
            identity = canonical_bytes({k: reference[k] for k in ('ownerHubId', 'storeRef', 'artifactId', 'version')})
            if identity in identities and identities[identity] != full:
                raise ValueError()
            identities[identity] = full
            if full not in references:
                if len(references) >= max_artifacts or reference['bytes'] > MAX_SHARD_BYTES:
                    raise ValueError()
                total += reference['bytes']
                if total > max_total_bytes:
                    raise ValueError()
                references[full] = reference
    return references


def _data(raw, reference):
    if type(raw) is not bytes or len(raw) != reference['bytes'] or _digest(raw) != reference['digest']:
        raise ValueError()


def _name():
    return 'backup-' + secrets.token_hex(16) + '.box'


def _decrypt(directory, component, box):
    raw = _read(directory, component['name'], component['cipherBytes'])
    if len(raw) != component['cipherBytes'] or _digest(raw) != component['cipherDigest']:
        raise ValueError()
    plain = box.decrypt(raw)
    if len(plain) != component['plainBytes'] or _digest(plain) != component['plainDigest']:
        raise ValueError()
    return plain


async def export_backup(directory, history, binding, stream_identity, *, key,
                        retrieve_artifact, max_total_bytes=1_073_741_824, max_artifacts=1024):
    """Capture one verified prefix and publish its encrypted top manifest last.

    retrieve_artifact is a trusted async resolver that rechecks current access,
    typically OwnerArtifacts.retrieve after the receiving service authorizes it.
    max_total_bytes covers ciphertext including encryption overhead and the top
    manifest. Each artifact is limited to 64 MiB. Private local staging needs
    disk space for the whole plaintext checkpoint. Failure before final
    publication may leave ciphertext components; a final publication error is
    uncertain and may leave a complete top manifest.

    SQLite pages and authorized artifact reads stay on the caller's event loop.
    An owned worker serializes, encrypts and publishes files. Cancellation joins
    that worker and all reader cleanup before returning; keep history open until
    then. A blocked disk can delay cancellation and publication remains uncertain.
    """
    from ._history_worker import run_history_worker
    async def retrieve(reference):
        async with asyncio.timeout(60):
            return await retrieve_artifact(reference)
    def write(view, call_on_owner):
        return _export_backup(directory, view, binding, stream_identity, key=key,
                              retrieve_artifact=retrieve, call_on_owner=call_on_owner,
                              max_total_bytes=max_total_bytes, max_artifacts=max_artifacts)
    try:
        return await run_history_worker(history, write)
    except Exception:
        raise ContractError('owner_backup_export_uncertain') from None


def _export_backup(directory, history, binding, stream_identity, *, key,
                   retrieve_artifact, call_on_owner, max_total_bytes, max_artifacts):
    destination = None
    try:
        box = _config(key, max_total_bytes, max_artifacts)
        cursor = history.verified_cursor
        references = _refs(history.records(cursor), binding, max_artifacts, max_total_bytes)
        top_name = _name()
        destination, _ = _directory(Path(directory) / top_name)
        components = []
        total = 0
        with tempfile.TemporaryDirectory(prefix='amx-backup-') as temporary:
            staging = Path(temporary).resolve()
            if staging.is_relative_to(Path(directory).resolve()):
                raise ValueError()
            checkpoint_path = staging / 'manifest.json'
            checkpoint_digest = export_checkpoint(checkpoint_path, history, binding, stream_identity, through=cursor)
            checkpoint_raw = checkpoint_path.read_bytes()
            checkpoint = strict_loads(checkpoint_raw)
            manifest = {'format': 'amx-owner-encrypted-backup-v1', 'binding': _binding(binding),
                        'source': checkpoint['source'], 'cursor': cursor,
                        'checkpointDigest': checkpoint_digest, 'components': components}

            def publish(raw, kind, logical=None, reference=None):
                nonlocal total
                if len(raw) > MAX_SHARD_BYTES:
                    raise ValueError()
                encrypted = bytes(box.encrypt(raw))
                entry = {'name': _name(), 'kind': kind, 'plainBytes': len(raw),
                         'plainDigest': _digest(raw), 'cipherBytes': len(encrypted),
                         'cipherDigest': _digest(encrypted), 'logical': logical, 'reference': reference}
                components.append(entry)
                if len(canonical_bytes(manifest)) > MAX_MANIFEST:
                    raise ValueError()
                total += len(encrypted)
                if total + len(canonical_bytes(manifest)) + OVERHEAD > max_total_bytes:
                    raise ValueError()
                _publish(destination, entry['name'], encrypted)

            publish(checkpoint_raw, 'checkpoint', logical='manifest.json')
            for shard in checkpoint['shards']:
                raw = (staging / shard['name']).read_bytes()
                if len(raw) != shard['bytes'] or _digest(raw) != shard['digest']:
                    raise ValueError()
                publish(raw, 'checkpoint', logical=shard['name'])
            for reference in references.values():
                raw = call_on_owner(retrieve_artifact, strict_loads(canonical_bytes(reference)))
                _data(raw, reference)
                publish(raw, 'artifact', reference=reference)
            top = bytes(box.encrypt(canonical_bytes(manifest)))
            if total + len(top) > max_total_bytes:
                raise ValueError()
            _publish(destination, top_name, top)
            return BackupReceipt(top_name, _digest(top), cursor)
    except Exception:
        raise ContractError('owner_backup_export_uncertain') from None
    finally:
        if destination is not None:
            os.close(destination)


class FencedBackup:
    """Verified local artifact reads plus history that still needs reconciliation."""
    def __init__(self, restored, directory, box, artifacts):
        self._restored, self._directory, self._box = restored, Path(directory).resolve(), box
        self._artifacts = artifacts

    def __repr__(self):
        return '<FencedBackup reconciliation-required>'

    @property
    def history(self):
        return self._restored.history

    @property
    def cursor(self):
        return self._restored.cursor

    @property
    def reconciliation_required(self):
        return True

    def retrieve(self, reference):
        directory = None
        try:
            if self._box is None:
                raise ValueError()
            full = canonical_bytes(reference)
            entry = self._artifacts[full]
            directory, _ = _directory(self._directory / entry['name'])
            raw = _decrypt(directory, entry, self._box)
            _data(raw, reference)
            return raw
        except Exception:
            raise ContractError('owner_backup_artifact_unavailable') from None
        finally:
            if directory is not None:
                os.close(directory)

    def close(self):
        self._box = None
        self._restored.history.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def restore_backup(directory, manifest_name, *, expected_digest, key, binding,
                   stream_identity, history_path, max_total_bytes=1_073_741_824,
                   max_artifacts=1024, max_history_bytes=1_073_741_824):
    """Require trusted ciphertext identity; restore no live source or effects.

    max_total_bytes includes all ciphertext and encryption overhead. Each artifact
    is limited to 64 MiB. Private local staging needs space for the whole plaintext
    checkpoint, in addition to the separate restored SQLite cache and its indexes.
    """
    source = None
    restored = None
    result = None
    completed = False
    try:
        box = _config(key, max_total_bytes, max_artifacts)
        if (not isinstance(manifest_name, str) or not _NAME.fullmatch(manifest_name)
                or not isinstance(expected_digest, str) or not _DIGEST.fullmatch(expected_digest)):
            raise ValueError()
        # The restored SQLite cache contains plaintext and belongs outside backup storage.
        if Path(history_path).resolve().is_relative_to(Path(directory).resolve()):
            raise ValueError()
        source, _ = _directory(Path(directory) / manifest_name)
        encrypted = _read(source, manifest_name, min(MAX_MANIFEST + OVERHEAD, max_total_bytes))
        if _digest(encrypted) != expected_digest:
            raise ValueError()
        raw = box.decrypt(encrypted)
        manifest = strict_loads(raw)
        if (len(raw) > MAX_MANIFEST or canonical_bytes(manifest) != raw
                or set(manifest) != {'format', 'binding', 'source', 'cursor', 'checkpointDigest', 'components'}
                or manifest['format'] != 'amx-owner-encrypted-backup-v1'
                or manifest['binding'] != _binding(binding)
                or type(manifest['source']) is not dict
                or set(manifest['source']) != {'created', 'minimumSequence'}
                or manifest['source']['created'] != stream_identity.created.isoformat()
                or type(manifest['source']['minimumSequence']) is not int
                or type(manifest['cursor']) is not int
                or not 0 <= manifest['source']['minimumSequence'] <= manifest['cursor']
                or manifest['cursor'] < stream_identity.minimum_sequence
                or not _DIGEST.fullmatch(manifest['checkpointDigest'])
                or type(manifest['components']) is not list
                or not 2 <= len(manifest['components']) <= 8192):
            raise ValueError()
        names, logical_names, artifacts = {manifest_name}, set(), {}
        total = len(encrypted)
        with tempfile.TemporaryDirectory(prefix='amx-restore-') as temporary:
            staging = Path(temporary).resolve()
            if staging.is_relative_to(Path(directory).resolve()):
                raise ValueError()
            checkpoint_raw = None
            for entry in manifest['components']:
                if (type(entry) is not dict or set(entry) != {'name', 'kind', 'plainBytes', 'plainDigest', 'cipherBytes', 'cipherDigest', 'logical', 'reference'}
                        or not isinstance(entry['name'], str) or not _NAME.fullmatch(entry['name'])
                        or entry['name'] in names or type(entry['plainBytes']) is not int
                        or not 0 <= entry['plainBytes'] <= MAX_SHARD_BYTES
                        or type(entry['cipherBytes']) is not int or entry['cipherBytes'] != entry['plainBytes'] + OVERHEAD
                        or not isinstance(entry['plainDigest'], str) or not _DIGEST.fullmatch(entry['plainDigest'])
                        or not isinstance(entry['cipherDigest'], str) or not _DIGEST.fullmatch(entry['cipherDigest'])):
                    raise ValueError()
                names.add(entry['name'])
                total += entry['cipherBytes']
                if total > max_total_bytes:
                    raise ValueError()
                plain = _decrypt(source, entry, box)
                if entry['kind'] == 'checkpoint':
                    logical = entry['logical']
                    if (entry['reference'] is not None or not isinstance(logical, str)
                            or (logical != 'manifest.json' and not _PART.fullmatch(logical))
                            or logical in logical_names):
                        raise ValueError()
                    logical_names.add(logical)
                    # Staging is newly created private storage, never the destination.
                    fd = os.open(staging / logical, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as output:
                        output.write(plain)
                    if logical == 'manifest.json':
                        checkpoint_raw = plain
                elif entry['kind'] == 'artifact':
                    if entry['logical'] is not None or len(artifacts) >= max_artifacts:
                        raise ValueError()
                    reference = entry['reference']
                    _data(plain, reference)
                    full = canonical_bytes(reference)
                    if full in artifacts:
                        raise ValueError()
                    artifacts[full] = entry
                else:
                    raise ValueError()
            if checkpoint_raw is None or _digest(checkpoint_raw) != manifest['checkpointDigest']:
                raise ValueError()
            checkpoint = strict_loads(checkpoint_raw)
            if (logical_names != {'manifest.json', *(item['name'] for item in checkpoint['shards'])}
                    or checkpoint['cursor'] != manifest['cursor'] or checkpoint['source'] != manifest['source']):
                raise ValueError()
            restored = load_checkpoint(staging / 'manifest.json', expected_digest=manifest['checkpointDigest'],
                binding=binding, stream_identity=stream_identity, history_path=history_path,
                max_bytes=max_history_bytes)
            expected_refs = _refs(restored.history.records(restored.cursor), binding, max_artifacts, max_total_bytes)
            if set(expected_refs) != set(artifacts):
                raise ValueError()
        result = FencedBackup(restored, directory, box, artifacts)
        completed = True
        return result
    except Exception:
        raise ContractError('owner_backup_restore_failed') from None
    finally:
        cleanup_error = None
        if source is not None:
            try:
                os.close(source)
            except BaseException as error:
                cleanup_error = error
        if restored is not None and (not completed or cleanup_error is not None):
            try:
                if result is not None:
                    result.close()
                else:
                    restored.history.close()
            except BaseException as error:
                cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            if isinstance(cleanup_error, Exception):
                raise ContractError('owner_backup_restore_failed') from None
            raise cleanup_error
