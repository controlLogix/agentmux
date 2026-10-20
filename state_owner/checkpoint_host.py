"""Protected local checkpoint receipts for one enrolled owner and stream.

This recovery inventory is not a business-state ledger or an encrypted backup.
It never deletes a generation, advances a source, or permits restored effects.
"""
import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import re
import stat
import tempfile
import threading

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from .backup_host import BackupHost, _native_guard
from .checkpoints import (CheckpointReceipt, load_checkpoint, _directory, _read, _publish,
                          _digest, _DIGEST, MAX_RECORDS, DEFAULT_HISTORY_BYTES)
from .ledger import OwnerBinding, StreamIdentity, owner_subject
from .recovery import _binding

MAX_ENTRIES = 100_000
MAX_ENTRY_BYTES = 4096


def _durable_checkpoint_file(fd):
    _native_guard(fd)
    os.fsync(fd)


@dataclass(frozen=True, repr=False)
class CheckpointEntry:
    receipt: CheckpointReceipt
    stream_identity: StreamIdentity


class CheckpointHost:
    def __init__(self, checkpoint_prefix, *, stream, commit_ref, binding, stream_identity,
                 max_records=MAX_RECORDS, max_bytes=DEFAULT_HISTORY_BYTES):
        try:
            prefix = Path(checkpoint_prefix)
            if (not prefix.is_absolute() or str(prefix) != os.path.normpath(str(prefix))
                    or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', prefix.name)
                    or not isinstance(binding, OwnerBinding) or not isinstance(stream_identity, StreamIdentity)
                    or not isinstance(stream, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', stream)
                    or type(commit_ref) is not dict or set(commit_ref) != {'id', 'ownerHubId', 'revision'}
                    or not isinstance(commit_ref['id'], str)
                    or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', commit_ref['id'])
                    or commit_ref['ownerHubId'] != binding.hub_id
                    or type(commit_ref['revision']) is not int or not 0 <= commit_ref['revision'] <= 9_007_199_254_740_991
                    or type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS
                    or type(max_bytes) is not int or not 65_536 <= max_bytes <= 1_099_511_627_776):
                raise ValueError()
            self._prefix, self._stream, self._binding = prefix, stream, binding
            self._ref = canonical_bytes(commit_ref)
            self._identity = stream_identity
            self._floor = stream_identity.minimum_sequence
            self._inventory_floor = 0
            self._max_records, self._max_bytes = max_records, max_bytes
            self._namespace = 'checkpoint-inventory-' + _digest(self._ref).split(':')[1] + '-'
            self._generation = re.compile(re.escape(prefix.name) + r'\.([1-9][0-9]{0,15})\.[a-f0-9]{32}\.json\Z')
            self._lock = threading.RLock()
            fd, _ = _directory(prefix)
            try:
                info = os.fstat(fd)
                if stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError()
                BackupHost._ancestor_identities(fd)
                self._root_identity = info.st_dev, info.st_ino
            finally:
                os.close(fd)
        except Exception:
            raise ContractError('checkpoint_host_configuration') from None

    def __repr__(self):
        return '<CheckpointHost private>'

    @property
    def binding(self):
        return self._binding

    @property
    def stream(self):
        return self._stream

    @property
    def checkpoint_prefix(self):
        return self._prefix

    @property
    def commit_ref(self):
        return strict_loads(self._ref)

    @property
    def stream_identity(self):
        return self._identity

    def _open(self):
        fd, _ = _directory(self._prefix)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self._root_identity or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError()
            BackupHost._ancestor_identities(fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _receipt(self, receipt):
        if (type(receipt) is not CheckpointReceipt or type(receipt.manifest_path) is not str
                or type(receipt.cursor) is not int or not 1 <= receipt.cursor <= 9_007_199_254_740_991
                or not isinstance(receipt.digest, str) or not _DIGEST.fullmatch(receipt.digest)):
            raise ValueError()
        path = Path(receipt.manifest_path)
        match = self._generation.fullmatch(path.name)
        if path.parent != self._prefix.parent or str(path) != receipt.manifest_path or match is None or int(match[1]) != receipt.cursor:
            raise ValueError()

    def _acquire(self, directory):
        name = '.checkpoint-custody-' + _digest(self._ref).split(':')[1] + '.lock'
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=directory)
        acquired = False
        try:
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
                raise ValueError()
            _native_guard(fd)
            # A competing host must retry explicitly. Never wait indefinitely
            # or publish against an inventory being changed by another host.
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ValueError()
            acquired = True
            return fd
        finally:
            if not acquired:
                os.close(fd)

    @contextmanager
    def _custody(self):
        with self._lock:
            directory = lock = None
            try:
                directory = self._open()
                lock = self._acquire(directory)
                yield directory
            finally:
                try:
                    if lock is not None:
                        try:
                            fcntl.flock(lock, fcntl.LOCK_UN)
                        finally:
                            os.close(lock)
                finally:
                    if directory is not None:
                        os.close(directory)

    def _encode(self, receipt):
        return canonical_bytes({'format': 'amx-owner-checkpoint-receipt-v1',
            'commitRef': strict_loads(self._ref), 'binding': _binding(self._binding),
            'stream': self._stream, 'subject': owner_subject(self._binding),
            'source': {'created': self._identity.created.isoformat(), 'minimumSequence': receipt.cursor},
            'manifestPath': receipt.manifest_path, 'digest': receipt.digest, 'cursor': receipt.cursor})

    def _decode(self, raw):
        value = strict_loads(raw)
        receipt = CheckpointReceipt(value['manifestPath'], value['digest'], value['cursor'])
        self._receipt(receipt)
        if self._encode(receipt) != raw:
            raise ValueError()
        return CheckpointEntry(receipt, StreamIdentity(self._identity.created, receipt.cursor))

    def _latest(self, directory):
        selected = None
        count = 0
        with os.scandir(directory) as entries:
            for item in entries:
                if not item.name.startswith(self._namespace):
                    continue
                count += 1
                if count > MAX_ENTRIES or not re.fullmatch(re.escape(self._namespace) + r'[a-f0-9]{64}\.json', item.name):
                    raise ValueError()
                raw = _read(directory, item.name, MAX_ENTRY_BYTES, admit=_native_guard)
                if item.name != self._namespace + _digest(raw).split(':')[1] + '.json':
                    raise ValueError()
                entry = self._decode(raw)
                if selected is None or (entry.receipt.cursor, entry.receipt.digest) > (selected.receipt.cursor, selected.receipt.digest):
                    selected = entry
        if selected is not None:
            self._floor = max(self._floor, selected.receipt.cursor)
            self._inventory_floor = max(self._inventory_floor, selected.receipt.cursor)
        if self._inventory_floor > (0 if selected is None else selected.receipt.cursor):
            raise ValueError()
        return selected

    def _verify(self, receipt, directory):
        # Use the existing complete restore validator, including operation/effect
        # indexes. This disposable cache never becomes a live owner or authority.
        with tempfile.TemporaryDirectory(prefix='.checkpoint-verify-', dir=self._prefix.parent) as temporary:
            restored = load_checkpoint(receipt.manifest_path, expected_digest=receipt.digest,
                binding=self._binding, stream_identity=StreamIdentity(self._identity.created, receipt.cursor),
                history_path=Path(temporary) / 'history.sqlite', max_records=self._max_records,
                max_bytes=self._max_bytes, _source_directory=directory, _admit=_durable_checkpoint_file)
            try:
                if restored.cursor != receipt.cursor:
                    raise ValueError()
            finally:
                restored.history.close()

    def commit(self, receipt):
        """Acknowledge only a fully verified generation and synced receipt."""
        try:
            with self._custody() as directory:
                self._receipt(receipt)
                self._latest(directory)
                if receipt.cursor < self._floor:
                    raise ValueError()
                self._verify(receipt, directory)
                raw = self._encode(receipt)
                if len(raw) > MAX_ENTRY_BYTES:
                    raise ValueError()
                name = self._namespace + _digest(raw).split(':')[1] + '.json'
                try:
                    existing = _read(directory, name, MAX_ENTRY_BYTES, admit=_native_guard)
                except FileNotFoundError:
                    _publish(directory, name, raw, admit=_native_guard)
                else:
                    if existing != raw:
                        raise ValueError()
                if _read(directory, name, MAX_ENTRY_BYTES, admit=_native_guard) != raw:
                    raise ValueError()
                os.fsync(directory)
                self._floor = max(self._floor, receipt.cursor)
                selected = self._latest(directory)
                if selected is None or selected.receipt.cursor != receipt.cursor:
                    raise ValueError()
                current = self._open()
                os.close(current)
                return self._decode(raw)
        except Exception:
            raise ContractError('checkpoint_inventory_commit_uncertain') from None

    def latest(self):
        """Resolve trusted receipts only; never derive trust from export files."""
        try:
            with self._custody() as directory:
                selected = self._latest(directory)
                if selected is not None:
                    self._verify(selected.receipt, directory)
                    os.fsync(directory)
                current = self._open()
                os.close(current)
                return selected
        except Exception:
            raise ContractError('checkpoint_inventory_unavailable') from None

    async def _run(self, function, *args):
        worker = asyncio.create_task(asyncio.to_thread(function, *args))
        cancelled = None
        finished = asyncio.Event()
        worker.add_done_callback(lambda _: finished.set())
        while not worker.done():
            try:
                await finished.wait()
            except asyncio.CancelledError as error:
                cancelled = cancelled or error
        if cancelled is not None:
            if not worker.cancelled():
                worker.exception()
            raise cancelled
        return worker.result()

    async def committed(self, receipt):
        return await self._run(self.commit, receipt)

    async def resolve(self):
        return await self._run(self.latest)

    def restore(self, history_path):
        """Build a fenced cache on this calling thread; its caller owns close.

        This synchronous method preserves SQLite thread ownership. It does not
        make a service ready or resolve external effects/reservations.
        """
        result = None
        try:
            with self._custody() as directory:
                entry = self._latest(directory)
                if entry is None:
                    raise ValueError()
                result = load_checkpoint(entry.receipt.manifest_path, expected_digest=entry.receipt.digest,
                    binding=self._binding, stream_identity=StreamIdentity(self._identity.created, self._floor),
                    history_path=history_path, max_records=self._max_records, max_bytes=self._max_bytes,
                    _source_directory=directory, _admit=_native_guard)
                os.fsync(directory)
                current = self._open()
                os.close(current)
            # Transfer cache ownership only after all descriptor cleanup succeeds.
            return result
        except BaseException as error:
            try:
                if result is not None:
                    result.history.close()
            finally:
                if isinstance(error, Exception):
                    raise ContractError('checkpoint_inventory_restore_failed') from None
            raise

    async def recovery_identity(self):
        def resolve():
            with self._lock:
                self.latest()
                return StreamIdentity(self._identity.created, self._floor)
        return await self._run(resolve)
