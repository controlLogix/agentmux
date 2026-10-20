"""Private immutable ordinary generations; identity remains the authority.

This owner-only API stages bytes before a signed enrollment commits. It supplies
private material only to the fixed trusted consumer, never to a plugin handle.
The following owner must retain effect intent and outcomes in its NATS ledger.
"""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import threading
import weakref

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from identity.authority import LedgerAuthorityReader, evaluate_snapshot, _active
from identity.ordinary_secret import OrdinarySecretAuthority
from identity.transitions import transition
from .secret_custody import (PrivateSecret, SECRET_LIMIT, _FILE_LIMIT, _admit,
    _open_namespace, _open_root, _read_file)
from .descriptor_admission import DescriptorPurpose


def _refused(code='ordinary_secret_custody_refused'):
    raise ContractError(code)


def _binding(value):
    value = strict_loads(canonical_bytes(value))
    validate('identity-ordinary-secret-reference', value)
    if (value['status'] != 'active' or value['generationRef'] != value['ref']
            or value['ref']['revision'] != 1):
        _refused()
    return canonical_bytes(value)


def _directory_identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


class _OrdinarySecretStore:
    """Reuse native admission and descriptor traversal, with a separate format."""
    def __init__(self, root):
        self._root = Path(root)
        self._fd = _open_root(self._root)
        try:
            self._identity = _directory_identity(self._fd)
        except BaseException:
            os.close(self._fd)
            self._fd = None
            raise
        self._busy = threading.Lock()

    def __repr__(self):
        return '<_OrdinarySecretStore private>'

    def _check(self):
        if self._fd is None:
            _refused('ordinary_secret_custody_closed')
        _admit(self._fd, DescriptorPurpose.PRIVATE_DIRECTORY)
        current = _open_root(self._root)
        try:
            if (_directory_identity(current) != self._identity
                    or _directory_identity(self._fd) != self._identity):
                _refused('ordinary_secret_custody_changed')
        finally:
            os.close(current)

    @staticmethod
    def _encoded(binding, secret):
        if type(secret) is not bytes or not 0 < len(secret) <= SECRET_LIMIT:
            _refused()
        raw = canonical_bytes({'format': 'agentmux-ordinary-secret-custody-v1',
            'binding': strict_loads(binding),
            'bindingSha256': 'sha256:' + hashlib.sha256(binding).hexdigest(),
            'secretBase64': base64.b64encode(secret).decode('ascii')})
        if len(raw) > _FILE_LIMIT:
            _refused()
        return raw

    @staticmethod
    def _decoded(raw, binding):
        try:
            value = strict_loads(raw)
            if (set(value) != {'format', 'binding', 'bindingSha256', 'secretBase64'}
                    or value['format'] != 'agentmux-ordinary-secret-custody-v1'
                    or canonical_bytes(value['binding']) != binding
                    or value['bindingSha256'] != 'sha256:' + hashlib.sha256(binding).hexdigest()):
                raise ValueError
            secret = base64.b64decode(value['secretBase64'], validate=True)
            if not 0 < len(secret) <= SECRET_LIMIT:
                raise ValueError
            return PrivateSecret(secret)
        except Exception:
            _refused('ordinary_secret_custody_changed')

    def _access(self, binding, secret=None):
        if not self._busy.acquire(blocking=False):
            _refused('ordinary_secret_custody_busy')
        try:
            return self._access_locked(binding, secret)
        finally:
            self._busy.release()

    def _access_locked(self, binding, secret):
        binding = _binding(strict_loads(binding))
        item = strict_loads(binding)
        self._check()
        descriptors = []
        locked = False
        try:
            try:
                fcntl.flock(self._fd, (fcntl.LOCK_EX if secret is not None else fcntl.LOCK_SH)
                            | fcntl.LOCK_NB)
                locked = True
            except BlockingIOError:
                _refused('ordinary_secret_custody_busy')
            directory = self._fd
            for component in ('ordinary-secrets', item['ref']['ownerHubId'], item['ref']['id']):
                directory = _open_namespace(directory, component, create=secret is not None)
                descriptors.append(directory)
            name = '1.secret'
            if secret is not None:
                expected = self._encoded(binding, secret)
                try:
                    existing = _read_file(directory, name)
                except FileNotFoundError:
                    fd = None
                    try:
                        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     os.O_NOFOLLOW, 0o600, dir_fd=directory)
                        _admit(fd, DescriptorPurpose.PRIVATE_FILE)
                        offset = 0
                        while offset < len(expected):
                            written = os.write(fd, expected[offset:])
                            if written <= 0:
                                _refused('ordinary_secret_custody_write_uncertain')
                            offset += written
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                    finally:
                        if fd is not None:
                            os.close(fd)
                    os.fsync(directory)
                    existing = _read_file(directory, name)
                if existing != expected:
                    _refused('ordinary_secret_custody_recovery_required')
                self._decoded(existing, binding)
                self._check()
                return item['generationRef']
            result = self._decoded(_read_file(directory, name), binding)
            self._check()
            return result
        except ContractError:
            raise
        except Exception:
            _refused('ordinary_secret_custody_unavailable')
        finally:
            for fd in reversed(descriptors):
                os.close(fd)
            if locked:
                fcntl.flock(self._fd, fcntl.LOCK_UN)

    def provision(self, binding, secret):
        return self._access(binding, secret)

    def read(self, binding):
        return self._access(binding)

    def close(self):
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)


class OrdinarySecretUse:
    """An owner-local correlation handle, never a reusable authorization permit."""
    __slots__ = ('__weakref__',)

    def __new__(cls):
        _refused('ordinary_secret_custody_admission_required')

    def __repr__(self):
        return '<OrdinarySecretUse private; current authority required>'

    def __reduce__(self):
        raise TypeError('OrdinarySecretUse cannot be serialized.')


@dataclass(frozen=True, slots=True)
class _Use:
    request: bytes
    binding: bytes
    operation: bytes
    scope: bytes
    request_digest: str
    native_proof: object = None


class OrdinarySecretCustody:
    """Retain exact private work through cancellation and joined close.

    ``_material`` is reserved for the trusted owner and fixed consumer. A caller
    must check authority again at actual effect and receipt-disclosure boundaries.
    Already disclosed copies cannot be recalled; external revocation belongs to
    the provider. Offline, expired, revoked or rotated authority never serves bytes.
    """
    def __init__(self, root, reader):
        if type(reader) is not LedgerAuthorityReader:
            _refused('ordinary_secret_custody_authority_required')
        self._reader, self._authority = reader, OrdinarySecretAuthority(reader)
        self._store = _OrdinarySecretStore(root)
        self._uses = weakref.WeakKeyDictionary()
        self._tasks, self._closed, self._closing, self._loop = set(), False, None, None

    def __repr__(self):
        return '<OrdinarySecretCustody private>'

    def _open(self):
        if self._closed:
            _refused('ordinary_secret_custody_closed')

    async def _owned(self, method, *args):
        self._open()
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        if self._loop is not loop or len(self._tasks) >= 16:
            _refused('ordinary_secret_custody_unavailable')
        task = asyncio.create_task(self._run(method, *args))
        self._tasks.add(task)
        def finished(done):
            self._tasks.discard(done)
            if not done.cancelled():
                done.exception()
        task.add_done_callback(finished)
        # Waiting does not transfer cancellation to the private task. Unlike a
        # detached shield future, it also leaves no abandoned failure reporter.
        await asyncio.wait((task,))
        return task.result()

    async def _run(self, method, *args):
        try:
            return await method(*args)
        except asyncio.CancelledError:
            raise
        except ContractError:
            raise
        except Exception:
            _refused('ordinary_secret_custody_unavailable')

    async def _proposed(self, raw):
        if type(raw) is not bytes or len(raw) > 65536:
            _refused()
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if envelope['contractId'] != 'identity-ordinary-secret-set':
            _refused()
        validate('identity-ordinary-secret-set', envelope['payload'])
        snapshot = await self._reader.current()
        now = datetime.now(timezone.utc)
        current = strict_loads(snapshot.record)
        decision = evaluate_snapshot(snapshot, raw, audience={
            'hubId': self._reader._hub, 'serviceId': 'identity-owner'}, now=now)
        self._open()
        if (decision.outcome != 'allowed' or decision.operation is None
                or decision.valid_until is None or now >= decision.valid_until
                or envelope['payload']['authorityId'] != self._reader._entity
                or envelope['operation']['expectedVersion'] != current['entityVersion']):
            _refused('ordinary_secret_custody_not_authorized')
        transition(current['state'], envelope['contractId'], envelope['payload'],
                   hub_id=self._reader._hub)
        item = envelope['payload']['record']
        if not _active(item, now):
            _refused('ordinary_secret_custody_not_authorized')
        return _binding(item)

    async def provision(self, enrollment_envelope, *, secret):
        """Stage one generation before committing its signed public enrollment."""
        return await self._owned(self._provision, enrollment_envelope, secret)

    async def _provision(self, raw, secret):
        return await asyncio.to_thread(self._write_worker, raw, secret,
                                       asyncio.get_running_loop())

    def _write_worker(self, raw, secret, loop):
        # Read authority after this exact worker starts, rather than before it
        # waits in the executor queue. The outer task retains this whole worker.
        binding = asyncio.run_coroutine_threadsafe(self._proposed(raw), loop).result()
        result = self._store.provision(binding, secret)
        if asyncio.run_coroutine_threadsafe(self._proposed(raw), loop).result() != binding:
            _refused('ordinary_secret_custody_not_authorized')
        return result

    async def authorize(self, resolve_envelope, *, native_proof=None):
        return await self._owned(self._authorize, resolve_envelope, native_proof)

    async def _authorize(self, raw, native_proof):
        if type(raw) is not bytes:
            _refused()
        resolution = await self._authority.resolve(raw, native_proof=native_proof)
        self._open()
        use = object.__new__(OrdinarySecretUse)
        self._uses[use] = _Use(raw, _binding(strict_loads(resolution.record)),
            resolution.original_operation, resolution.scope, resolution.original_request_digest, native_proof)
        return use

    def _use(self, use):
        if type(use) is not OrdinarySecretUse or use not in self._uses:
            _refused('ordinary_secret_custody_admission_required')
        return self._uses[use]

    async def check(self, use):
        return await self._owned(self._check, use)

    async def _check(self, use):
        item = self._use(use)
        resolution = await self._authority.resolve(item.request, native_proof=item.native_proof)
        self._open()
        if (resolution.record != item.binding or resolution.scope != item.scope
                or resolution.original_operation != item.operation
                or resolution.original_request_digest != item.request_digest):
            _refused('ordinary_secret_custody_not_authorized')
        return resolution

    async def _material(self, use):
        """Hand a fresh immutable private copy to the fixed trusted consumer.

        The receiving owner retains this object until its original consumer
        worker joins. Neither custody nor another use destroys shared material.
        Python immutable bytes do not provide reliable in-memory zeroization.
        """
        return await self._owned(self._read, use, True)

    async def recover(self, use):
        """Check the exact retained generation without returning its material."""
        return await self._owned(self._read, use, False)

    async def _read(self, use, disclose):
        return await asyncio.to_thread(self._read_worker, use, disclose,
                                       asyncio.get_running_loop())

    def _read_worker(self, use, disclose, loop):
        resolution = asyncio.run_coroutine_threadsafe(self._check(use), loop).result()
        private = self._store.read(resolution.record)
        asyncio.run_coroutine_threadsafe(self._check(use), loop).result()
        return private if disclose else strict_loads(resolution.record)['generationRef']

    async def _close(self):
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
        self._store.close()
        self._uses.clear()

    async def close(self, *, timeout=5):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            _refused('ordinary_secret_custody_cleanup_invalid')
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            _refused('ordinary_secret_custody_unavailable')
        self._closed = True
        if self._closing is None:
            self._closing = asyncio.create_task(self._close())
        try:
            await asyncio.wait_for(asyncio.shield(self._closing), timeout)
        except TimeoutError:
            _refused('ordinary_secret_custody_cleanup_incomplete')
