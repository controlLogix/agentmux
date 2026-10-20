"""Bind legacy SQLite recovery to retained authority-switch state."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import os
import stat
import threading

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from state_owner.authority_switch import (AuthoritySwitchOwner,
    AuthoritySwitchHost, VerifiedLegacyRecoveryPermit, authority_switch_id,
    validate_authority_switch_record)
from state_owner.ledger import StreamIdentity
from state_owner.backup_host import _native_guard

from .store import HubError


def _database_anchor_name(path):
    return '.agentmux-authority-switch-' + hashlib.sha256(
        os.path.abspath(path).encode('utf-8')).hexdigest() + '.json'


def _database_lock_name(path):
    return '.agentmux-authority-switch-' + hashlib.sha256(
        os.path.abspath(path).encode('utf-8')).hexdigest() + '.lock'


def _anchor_bytes(path, *, source, switch_id, stream_identity):
    value = {'format': 'amx-legacy-database-authority-switch-v1',
        'databasePath': os.path.abspath(path), 'switchId': switch_id,
        'source': source, 'streamIdentity': {
            'created': stream_identity.created.isoformat(),
            'minimumSequence': stream_identity.minimum_sequence}}
    validate('authority-switch', {'action': 'record-source-fence',
        'switchId': switch_id, 'source': source})
    if authority_switch_id(source) != switch_id:
        raise ValueError()
    return canonical_bytes(value)


def _read_database_anchor(path):
    directory = file = None
    try:
        root = os.path.dirname(os.path.abspath(path))
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            file = os.open(_database_anchor_name(path),
                           os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=directory)
        except FileNotFoundError:
            return None
        _native_guard(directory, directory=True)
        info = os.fstat(file)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 65536):
            raise ValueError()
        _native_guard(file)
        raw = os.read(file, 65537)
        value = strict_loads(raw)
        stream = value['streamIdentity']
        identity = StreamIdentity(datetime.fromisoformat(stream['created']),
                                  stream['minimumSequence'])
        if (set(value) != {'format', 'databasePath', 'switchId', 'source', 'streamIdentity'}
                or value['format'] != 'amx-legacy-database-authority-switch-v1'
                or value['databasePath'] != os.path.abspath(path)
                or canonical_bytes(value) != raw
                or _anchor_bytes(path, source=value['source'], switch_id=value['switchId'],
                                 stream_identity=identity) != raw):
            raise ValueError()
        return raw
    except HubError:
        raise
    except Exception:
        raise HubError('legacy migration authority unavailable') from None
    finally:
        if file is not None:
            os.close(file)
        if directory is not None:
            os.close(directory)


def retained_database_authority(path):
    """Return whether this exact legacy database has an external authority anchor."""
    return _read_database_anchor(path) is not None


def acquire_database_authority(path, recovery):
    """Serialize authority admission and retain shared database lifetime custody."""
    directory = lock = None
    retained = False
    try:
        selected = os.path.abspath(path)
        if os.path.normpath(selected) != selected:
            raise ValueError()
        directory = os.open(os.path.dirname(selected),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        lock = os.open(_database_lock_name(selected),
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
            dir_fd=directory)
        os.fchmod(lock, 0o600)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError()
        _native_guard(lock)
        exclusive = True
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            exclusive = False
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        anchored = _read_database_anchor(selected)
        if recovery is None:
            if anchored is not None:
                raise HubError('legacy migration authority unavailable')
        else:
            if os.path.realpath(selected) != selected:
                raise ValueError()
            if not exclusive and anchored is None:
                raise ValueError()
            recovery._bind_database(selected)
        if exclusive:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        os.close(directory)
        directory = None
        retained = True
        return lock
    except HubError:
        raise
    except Exception:
        raise HubError('legacy migration authority unavailable') from None
    finally:
        if directory is not None:
            try:
                os.close(directory)
            except OSError:
                pass
        if lock is not None and not retained:
            os.close(lock)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class _LegacyRecoveryUse:
    _seal: object
    _permit: object
    _fence_id: str
    _fence_generation: int
    _valid_until: datetime

    def __repr__(self):
        return '<LegacyRecoveryUse private>'


class LegacyWriterRecoveryGuard:
    """Keep one configured legacy Store closed until owner-authorized recovery."""

    def __init__(self, owner, *, source, switch_id, stream_identity):
        try:
            validate('authority-switch', {'action': 'record-source-fence',
                'switchId': switch_id, 'source': source})
            if (type(owner) is not AuthoritySwitchOwner
                    or authority_switch_id(source) != switch_id
                    or not isinstance(stream_identity, StreamIdentity)):
                raise ValueError()
        except Exception:
            raise HubError('legacy migration recovery configuration is invalid') from None
        self._owner = owner
        self._authorizer = None
        self._source = canonical_bytes(source)
        self._switch_id = switch_id
        self._stream_identity = stream_identity
        self._seal = object()
        self._lock = threading.RLock()
        self._store = None
        self._database_path = None
        self._issued = None
        self._admitted = False

    @classmethod
    def closed(cls, *, source, switch_id, stream_identity, host):
        """Create a fail-closed startup guard from retained host custody.

        This form cannot authorize recovery. The service-owned authority-switch
        owner must supply a freshly verified permit through the later signed
        recovery route before a recoverable guard can replace it.
        """
        try:
            validate('authority-switch', {'action': 'record-source-fence',
                'switchId': switch_id, 'source': source})
            if (authority_switch_id(source) != switch_id
                    or not isinstance(stream_identity, StreamIdentity)
                    or type(host) is not AuthoritySwitchHost
                    or host._binding.entity_id != switch_id
                    or host._stream_identity.created != stream_identity.created):
                raise ValueError()
            observed = host.latest()
            if observed is None:
                raise ValueError()
            record = validate_authority_switch_record(observed.stored, host._binding)
            if (record['state']['source'] != source
                    or observed.stream_identity.created != stream_identity.created
                    or observed.stored.sequence < stream_identity.minimum_sequence):
                raise ValueError()
        except Exception:
            raise HubError('legacy migration recovery configuration is invalid') from None
        guard = object.__new__(cls)
        guard._owner = None
        guard._authorizer = None
        guard._source = canonical_bytes(source)
        guard._switch_id = switch_id
        guard._stream_identity = StreamIdentity(stream_identity.created,
            max(stream_identity.minimum_sequence, observed.stored.sequence))
        guard._seal = object()
        guard._lock = threading.RLock()
        guard._store = None
        guard._database_path = None
        guard._issued = None
        guard._admitted = False
        return guard

    def with_enrolled_recovery(self, authorizer):
        """Attach only the fixed enrolled caller to this retained closed guard."""
        from .authority_switch_recovery_client import EnrolledAuthoritySwitchRecovery
        if (type(authorizer) is not EnrolledAuthoritySwitchRecovery
                or authorizer.source != self.source or self._owner is not None
                or self._authorizer is not None or self._store is not None):
            raise HubError('legacy migration recovery configuration is invalid')
        guard = object.__new__(type(self))
        guard._owner = None
        guard._authorizer = authorizer
        guard._source = self._source
        guard._switch_id = self._switch_id
        guard._stream_identity = self._stream_identity
        guard._seal = object()
        guard._lock = threading.RLock()
        guard._store = None
        guard._database_path = None
        guard._issued = None
        guard._admitted = False
        return guard

    def __repr__(self):
        return '<LegacyWriterRecoveryGuard private>'

    def _bind(self, store):
        with self._lock:
            if self._store is not None and self._store is not store:
                raise HubError('legacy migration recovery configuration is invalid')
            self._store = store

    def _bind_database(self, path):
        """Retain an immutable authority anchor beside the exact legacy database."""
        try:
            selected_path = os.path.abspath(path)
            with self._lock:
                if self._database_path is not None and self._database_path != selected_path:
                    raise ValueError()
                self._database_path = selected_path
            raw = _anchor_bytes(path, source=self.source, switch_id=self._switch_id,
                                stream_identity=self._stream_identity)
            existing = _read_database_anchor(path)
            if existing is not None:
                if existing != raw:
                    raise ValueError()
                return
            directory = os.open(os.path.dirname(os.path.abspath(path)),
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                _native_guard(directory, directory=True)
                fd = os.open(_database_anchor_name(path),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=directory)
                try:
                    os.fchmod(fd, 0o600)
                    view = memoryview(raw)
                    while view:
                        count = os.write(fd, view)
                        if count <= 0:
                            raise OSError()
                        view = view[count:]
                    os.fsync(fd)
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                        raise ValueError()
                    _native_guard(fd)
                finally:
                    os.close(fd)
                os.fsync(directory)
                if _read_database_anchor(path) != raw:
                    raise ValueError()
            finally:
                os.close(directory)
        except FileExistsError:
            if _read_database_anchor(path) != raw:
                raise HubError('legacy migration recovery configuration is invalid') from None
        except HubError:
            raise
        except Exception:
            raise HubError('legacy migration recovery configuration is invalid') from None

    def _allows_write(self, store, token=None):
        with self._lock:
            if store is not self._store:
                return False
            if self._admitted:
                return True
            return self._allows_recovery(store, token)

    def _allows_recovery(self, store, token):
        with self._lock:
            if store is not self._store:
                return False
            if type(token) is not _LegacyRecoveryUse or token is not self._issued:
                return False
            try:
                return (token._seal is self._seal
                    and token._fence_id == self.source['fenceId']
                    and datetime.now(timezone.utc) < token._valid_until)
            except Exception:
                return False

    def _commit(self, store, token):
        with self._lock:
            if token is not self._issued or store is not self._store:
                raise HubError('legacy migration recovery refused')
            self._issued = None
            self._admitted = True

    def _closed(self, store):
        with self._lock:
            return store is not self._store or not self._admitted

    @property
    def source(self):
        from agentmux_contracts import strict_loads
        return strict_loads(self._source)

    def _matches_fence(self, fence, fence_id):
        source = self.source
        return (type(fence) is dict and fence.get('state') in ('fenced', 'open')
            and fence_id == source['fenceId'] and fence.get('fenceId') == fence_id
            and fence.get('generation') == source['fenceGeneration'])

    def _admit_existing_recovery(self, store, token):
        """Reconcile an exact durable open row after restart or lost local completion."""
        if not self._allows_recovery(store, token):
            raise HubError('legacy migration recovery refused')
        self._commit(store, token)

    async def authorize(self, store, fence, fence_id, permit=None):
        """Mint one short lived use token after current owner verification."""
        source = self.source
        if (store is not self._store or self._admitted
                or not self._matches_fence(fence, fence_id)):
            raise HubError('legacy migration recovery refused')
        try:
            if self._owner is not None:
                if type(permit) is not VerifiedLegacyRecoveryPermit:
                    raise ValueError()
                await self._owner.validate_recovery_permit(permit, source=source,
                    switch_id=self._switch_id, stream_identity=self._stream_identity)
                valid_until = datetime.fromisoformat(permit.receipt['validUntil'])
            else:
                if permit is not None or self._authorizer is None:
                    raise ValueError()
                permit = await self._authorizer.authorize(fence=fence, fence_id=fence_id)
                valid_until = permit._valid_until
            if datetime.now(timezone.utc) >= valid_until:
                raise ValueError()
        except Exception:
            raise HubError('legacy migration recovery refused') from None
        token = object.__new__(_LegacyRecoveryUse)
        object.__setattr__(token, '_seal', self._seal)
        object.__setattr__(token, '_permit', permit)
        object.__setattr__(token, '_fence_id', fence_id)
        object.__setattr__(token, '_fence_generation', fence['generation'])
        object.__setattr__(token, '_valid_until', valid_until)
        with self._lock:
            if (self._issued is not None
                    and datetime.now(timezone.utc) < self._issued._valid_until):
                raise HubError('legacy migration recovery refused')
            self._issued = token
        return token
