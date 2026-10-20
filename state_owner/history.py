"""Private rebuildable replay cache. Broker verification, not SQLite, is authority."""
from collections.abc import Sequence
import fcntl
import hashlib
import os
import re
from pathlib import Path
import sqlite3
import stat
import time

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from .ledger import StoredRecord, StreamIdentity, validate_record


def _fail():
    raise ContractError('owner_history_cache_invalid') from None


class _Records(Sequence):
    __slots__ = ('_owner', '_count', '_through')

    def __init__(self, owner, count, through):
        self._owner, self._count, self._through = owner, count, through

    def __repr__(self):
        return '<OwnerHistoryRecords private>'

    def __len__(self):
        return self._count

    def __getitem__(self, index):
        if isinstance(index, slice):
            # Avoid a slice allocating the entire cache accidentally.
            raise TypeError('owner_history_slice_unsupported')
        if type(index) is not int:
            raise TypeError('owner_history_index_invalid')
        if index < 0:
            index += self._count
        if not 0 <= index < self._count:
            raise IndexError('owner_history_index_invalid')
        return self._owner._at(index + 1, self._through)


class OwnerHistory:
    """Single-process cache with bounded rows and explicit broker revalidation.

    Use a private administrator-owned directory. A cache mismatch requires an
    explicit rebuild; this class never deletes history or executes effects.
    """
    def __init__(self, path, binding, *, stream_identity: StreamIdentity, max_records=1_000_000, max_bytes=1_073_741_824):
        self._db = None
        self._lock = None
        self._closed = False
        self._binding = binding
        self._source_identity = stream_identity
        self._verified = self._verified_count = 0
        self._max_records, self._max_bytes = max_records, max_bytes
        try:
            if not isinstance(stream_identity, StreamIdentity):
                _fail()
            if type(max_records) is not int or not 1 <= max_records <= 1_000_000 or type(max_bytes) is not int or not 1 <= max_bytes <= 1_099_511_627_776:
                _fail()
            path = Path(path).absolute()
            if path.name in ('', '.', '..'):
                _fail()
            parent = path.parent
            # Resolve every component, refusing symbolic links before opening.
            for component in (parent, *parent.parents):
                if component.is_symlink():
                    _fail()
            metadata = parent.stat()
            if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                _fail()
            self._lock = self._private_open(str(path) + '.lock')
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd = self._private_open(path)
            identity = os.fstat(fd)
            os.close(fd)
            for suffix in ('-journal', '-wal', '-shm'):
                side = Path(str(path) + suffix)
                if side.exists() or side.is_symlink():
                    m = side.lstat()
                    if not stat.S_ISREG(m.st_mode) or m.st_uid != os.getuid() or m.st_mode & 0o077:
                        _fail()
            self._db = sqlite3.connect(path, timeout=0, isolation_level=None)
            self._db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 131_072)
            now = path.stat(follow_symlinks=False)
            self._path = path
            self._identity = (identity.st_dev, identity.st_ino)
            if self._identity != (now.st_dev, now.st_ino):
                _fail()
            self._db.execute('PRAGMA trusted_schema=OFF')
            self._db.execute('PRAGMA journal_mode=DELETE')
            self._db.execute('PRAGMA synchronous=FULL')
            self._db.execute('PRAGMA foreign_keys=ON')
            self._db.execute('CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), binding BLOB NOT NULL)')
            self._db.execute('CREATE TABLE IF NOT EXISTS records (position INTEGER PRIMARY KEY, sequence INTEGER UNIQUE NOT NULL, record BLOB NOT NULL, digest BLOB NOT NULL, operation_id TEXT UNIQUE NOT NULL, payload_digest TEXT NOT NULL, record_id TEXT UNIQUE NOT NULL)')
            self._db.execute('CREATE TABLE IF NOT EXISTS effects (effect_id TEXT PRIMARY KEY, content BLOB NOT NULL)')
            binding_bytes = canonical_bytes({'hubId': binding.hub_id, 'ownerDomain': binding.owner_domain,
                                             'entityId': binding.entity_id, 'entityKind': binding.entity_kind,
                                             'scope': strict_loads(binding.scope),
                                             'sourceCreated': stream_identity.created.isoformat(timespec='microseconds')})
            if self._db.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view')").fetchone() is not None:
                _fail()
            self._fingerprint = self._file_fingerprint()
            self._verify_integrity()
            if self._fingerprint != self._file_fingerprint():
                _fail()
            self._version = self._db.execute('PRAGMA data_version').fetchone()[0]
            row = self._db.execute('SELECT binding FROM metadata WHERE id=1').fetchone()
            if row is None:
                if self._db.execute('SELECT COUNT(*) FROM records').fetchone()[0]:
                    _fail()
                self._db.execute('INSERT INTO metadata VALUES (1,?)', (binding_bytes,))
            elif row[0] != binding_bytes:
                _fail()
            self._count, self._cursor, self._total = self._db.execute('SELECT COUNT(*), COALESCE(MAX(sequence),0), COALESCE(SUM(length(record)),0) FROM records').fetchone()
            maximum = self._db.execute('SELECT COALESCE(MAX(position),0) FROM records').fetchone()[0]
            if maximum != self._count or self._count > max_records or self._total > max_bytes:
                _fail()
            self._fingerprint = self._file_fingerprint()
            self._check()
        except Exception:
            self.close()
            _fail()

    @staticmethod
    def _private_open(path):
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077 or metadata.st_nlink != 1:
            os.close(fd)
            _fail()
        return fd

    def __repr__(self):
        return '<OwnerHistory private>'

    def _file_fingerprint(self):
        metadata = self._path.stat(follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != self._identity or not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            _fail()
        return metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns

    def _verify_integrity(self):
        # Full checking includes secondary-index consistency. quick_check does not.
        deadline = time.monotonic() + 30.0
        self._db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        try:
            rows = self._db.execute('PRAGMA integrity_check').fetchmany(2)
            if rows != [('ok',)] or time.monotonic() >= deadline:
                _fail()
        finally:
            self._db.set_progress_handler(None, 0)

    def _check(self):
        try:
            if self._closed or self._db.execute('PRAGMA data_version').fetchone()[0] != self._version:
                _fail()
            if self._file_fingerprint() != self._fingerprint:
                _fail()
        except Exception:
            _fail()

    @property
    def max_records(self):
        self._check()
        return self._max_records

    @property
    def max_bytes(self):
        self._check()
        return self._max_bytes

    @property
    def source_identity(self):
        self._check()
        return self._source_identity

    @property
    def binding(self):
        self._check()
        return self._binding

    @property
    def cursor(self):
        self._check()
        return self._cursor

    @property
    def verified_cursor(self):
        self._check()
        return self._verified

    @property
    def total_bytes(self):
        self._check()
        return self._total

    def _row(self, position):
        row = self._db.execute('SELECT sequence,record,digest,operation_id,payload_digest,record_id FROM records WHERE position=?', (position,)).fetchone()
        if row is None or type(row[1]) is not bytes or len(row[1]) > 65_536 or hashlib.sha256(row[1]).digest() != row[2]:
            _fail()
        value = validate_record(row[1], self._binding)
        if canonical_bytes(value) != row[1] or value['entityVersion'] != position or (value['operation']['operationId'], value['operation']['payloadDigest'], value['recordId']) != row[3:]:
            _fail()
        duplicate = self._db.execute('SELECT 1 FROM records WHERE position<? AND (operation_id=? OR record_id=?) LIMIT 1', (position, row[3], row[5])).fetchone()
        if duplicate is not None:
            _fail()
        previous = self._db.execute('SELECT sequence FROM records WHERE position=?', (position - 1,)).fetchone() if position > 1 else (0,)
        if previous is None or value['previousRevision'] != previous[0] or type(row[0]) is not int or not row[0] == previous[0] + 1 <= 9_007_199_254_740_991:
            _fail()
        for effect in value['effects']:
            found = self._db.execute('SELECT content FROM effects WHERE effect_id=?', (effect['effectId'],)).fetchone()
            if found != (canonical_bytes(effect),):
                _fail()
        return StoredRecord(row[1], row[0])

    def _at(self, position, through):
        try:
            self._check()
            stored = self._row(position)
            if stored.sequence > through or stored.sequence > self._verified:
                _fail()
            self._check()
            return stored
        except Exception:
            _fail()

    def record(self, sequence):
        try:
            self._check()
            if type(sequence) is not int or not 0 < sequence <= self._verified:
                _fail()
            row = self._db.execute('SELECT position FROM records WHERE sequence=?', (sequence,)).fetchone()
            if row is None:
                _fail()
            return self._at(row[0], self._verified)
        except Exception:
            _fail()

    def records(self, through):
        try:
            self._check()
            if type(through) is not int or not 0 <= through <= self._verified:
                _fail()
            count = 0
            if through:
                row = self._db.execute('SELECT position FROM records WHERE sequence=?', (through,)).fetchone()
                if row is None:
                    _fail()
                count = row[0]
            return _Records(self, count, through)
        except Exception:
            _fail()

    def outcome(self, op_id, digest):
        try:
            self._check()
            if not isinstance(op_id, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', op_id) or not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                raise ContractError('owner_operation_invalid')
            if self._verified != self._cursor:
                _fail()
            row = self._db.execute('SELECT position,payload_digest FROM records WHERE operation_id=? AND sequence<=?', (op_id, self._verified)).fetchone()
            if row is None:
                self._check()
                return None
            if row[1] != digest:
                raise ContractError('owner_operation_conflict')
            stored = self._at(row[0], self._verified)
            return StoredRecord(stored.record, stored.sequence, replayed=True)
        except ContractError:
            raise
        except Exception:
            _fail()

    def _next(self, stored):
        self._check()
        if self._verified != self._cursor:
            _fail()
        value = validate_record(stored.record, self._binding)
        raw = canonical_bytes(value)
        if type(stored.sequence) is not int or stored.sequence != self._cursor + 1 or stored.sequence > 9_007_199_254_740_991 or value['previousRevision'] != self._cursor or value['entityVersion'] != self._count + 1:
            _fail()
        if self._count >= self._max_records or self._total + len(raw) > self._max_bytes:
            _fail()
        if self._db.execute('SELECT 1 FROM records WHERE operation_id=? OR record_id=?',
                            (value['operation']['operationId'], value['recordId'])).fetchone() is not None:
            _fail()
        for effect in value['effects']:
            old = self._db.execute('SELECT content FROM effects WHERE effect_id=?', (effect['effectId'],)).fetchone()
            if old is not None and old != (canonical_bytes(effect),):
                _fail()
        self._check()
        return value, raw

    def check_next(self, stored):
        """Validate the next proposed record without changing the cache."""
        try:
            self._next(stored)
        except Exception:
            _fail()

    def append_verified(self, stored):
        try:
            value, raw = self._next(stored)
            self._db.execute('BEGIN IMMEDIATE')
            try:
                self._check()
                for effect in value['effects']:
                    encoded = canonical_bytes(effect)
                    old = self._db.execute('SELECT content FROM effects WHERE effect_id=?', (effect['effectId'],)).fetchone()
                    if old is not None and old != (encoded,):
                        _fail()
                    self._db.execute('INSERT OR IGNORE INTO effects VALUES (?,?)', (effect['effectId'], encoded))
                self._db.execute('INSERT INTO records VALUES (?,?,?,?,?,?,?)',
                                 (self._count + 1, stored.sequence, raw, hashlib.sha256(raw).digest(),
                                  value['operation']['operationId'], value['operation']['payloadDigest'], value['recordId']))
                self._db.execute('COMMIT')
                self._fingerprint = self._file_fingerprint()
            except Exception:
                self._db.execute('ROLLBACK')
                raise
            self._count += 1
            self._total += len(raw)
            self._cursor = self._verified = stored.sequence
            self._verified_count = self._count
        except Exception:
            _fail()

    def verify_source(self, stored):
        try:
            self._check()
            if self._verified_count == self._count:
                return self.append_verified(stored)
            expected = self._row(self._verified_count + 1)
            value = validate_record(stored.record, self._binding)
            if type(stored.sequence) is not int or expected.sequence != stored.sequence or expected.record != canonical_bytes(value) or value['previousRevision'] != self._verified:
                _fail()
            self._check()
            self._verified_count += 1
            self._verified = stored.sequence
        except Exception:
            _fail()

    def close(self):
        self._closed = True
        try:
            if self._db is not None:
                self._db.close()
        finally:
            self._db = None
            if self._lock is not None:
                os.close(self._lock)
                self._lock = None

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *args):
        self.close()
