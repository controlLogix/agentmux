"""Private legacy task capture; no writer transfer, grants or effect dispatch.

Call capture on the existing Store's writer thread outside a transaction. Its
online backup contains every SQLite table, including other owners' data. Task
readback preserves source values; it does not normalize legacy states into task
execution permission. Relevant files and other authoritative stores still need
separate capture before a platform migration can transfer writer authority.
"""
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.store import APP_ID, MIGRATIONS, Store
from hub.fed import redact
from .checkpoints import _directory
from .ledger import OwnerBinding

_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_WORK_COLUMNS = frozenset(('id', 'parent_id', 'task_key', 'repo', 'target', 'target_kind', 'title',
    'body', 'created_by', 'requirements', 'priority', 'state', 'claimed_by', 'lease_until',
    'attempts', 'max_attempts', 'result', 'blocked_reason', 'created', 'updated'))


def _source(value):
    try:
        value = strict_loads(canonical_bytes(value))
        if (set(value) != {'id', 'ownerHubId', 'revision'}
                or any(type(value[k]) is not str or not _ID.fullmatch(value[k]) for k in ('id', 'ownerHubId'))
                or type(value['revision']) is not int or not 1 <= value['revision'] <= 9007199254740991):
            raise ValueError()
        return value
    except Exception:
        raise ContractError('task_migration_source_invalid') from None


def task_import_identity(source_ref, legacy_id, *, target_hub_id, scope):
    """Keep legacy IDs separately; target tokens are stable for one source owner."""
    source = _source(source_ref)
    if type(legacy_id) is not str or not 1 <= len(legacy_id.encode()) <= 4096:
        raise ContractError('task_migration_identity_invalid')
    target = OwnerBinding(target_hub_id, 'task', 'import-target', 'task', canonical_bytes(scope))
    # Source revision belongs to capture provenance, not the logical task key.
    # A new capture must not silently create a second task for the same old ID.
    digest = payload_digest({'format': 'amx-legacy-task-identity-v1',
        'targetOwnerHubId': target.hub_id, 'ownerDomain': 'task', 'scope': strict_loads(target.scope),
        'source': {k: source[k] for k in ('id', 'ownerHubId')}, 'legacyId': legacy_id}).split(':')[1]
    return {'taskId': 'legacy_'+digest, 'operationId': 'import_'+digest}


def _hash_file(fd):
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while block := os.read(fd, 1048576):
        digest.update(block)
    return 'sha256:'+digest.hexdigest()


def _private_file(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid() or info.st_nlink != 1):
        os.close(fd)
        raise ValueError()
    return fd, info


def _unlink_owned(directory, name, identity):
    try:
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
        os.unlink(name, dir_fd=directory)


class TaskMigrationSnapshot:
    """Own the exact captured file and read-only SQLite connection until close."""
    def __init__(self, path, *, digest, source_ref, application_version):
        self._fd = self._directory = self._db = None
        self._closed = False
        self._source = _source(source_ref)
        if type(application_version) is not str or not 1 <= len(application_version.encode()) <= 256:
            raise ContractError('task_migration_version_invalid')
        self._application_version = application_version
        self._path = Path(os.path.abspath(path))
        try:
            self._directory, self._name = _directory(self._path)
            self._fd, self._file_identity = _private_file(self._directory, self._name)
            if _hash_file(self._fd) != digest:
                raise ValueError()
            self._digest = digest
            # Native macOS fdescfs duplicates the admitted descriptor. Opening
            # the pathname again would permit a different database to be read
            # during a temporary parent-directory substitution. Never fall back
            # to pathname reopening if descriptor-backed SQLite is unavailable.
            self._db = sqlite3.connect('file:/dev/fd/'+str(self._fd)+'?mode=ro&immutable=1', uri=True)
            self._db.row_factory = sqlite3.Row
            self._db.execute('PRAGMA query_only=ON')
            self._check_file()
            self._schema_version = self._db.execute('PRAGMA user_version').fetchone()[0]
            if (self._db.execute('PRAGMA application_id').fetchone()[0] != APP_ID
                    or not 1 <= self._schema_version <= len(MIGRATIONS)
                    or self._db.execute('PRAGMA quick_check').fetchone()[0] != 'ok'
                    or self._db.execute('PRAGMA foreign_key_check').fetchone() is not None):
                raise ValueError()
            columns = {row['name'] for row in self._db.execute('PRAGMA table_xinfo(work_items)')}
            expected = (_WORK_COLUMNS | ({'origin'} if self._schema_version >= 3 else set())
                | ({'origin_peer', 'fed_flags'} if self._schema_version >= 4 else set()))
            if columns != expected:
                raise ValueError()
            self._check_file()
        except BaseException:
            self.close()
            raise ContractError('task_migration_snapshot_invalid') from None

    def __repr__(self):
        return '<TaskMigrationSnapshot private read-only>'

    def _check_file(self):
        if self._closed:
            raise ContractError('task_migration_snapshot_closed')
        current = os.stat(self._name, dir_fd=self._directory, follow_symlinks=False)
        original = self._file_identity
        parent = os.stat(self._path.parent, follow_symlinks=False)
        pinned_parent = os.fstat(self._directory)
        if ((parent.st_dev, parent.st_ino) != (pinned_parent.st_dev, pinned_parent.st_ino)
                or (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino)
                or (current.st_size, current.st_mtime_ns, current.st_ctime_ns) !=
                   (original.st_size, original.st_mtime_ns, original.st_ctime_ns)
                or stat.S_IMODE(current.st_mode) != 0o600 or current.st_nlink != 1):
            raise ContractError('task_migration_snapshot_changed')

    def inventory(self):
        """Full SQLite inventory; bodies and other owners' rows stay private."""
        self._check_file()
        tables = []
        for row in self._db.execute("SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name"):
            name = row['name']
            quoted = '"'+name.replace('"', '""')+'"'
            count = self._db.execute('SELECT count(*) FROM '+quoted).fetchone()[0]
            tables.append({'name': name, 'schema': row['sql'], 'rows': count})
        result = {'format': 'amx-legacy-task-capture-v1', 'sourceRef': self._source,
            'applicationVersion': self._application_version, 'schemaVersion': self._schema_version,
            'databaseDigest': self._digest, 'tables': tables, 'writerAuthorityTransferred': False}
        self._check_file()
        return strict_loads(canonical_bytes(result))

    def task_ids(self):
        self._check_file()
        result = tuple(row[0] for row in self._db.execute('SELECT id FROM work_items ORDER BY id'))
        self._check_file()
        return result

    def task(self, legacy_id):
        """Read exact source row, work events and claims without firing triggers."""
        self._check_file()
        row = self._db.execute('SELECT * FROM work_items WHERE id=?', (legacy_id,)).fetchone()
        if row is None:
            raise ContractError('task_migration_task_not_found')
        value = dict(row)
        events = [dict(row) for row in self._db.execute(
            "SELECT * FROM events WHERE entity='work' AND entity_id=? ORDER BY seq", (legacy_id,))]
        claims = [dict(row) for row in self._db.execute(
            'SELECT * FROM claims WHERE work_id=? ORDER BY repo,path', (legacy_id,))]
        # Preserve raw JSON strings, nulls, local lease state and original status.
        # These observations never free a reservation or grant execution.
        result = {'format': 'amx-legacy-task-source-v1', 'sourceRef': self._source,
            'databaseDigest': self._digest, 'schemaVersion': self._schema_version,
            'applicationVersion': self._application_version, 'work': value,
            'events': events, 'claims': claims}
        self._check_file()
        return canonical_bytes(result)

    def close(self):
        self._closed = True
        if self._db is not None:
            self._db.close()
            self._db = None
        for name in ('_fd', '_directory'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


def capture_tasks(store, path, *, source_ref, application_version):
    """Capture on Store's existing writer thread, without changing its state."""
    _source(source_ref)
    if type(store) is not Store or store.db.in_transaction:
        raise ContractError('task_migration_capture_unavailable')
    directory = fd = None
    allocated = None
    temporary = None
    try:
        path = Path(os.path.abspath(path))
        directory, name = _directory(path)
        temporary = '.task-capture-'+secrets.token_hex(16)
        fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        allocated = os.fstat(fd)
        # Store.backup must write the allocated file, not reopen a mutable
        # destination path. Native macOS fdescfs keeps this exact fd binding.
        destination = sqlite3.connect('file:/dev/fd/'+str(fd)+'?mode=rw', uri=True)
        try:
            # The private incomplete file needs no on-disk recovery journal.
            # MEMORY avoids opening a sidecar through an unrelated pathname;
            # validation, fsync and publication happen only after backup closes.
            if destination.execute('PRAGMA journal_mode=MEMORY').fetchone()[0] != 'memory':
                raise ValueError()
            store.backup(destination)
        finally:
            destination.close()
        current = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (allocated.st_dev, allocated.st_ino):
            raise ValueError()
        os.fsync(fd)
        digest = _hash_file(fd)
        # Validate the completed snapshot before publishing a no-replace name.
        candidate = TaskMigrationSnapshot(path.parent/temporary, digest=digest,
            source_ref=source_ref, application_version=application_version)
        candidate.close()
        os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        _unlink_owned(directory, temporary, allocated)
        temporary = None
        os.fsync(directory)
        return TaskMigrationSnapshot(path, digest=digest, source_ref=source_ref,
            application_version=application_version)
    except Exception:
        # A completed published snapshot survives an uncertain return. Never
        # remove or replace it, and never prune an older captured database.
        raise ContractError('task_migration_capture_unavailable') from None
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None and directory is not None and allocated is not None:
            _unlink_owned(directory, temporary, allocated)
        if directory is not None:
            os.close(directory)


def prepare_task_import(snapshot, legacy_id, *, binding, source_repository):
    """Bind exact private source evidence to one explicit target; grant nothing."""
    if (type(snapshot) is not TaskMigrationSnapshot or type(binding) is not OwnerBinding
            or (binding.owner_domain, binding.entity_kind) != ('task', 'task')
            or type(source_repository) is not str or not source_repository):
        raise ContractError('task_import_configuration')
    source_record = strict_loads(snapshot.task(legacy_id))
    identity = task_import_identity(source_record['sourceRef'], legacy_id,
        target_hub_id=binding.hub_id, scope=strict_loads(binding.scope))
    if identity['taskId'] != binding.entity_id or source_record['work']['repo'] != source_repository:
        raise ContractError('task_import_binding_mismatch')
    parent_id = source_record['work']['parent_id']
    parent_target_id = None
    if parent_id is not None:
        # A legacy FK does not prove that two repository/project scopes match.
        parent = strict_loads(snapshot.task(parent_id))
        if parent['work']['repo'] != source_repository:
            raise ContractError('task_import_parent_scope_unavailable')
        parent_identity = task_import_identity(source_record['sourceRef'], parent_id,
            target_hub_id=binding.hub_id, scope=strict_loads(binding.scope))
        parent_target_id = parent_identity['taskId']
    payload = {'taskId': binding.entity_id, 'sourceRef': source_record['sourceRef'],
        'captureDigest': source_record['databaseDigest'], 'legacyId': legacy_id,
        'sourceTaskDigest': payload_digest(source_record), 'parentTaskId': parent_target_id,
        'sourceRecord': source_record}
    if len(canonical_bytes(payload)) > 65536:
        raise ContractError('task_import_artifact_required')
    return payload


def require_unmodified_import_source(source_record):
    """Refuse existing protected-content patterns; never redact source evidence."""
    pending = [(source_record, 0)]
    remaining = 65536
    while pending:
        value, depth = pending.pop()
        remaining -= 1
        if remaining < 0 or depth > 128:
            raise ContractError('task_import_source_unavailable')
        if isinstance(value, dict):
            for key, item in value.items():
                pending.extend(((key, depth+1), (item, depth+1)))
        elif isinstance(value, list):
            for item in value:
                pending.append((item, depth+1))
        elif isinstance(value, str):
            try:
                cleaned, kinds = redact.scrub(value)
            except redact.Blocked:
                raise ContractError('task_import_protected_source') from None
            if kinds or cleaned != value:
                raise ContractError('task_import_protected_source')
            # Legacy JSON columns are text. Inspect all decoded strings
            # too, so JSON escaping cannot bypass the existing pattern policy.
            try:
                # Keep duplicate keys and values. Numeric conversion is unrelated
                # to string filtering and must not bypass inspection on a large int.
                structured = json.loads(value, parse_int=str, parse_float=str,
                    object_pairs_hook=lambda pairs: [item for pair in pairs for item in pair])
            except json.JSONDecodeError:
                continue  # Ordinary non-JSON task text still received the same filter.
            except (ValueError, UnicodeError, RecursionError, OverflowError):
                raise ContractError('task_import_source_unavailable') from None
            if structured != value:
                pending.append((structured, depth+1))


def validate_imported_task(record, binding, *, authority_id):
    """Only an exact import can carry unknown modern reservation and epoch."""
    from agentmux_contracts import validate
    try:
        state, operation = record['state'], record['operation']
        if (set(state) != {'taskId', 'legacyId', 'status', 'assignmentEpoch', 'reservation', 'migration'}
                or state['taskId'] != binding.entity_id or state['status'] != 'reconciliation_required'
                or state['assignmentEpoch'] is not None or state['reservation'] is not None):
            raise ValueError()
        migration = state['migration']
        if (set(migration) != {'format', 'phase', 'writerTransferRequired', 'payload', 'importAuthorityRef'}
                or migration['format'] != 'amx-task-import-v1'
                or migration['phase'] != 'reconciliation-required' or migration['writerTransferRequired'] is not True):
            raise ValueError()
        payload = migration['payload']
        validate('task-import', payload)
        source = payload['sourceRecord']
        require_unmodified_import_source(source)
        identity = task_import_identity(payload['sourceRef'], payload['legacyId'],
            target_hub_id=binding.hub_id, scope=strict_loads(binding.scope))
        work = source['work']
        expected_columns = (_WORK_COLUMNS | ({'origin'} if source['schemaVersion'] >= 3 else set())
            | ({'origin_peer', 'fed_flags'} if source['schemaVersion'] >= 4 else set()))
        parent_id = work['parent_id']
        parent_target = None if parent_id is None else task_import_identity(payload['sourceRef'], parent_id,
            target_hub_id=binding.hub_id, scope=strict_loads(binding.scope))['taskId']
        if (set(work) != expected_columns or work['id'] != payload['legacyId']
                or payload['legacyId'] != state['legacyId'] or payload['taskId'] != identity['taskId']
                or identity['taskId'] != binding.entity_id or operation['operationId'] != identity['operationId']
                or payload['sourceRef'] != source['sourceRef'] or payload['captureDigest'] != source['databaseDigest']
                or payload['sourceTaskDigest'] != payload_digest(source) or payload['parentTaskId'] != parent_target
                or record['entityVersion'] != 1 or record['previousRevision'] != 0
                or operation['expectedVersion'] != 0 or operation['taskId'] != binding.entity_id
                or operation['attemptId'] is not None or operation['runId'] is not None
                or operation['delegationRef'] is not None or operation['caller']['kind'] == 'plugin'
                or operation['payloadDigest'] != payload_digest(payload)
                or operation['effectiveActorRef'] != operation['caller']['authenticatedIdentityRef']
                or record['outcome'] != 'committed' or record['effects'] or record['artifacts']
                or record['repository'] is not None
                or record['authorizationDecision'] != {'operationId': operation['operationId'], 'decision': 'allowed',
                    'reason': 'authorized', 'actorRef': operation['effectiveActorRef'], 'contractId': 'task-import'}):
            raise ValueError()
        authority = _source(migration['importAuthorityRef'])
        if authority['id'] != authority_id or authority['ownerHubId'] != binding.hub_id:
            raise ValueError()
        sequences = []
        for event in source['events']:
            if event['entity'] != 'work' or event['entity_id'] != payload['legacyId'] or type(event['seq']) is not int:
                raise ValueError()
            sequences.append(event['seq'])
        if sequences != sorted(set(sequences)):
            raise ValueError()
        for claim in source['claims']:
            if claim['work_id'] != payload['legacyId']:
                raise ValueError()
        return record
    except Exception:
        raise ContractError('task_import_record_invalid') from None


class TaskImporter:
    """Append one explicitly authorized, fenced task import; never activate it."""
    def __init__(self, authority, ledger, *, snapshot, source_repository):
        from .task import TaskOwner
        if (type(snapshot) is not TaskMigrationSnapshot or type(source_repository) is not str
                or not source_repository or not ledger.completion_budget_required):
            raise ContractError('task_import_configuration')
        self._owner = TaskOwner(authority, ledger)
        self._ledger, self._snapshot, self._source_repository = ledger, snapshot, source_repository

    def __repr__(self):
        return '<TaskImporter private reconciliation-required>'

    async def handle(self, raw):
        from agentmux_contracts import validate
        from .ledger import MAX_RECORD_BYTES, find_outcome
        if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
            raise ContractError('task_import_artifact_required')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if envelope['kind'] != 'command' or envelope['contractId'] != 'task-import' or canonical_bytes(envelope) != raw:
            raise ContractError('task_import_contract_unavailable')
        validate('task-import', envelope['payload'])
        operation, payload = envelope['operation'], envelope['payload']
        async with asyncio.timeout(5):
            await self._owner._authorize(raw, envelope)
            # The host selected the actual private capture and repository. Caller
            # supplied source text cannot replace either, even with an import grant.
            expected = prepare_task_import(self._snapshot, payload['legacyId'],
                binding=self._ledger._binding, source_repository=self._source_repository)
            identity = task_import_identity(expected['sourceRef'], expected['legacyId'],
                target_hub_id=self._ledger._binding.hub_id, scope=strict_loads(self._ledger._binding.scope))
            if (payload != expected or operation['operationId'] != identity['operationId']
                    or operation['expectedVersion'] != 0 or operation['taskId'] != identity['taskId']
                    or operation['attemptId'] is not None or operation['runId'] is not None
                    or operation['delegationRef'] is not None):
                raise ContractError('task_import_binding_mismatch')
            require_unmodified_import_source(expected['sourceRecord'])
            current = await self._ledger.current()
            replay = find_outcome(current, operation['operationId'], operation['payloadDigest'])
            if replay is not None:
                self._owner._retained(replay)
                await self._owner._authorize(raw, envelope)
                return replay
            if current.sequence != 0:
                raise ContractError('owner_revision_conflict')
            decision = await self._owner._authorize(raw, envelope)
            record = {'schemaVersion': '1.0.0', 'recordId': 'task'+identity['operationId'],
                'entityId': self._ledger._binding.entity_id, 'entityKind': 'task',
                'ownerHubId': self._ledger._binding.hub_id, 'ownerDomain': 'task',
                'entityVersion': 1, 'previousRevision': 0, 'operation': operation,
                'recordedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'), 'outcome': 'committed',
                'state': {'taskId': identity['taskId'], 'legacyId': payload['legacyId'],
                    'status': 'reconciliation_required', 'assignmentEpoch': None, 'reservation': None,
                    'migration': {'format': 'amx-task-import-v1', 'phase': 'reconciliation-required',
                        'writerTransferRequired': True, 'payload': payload,
                        'importAuthorityRef': strict_loads(decision.authority_ref)}},
                'effects': [], 'artifacts': [], 'repository': None,
                'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                    'reason': 'authorized', 'actorRef': operation['effectiveActorRef'], 'contractId': 'task-import'}}
            validate_imported_task(record, self._ledger._binding, authority_id=self._owner._authority._entity)
            encoded = canonical_bytes(record)
            if len(encoded) > MAX_RECORD_BYTES:
                raise ContractError('task_import_artifact_required')
            # Import commits preservation only. Any later delivery/reconciliation
            # command needs its own explicit authority and completion budget.
            stored = await self._ledger.append(record, expected_sequence=0, completion_records=0,
                valid_until=decision.valid_until)
            await self._owner._authorize(raw, envelope)
            return stored
