"""Authorize exact local dashboard mutations through a retained effect owner.

The browser supplies no actor, identity, scope, grant or resource. The host passes
only a branded enrolled browser context and a protected dashboard descriptor. The
effect owner must durably bind the operation ID and payload digest before applying
an effect; this adapter never treats an HTTP response as proof of completion.
"""
import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import re
import os
from pathlib import Path
import sqlite3
import stat

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.application_binding import _permission
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key
from identity.local_browser_session import verified_local_browser_context


_ACTIONS = frozenset({
    'create', 'update', 'status', 'move', 'delete', 'acceptance', 'label', 'dep',
    'evidence', 'commit', 'touch', 'comment', 'link', 'triage', 'state', 'config',
    'override', 'recruit', 'approve', 'retire', 'hire', 'plcstate', 'bootapp',
    'chatsend', 'run-review'
})
_BOARD_PATH = re.compile(r'/api/board/([a-z]{1,16})\Z')
_RUN_PATH = re.compile(r'/api/runs/([0-9a-f]{6})/review\Z')
_OPERATION = re.compile(r'dashboard_[0-9a-f]{64}\Z')
_FORGED = frozenset({'actor', 'identity', 'userId', 'user_id', 'projectId',
                     'project_id', 'scope', 'grantRef', 'resourceRef'})
_FIELDS = {
    'create': frozenset({'kind', 'session', 'title', 'body', 'status', 'notes', 'plan',
        'jira_key', 'epic', 'supersedes', 'decisionKey', 'ends', 'area', 'impact',
        'effort', 'confidence', 'source', 'task', 'acceptance', 'labels', 'assignee',
        'priority', 'type', 'estimate', 'rank', 'sprint', 'parent', 'capability',
        'goalDoc', 'blockedReason', 'parkedReason', 'human'}),
    'update': frozenset({'id', 'patch', 'session'}),
    'status': frozenset({'id', 'status', 'session', 'reason'}),
    'move': frozenset({'id', 'epic', 'session'}),
    'delete': frozenset({'id', 'session'}),
    'acceptance': frozenset({'id', 'text', 'remove', 'index', 'done'}),
    'label': frozenset({'id', 'label', 'present'}),
    'dep': frozenset({'id', 'blockedBy', 'present'}),
    'evidence': frozenset({'id', 'ref'}), 'commit': frozenset({'id', 'ref'}),
    'touch': frozenset({'id', 'path'}), 'comment': frozenset({'id', 'text'}),
    'link': frozenset({'id', 'type', 'target', 'present'}),
    'triage': frozenset({'all', 'dryRun'}), 'state': frozenset({'name', 'value'}),
    'config': frozenset({'name', 'value'}), 'override': frozenset({'reason'}),
    'recruit': frozenset({'id', 'lead'}), 'approve': frozenset({'id', 'members'}),
    'retire': frozenset({'id', 'members'}), 'hire': frozenset({'id', 'name'}),
    'plcstate': frozenset({'target', 'action', 'phase', 'reset_type', 'token', 'confirm'}),
    'bootapp': frozenset({'target', 'action', 'phase', 'token', 'confirm'}),
    'chatsend': frozenset({'recipient', 'text', 'ref'}),
    'run-review': frozenset({'decision', 'note'})
}


def _contains_identity(value):
    if isinstance(value, dict):
        return bool(_FORGED.intersection(value)) or any(
            _contains_identity(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_identity(item) for item in value)
    return False


def _action(target):
    board = _BOARD_PATH.fullmatch(target) if isinstance(target, str) else None
    if board is not None and board.group(1) in _ACTIONS:
        return board.group(1)
    run = _RUN_PATH.fullmatch(target) if isinstance(target, str) else None
    if run is not None:
        return 'run-review'
    raise ContractError('dashboard_command_unavailable')


@dataclass(frozen=True, repr=False)
class DashboardEffectReceipt:
    operation_id: str
    payload_digest: str
    status: str
    result: bytes | None = None

    def __post_init__(self):
        if (not _OPERATION.fullmatch(self.operation_id)
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.payload_digest)
                or self.status not in ('applied', 'not-applied', 'uncertain')
                or self.result is not None and (type(self.result) is not bytes
                    or len(self.result) > 262144
                    or canonical_bytes(strict_loads(self.result)) != self.result)
                or self.status != 'applied' and self.result is not None):
            raise ContractError('dashboard_effect_receipt_invalid')

    def __repr__(self):
        return '<DashboardEffectReceipt private>'

    def result_copy(self):
        return None if self.result is None else strict_loads(self.result)

class DashboardEffectOwner:
    """Interface for the retained database or delegated effect owner."""
    async def execute(self, *, operation_id, payload, action, body, actor):
        raise NotImplementedError


class DashboardEffectNotApplied(RuntimeError):
    def __init__(self, cause):
        super().__init__('dashboard_effect_not_applied')
        self.cause = cause

    def __repr__(self):
        return '<DashboardEffectNotApplied private>'


class DashboardDomainEffects:
    """Closed domain adapter supplied by the dashboard and orchestration owners."""
    def apply_transactional(self, db, target, action, body, actor):
        raise NotImplementedError

    def apply_external(self, target, action, body, actor):
        raise NotImplementedError


class SQLiteDashboardEffectOwner(DashboardEffectOwner):
    """Retain intent and exact outcome in the protected dashboard database."""
    _EXTERNAL = frozenset({'retire', 'hire', 'plcstate', 'bootapp', 'chatsend',
                           'run-review'})
    _EPHEMERAL = frozenset({'plcstate', 'bootapp'})
    _SCHEMA = """CREATE TABLE IF NOT EXISTS dashboard_command_effects (
        operation_id TEXT PRIMARY KEY, payload_digest TEXT NOT NULL,
        action TEXT NOT NULL, actor TEXT NOT NULL, status TEXT NOT NULL,
        created_at TEXT NOT NULL, completed_at TEXT, result BLOB)"""

    def __init__(self, database_path, *, device, inode, owner_uid, effects):
        path = Path(database_path)
        if (not path.is_absolute() or type(device) is not int or type(inode) is not int
                or type(owner_uid) is not int or owner_uid != os.getuid()
                or not isinstance(effects, DashboardDomainEffects)):
            raise ContractError('dashboard_effect_configuration')
        self._path, self._identity = path, (device, inode, owner_uid)
        self._effects = effects
        self._lock = asyncio.Lock()
        self._jobs = set()
        self._close_task = None
        self._ephemeral_results = {}
        self._closed = False
        self._check_path()

    def __repr__(self):
        return '<SQLiteDashboardEffectOwner private>'

    def _check_path(self):
        info = self._path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (info.st_dev, info.st_ino, info.st_uid) != self._identity):
            raise ContractError('dashboard_effect_database_changed')

    @contextmanager
    def _connection(self):
        self._check_path()
        db = sqlite3.connect(self._path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute(self._SCHEMA)
        columns = {row['name'] for row in
                   db.execute('PRAGMA table_info(dashboard_command_effects)')}
        if 'result' not in columns:
            db.execute('ALTER TABLE dashboard_command_effects ADD COLUMN result BLOB')
        try:
            with db:
                yield db
        finally:
            db.close()

    def _existing(self, db, operation_id, digest, action):
        row = db.execute("SELECT payload_digest,action,status,result FROM dashboard_command_effects "
                         "WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            return None
        if row['payload_digest'] != digest or row['action'] != action:
            raise ContractError('dashboard_effect_retargeted')
        result = row['result']
        if result is None and row['status'] == 'applied':
            result = self._ephemeral_results.get(operation_id)
            if result is None:
                # An applied ephemeral response cannot be reconstructed after a
                # process restart. Never repeat its effect to mint a replacement.
                return DashboardEffectReceipt(operation_id, digest, 'uncertain')
        return DashboardEffectReceipt(operation_id, digest, row['status'], result)

    def _transactional(self, operation_id, digest, target, action, body, actor):
        try:
            with self._connection() as db:
                existing = self._existing(db, operation_id, digest, action)
                if existing is not None:
                    return existing
                now = datetime.now(timezone.utc).isoformat(timespec='microseconds')
                db.execute("INSERT INTO dashboard_command_effects "
                           "(operation_id,payload_digest,action,actor,status,created_at,"
                           "completed_at,result) VALUES (?,?,?,?,?,?,NULL,NULL)",
                           (operation_id, digest, action, actor, 'uncertain', now))
                result = canonical_bytes(self._effects.apply_transactional(db, target, action,
                    strict_loads(canonical_bytes(body)), actor))
                if len(result) > 262144:
                    raise ContractError('dashboard_effect_result_too_large')
                completed = datetime.now(timezone.utc).isoformat(timespec='microseconds')
                db.execute("UPDATE dashboard_command_effects SET status='applied',completed_at=?,"
                           "result=? WHERE operation_id=?", (completed, result, operation_id))
        except DashboardEffectNotApplied:
            raise
        except ContractError:
            raise
        except Exception as error:
            raise DashboardEffectNotApplied(error) from None
        return DashboardEffectReceipt(operation_id, digest, 'applied', result)

    def _begin_external(self, operation_id, digest, action, actor):
        with self._connection() as db:
            existing = self._existing(db, operation_id, digest, action)
            if existing is not None:
                return existing
            now = datetime.now(timezone.utc).isoformat(timespec='microseconds')
            db.execute("INSERT INTO dashboard_command_effects "
                       "(operation_id,payload_digest,action,actor,status,created_at,"
                       "completed_at,result) VALUES (?,?,?,?,?,?,NULL,NULL)",
                       (operation_id, digest, action, actor, 'uncertain', now))
        return None

    def _finish_external(self, operation_id, digest, action, result):
        raw = canonical_bytes(result)
        if len(raw) > 262144:
            raise ContractError('dashboard_effect_result_too_large')
        with self._connection() as db:
            existing = self._existing(db, operation_id, digest, action)
            if existing is None:
                raise ContractError('dashboard_effect_intent_missing')
            completed = datetime.now(timezone.utc).isoformat(timespec='microseconds')
            retained = None if action in self._EPHEMERAL else raw
            db.execute("UPDATE dashboard_command_effects SET status='applied',completed_at=?,"
                       "result=? WHERE operation_id=? AND status='uncertain'",
                       (completed, retained, operation_id))
        if action in self._EPHEMERAL:
            self._ephemeral_results[operation_id] = raw
        return DashboardEffectReceipt(operation_id, digest, 'applied', raw)

    async def _execute(self, operation_id, payload, action, body, actor):
        digest = payload_digest(payload)
        async with self._lock:
            if action not in self._EXTERNAL:
                return await asyncio.to_thread(self._transactional, operation_id,
                    digest, payload['target'], action, body, actor)
            existing = await asyncio.to_thread(self._begin_external, operation_id,
                digest, action, actor)
            if existing is not None:
                return existing
            # The durable uncertain row prevents a retry from repeating an effect
            # after the caller, process or host loses its result.
            result = await asyncio.to_thread(self._effects.apply_external,
                payload['target'], action, strict_loads(canonical_bytes(body)), actor)
            return await asyncio.to_thread(self._finish_external, operation_id,
                                           digest, action, result)

    def _job_done(self, job):
        self._jobs.discard(job)
        try:
            job.exception()
        except BaseException:
            pass

    async def execute(self, *, operation_id, payload, action, body, actor):
        if self._closed or action not in _ACTIONS:
            raise ContractError('dashboard_effect_unavailable')
        job = asyncio.create_task(self._execute(operation_id, payload, action, body, actor))
        self._jobs.add(job)
        job.add_done_callback(self._job_done)
        return await asyncio.shield(job)

    async def _finish_close(self):
        self._closed = True
        while self._jobs:
            await asyncio.gather(*tuple(self._jobs), return_exceptions=True)
        self._ephemeral_results.clear()

    async def close(self):
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._finish_close())
        await asyncio.shield(self._close_task)


class DashboardOutcomeUnconfirmed(RuntimeError):
    def __init__(self, operation_id):
        super().__init__('dashboard_outcome_unconfirmed')
        self.operation_id = operation_id

    def __repr__(self):
        return '<DashboardOutcomeUnconfirmed private>'


class DashboardCommandService:
    """Bind one browser request to current authority and one retained effect."""
    def __init__(self, authority, *, scope, resource_ref, effects):
        if (not isinstance(authority, LedgerAuthorityReader)
                or not isinstance(effects, DashboardEffectOwner)):
            raise ContractError('dashboard_service_configuration')
        scope = strict_loads(canonical_bytes(scope))
        resource = strict_loads(canonical_bytes(resource_ref))
        if (not isinstance(scope, dict) or set(scope) != {
                'organizationId', 'projectId', 'workspaceId'}
                or not isinstance(scope['projectId'], str) or not scope['projectId']
                or not isinstance(resource, dict) or set(resource) != {
                    'id', 'ownerHubId', 'revision'}
                or resource['ownerHubId'] != authority._hub
                or type(resource['revision']) is not int or resource['revision'] < 0):
            raise ContractError('dashboard_service_configuration')
        self._authority, self._scope = authority, canonical_bytes(scope)
        self._resource, self._effects = canonical_bytes(resource), effects
        self._lock = asyncio.Lock()
        self._active = set()
        self._closed = False

    def __repr__(self):
        return '<DashboardCommandService private>'

    async def _authorize(self, context, payload):
        if not verified_local_browser_context(context):
            raise ContractError('local_browser_context_invalid')
        snapshot = await self._authority.current()
        now = datetime.now(timezone.utc)
        record = strict_loads(snapshot.record)
        expected_ref = {'id': record['entityId'], 'ownerHubId': record['ownerHubId'],
                        'revision': record['entityVersion']}
        if (context.scope != strict_loads(self._scope)
                or context.authority_ref != expected_ref
                or snapshot.sequence < context.authority_sequence):
            raise ContractError('dashboard_not_authorized')
        index = _indexes(record['state'], record['ownerHubId'])
        caller = index['identities'].get(_key(context.caller_ref))
        if caller is None or caller['kind'] != 'human' or not _active(caller, now):
            raise ContractError('dashboard_not_authorized')
        resource = strict_loads(self._resource)
        _permission(index, caller['ref'], context.scope, 'dashboard-command',
                    resource['id'], now)
        if payload['resourceRef'] != resource:
            raise ContractError('dashboard_command_binding')
        return caller['principalId']

    async def handle_local_browser(self, context, target, body, *, operation_id):
        if self._closed or not _OPERATION.fullmatch(operation_id or ''):
            raise ContractError('dashboard_service_unavailable')
        action = _action(target)
        if (not isinstance(body, dict) or set(body) - _FIELDS[action]
                or _contains_identity(body)):
            raise ContractError('dashboard_identity_field_refused')
        raw = canonical_bytes(body)
        if len(raw) > 65536:
            raise ContractError('owner_body_limit')
        detached = strict_loads(raw)
        payload = {'resourceRef': strict_loads(self._resource), 'requestId': operation_id,
                   'target': target, 'action': action,
                   'bodyDigest': payload_digest(detached)}
        if len(self._active) >= 32:
            raise ContractError('dashboard_service_busy')
        marker = asyncio.get_running_loop().create_future()
        self._active.add(marker)
        try:
            async with self._lock:
                actor = await self._authorize(context, payload)
                try:
                    receipt = await self._effects.execute(operation_id=operation_id,
                        payload=strict_loads(canonical_bytes(payload)), action=action,
                        body=detached, actor=actor)
                except asyncio.CancelledError:
                    raise
                except DashboardEffectNotApplied as error:
                    raise error.cause
                except Exception:
                    raise DashboardOutcomeUnconfirmed(operation_id) from None
                if (not isinstance(receipt, DashboardEffectReceipt)
                        or receipt.operation_id != operation_id
                        or receipt.payload_digest != payload_digest(payload)):
                    raise DashboardOutcomeUnconfirmed(operation_id)
                if receipt.status == 'uncertain':
                    raise DashboardOutcomeUnconfirmed(operation_id)
                # Recheck before publishing an applied/not-applied owner outcome.
                try:
                    await self._authorize(context, payload)
                except Exception:
                    raise DashboardOutcomeUnconfirmed(operation_id) from None
                result = receipt.result_copy()
                if receipt.status == 'applied' and not isinstance(result, dict):
                    raise DashboardOutcomeUnconfirmed(operation_id)
                response = {} if result is None else result
                if set(response).intersection({'operationId', 'outcome'}):
                    raise DashboardOutcomeUnconfirmed(operation_id)
                response.update(operationId=operation_id, outcome=receipt.status)
                response.setdefault('ok', receipt.status == 'applied')
                return response
        finally:
            self._active.discard(marker)
            marker.set_result(None)

    async def close(self):
        self._closed = True
        if self._active:
            await asyncio.gather(*tuple(self._active), return_exceptions=True)
        close = getattr(self._effects, 'close', None)
        if callable(close):
            result = close()
            if asyncio.iscoroutine(result):
                await result

