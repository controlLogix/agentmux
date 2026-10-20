"""Preserve a complete legacy federation ledger without activating delivery.

The host supplies an admitted private capture and its source organization. The
archive has one initial conditional record; later reconciliation and writer
transfer require separate commands and authority.
"""
import asyncio
from datetime import datetime, timezone
import sqlite3
import time

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.authority import LedgerAuthorityReader, evaluate_snapshot
from .ledger import (MAX_RECORD_BYTES, OwnerBinding, OwnerLedger, find_outcome,
                     validate_record)
from .task_migration import TaskMigrationSnapshot, _source, require_unmodified_import_source


# Fixed source names and columns are never taken from request data. Sequence
# order is retained where present; other families use their binary primary key.
TABLES = {
    'fed_outbox': ('seq', ('seq', 'msg_id', 'subject', 'payload', 'created', 'sent', 'attempts', 'last_error')),
    'fed_seen': ('msg_id', ('msg_id', 'at')),
    'fed_audit': ('seq', ('seq', 'at', 'dir', 'plane', 'peer', 'rid', 'subject', 'msg_id', 'sha', 'size', 'decision', 'detail')),
    'fed_quarantine': ('id', ('id', 'at', 'peer', 'plane', 'reason', 'subject', 'envelope', 'state', 'decided', 'decided_by')),
    'fed_state': ('k', ('k', 'v')),
}
MAX_FAMILY_ROWS = 1024
MAX_READ_INSTRUCTIONS = 10000
MAX_READ_SECONDS = 1.0


def _binding(binding):
    if (type(binding) is not OwnerBinding
            or (binding.owner_domain, binding.entity_kind) != ('federation-archive', 'federation-archive')):
        raise ContractError('federation_archive_configuration')
    scope = strict_loads(binding.scope)
    if scope['projectId'] is not None or scope['workspaceId'] is not None:
        raise ContractError('federation_archive_organization_required')
    return scope


def _namespace(source_ref, *, target_hub_id, scope):
    source = _source(source_ref)
    target = OwnerBinding(target_hub_id, 'federation-archive', 'archive-target',
        'federation-archive', canonical_bytes(scope))
    return {'format': 'amx-federation-archive-identity-v1', 'targetOwnerHubId': target.hub_id,
        'ownerDomain': target.owner_domain, 'scope': _binding(target),
        'source': {k: source[k] for k in ('id', 'ownerHubId')}}


def federation_archive_identity(source_ref, *, target_hub_id, scope):
    digest = payload_digest(_namespace(source_ref, target_hub_id=target_hub_id, scope=scope)).split(':')[1]
    return {'archiveId': 'archive_'+digest, 'operationId': 'import_'+digest}


def _member_id(source_ref, table, primary_key, binding):
    namespace = _namespace(source_ref, target_hub_id=binding.hub_id, scope=strict_loads(binding.scope))
    return 'member_'+payload_digest(namespace | {'table': table, 'primaryKey': primary_key}).split(':')[1]


def _primary_key(table, row):
    key = TABLES[table][0]
    value = row[key]
    expected = int if key == 'seq' else str
    if type(value) is not expected:
        raise ContractError('federation_archive_source_invalid')
    return {'column': key, 'type': 'integer' if expected is int else 'text', 'value': value}


class FederationArchiveSource:
    """Borrow the original descriptor-bound snapshot; never reopen its path."""
    def __init__(self, snapshot, *, source_owner_organization_id):
        if type(snapshot) is not TaskMigrationSnapshot:
            raise ContractError('federation_archive_configuration')
        # Validate the protected ownership selection without treating it as a grant.
        OwnerBinding('source', 'federation-archive', 'source', 'federation-archive',
            canonical_bytes({'organizationId': source_owner_organization_id,
                'projectId': None, 'workspaceId': None}))
        self._snapshot = snapshot
        self._organization = source_owner_organization_id

    def __repr__(self):
        return '<FederationArchiveSource private read-only>'

    def read(self, binding):
        scope = _binding(binding)
        if scope['organizationId'] != self._organization:
            raise ContractError('federation_archive_source_scope_mismatch')
        snapshot = self._snapshot
        db = prior_limit = None
        progress_installed = False
        try:
            snapshot._check_file()
            db = snapshot._db
            prior_limit = db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_RECORD_BYTES)
            instructions = 0
            deadline = time.monotonic() + MAX_READ_SECONDS
            def stop_read():
                nonlocal instructions
                instructions += 1
                return (instructions > MAX_READ_INSTRUCTIONS
                    or (instructions % 100 == 0 and time.monotonic() >= deadline))
            # The exact TaskMigrationSnapshot owns this private connection and
            # installs no progress handler. This synchronous borrow cannot
            # overlap its other reads; return it with that original empty handler.
            db.set_progress_handler(stop_read, 1)
            progress_installed = True
            families = {}
            budget = MAX_RECORD_BYTES
            for table, (key, columns) in TABLES.items():
                info = list(db.execute('PRAGMA table_xinfo('+table+')'))
                present = bool(info)
                if present != (snapshot._schema_version >= 4):
                    raise ContractError('federation_archive_source_invalid')
                rows = []
                count = 0
                if present:
                    if (tuple(r['name'] for r in info) != columns
                            or any(r['hidden'] or bool(r['pk']) != (r['name'] == key) for r in info)):
                        raise ContractError('federation_archive_source_invalid')
                    # Counting and sorting a whole large family before checking
                    # row bytes would bypass the bounded archive admission.
                    count = db.execute('SELECT count(*) FROM (SELECT 1 FROM '+table+' LIMIT ?)',
                        (MAX_FAMILY_ROWS+1,)).fetchone()[0]
                    if count > MAX_FAMILY_ROWS:
                        raise ContractError('federation_archive_artifact_required')
                    for row in db.execute('SELECT * FROM '+table+' ORDER BY '+key+' COLLATE BINARY'):
                        if time.monotonic() >= deadline:
                            raise ContractError('federation_archive_source_unavailable')
                        raw = dict(row)
                        primary = _primary_key(table, raw)
                        member = {'memberId': _member_id(snapshot._source, table, primary, binding),
                            'primaryKey': primary, 'row': raw}
                        budget -= len(canonical_bytes(member))
                        if budget < 0:
                            raise ContractError('federation_archive_artifact_required')
                        rows.append(member)
                families[table] = {'present': present, 'count': count, 'rows': rows}
            result = {'format': 'amx-legacy-federation-source-v1', 'sourceRef': snapshot._source,
                'sourceOwnerOrganizationId': self._organization,
                'databaseDigest': snapshot._digest, 'schemaVersion': snapshot._schema_version,
                'applicationVersion': snapshot._application_version, 'families': families,
                'historicalHoldingPolicy': 'unknown', 'policyRevalidationRequired': True}
            raw = canonical_bytes(result)
            if len(raw) > MAX_RECORD_BYTES:
                raise ContractError('federation_archive_artifact_required')
            snapshot._check_file()
            return strict_loads(raw)
        except ContractError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError, OverflowError):
            raise ContractError('federation_archive_source_unavailable') from None
        finally:
            if progress_installed:
                db.set_progress_handler(None, 0)
            if db is not None and prior_limit is not None:
                db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, prior_limit)


def prepare_federation_import(source, *, binding):
    if type(source) is not FederationArchiveSource:
        raise ContractError('federation_archive_configuration')
    archive = source.read(binding)
    identity = federation_archive_identity(archive['sourceRef'], target_hub_id=binding.hub_id,
        scope=strict_loads(binding.scope))
    if identity['archiveId'] != binding.entity_id:
        raise ContractError('federation_archive_binding_mismatch')
    payload = {'archiveId': identity['archiveId'], 'sourceRef': archive['sourceRef'],
        'captureDigest': archive['databaseDigest'], 'archiveDigest': payload_digest(archive),
        'sourceArchive': archive}
    validate('federation-ledger-import', payload)
    require_unmodified_import_source(archive)
    if len(canonical_bytes(payload)) > MAX_RECORD_BYTES:
        raise ContractError('federation_archive_artifact_required')
    return payload


def validate_federation_archive(raw, binding, *, authority_id):
    """Validate retained complete evidence, including member identity and order."""
    try:
        _binding(binding)
        record = validate_record(raw, binding)
        state, op = record['state'], record['operation']
        if (set(state) != {'archiveId', 'status', 'captureComplete', 'writerTransferRequired',
                'payload', 'importAuthorityRef'} or state['archiveId'] != binding.entity_id
                or state['status'] != 'reconciliation_required' or state['captureComplete'] is not True
                or state['writerTransferRequired'] is not True):
            raise ValueError()
        payload = state['payload']
        validate('federation-ledger-import', payload)
        archive = payload['sourceArchive']
        require_unmodified_import_source(archive)
        identity = federation_archive_identity(payload['sourceRef'], target_hub_id=binding.hub_id,
            scope=strict_loads(binding.scope))
        authority = _source(state['importAuthorityRef'])
        if (archive['sourceOwnerOrganizationId'] != strict_loads(binding.scope)['organizationId']
                or identity['archiveId'] != binding.entity_id or op['operationId'] != identity['operationId']
                or payload['archiveId'] != binding.entity_id or payload['sourceRef'] != archive['sourceRef']
                or payload['captureDigest'] != archive['databaseDigest']
                or payload['archiveDigest'] != payload_digest(archive)
                or op['payloadDigest'] != payload_digest(payload)
                or record['entityVersion'] != 1 or record['previousRevision'] != 0
                or op['expectedVersion'] != 0 or any(op[k] is not None for k in
                    ('taskId', 'runId', 'attemptId', 'delegationRef'))
                or op['caller']['kind'] not in ('human', 'service')
                or op['effectiveActorRef'] != op['caller']['authenticatedIdentityRef']
                or record['outcome'] != 'committed' or record['effects'] or record['artifacts']
                or record['repository'] is not None
                or authority['id'] != authority_id or authority['ownerHubId'] != binding.hub_id
                or record['authorizationDecision'] != {'operationId': op['operationId'],
                    'decision': 'allowed', 'reason': 'authorized', 'actorRef': op['effectiveActorRef'],
                    'contractId': 'federation-ledger-import'}):
            raise ValueError()
        for table, (key, columns) in TABLES.items():
            family = archive['families'][table]
            if (family['present'] != (archive['schemaVersion'] >= 4)
                    or family['count'] != len(family['rows'])
                    or (not family['present'] and family['rows'])):
                raise ValueError()
            keys = []
            for member in family['rows']:
                row = member['row']
                if set(row) != set(columns) or any(type(v) not in (str, int, type(None)) for v in row.values()):
                    raise ValueError()
                primary = _primary_key(table, row)
                if (member['primaryKey'] != primary or member['memberId'] != _member_id(
                        payload['sourceRef'], table, primary, binding)):
                    raise ValueError()
                keys.append(row[key])
            if keys != sorted(set(keys)):
                raise ValueError()
        return record
    except Exception:
        raise ContractError('federation_archive_record_invalid') from None


class FederationArchiveImporter:
    def __init__(self, authority, ledger, *, source):
        if (not isinstance(authority, LedgerAuthorityReader) or not isinstance(ledger, OwnerLedger)
                or type(source) is not FederationArchiveSource or not ledger.completion_budget_required):
            raise ContractError('federation_archive_configuration')
        scope = _binding(ledger._binding)
        if (authority._hub != ledger._binding.hub_id or authority._organization != scope['organizationId']
                or source._organization != scope['organizationId']):
            raise ContractError('federation_archive_source_scope_mismatch')
        self._authority, self._ledger, self._source = authority, ledger, source

    def __repr__(self):
        return '<FederationArchiveImporter private reconciliation-required>'

    async def _authorize(self, raw, envelope):
        snapshot = await self._authority.current()
        now = datetime.now(timezone.utc)
        decision = evaluate_snapshot(snapshot, raw,
            audience={'hubId': self._ledger._binding.hub_id, 'serviceId': 'federation-ledger-owner'}, now=now)
        if (decision.outcome != 'allowed' or decision.valid_until is None or not now < decision.valid_until
                or decision.operation != canonical_bytes(envelope['operation'])
                or canonical_bytes(envelope['operation']['scope']) != self._ledger._binding.scope):
            raise ContractError('federation_archive_access_refused')
        return decision

    async def handle(self, raw):
        if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES:
            raise ContractError('federation_archive_artifact_required')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if (envelope['kind'] != 'command' or envelope['contractId'] != 'federation-ledger-import'
                or canonical_bytes(envelope) != raw):
            raise ContractError('federation_archive_contract_unavailable')
        payload, op = envelope['payload'], envelope['operation']
        validate('federation-ledger-import', payload)
        async with asyncio.timeout(5):
            await self._authorize(raw, envelope)
            expected = prepare_federation_import(self._source, binding=self._ledger._binding)
            identity = federation_archive_identity(expected['sourceRef'], target_hub_id=self._ledger._binding.hub_id,
                scope=strict_loads(self._ledger._binding.scope))
            if (payload != expected or op['operationId'] != identity['operationId'] or op['expectedVersion'] != 0
                    or any(op[k] is not None for k in ('taskId', 'runId', 'attemptId', 'delegationRef'))):
                raise ContractError('federation_archive_binding_mismatch')
            current = await self._ledger.current()
            # This domain permits exactly one complete initial archive record.
            # An earlier outcome cannot conceal an unrecognized later write.
            if current.sequence not in (0, 1) or len(current.records) != current.sequence:
                raise ContractError('federation_archive_record_invalid')
            if current.latest is not None:
                validate_federation_archive(current.latest.record, self._ledger._binding,
                    authority_id=self._authority._entity)
            replay = find_outcome(current, op['operationId'], op['payloadDigest'])
            if replay is not None:
                await self._authorize(raw, envelope)
                return replay
            if current.sequence:
                raise ContractError('owner_revision_conflict')
            decision = await self._authorize(raw, envelope)
            record = {'schemaVersion': '1.0.0', 'recordId': 'federation'+identity['operationId'],
                'entityId': self._ledger._binding.entity_id, 'entityKind': 'federation-archive',
                'ownerHubId': self._ledger._binding.hub_id, 'ownerDomain': 'federation-archive',
                'entityVersion': 1, 'previousRevision': 0, 'operation': op,
                'recordedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'), 'outcome': 'committed',
                'state': {'archiveId': payload['archiveId'], 'status': 'reconciliation_required',
                    'captureComplete': True, 'writerTransferRequired': True, 'payload': payload,
                    'importAuthorityRef': strict_loads(decision.authority_ref)},
                'effects': [], 'artifacts': [], 'repository': None,
                'authorizationDecision': {'operationId': op['operationId'], 'decision': 'allowed',
                    'reason': 'authorized', 'actorRef': op['effectiveActorRef'], 'contractId': 'federation-ledger-import'}}
            encoded = canonical_bytes(record)
            if len(encoded) > MAX_RECORD_BYTES:
                raise ContractError('federation_archive_artifact_required')
            validate_federation_archive(encoded, self._ledger._binding, authority_id=self._authority._entity)
            stored = await self._ledger.append(record, expected_sequence=0, completion_records=0,
                valid_until=decision.valid_until)
            await self._authorize(raw, envelope)
            return stored
