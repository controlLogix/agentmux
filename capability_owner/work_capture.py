"""Resolve declared work capture sources from exact retained owner receipts."""
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, verify_envelope
from identity.authority import _active, _indexes, _key, approval_reason


@dataclass(frozen=True, repr=False)
class _Source:
    resource: object
    store: object
    connection: object
    executor: object
    source: object
    owner: object
    db: object
    knowledge_owner: object
    knowledge_db: object
    authority: object
    journal: object
    journal_binding: bytes


def _executor(owner):
    source = getattr(owner, '_source', None)
    if source is not None:
        return getattr(source, '_executor', None)
    hub = getattr(owner, '_hub', None) or getattr(owner, 'hub', None)
    return getattr(hub, 'dbx', None)


def bind_sources(knowledge, sources):
    """Pin explicit host declarations before the knowledge journal is opened."""
    from .work import WorkStorageResource
    if (type(sources) is not tuple or any(type(item) is not WorkStorageResource for item in sources)
            or len({item.binding.entity_id for item in sources}) != len(sources)):
        raise ContractError('capability_owner_configuration')
    result = []
    for work in sources:
        executor = _executor(work._owner)
        if (work._store is not knowledge._store or work._connection is not knowledge._store.db
                or executor is None or executor is not _executor(knowledge._owner)
                or work._source is not getattr(knowledge._owner, '_source', None)
                or work.binding.hub_id != knowledge.binding.hub_id
                or work.binding.scope != knowledge.binding.scope or work.repository != knowledge.repository
                or work._node != knowledge._node or work._legacy_authority is None
                or work.repository_id is not None and work.repository_id != knowledge.repository_id):
            raise ContractError('capability_owner_configuration')
        result.append(_Source(work, work._store, work._connection, executor, work._source,
            work._owner, work._db, knowledge._owner, knowledge._owner.db, work._legacy_authority,
            work._journal, work._journal.binding))
    return tuple(result)


def _current(knowledge, pin):
    work = pin.resource
    knowledge._current()
    work._current()
    if (work._owner is not pin.owner or knowledge._owner is not pin.knowledge_owner
            or work._store is not pin.store or knowledge._store is not pin.store
            or pin.store.db is not pin.connection or work._owner.db != pin.db
            or knowledge._owner.db != pin.knowledge_db
            or _executor(work._owner) is not pin.executor or _executor(knowledge._owner) is not pin.executor
            or work._source is not pin.source or getattr(knowledge._owner, '_source', None) is not pin.source
            or work._legacy_authority is not pin.authority
            or work._journal is not pin.journal or work._journal.binding != pin.journal_binding
            or work.binding.hub_id != knowledge.binding.hub_id or work.binding.scope != knowledge.binding.scope
            or work.repository != knowledge.repository or work._node != knowledge._node
            or work.repository_id is not None and work.repository_id != knowledge.repository_id):
        raise ContractError('capability_resource_stale')
    work._journal.current()


def _permission(work, original, snapshot):
    """Check present permission for an already applied original, without resubmission."""
    from .work_legacy import _permission as permission, _mutation_target, check_actor
    record = strict_loads(snapshot.record)
    reader = work._legacy_authority
    if (record['ownerHubId'] != reader._hub or record['entityId'] != reader._entity
            or record['state']['profileId'] != reader._profile
            or record['state']['organizationId'] != reader._organization):
        raise ContractError('capability_access_refused')
    index, now = _indexes(record['state'], work.binding.hub_id), datetime.now(timezone.utc)
    operation, claims = original['operation'], original['ingressAttestation']['claims']
    def live(collection, reference):
        value = index[collection].get(_key(reference))
        if value is None or not _active(value, now):
            raise ContractError('capability_access_refused')
        return value
    issuer = live('issuers', claims['signingKeyRef'])
    issuer_identity = live('identities', issuer['identityRef'])
    caller = live('identities', operation['caller']['authenticatedIdentityRef'])
    actor = live('identities', operation['effectiveActorRef'])
    transport = live('transports', claims['authenticatedTransportRef'])
    if (issuer_identity['kind'] != 'service' or issuer['instanceId'] != claims['sourceInstanceId']
            or claims['sourceHubId'] != work.binding.hub_id
            or transport['issuerRef'] != issuer['ref'] or transport['identityRef'] != caller['ref']
            or transport['method'] != claims['authenticationMethod']
            or caller['principalId'] != operation['caller']['principalId']
            or caller['kind'] != operation['caller']['kind'] or caller['ref'] != actor['ref']
            or operation['delegationRef'] is not None
            or canonical_bytes(operation['scope']) != work.binding.scope
            or not any(_active(member, now) and member['identityRef'] == actor['ref']
                and member['scope'] == operation['scope'] for member in index['memberships'].values())):
        raise ContractError('capability_access_refused')
    # A retained journal proves application; validate the original signed bytes
    # at their admitted time, then independently require current permission.
    verify_envelope(original, base64.urlsafe_b64decode(issuer['publicKey'] + '='),
        {'hubId': work.binding.hub_id, 'serviceId': 'storage-owner'},
        datetime.fromisoformat(claims['issuedAt']))
    matches = [item for item in work._legacy_actors if item.identity_ref == canonical_bytes(actor['ref'])
        and item.transport_ref == canonical_bytes(transport['ref'])]
    if len(matches) != 1:
        raise ContractError('capability_access_refused')
    selected = matches[0]
    check_actor(work, selected)
    grant = permission(work, index, selected, operation, original['contractId'], now)
    if (grant['ref'] != operation['grantRef'] or approval_reason(index, grant, operation,
            audience={'hubId': work.binding.hub_id, 'serviceId': 'storage-owner'},
            scope=operation['scope'], contract=original['contractId'], now=now) is not None):
        raise ContractError('capability_access_refused')
    _mutation_target(work, selected, actor, original['contractId'], original['payload']['input'])
    limits = [now + timedelta(seconds=5)]
    for collection in ('issuers', 'transports', 'grants', 'approvals'):
        for item in record['state'][collection]:
            if item['status'] == 'active':
                limits.extend(datetime.fromisoformat(item[key]) for key in ('issuedAt', 'expiresAt')
                    if datetime.fromisoformat(item[key]) > now)
    return min(limits)


def capture_source(knowledge, source, snapshot):
    """Run on the shared owner executor before effect and final disclosure."""
    if (type(source) is not dict or set(source) != {'kind', 'id', 'digest', 'resourceRef',
            'receiptRef', 'operationId', 'payloadDigest'} or source['kind'] not in ('work-released', 'fed-result')):
        raise ContractError('capability_access_refused')
    pins = [pin for pin in knowledge._work_capture_sources
        if pin.resource.binding.entity_id == source['resourceRef']['id']
        and pin.resource.binding.hub_id == source['resourceRef']['ownerHubId']]
    if len(pins) != 1:
        raise ContractError('capability_access_refused')
    pin, work = pins[0], pins[0].resource
    _current(knowledge, pin)
    stored = work._journal.outcome(source['operationId'], source['payloadDigest'])
    if (stored is None or stored['reply']['outcome'] != 'applied'
            or stored['reply']['resourceRef'] != source['resourceRef']
            or stored['reply']['receiptRef'] != source['receiptRef']):
        raise ContractError('capability_access_refused')
    original = stored['envelope']
    reference = original['payload']['resourceRef']
    if (reference['id'] != work.binding.entity_id or reference['ownerHubId'] != work.binding.hub_id
            or reference['revision'] != original['operation']['expectedVersion']
            or source['resourceRef']['revision'] != reference['revision'] + 1):
        raise ContractError('capability_access_refused')
    if source['kind'] == 'work-released':
        if original['contractId'] != 'federation-work-release':
            raise ContractError('capability_access_refused')
        row = stored['result']
        if original['payload']['input']['workId'] != source['id']:
            raise ContractError('capability_access_refused')
    else:
        if (original['contractId'] not in ('federation-work-result-envelope',
                'federation-work-approve', 'federation-work-approve-privileged')
                or original['payload']['input']['envelope']['type'] != 'result'
                or stored['result'].get('outcome') != 'delivered'):
            raise ContractError('capability_access_refused')
        row = stored['result'].get('work')
        if original['payload']['input']['envelope']['data']['origin_id'] != source['id']:
            raise ContractError('capability_access_refused')
    if (type(row) is not dict or row.get('id') != source['id'] or row.get('repo') != knowledge.repository
            or payload_digest(row) != source['digest'] or not row.get('result')):
        raise ContractError('capability_access_refused')
    deadline = _permission(work, original, snapshot)
    _current(knowledge, pin)
    return row, deadline
