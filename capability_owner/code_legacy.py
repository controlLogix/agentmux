"""Current caller admission and retained commands for original code records."""
from dataclasses import dataclass, field
from datetime import datetime, timezone

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from hub.fed import envelope, guard
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key, evaluate_snapshot
from identity.code_client import CODE_COMMANDS
from .messages import MessageActor


@dataclass(frozen=True, repr=False)
class LegacyCodeActor(MessageActor):
    grants: bytes = field(repr=False)

    def __post_init__(self):
        super().__post_init__()
        from .policy import _reference
        grants = strict_loads(self.grants)
        if (canonical_bytes(grants) != self.grants or type(grants) is not dict or not grants
                or set(grants) - CODE_COMMANDS or any(not _reference(ref) for ref in grants.values())):
            raise ContractError('capability_owner_configuration')


@dataclass(frozen=True, repr=False, init=False, slots=True)
class _Admission:
    resource: object
    original: bytes
    actor: LegacyCodeActor
    valid_until: datetime
    snapshot: object

    def __new__(cls):
        raise TypeError('Current code authorization is required')


async def authorize(resource, authority, raw):
    if not isinstance(authority, LedgerAuthorityReader) or type(raw) is not bytes or len(raw) > 1048576:
        raise ContractError('capability_access_refused')
    original = strict_loads(raw)
    validate('message-envelope', original)
    contract = original['contractId']
    if canonical_bytes(original) != raw or contract not in CODE_COMMANDS:
        raise ContractError('capability_access_refused')
    validate(contract, original['payload'])
    resource._current()
    if contract == 'federation-code-approve':
        await resource._owner.db(check_approval, resource, original)
    snapshot = await authority.current()
    now = datetime.now(timezone.utc)
    decision = evaluate_snapshot(snapshot, raw,
        audience={'hubId': resource.binding.hub_id, 'serviceId': 'storage-owner'}, now=now)
    operation, payload = original['operation'], original['payload']
    reference = payload['resourceRef']
    actor_ref = canonical_bytes(operation['effectiveActorRef'])
    transport_ref = canonical_bytes(original['ingressAttestation']['claims']['authenticatedTransportRef'])
    matches = [actor for actor in resource._legacy_actors
        if (actor.identity_ref, actor.transport_ref) == (actor_ref, transport_ref)]
    if (decision.outcome != 'allowed' or len(matches) != 1 or operation['delegationRef'] is not None
            or canonical_bytes(operation['scope']) != resource.binding.scope
            or reference['id'] != resource.binding.entity_id or reference['ownerHubId'] != resource.binding.hub_id):
        raise ContractError('capability_access_refused')
    actor = matches[0]
    grants = strict_loads(actor.grants)
    if grants.get(contract) != operation['grantRef']:
        raise ContractError('capability_access_refused')
    index = _indexes(strict_loads(snapshot.record)['state'], resource.binding.hub_id)
    principal = index['identities'].get(_key(operation['effectiveActorRef']))
    if (principal is None
            or contract == 'federation-code-index' and (principal['kind'] != 'service' or actor.caller != 'federation')
            or contract in ('federation-code-publish', 'federation-code-fetched')
                and (principal['kind'] not in ('human', 'device') or actor.caller == 'federation')
            or contract == 'federation-code-approve' and (principal['kind'] != 'human'
                or actor.caller != 'operator' or payload['attribution'] != 'operator')):
        raise ContractError('capability_access_refused')
    if contract == 'federation-code-outcome':
        selected = grants.get(payload['input']['contractId'])
        grant = None if selected is None else index['grants'].get(_key(selected))
        if (grant is None or not _active(grant, now) or grant['decision'] != 'allowed'
                or grant['delegationRef'] is not None or grant['callerRef'] != operation['effectiveActorRef']
                or grant['actorRef'] != operation['effectiveActorRef'] or grant['scope'] != operation['scope']
                or grant['resourceId'] != resource.binding.entity_id
                or grant['contractId'] != payload['input']['contractId']):
            raise ContractError('capability_access_refused')
    if contract == 'federation-code-index' and payload['attribution'] != 'federation':
        raise ContractError('capability_access_refused')
    if contract in ('federation-code-publish', 'federation-code-index', 'federation-code-approve'):
        item = payload['input']['envelope']
        resource._validate_item(item, incoming=contract != 'federation-code-publish')
        if contract == 'federation-code-publish':
            attribution = payload['attribution']
            if actor.caller not in ('operator', 'virtual:operator') and attribution != actor.caller:
                raise ContractError('capability_access_refused')
            resource._check_publication_author(item, attribution)
        elif (item['from'] == resource._peer or payload['input']['localNode'] != resource._node
                or payload['input']['subject'] != envelope.subject('code', item['from'], resource.repository_id)):
            raise ContractError('capability_access_refused')
    elif contract == 'federation-code-fetched':
        if actor.caller not in ('operator', 'virtual:operator') and payload['attribution'] != actor.caller:
            raise ContractError('capability_access_refused')
    checked = object.__new__(_Admission)
    for name, value in (('resource', resource), ('original', raw), ('actor', actor),
            ('valid_until', decision.valid_until), ('snapshot', snapshot)):
        object.__setattr__(checked, name, value)
    return checked


def check_approval(resource, original):
    resource._current()
    value, item = original['payload']['input'], original['payload']['input']['envelope']
    held = resource._store.q1('SELECT * FROM fed_quarantine WHERE id=?', (value['quarantineId'],))
    current = guard.inbound(resource._owner.policy, value['subject'], item)
    if (held is None or held['state'] not in ('held', 'approved') or held['plane'] != 'code'
            or held['peer'] != item['from'] or held['subject'] != value['subject']
            or canonical_bytes(strict_loads(held['envelope'])) != canonical_bytes(item)
            or current.action == 'drop' or current.local_repo != resource.repository):
        raise ContractError('capability_access_refused')
    return guard.Decision('deliver', 'approved by operator', current.trust, untrusted=True,
        local_repo=current.local_repo, approved=True, privileged_ok=value['privileged'])


async def _read(resource, value, valid_until):
    def load():
        resource._current()
        resource._journal._deadline(valid_until)
        command = value['command']
        if command == 'get':
            sql = 'SELECT * FROM p_code_shares WHERE id=? AND repo=? AND rid=?'
            args = (value['id'], resource.repository, resource.repository_id)
        else:
            fields = ('id, repo, from_peer, author, ref, substr(sha,1,12) sha, stat, note, fetched, at'
                if command == 'list' else 'id, repo, from_peer, author, ref, sha, stat, note, fetched, at')
            sql = 'SELECT ' + fields + ' FROM p_code_shares WHERE repo=? AND rid=? ORDER BY at DESC LIMIT ?'
            args = (resource.repository, resource.repository_id, 50 if command == 'list' else 20)
        rows, size = [], 2
        cursor = resource._store.db.execute(sql, args)
        try:
            for row in cursor:
                row = dict(row)
                size += len(canonical_bytes(row)) + 1
                if size > 1_000_000:
                    raise ContractError('capability_service_unavailable')
                rows.append(row)
        finally:
            cursor.close()
        resource._journal._deadline(valid_until)
        if command == 'get':
            return {'row': rows[0] if rows else None}
        return {'rows': rows}
    return await resource._owner.db(load)


async def apply(resource, authority, raw):
    async with resource._lock:
        checked = await authorize(resource, authority, raw)
        original = strict_loads(raw)
        contract, payload = original['contractId'], original['payload']
        value = payload['input']
        if contract == 'federation-code-read':
            result = await _read(resource, value, checked.valid_until)
            await authorize(resource, authority, raw)
            return result
        if contract in ('federation-code-inspect', 'federation-code-outcome'):
            def load():
                resource._current()
                resource._journal._deadline(checked.valid_until)
                current = resource._journal.current()
                reference = {'id': resource.binding.entity_id, 'ownerHubId': resource.binding.hub_id,
                    'revision': current['revision']}
                if contract == 'federation-code-inspect':
                    return {'resourceRef': reference}
                stored = resource._journal.outcome(value['operationId'], value['payloadDigest'])
                if stored is None:
                    return {**value, 'outcome': 'absent', 'resourceRef': None, 'receiptRef': None, 'result': None}
                if (stored['envelope']['contractId'] != value['contractId']
                        or stored['envelope']['operation']['effectiveActorRef'] != original['operation']['effectiveActorRef']):
                    raise ContractError('capability_access_refused')
                return {**value, **stored['reply'], 'result': stored['result']}
            result = await resource._owner.db(load)
            await authorize(resource, authority, raw)
            return result
        checked = await authorize(resource, authority, raw)
        def effect():
            resource._current()
            command = {'federation-code-publish': 'publish', 'federation-code-index': 'index',
                'federation-code-approve': 'index', 'federation-code-fetched': 'fetched'}[contract]
            result, source = resource._effect({**value, 'command': command},
                approval=checked if contract == 'federation-code-approve' else None)
            if command == 'index':
                result['outcome'] = 'delivered'
            return result, source
        stored = await resource._owner.db(resource._journal.commit, original, payload['resourceRef']['revision'],
            checked.valid_until, effect)
        return {**stored['reply'], 'result': stored['result']}
