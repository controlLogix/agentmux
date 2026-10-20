"""Current signed work commands over the original work transactions."""
from dataclasses import dataclass, field
from datetime import datetime, timezone

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from hub.fed import envelope, guard
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key, evaluate_snapshot
from identity.work_client import (WORK_COMMANDS, WORK_MUTATIONS, WORK_SERVICE_COMMANDS, WORK_LIFECYCLE_COMMANDS,
    WORK_PEER_COMMANDS, WORK_OPERATOR_COMMANDS)
from .messages import MessageActor


_ON_BEHALF_COMMANDS = frozenset('federation-work-' + name
    for name in ('create', 'offer', 'claim', 'heartbeat', 'release', 'claim-path'))


@dataclass(frozen=True, repr=False)
class LegacyWorkActor(MessageActor):
    grants: bytes = field(repr=False)

    def __post_init__(self):
        super().__post_init__()
        from .policy import _reference
        grants = strict_loads(self.grants)
        if (canonical_bytes(grants) != self.grants or type(grants) is not dict or not grants
                or set(grants) - WORK_COMMANDS or any(not _reference(ref) for ref in grants.values())):
            raise ContractError('capability_owner_configuration')


@dataclass(frozen=True, repr=False, init=False, slots=True)
class _Admission:
    resource: object
    original: bytes
    actor: LegacyWorkActor
    valid_until: datetime
    snapshot: object
    target: object
    control: object
    core: object
    source: object

    def __new__(cls):
        raise TypeError('Current work authorization is required')


def check_actor(resource, actor, *, original=None):
    resource._current()
    if type(actor) is not LegacyWorkActor or actor not in resource._legacy_actors:
        raise ContractError('capability_access_refused')
    from .first_worker import check_active, source_inspection
    if source_inspection(resource, actor, original):
        return
    check_active(resource, actor.caller)
    if actor.caller not in ('operator', 'federation'):
        current = resource._agent(actor.caller)
        if resource._legacy_actor_generations.get(actor.caller) != current['generation']:
            raise ContractError('capability_access_refused')


def _permission(resource, index, actor, operation, contract, now):
    reference = strict_loads(actor.grants).get(contract)
    grant = None if reference is None else index['grants'].get(_key(reference))
    principal = index['identities'].get(_key(operation['effectiveActorRef']))
    denied = any(candidate['decision'] == 'denied' and _active(candidate, now)
        and candidate['callerRef'] == operation['effectiveActorRef']
        and candidate['actorRef'] == operation['effectiveActorRef']
        and candidate['scope'] == operation['scope'] and candidate['resourceId'] == resource.binding.entity_id
        and candidate['contractId'] == contract for candidate in index['grants'].values())
    if (denied or principal is None or grant is None or not _active(grant, now)
            or grant['decision'] != 'allowed' or grant['delegationRef'] is not None
            or grant['callerRef'] != operation['effectiveActorRef']
            or grant['actorRef'] != operation['effectiveActorRef'] or grant['scope'] != operation['scope']
            or grant['resourceId'] != resource.binding.entity_id or grant['contractId'] != contract):
        raise ContractError('capability_access_refused')
    if (contract in WORK_SERVICE_COMMANDS and (principal['kind'] != 'service' or actor.caller != 'federation')
            or contract in WORK_OPERATOR_COMMANDS and (principal['kind'] != 'human' or actor.caller != 'operator')
            or contract in WORK_MUTATIONS - WORK_SERVICE_COMMANDS - WORK_OPERATOR_COMMANDS
                and (principal['kind'] not in ('human', 'device') or actor.caller == 'federation')
            or actor.caller == 'federation' and principal['kind'] != 'service'):
        raise ContractError('capability_access_refused')
    return grant


def _mutation_target(resource, actor, principal, contract, value):
    """Select an effective agent without replacing the actual signed operator."""
    if 'onBehalfOf' not in value:
        return None
    target = value['onBehalfOf']
    if (contract not in _ON_BEHALF_COMMANDS or actor.caller != 'operator'
            or principal is None or principal['kind'] != 'human'
            or type(target) is not dict or set(target) != {'session', 'generation'}
            or not resource._identifier(target['session']) or type(target['generation']) is not int
            or not 1 <= target['generation'] <= 9007199254740991):
        raise ContractError('capability_access_refused')
    resource._named_repo()
    current = resource._agent(target['session'])
    if current['generation'] != target['generation']:
        raise ContractError('capability_access_refused')
    return target['session'], target['generation']


def effect_caller(resource, checked):
    """Use the checked target only inside the original owner transaction."""
    if type(checked) is not _Admission or checked.resource is not resource:
        raise ContractError('capability_access_refused')
    check_actor(resource, checked.actor)
    resource._journal._deadline(checked.valid_until)
    original = strict_loads(checked.original)
    index = _indexes(strict_loads(checked.snapshot.record)['state'], resource.binding.hub_id)
    target = _mutation_target(resource, checked.actor,
        index['identities'].get(_key(original['operation']['effectiveActorRef'])),
        original['contractId'], original['payload']['input'])
    if target != checked.target:
        raise ContractError('capability_access_refused')
    return checked.actor.caller if target is None else target[0]


def _value(resource, contract, value):
    command = contract.removeprefix('federation-work-')
    if contract in WORK_LIFECYCLE_COMMANDS:
        return {'formatVersion': 1, 'command': command, **value}
    if contract in WORK_PEER_COMMANDS or command in ('approve', 'approve-privileged'):
        item = value['envelope']
        selected = {'work': 'ingest', 'work_claim': 'claim-envelope',
            'work_grant': 'grant-envelope', 'result': 'result-envelope'}.get(item.get('type'))
        if selected is None or command not in ('approve', 'approve-privileged', selected):
            raise ContractError('capability_access_refused')
        normalized = {'formatVersion': 1, 'command': selected, 'envelope': item}
        resource._value({'payload': {'input': {'value': normalized}}})
        plane = envelope.PLANE_OF[item['type']]
        tail = [item['rid'], item['data']['role']] if plane == 'work' else [item['to']]
        if (value['localNode'] != resource._node
                or value['subject'] != envelope.subject(plane, item['from'], *tail)
                or plane == 'msg' and item['to'] != resource._peer):
            raise ContractError('capability_access_refused')
        return normalized
    if command in ('return-leases', 'sweep-leases', 'ingest-legacy', 'result-legacy'):
        if command == 'ingest-legacy' and value['envelope']['origin'] != (
                value['envelope']['origin_node'] + ':' + value['envelope']['origin_id']):
            raise ContractError('capability_access_refused')
        return {'formatVersion': 1, 'command': command,
            **{key: item for key, item in value.items() if key != 'coreTransport'}}
    normalized = {'formatVersion': 1, 'command': command,
        **{key: item for key, item in value.items() if key != 'onBehalfOf' and not (command == 'revoke' and key == 'control')}}
    return resource._value({'payload': {'input': {'value': normalized}}})


async def authorize(resource, authority, raw, *, source_expectation=None):
    if (not isinstance(authority, LedgerAuthorityReader) or authority is not resource._legacy_authority
            or type(raw) is not bytes or len(raw) > 1048576):
        raise ContractError('capability_access_refused')
    original = strict_loads(raw)
    expected_source=None if source_expectation is None else canonical_bytes(source_expectation)
    validate('message-envelope', original)
    contract, operation, payload = original['contractId'], original['operation'], original['payload']
    if canonical_bytes(original) != raw or contract not in WORK_COMMANDS:
        raise ContractError('capability_access_refused')
    validate(contract, payload)
    resource._current()
    snapshot = await authority.current()
    now = datetime.now(timezone.utc)
    decision = evaluate_snapshot(snapshot, raw,
        audience={'hubId': resource.binding.hub_id, 'serviceId': 'storage-owner'}, now=now)
    actor_ref = canonical_bytes(operation['effectiveActorRef'])
    transport_ref = canonical_bytes(original['ingressAttestation']['claims']['authenticatedTransportRef'])
    matches = [actor for actor in resource._legacy_actors
        if (actor.identity_ref, actor.transport_ref) == (actor_ref, transport_ref)]
    reference = payload['resourceRef']
    if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(operation)
            or len(matches) != 1 or operation['delegationRef'] is not None
            or canonical_bytes(operation['scope']) != resource.binding.scope
            or reference['id'] != resource.binding.entity_id or reference['ownerHubId'] != resource.binding.hub_id
            or operation['expectedVersion'] != reference['revision']):
        raise ContractError('capability_access_refused')
    actor = matches[0]
    index = _indexes(strict_loads(snapshot.record)['state'], resource.binding.hub_id)
    grant = _permission(resource, index, actor, operation, contract, now)
    if grant['ref'] != operation['grantRef']:
        raise ContractError('capability_access_refused')
    target = None
    lifecycle_deadline = None
    core_recovery_deadline = None
    source_deadline = None
    def check_request_actor():
        nonlocal lifecycle_deadline, core_recovery_deadline, source_deadline
        check_actor(resource, actor, original=original)
        if expected_source is not None:
            from .work_source import check_owner_source
            source_deadline = check_owner_source(resource,strict_loads(expected_source), snapshot)
        request = payload['input'].get('sourceBinding') if contract == 'federation-work-inspect' else None
        if request is not None and 'coreTransport' in request:
            from .work_source import owner_core_mode
            _, source_deadline = owner_core_mode(resource, snapshot)
        if (contract in WORK_LIFECYCLE_COMMANDS or contract == 'federation-work-outcome'
                and payload['input']['contractId'] in WORK_LIFECYCLE_COMMANDS):
            from .work_lifecycle import check_target
            lifecycle_deadline = check_target(resource, original, snapshot)
        principal = index['identities'].get(_key(operation['effectiveActorRef']))
        if contract == 'federation-work-outcome':
            stored = resource._journal.outcome(payload['input']['operationId'], payload['input']['payloadDigest'])
            if stored is None:
                return None
            retained = stored['envelope']
            from .core_work import check_recovery as check_core_recovery
            core_recovery_deadline = check_core_recovery(resource, stored, original, snapshot)
            return _mutation_target(resource, actor, principal,
                retained['contractId'], retained['payload']['input'])
        if contract in WORK_MUTATIONS:
            return _mutation_target(resource, actor, principal, contract, payload['input'])
        if contract != 'federation-work-read' or payload['input']['query'].get('kind') != 'readiness':
            return None
        query = resource._query(payload['input']['query'])
        resource._named_repo()
        if (actor.caller == 'operator' and principal['kind'] != 'human'
                or actor.caller == 'federation' and principal['kind'] != 'service'
                or actor.caller not in ('operator', 'federation') and actor.caller != query['session']):
            raise ContractError('capability_access_refused')
        row = resource._agent(query['session'])
        return query['session'], row['generation']
    target = await resource._owner.db(check_request_actor)
    if contract == 'federation-work-outcome':
        _permission(resource, index, actor, operation, payload['input']['contractId'], now)
    elif contract in WORK_MUTATIONS:
        if payload['attribution'] != actor.caller:
            raise ContractError('capability_access_refused')
        _value(resource, contract, payload['input'])
    elif contract == 'federation-work-read':
        resource._query(payload['input']['query'])
    control = None
    valid_until = (decision.valid_until if lifecycle_deadline is None
        else min(decision.valid_until, lifecycle_deadline))
    core = None
    if source_deadline is not None:
        valid_until = min(valid_until, source_deadline)
    if core_recovery_deadline is not None:
        valid_until = min(valid_until, core_recovery_deadline)
    if contract in ('federation-work-ingest-legacy', 'federation-work-result-legacy'):
        from .core_work import CoreWorkOwner
        owner = getattr(resource, '_core_work_owner', None)
        if type(owner) is not CoreWorkOwner:
            raise ContractError('capability_access_refused')
        core = await owner.admit(resource, raw, snapshot)
        valid_until = min(valid_until, core.valid_until)
    if contract == 'federation-work-revoke' and 'control' in payload['input']:
        from .work_control import WorkControlOwner, check_recovery
        owner = getattr(resource, '_control_owner', None)
        if type(owner) is not WorkControlOwner:
            raise ContractError('capability_access_refused')
        def committed():
            check_actor(resource, actor)
            stored = resource._journal.outcome(operation['operationId'], operation['payloadDigest'])
            if stored is not None and stored['reply']['outcome'] in ('applied', 'rejected'):
                check_recovery(resource, stored, original, snapshot)
                return True
            return False
        if not await resource._owner.db(committed):
            control = await owner.admit(resource, raw, valid_until)
            valid_until = min(valid_until, control.valid_until)
    checked = object.__new__(_Admission)
    for name, value in (('resource', resource), ('original', raw), ('actor', actor),
            ('valid_until', valid_until), ('snapshot', snapshot), ('target', target), ('control', control), ('core', core),
            ('source', expected_source)):
        object.__setattr__(checked, name, value)
    return checked


def check_disclosure(resource, original, current):
    """Keep the original target generation and validity through final signing."""
    if (type(original) is not _Admission or type(current) is not _Admission
            or original.resource is not resource or current.resource is not resource
            or original.actor != current.actor or original.target != current.target):
        raise ContractError('capability_access_refused')
    if original.source != current.source:
        raise ContractError('capability_access_refused')
    from .work_source import check_source_disclosure
    if not check_source_disclosure(resource, current):
        resource._current()
    resource._journal._deadline(original.valid_until)
    resource._journal._deadline(current.valid_until)
    if current.core is not None:
        from .core_work import check_disclosure_fence
        check_disclosure_fence(resource, current.core)
    if original.control is not None:
        from .work_control import check_disclosure as check_control
        check_control(resource, original)


def check_approval(resource, checked):
    """Derive the first approval from this exact current signed operator request."""
    if type(checked) is not _Admission or checked.resource is not resource:
        raise ContractError('capability_access_refused')
    original = strict_loads(checked.original)
    if original['contractId'] not in WORK_OPERATOR_COMMANDS or original['contractId'] not in (
            'federation-work-approve', 'federation-work-approve-privileged'):
        raise ContractError('capability_access_refused')
    check_actor(resource, checked.actor)
    resource._journal._deadline(checked.valid_until)
    _permission(resource, _indexes(strict_loads(checked.snapshot.record)['state'], resource.binding.hub_id),
        checked.actor, original['operation'], original['contractId'], datetime.now(timezone.utc))
    value, item = original['payload']['input'], original['payload']['input']['envelope']
    held = resource._store.q1('SELECT * FROM fed_quarantine WHERE id=?', (value['quarantineId'],))
    current = guard.inbound(resource._owner.policy, value['subject'], item)
    if (held is None or held['state'] not in ('held', 'approved')
            or held['plane'] != envelope.PLANE_OF[item['type']] or held['peer'] != item['from']
            or held['subject'] != value['subject']
            or canonical_bytes(strict_loads(held['envelope'])) != canonical_bytes(item)
            or current.action == 'drop' or current.local_repo != resource.repository):
        raise ContractError('capability_access_refused')
    return guard.Decision('deliver', 'approved by operator', current.trust, untrusted=True,
        local_repo=current.local_repo, approved=True,
        privileged_ok=original['contractId'] == 'federation-work-approve-privileged')


def _recover(resource, original, stored, checked):
    retained = stored['envelope']
    if retained['contractId'] in WORK_LIFECYCLE_COMMANDS:
        from .work_lifecycle import check_target
        deadline = check_target(resource, original, checked.snapshot)
        if deadline is not None:
            resource._journal._deadline(deadline)
    old, current = retained['operation'], original['operation']
    if (retained['contractId'] != original['payload']['input']['contractId']
            or retained['payload']['resourceRef']['id'] != resource.binding.entity_id
            or retained['payload']['resourceRef']['ownerHubId'] != resource.binding.hub_id
            or canonical_bytes(old['scope']) != resource.binding.scope
            or old['scope'] != current['scope'] or old['effectiveActorRef'] != current['effectiveActorRef']
            or old['caller'] != current['caller'] or old['delegationRef'] is not None
            or old['grantRef'] != strict_loads(checked.actor.grants).get(retained['contractId'])
            or retained['ingressAttestation']['claims']['authenticatedTransportRef'] !=
                original['ingressAttestation']['claims']['authenticatedTransportRef']):
        raise ContractError('capability_access_refused')
    from .work_control import check_recovery
    check_recovery(resource, stored, original, checked.snapshot)
    from .core_work import check_recovery as check_core_recovery
    core_deadline = check_core_recovery(resource, stored, original, checked.snapshot)
    if core_deadline is not None:
        resource._journal._deadline(core_deadline)
    index = _indexes(strict_loads(checked.snapshot.record)['state'], resource.binding.hub_id)
    target = _mutation_target(resource, checked.actor,
        index['identities'].get(_key(current['effectiveActorRef'])),
        retained['contractId'], retained['payload']['input'])
    if target != checked.target:
        raise ContractError('capability_access_refused')


def _peer_effect(resource, value, checked):
    item, command = value['envelope'], value['command']
    original = strict_loads(checked.original)
    if original['contractId'] in ('federation-work-approve', 'federation-work-approve-privileged'):
        decision = check_approval(resource, checked)
    else:
        # Retained quarantine state cannot turn a service call into an operator
        # approval or grant privileged tools. Recheck actual admission here.
        decision = guard.inbound(resource._owner.policy, original['payload']['input']['subject'], item)
        if decision.action != 'deliver' or decision.local_repo != resource.repository:
            raise ContractError('capability_access_refused')
    tx, owner = resource._transactions, resource._owner
    if command == 'ingest':
        if item['from'] == resource._peer and item['node'] == resource._node:
            resource._row(item['data']['origin_id'])
        result = tx._ingest(owner, item, decision, resource.repository)
        row = (resource._store.q1('SELECT id FROM work_items WHERE id=?', (item['data']['origin_id'],))
            if item['from'] == resource._peer and item['node'] == resource._node else resource._store.q1(
                "SELECT id FROM work_items WHERE origin_peer=? AND json_extract(fed_flags,'$.origin_node')=? "
                "AND json_extract(fed_flags,'$.env')=?", (item['from'], item['node'], item['id'])))
        work = None if row is None else resource._row(row['id'])
    elif command == 'claim-envelope':
        resource._row(item['data']['origin_id'])
        result = tx._claim(owner, item, decision)
        work = resource._row(item['data']['origin_id'])
    elif command == 'grant-envelope':
        result = tx._grant(owner, item, decision)
        row = resource._store.q1("SELECT id FROM work_items WHERE origin_peer=? AND json_extract(fed_flags,'$.env')=? "
            "AND json_extract(fed_flags,'$.execution_id')=?",
            (item['from'], item['data']['offer_id'], item['data']['execution_id']))
        work = None if row is None else resource._row(row['id'])
    else:
        resource._row(item['data']['origin_id'])
        result, work = tx._result(owner, item, decision)
        work = None if work is None else resource._row(work['id'])
    result = {'outcome': result, 'work': work}
    return result, {'kind': 'result', 'value': result}


def _effect(resource, contract, value, checked):
    check_actor(resource, checked.actor)
    normalized = _value(resource, contract, value)
    command = normalized['command']
    if contract in WORK_PEER_COMMANDS | {'federation-work-approve', 'federation-work-approve-privileged'}:
        return _peer_effect(resource, normalized, checked)
    if command == 'return-leases':
        result = {'returned': resource._return_leases(value['session'], value['reason'])}
    elif command == 'sweep-leases':
        result = {'swept': resource._sweep_leases()}
    elif command == 'ingest-legacy':
        result = resource._ingest_legacy(value['envelope'])
    elif command == 'result-legacy':
        result = resource._result_legacy(value['envelope'])
    elif command == 'stage-result':
        resource._row(value['workId'])
        resource._transactions._stage_result(resource._owner, value['workId'])
        result = resource._row(value['workId'])
    elif command == 'revoke':
        if 'control' in value:
            from .work_control import stage_withdrawal
            return stage_withdrawal(resource, value, checked)
        peer = value['peer']
        if (resource._local or peer == resource._peer or resource._owner.policy.known_peer(peer)
                and resource._owner.policy.trust(peer) != 'deny'):
            raise ContractError('capability_access_refused')
        result = {'cancelled': resource._transactions._revoke(resource._owner, peer, resource.repository)}
    else:
        return resource._effect(normalized, checked.actor.caller, _admission=checked)
    return result, {'kind': 'result', 'value': result}


def check_source_admission(resource, checked, *, snapshot=None):
    if checked.source is not None:
        from .work_source import check_owner_source
        return check_owner_source(resource, strict_loads(checked.source),
            checked.snapshot if snapshot is None else snapshot)


async def apply(resource, authority, raw, *, source_expectation=None):
    async with resource._lock:
        checked = await authorize(resource, authority, raw, source_expectation=source_expectation)
        original = strict_loads(raw)
        contract, payload = original['contractId'], original['payload']
        value = payload['input']
        if contract in ('federation-work-read', 'federation-work-inspect', 'federation-work-outcome'):
            def load():
                check_actor(resource, checked.actor, original=original)
                check_source_admission(resource, checked)
                resource._journal._deadline(checked.valid_until)
                current = resource._journal.current()
                if contract == 'federation-work-read':
                    result = {'value': resource._select(value['query'], checked.actor.caller, _admission=checked)}
                    if len(canonical_bytes(result)) > 1_000_000:
                        raise ContractError('capability_service_unavailable')
                elif contract == 'federation-work-inspect':
                    result = {'resourceRef': {'id': resource.binding.entity_id,
                        'ownerHubId': resource.binding.hub_id, 'revision': current['revision']}}
                    if 'sourceBinding' in value:
                        from .work_source import owner_source
                        result['sourceBinding'] = owner_source(resource, value['sourceBinding'], checked.snapshot)
                else:
                    stored = resource._journal.outcome(value['operationId'], value['payloadDigest'])
                    if stored is None:
                        result = {**value, 'outcome': 'absent', 'resourceRef': None, 'receiptRef': None, 'result': None}
                    else:
                        _recover(resource, original, stored, checked)
                        result = {**value, **stored['reply'], 'result': stored['result']}
                        if 'readyState' in value:
                            ready = resource._lifecycle_owner._ready_original(resource, stored, value['readyState'])
                            result['readyStateReceipt'] = {**ready['reply'], 'result': ready['result']}
                resource._journal._deadline(checked.valid_until)
                return result
            result = await resource._owner.db(load)
            current = await authorize(resource, authority, raw, source_expectation=source_expectation)
            check_disclosure(resource, checked, current)
            return result
        checked = await authorize(resource, authority, raw, source_expectation=source_expectation)
        from .work_control import WorkControlRejection
        if type(checked.control) is WorkControlRejection:
            refused = checked.control
            if (refused.resource is not resource or refused.original != raw
                    or refused.owner is not getattr(resource, '_control_owner', None)):
                raise ContractError('capability_access_refused')
            stored = await resource._owner.db(resource._journal.reject, original, checked.valid_until)
            return {**stored['reply'], 'result': stored['result']}
        def commit():
            check_actor(resource, checked.actor)
            check_source_admission(resource, checked)
            with resource._store.tx():
                # Replays also fence the original target before journal lookup.
                effect_caller(resource, checked)
                if checked.core is not None:
                    checked.core.owner.check_commit(resource, checked.core)
                resource._journal._deadline(checked.valid_until)
                return resource._journal.commit(original, payload['resourceRef']['revision'],
                    checked.valid_until, lambda: _effect(resource, contract, value, checked))
        stored = await resource._owner.db(commit)
        return {**stored['reply'], 'result': stored['result']}


async def check_core_disclosure(resource, original, current):
    """Recheck core proof on the same DB executor after the final authority read."""
    current_request = strict_loads(current.original)
    contract = current_request['contractId']
    if current.core is None and (contract != 'federation-work-outcome'
            or current_request['payload']['input']['contractId'] not in (
                'federation-work-ingest-legacy', 'federation-work-result-legacy')):
        return
    def final():
        check_disclosure(resource, original, current)
        if current.core is not None:
            current.core.owner.check_commit(resource, current.core)
        if contract == 'federation-work-outcome':
            value = current_request['payload']['input']
            stored = resource._journal.outcome(value['operationId'], value['payloadDigest'])
            if stored is not None:
                _recover(resource, current_request, stored, current)
    await resource._owner.db(final)
