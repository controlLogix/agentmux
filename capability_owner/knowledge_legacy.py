"""Actual enrolled legacy knowledge admission over the original Store owner."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.fed import envelope
from hub.fed import guard
from identity.authority import (KNOWLEDGE_COMMANDS, LedgerAuthorityReader, _active, _indexes, _key,
    evaluate_snapshot)
from .messages import MessageActor


@dataclass(frozen=True, repr=False)
class LegacyKnowledgeActor(MessageActor):
    grants: bytes = field(repr=False)

    def __post_init__(self):
        super().__post_init__()
        from .policy import _reference
        grants = strict_loads(self.grants)
        if (canonical_bytes(grants) != self.grants or type(grants) is not dict or not grants
                or set(grants) - KNOWLEDGE_COMMANDS or any(not _reference(ref) for ref in grants.values())):
            raise ContractError('capability_owner_configuration')


@dataclass(frozen=True, repr=False, init=False, slots=True)
class _Admission:
    resource: object
    original: bytes
    actor: LegacyKnowledgeActor
    valid_until: datetime
    snapshot: object
    control: object

    def __new__(cls):
        raise TypeError('Current knowledge authorization is required')


async def authorize(resource, authority, raw):
    if not isinstance(authority, LedgerAuthorityReader) or type(raw) is not bytes or len(raw) > 1048576:
        raise ContractError('capability_access_refused')
    original = strict_loads(raw)
    validate('message-envelope', original)
    contract = original['contractId']
    if canonical_bytes(original) != raw or contract not in KNOWLEDGE_COMMANDS:
        raise ContractError('capability_access_refused')
    validate(contract, original['payload'])
    resource._current()
    if contract == 'federation-knowledge-approve':
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
    service_action = contract in ('federation-knowledge-index', 'federation-knowledge-capture',
        'federation-knowledge-withdraw')
    if (principal is None or service_action and (principal['kind'] != 'service' or actor.caller != 'federation')
            or contract == 'federation-knowledge-share' and (principal['kind'] not in ('human', 'device')
                or actor.caller == 'federation')
            or contract == 'federation-knowledge-approve' and (principal['kind'] != 'human'
                or actor.caller != 'operator' or payload['attribution'] != 'operator')):
        raise ContractError('capability_access_refused')
    if contract == 'federation-knowledge-outcome':
        selected = grants.get(payload['input']['contractId'])
        grant = None if selected is None else index['grants'].get(_key(selected))
        if (grant is None or not _active(grant, now) or grant['decision'] != 'allowed'
                or grant['delegationRef'] is not None or grant['callerRef'] != operation['effectiveActorRef']
                or grant['actorRef'] != operation['effectiveActorRef'] or grant['scope'] != operation['scope']
                or grant['resourceId'] != resource.binding.entity_id
                or grant['contractId'] != payload['input']['contractId']):
            raise ContractError('capability_access_refused')
        if payload['input']['contractId'] == 'federation-knowledge-capture' and any(
                candidate['decision'] == 'denied' and _active(candidate, now)
                and candidate['callerRef'] == operation['effectiveActorRef']
                and candidate['actorRef'] == operation['effectiveActorRef']
                and candidate['scope'] == operation['scope']
                and candidate['resourceId'] == resource.binding.entity_id
                and candidate['contractId'] == 'federation-knowledge-capture'
                for candidate in index['grants'].values()):
            raise ContractError('capability_access_refused')
    if service_action and payload['attribution'] != 'federation':
        raise ContractError('capability_access_refused')
    if contract in ('federation-knowledge-share', 'federation-knowledge-index', 'federation-knowledge-approve'):
        item = payload['input']['envelope']
        resource._validate_item(item, incoming=contract != 'federation-knowledge-share')
        if contract == 'federation-knowledge-share':
            attribution = payload['attribution']
            if (item['data']['source'] != 'explicit' or actor.caller not in ('operator', 'virtual:operator')
                    and attribution != actor.caller):
                raise ContractError('capability_access_refused')
            resource._check_publication_author(item, attribution)
        else:
            if (item['from'] == resource._peer or payload['input']['localNode'] != resource._node
                    or payload['input']['subject'] != envelope.subject('know', item['from'], resource.repository_id)):
                raise ContractError('capability_access_refused')
    control = None
    valid_until = decision.valid_until
    capture = None
    if contract == 'federation-knowledge-capture':
        capture = payload['input']['source']
    elif contract == 'federation-knowledge-outcome' and payload['input']['contractId'] == 'federation-knowledge-capture':
        def retained_capture():
            resource._current()
            stored = resource._journal.outcome(payload['input']['operationId'], payload['input']['payloadDigest'])
            if stored is not None and stored['envelope']['contractId'] == 'federation-knowledge-capture':
                return stored['envelope']['payload']['input']['source']
            return None
        capture = await resource._owner.db(retained_capture)
    if capture is not None and capture['kind'] in ('work-released', 'fed-result'):
        if 'resourceRef' in capture:
            from .work_capture import capture_source
            _, work_deadline = await resource._owner.db(capture_source, resource, capture, snapshot)
            valid_until = min(valid_until, work_deadline)
        elif resource._work_capture_sources:
            raise ContractError('capability_access_refused')
    if contract == 'federation-knowledge-withdraw' and 'control' in payload['input']:
        from .knowledge_control import KnowledgeControlOwner, check_recovery
        owner = getattr(resource, '_control_owner', None)
        if type(owner) is not KnowledgeControlOwner:
            raise ContractError('capability_access_refused')
        def committed():
            resource._current()
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
            ('valid_until', valid_until), ('snapshot', snapshot), ('control', control)):
        object.__setattr__(checked, name, value)
    return checked


def check_disclosure(resource, original, current):
    """Keep the first authorization deadline through final reply signing."""
    if (type(original) is not _Admission or type(current) is not _Admission
            or original.resource is not resource or current.resource is not resource
            or original.actor != current.actor):
        raise ContractError('capability_access_refused')
    first, last = strict_loads(original.original), strict_loads(current.original)
    if any(first[key] != last[key] for key in ('contractId', 'operation', 'payload')):
        raise ContractError('capability_access_refused')
    resource._current()
    resource._journal._deadline(original.valid_until)
    resource._journal._deadline(current.valid_until)


def check_approval(resource, original):
    resource._current()
    value = original['payload']['input']
    item = value['envelope']
    held = resource._store.q1('SELECT * FROM fed_quarantine WHERE id=?', (value['quarantineId'],))
    current = guard.inbound(resource._owner.policy, value['subject'], item)
    if (held is None or held['state'] not in ('held', 'approved') or held['plane'] != 'know'
            or held['peer'] != item['from'] or held['subject'] != value['subject']
            or canonical_bytes(strict_loads(held['envelope'])) != canonical_bytes(item)
            or current.action == 'drop' or current.local_repo != resource.repository):
        raise ContractError('capability_access_refused')
    return guard.Decision('deliver', 'approved by operator', current.trust, untrusted=True,
        local_repo=current.local_repo, approved=True, privileged_ok=value['privileged'])


def _capture(resource, source, checked):
    if source['kind'] == 'handoff':
        matches = [item for item in resource._message_sources
            if item.binding.entity_id == source['resourceRef']['id']
            and item.binding.hub_id == source['resourceRef']['ownerHubId']]
        if len(matches) != 1:
            raise ContractError('capability_access_refused')
        message = matches[0]
        message._current()
        stored = message._journal.outcome(source['operationId'], source['payloadDigest'])
        if (stored is None or stored['reply']['outcome'] != 'applied'
                or stored['reply']['resourceRef'] != source['resourceRef']
                or stored['envelope']['contractId'] != 'federation-message-send'
                or stored['result']['id'] != source['id']):
            raise ContractError('capability_access_refused')
        original = stored['envelope']['payload']
        item, recipient = original['input']['envelope'], original['input'].get('requestedTo')
        if (item['type'] != 'handoff' or item['rid'] != resource.repository_id
                or type(recipient) is not str or not recipient):
            raise ContractError('capability_access_refused')
        caller, title, body = original['attribution'], 'handoff to ' + recipient, item['data']['body']
        tags, reference, kind = ['auto', 'handoff'], item['data'].get('ref'), 'auto:handoff'
    else:
        # Store.work adds a live children projection; source identity is the
        # actual committed row returned by Store.release, including extra fields.
        if 'resourceRef' in source:
            from .work_capture import capture_source
            work, deadline = capture_source(resource, source, checked.snapshot)
            resource._journal._deadline(deadline)
        else:
            if resource._work_capture_sources:
                raise ContractError('capability_access_refused')
            work = resource._store.q1('SELECT * FROM work_items WHERE id=?', (source['id'],))
        if (work is None or work['repo'] != resource.repository or payload_digest(work) != source['digest']
                or not work.get('result')):
            raise ContractError('capability_access_refused')
        reference = work.get('task_key') or work['id']
        body = work['result']
        if source['kind'] == 'work-released':
            caller = work.get('claimed_by') or 'operator'
            if work['state'] != 'done' or caller.startswith(('fed:', 'peer:', 'nats:')):
                raise ContractError('capability_access_refused')
            title, tags, kind = 'done: ' + work['title'], ['auto', 'work'], 'auto:work'
        else:
            from hub.fed.work_services import result_digest
            flags = json.loads(work.get('fed_flags') or '{}')
            accepted, executor = flags.get('accepted_result'), flags.get('executor')
            if (type(accepted) is not dict or type(executor) is not dict
                    or not accepted.get('envelope_id') or not accepted.get('digest') or not executor.get('peer')
                    or work['state'] not in ('done', 'failed') or flags.get('protocol') != 3
                    or not flags.get('outgoing') or flags.get('origin_node') != resource._node
                    or accepted['digest'] != result_digest({'state': work['state'], 'result': work['result']})
                    or any(type(executor.get(key)) is not str or not executor[key]
                        for key in ('peer', 'node', 'execution_id', 'grant_id'))):
                raise ContractError('capability_access_refused')
            caller, title = 'operator', f"result from {executor['peer']}: {work['title']}"
            tags, kind = ['auto', 'result'], 'auto:result'
    sender = resource._owner.sender_of(caller)
    author = 'operator' if sender.get('operator') else f"{sender['role']}/{sender['agent']}"
    item = envelope.make('knowledge', resource._peer, resource._node, resource.repository_id, '*',
        {'title': title, 'body': body, 'tags': tags, 'ref': reference, 'author': author, 'source': kind})
    resource._validate_item(item)
    if not resource._owner.fcfg.get('capture', True):
        return {'captured': False, 'id': None}, resource._journal.current()['source']
    result, retained = resource._effect({'command': 'publish', 'envelope': item})
    return {**result, 'captured': True, 'repo': resource.repository, 'title': title}, retained


async def _read(resource, value, valid_until):
    command = value['command']
    def load():
        resource._current()
        resource._journal._deadline(valid_until)
        if command == 'show':
            sql, args = ('SELECT * FROM p_knowledge_items WHERE id=? AND repo=? AND rid=?',
                (value['id'], resource.repository, resource.repository_id))
        elif command == 'search':
            fts = ' '.join(f'"{word}"' for word in value['query'].replace('"', ' ').split() if word)
            if not fts:
                raise ContractError('capability_access_refused')
            sql = ("SELECT k.id, k.repo, k.from_peer, k.author, k.title, snippet(p_knowledge_fts, 1, '[', ']', "
                "' … ', 16) AS snippet, k.tags, k.ref, k.at, k.untrusted, k.withdrawn, rank AS _rank "
                "FROM p_knowledge_fts JOIN p_knowledge_items k ON k.rowid = p_knowledge_fts.rowid "
                'WHERE p_knowledge_fts MATCH ? AND k.repo=? AND k.rid=? ORDER BY rank LIMIT ?')
            args = (fts, resource.repository, resource.repository_id, value['limit'])
        else:
            fields = ('id, repo, from_peer, author, title, source, tags, ref, at, untrusted, withdrawn'
                if command == 'recent' else 'id, repo, from_peer, author, title, source, at, untrusted, withdrawn')
            sql = 'SELECT ' + fields + ' FROM p_knowledge_items WHERE repo=? AND rid=? ORDER BY at DESC LIMIT ?'
            args = (resource.repository, resource.repository_id, value.get('limit', 30))
        # Read only a bounded result. A large valid query refuses as a whole;
        # it never returns a truncated prefix or loads an unbounded row list.
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
        if command == 'show':
            return {'row': rows[0] if rows else None}
        if command == 'panel':
            return {'panel': resource._knowledge.panel_value(rows), 'ordering': [row['at'] for row in rows]}
        return {'rows': rows}
    return await resource._owner.db(load)


async def apply(resource, authority, raw):
    async with resource._lock:
        checked = await authorize(resource, authority, raw)
        original = strict_loads(raw)
        contract, payload = original['contractId'], original['payload']
        value = payload['input']
        if contract == 'federation-knowledge-read':
            result = await _read(resource, value, checked.valid_until)
            await authorize(resource, authority, raw)
            return result
        if contract in ('federation-knowledge-inspect', 'federation-knowledge-outcome'):
            def load():
                resource._current()
                resource._journal._deadline(checked.valid_until)
                current = resource._journal.current()
                reference = {'id': resource.binding.entity_id, 'ownerHubId': resource.binding.hub_id,
                    'revision': current['revision']}
                if contract == 'federation-knowledge-inspect':
                    return {'resourceRef': reference}
                stored = resource._journal.outcome(value['operationId'], value['payloadDigest'])
                if stored is None:
                    return {**value, 'outcome': 'absent', 'resourceRef': None, 'receiptRef': None, 'result': None}
                if (stored['envelope']['contractId'] != value['contractId']
                        or stored['envelope']['operation']['effectiveActorRef'] != original['operation']['effectiveActorRef']):
                    raise ContractError('capability_access_refused')
                from .knowledge_control import check_recovery
                check_recovery(resource, stored, original, checked.snapshot)
                return {**value, **stored['reply'], 'result': stored['result']}
            result = await resource._owner.db(load)
            await authorize(resource, authority, raw)
            return result
        checked = await authorize(resource, authority, raw)
        from .knowledge_control import KnowledgeControlRejection
        if type(checked.control) is KnowledgeControlRejection:
            refused = checked.control
            if (refused.resource is not resource or refused.original != raw
                    or refused.owner is not getattr(resource, '_control_owner', None)):
                raise ContractError('capability_access_refused')
            stored = await resource._owner.db(resource._journal.reject, original, checked.valid_until)
            return {**stored['reply'], 'result': stored['result']}
        def effect():
            resource._current()
            if contract == 'federation-knowledge-capture':
                return _capture(resource, value['source'], checked)
            command = {'federation-knowledge-share': 'publish', 'federation-knowledge-index': 'index',
                'federation-knowledge-approve': 'index', 'federation-knowledge-withdraw': 'withdraw'}[contract]
            result, source = resource._effect({**value, 'command': command},
                approval=checked if contract == 'federation-knowledge-approve'
                    or contract == 'federation-knowledge-withdraw' and 'control' in value else None)
            if command == 'publish':
                result.update(repo=resource.repository, title=resource._read_source(source)['title'])
            elif command == 'index':
                result['outcome'] = 'delivered'
            return result, source
        stored = await resource._owner.db(resource._journal.commit, original, payload['resourceRef']['revision'],
            checked.valid_until, effect)
        return {**stored['reply'], 'result': stored['result']}
