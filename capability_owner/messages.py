"""Map signed storage commands to the existing message and publication owners."""
import asyncio
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from hub import names
from hub.fed import envelope as federation_envelope, guard
from hub.fed.message_services import LocalMessages, FederationPublisher
from hub.fed.message_storage import MessageStorageJournal
from hub.fed.session import FederationSession
from hub.store import HubError, Store
from identity.authority import LedgerAuthorityReader, AuthoritySnapshot
from identity.capability_service import evaluate_capability_service_request
from identity.capability_routes import CAPABILITY_DESTINATIONS
from state_owner.ledger import OwnerBinding
from .policy import _reference


@dataclass(frozen=True, repr=False)
class MessageActor:
    identity_ref: bytes = field(repr=False)
    transport_ref: bytes = field(repr=False)
    caller: str = field(repr=False)

    def __post_init__(self):
        if (type(self.identity_ref) is not bytes or type(self.transport_ref) is not bytes
                or not _reference(strict_loads(self.identity_ref)) or not _reference(strict_loads(self.transport_ref))
                or type(self.caller) is not str or not self.caller):
            raise ContractError('capability_owner_configuration')


@dataclass(frozen=True, repr=False)
class LegacyMessageActor(MessageActor):
    grants: bytes = field(repr=False)

    def __post_init__(self):
        super().__post_init__()
        from identity.authority import MESSAGE_COMMANDS
        grants = strict_loads(self.grants)
        if (canonical_bytes(grants) != self.grants or type(grants) is not dict or not grants
                or set(grants) - MESSAGE_COMMANDS or any(not _reference(ref) for ref in grants.values())):
            raise ContractError('capability_owner_configuration')


@dataclass(frozen=True, repr=False, init=False, slots=True)
class _LegacyMessageAdmission:
    """Only the concrete legacy authorizer creates this checked handoff."""
    resource: object
    original: bytes
    actor: LegacyMessageActor
    valid_until: datetime
    snapshot: AuthoritySnapshot

    def __new__(cls):
        raise TypeError('Current message authorization is required')

    def __repr__(self):
        return '<LegacyMessageAdmission private>'


class MessageStorageResource:
    def __init__(self, binding, messages, publisher, *, repository, peer, actors,
                 plugin_identity_ref, instance_id, initial_source=None, legacy_actors=(), _bootstrap=None):
        if (type(binding) is not OwnerBinding or binding.owner_domain != 'federation-messages'
                or binding.entity_kind != 'message-channel' or type(messages) is not LocalMessages
                or type(publisher) is not FederationPublisher or messages._owner is not publisher._owner
                or repository is not None and (type(repository) is not str or not repository)
                or not federation_envelope.TOKEN.fullmatch(peer)
                or type(actors) is not tuple or not actors or any(type(a) is not MessageActor for a in actors)
                or len({(a.identity_ref, a.transport_ref) for a in actors}) != len(actors)
                or not _reference(plugin_identity_ref) or type(instance_id) is not str
                or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', instance_id) is None
                or type(legacy_actors) is not tuple or any(type(actor) is not LegacyMessageActor for actor in legacy_actors)
                or len({(a.identity_ref, a.transport_ref) for a in legacy_actors}) != len(legacy_actors)):
            raise ContractError('capability_owner_configuration')
        if initial_source is not None and (type(initial_source) is not dict
                or set(initial_source) != {'kind', 'id'} or initial_source['kind'] not in ('message', 'publication')
                or type(initial_source['id']) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', initial_source['id']) is None):
            raise ContractError('capability_owner_configuration')
        owner = messages._owner
        if type(owner.store) is not Store or type(owner.session) is not FederationSession:
            raise ContractError('capability_owner_configuration')
        self.binding, self.messages, self.publisher = binding, messages, publisher
        self._owner, self._store, self._session = owner, owner.store, owner.session
        self.repository, self.peer, self.actors = repository, peer, actors
        self._legacy_actors = legacy_actors
        if _bootstrap is not None:
            from .policy_bootstrap import PolicyResourceBootstrap
            if type(_bootstrap) is not PolicyResourceBootstrap:
                raise ContractError('capability_owner_configuration')
            self.repository_id = _bootstrap.repository_id(owner, repository)
        else:
            self.repository_id = None if repository is None else owner.policy.rid_of(repository)
        if ((repository is None) != (strict_loads(binding.scope)['projectId'] is None)
                or repository is not None and self.repository_id is None):
            raise ContractError('capability_owner_configuration')
        self.plugin_identity, self.instance_id = canonical_bytes(plugin_identity_ref), instance_id
        descriptor = {'hubId': binding.hub_id, 'entityId': binding.entity_id,
            'scope': strict_loads(binding.scope), 'repository': repository, 'repositoryId': self.repository_id,
            'peer': peer, 'pluginIdentityRef': plugin_identity_ref, 'instanceId': instance_id,
            'actors': [{'identityRef': strict_loads(a.identity_ref), 'transportRef': strict_loads(a.transport_ref),
                        'caller': a.caller} for a in actors], 'initialSource': initial_source}
        if legacy_actors:
            descriptor['legacyActors'] = [{'identityRef': strict_loads(a.identity_ref),
                'transportRef': strict_loads(a.transport_ref), 'caller': a.caller,
                'grants': strict_loads(a.grants)} for a in legacy_actors]
        self._journal = MessageStorageJournal(owner.store, canonical_bytes(descriptor), initial_source)
        self._lock = asyncio.Lock()
        if _bootstrap is None:
            self._current()
        else:
            from .policy_bootstrap import check_bootstrap
            check_bootstrap(_bootstrap, self)

    def __repr__(self):
        return '<MessageStorageResource private>'

    def _current(self):
        if (self._owner.store is not self._store or self._owner.session is not self._session
                or self.repository is not None and (self._owner.policy.rid_of(self.repository) != self.repository_id
                    or self._owner.policy.local_of(self.repository_id) != self.repository)
                or not self._owner.policy.known_peer(self.peer) or self._owner.policy.trust(self.peer) == 'deny'):
            raise ContractError('capability_resource_stale')
        self._session.check_open()

    def check_request(self, snapshot, claims):
        self._current()
        record = strict_loads(snapshot.record)
        rows = [row for row in record['state'].get('nativeInstances', []) if row['owner'] == claims['owner']]
        if (len(rows) != 1 or rows[0]['status'] != 'active'
                or canonical_bytes(rows[0]['identityRef']) != self.plugin_identity
                or rows[0]['owner']['instanceId'] != self.instance_id
                or canonical_bytes(claims['scope']) != self.binding.scope
                or claims['resourceRef']['id'] != self.binding.entity_id
                or claims['resourceRef']['ownerHubId'] != self.binding.hub_id):
            raise ContractError('capability_access_refused')

    async def authorize(self, authority, raw, service_raw):
        if not isinstance(authority, LedgerAuthorityReader) or type(service_raw) is not bytes or len(service_raw) > 98304:
            raise ContractError('capability_access_refused')
        request = strict_loads(service_raw)
        claims = request['claims']
        if (canonical_bytes(request) != service_raw
                or base64.b64decode(claims['envelopeBytes'], validate=True) != raw
                or claims['requestContractId'] not in ('capability-storage-read', 'capability-storage-write', 'capability-outcome-query')
                or claims['serviceId'] != CAPABILITY_DESTINATIONS[claims['requestContractId']]):
            raise ContractError('capability_access_refused')
        snapshot = await authority.current()
        decision = evaluate_capability_service_request(snapshot, service_raw, service_id=claims['serviceId'],
            now=datetime.now(timezone.utc))
        self.check_request(snapshot, claims)
        self._actor(strict_loads(raw))
        return decision

    def _actor(self, original):
        actor = canonical_bytes(original['operation']['effectiveActorRef'])
        transport = canonical_bytes(original['ingressAttestation']['claims']['authenticatedTransportRef'])
        matches = [item for item in self.actors if (item.identity_ref, item.transport_ref) == (actor, transport)]
        if len(matches) != 1:
            raise ContractError('capability_access_refused')
        return matches[0]

    def _value(self, original):
        value = original['payload']['input']['value']
        if (type(value) is not dict or set(value) != {'formatVersion', 'command', 'envelope'}
                or type(value['formatVersion']) is not int or value['formatVersion'] != 1
                or value['command'] not in ('post', 'publish')):
            raise ContractError('capability_service_unavailable')
        env = value['envelope']
        if type(env) is not dict or env.get('type') not in ('message', 'handoff') or env.get('rid') != self.repository_id:
            raise ContractError('capability_access_refused')
        federation_envelope.validate(env)
        if value['command'] == 'post':
            if env['from'] != self.peer or env['to'] != self._owner.me:
                raise ContractError('capability_access_refused')
        else:
            sender = self._owner.sender_of(self._actor(original).caller)
            sender = {k: v for k, v in sender.items() if k != 'repo'}
            if (env['from'] != self._owner.me or env['to'] != self.peer or env['node'] != self._owner.node
                    or env['data'].get('sender') != sender):
                raise ContractError('capability_access_refused')
        return value

    def _post(self, env, selected, bindings, *, legacy=None):
        self._current()
        dec = guard.inbound(self._owner.policy, federation_envelope.subject('msg', self.peer, self._owner.me), env)
        if legacy is not None:
            if (type(legacy) is not _LegacyMessageAdmission or legacy.resource is not self
                    or strict_loads(legacy.original)['payload']['input']['envelope'] != env):
                raise ContractError('capability_access_refused')
            original = strict_loads(legacy.original)
            if original['contractId'] == 'federation-message-approve':
                value = original['payload']['input']
                self._check_legacy_quarantine(original)
                dec = guard.Decision('deliver', 'approved by operator', dec.trust, untrusted=True,
                    local_repo=dec.local_repo, approved=True, privileged_ok=value['privileged'])
        if dec.action == 'quarantine' and dec.reason == 'trust approve for ' + self.peer:
            approved = self._store.q('SELECT envelope FROM fed_quarantine WHERE state=? AND peer=? AND plane=? AND subject=? AND json_extract(envelope,?)=?',
                ('approved', self.peer, 'msg', federation_envelope.subject('msg', self.peer, self._owner.me), '$.id', env['id']))
            if any(canonical_bytes(strict_loads(row['envelope'])) == canonical_bytes(env) for row in approved):
                dec = guard.Decision('deliver', 'approved by operator', dec.trust, untrusted=True,
                    local_repo=dec.local_repo, approved=True)
        if dec.action != 'deliver' or dec.local_repo != self.repository:
            raise ContractError('capability_access_refused')
        data = env['data']
        target, prefix = self._target(env)
        if target != selected:
            raise ContractError('capability_resource_stale')
        body = guard.wrap(prefix + (data.get('body') or ''), self.peer, dec.trust, dec.untrusted)
        if data.get('code'):
            body += f"\n(code attached: agentmux hub fed code fetch {data['code']})"
        sender = self._owner.address_of(self.peer, data.get('sender') or {})
        body += f'\n(reply: agentmux hub post --to {sender} --kind reply "...")'
        kind = 'handoff' if env['type'] == 'handoff' else (data.get('kind') if data.get('kind') in ('note', 'request', 'reply', 'handoff') else 'note')
        meta = {'fed': {'peer': self.peer, 'trust': dec.trust, 'env': env['id'], 'untrusted': dec.untrusted}}
        def deliver(address, text, proof, *, require_primary=False):
            return self.messages._deliver(sender, address, kind, text, data.get('ref'), env['id'], meta,
                incoming=env, decision=dec, require_primary=require_primary, identity_bindings=proof)
        try:
            recipients = self._store.recipients(target)
        except HubError as error:
            result = deliver('virtual:operator', f'(for {target}: {error})\n{body}', ())
            delivery_outcome = 'to_operator'
        else:
            # Recipient identity failures cannot redirect an authorized target to
            # another inbox, including when Store.post finds a duplicate first.
            self._store._check_identity_bindings(target, recipients, bindings, False)
            result = deliver(target, body, bindings, require_primary=target == 'virtual:operator')
            delivery_outcome = 'delivered'
        if not isinstance(result, dict):
            raise ContractError('capability_access_refused')
        if legacy is not None:
            result = {**result, 'deliveryOutcome': delivery_outcome}
        return result, {'kind': 'message', 'id': result['id']}

    def _check_legacy_quarantine(self, original):
        self._current()
        value = original['payload']['input']
        env = value['envelope']
        q = self._store.q1('SELECT * FROM fed_quarantine WHERE id=?', (value['quarantineId'],))
        current = guard.inbound(self._owner.policy, value['subject'], env)
        if (q is None or q['state'] not in ('held', 'approved') or q['peer'] != self.peer
                or q['plane'] != 'msg' or q['subject'] != value['subject']
                or canonical_bytes(strict_loads(q['envelope'])) != canonical_bytes(env)
                or current.action == 'drop' or current.local_repo != self.repository):
            raise ContractError('capability_access_refused')

    def _target(self, env):
        target = env['data'].get('target')
        if not target:
            return 'virtual:operator', ''
        if self.repository is None or target.get('rid') not in (None, self.repository_id):
            raise ContractError('capability_access_refused')
        if target.get('agent'):
            session = names.session_name(self.repository, target['role'], target['agent'])
            agent = self._store.agent(session)
            if not agent or agent['state'] == 'dead':
                return 'virtual:operator', f'(for {session}, which is not live here)\n'
            return 'agent:' + session, ''
        return f"role:{self.repository}/{target['role']}", ''

    def _publish(self, env):
        self._current()
        if self.repository is not None and not self._owner.policy.may_send(self.repository, self.peer):
            raise ContractError('capability_access_refused')
        subject = federation_envelope.subject('msg', self._owner.me, self.peer)
        federation_envelope.validate_route(subject, env)
        clean, kinds = self._owner.stage(env, subject, self.repository, self.peer)
        retained = self._store.q1('SELECT payload FROM fed_outbox WHERE msg_id=?', (clean['id'],))
        if retained is None or canonical_bytes(strict_loads(retained['payload'])) != canonical_bytes(clean):
            raise ContractError('capability_outcome_conflict')
        return {'envelope': clean, 'redacted': kinds}, {'kind': 'publication', 'id': clean['id']}

    async def write(self, authority, raw, service_raw):
        async with self._lock:
            await self.authorize(authority, raw, service_raw)
            original = strict_loads(raw)
            value = self._value(original)
            env = value['envelope']
            target, bindings = None, ()
            if value['command'] == 'post':
                target, _ = await self._owner.db(self._target, env)
                hub = getattr(self._owner, 'hub', None)
                if hub is not None and getattr(hub, '_legacy_identity', None) is not None:
                    selected, bindings = await hub._current_identity_target(target)
                    if selected != target:
                        raise ContractError('capability_resource_stale')
            decision = await self.authorize(authority, raw, service_raw)
            def effect():
                return self._post(env, target, bindings) if value['command'] == 'post' else self._publish(env)
            stored = await self._owner.db(self._journal.commit, original,
                original['payload']['resourceRef']['revision'], decision.valid_until, effect)
            return stored['reply']

    async def authorize_legacy(self, authority, raw):
        """Explicit signed legacy admission; it cannot replace a native wrapper."""
        from identity.authority import MESSAGE_COMMANDS, _active, _indexes, _key, evaluate_snapshot
        if not isinstance(authority, LedgerAuthorityReader) or type(raw) is not bytes or len(raw) > 1048576:
            raise ContractError('capability_access_refused')
        original = strict_loads(raw)
        validate('message-envelope', original)
        contract = original['contractId']
        if canonical_bytes(original) != raw or contract not in MESSAGE_COMMANDS:
            raise ContractError('capability_access_refused')
        validate(contract, original['payload'])
        self._current()
        if contract == 'federation-message-approve':
            await self._owner.db(self._check_legacy_quarantine, original)
        if contract == 'federation-message-finding':
            await self._owner.db(self._finding_source, original['payload']['input'])
        snapshot = await authority.current()
        now = datetime.now(timezone.utc)
        decision = evaluate_snapshot(snapshot, raw,
            audience={'hubId': self.binding.hub_id, 'serviceId': 'storage-owner'}, now=now)
        operation, payload = original['operation'], original['payload']
        actor_ref = canonical_bytes(operation['effectiveActorRef'])
        transport_ref = canonical_bytes(original['ingressAttestation']['claims']['authenticatedTransportRef'])
        actors = [actor for actor in self._legacy_actors
            if (actor.identity_ref, actor.transport_ref) == (actor_ref, transport_ref)]
        if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(operation)
                or canonical_bytes(operation['scope']) != self.binding.scope
                or canonical_bytes(operation['caller']['authenticatedIdentityRef']) != actor_ref
                or payload['resourceRef']['id'] != self.binding.entity_id
                or payload['resourceRef']['ownerHubId'] != self.binding.hub_id or len(actors) != 1):
            raise ContractError('capability_access_refused')
        actor = actors[0]
        grants = strict_loads(actor.grants)
        if grants.get(contract) != operation['grantRef']:
            raise ContractError('capability_access_refused')
        state = strict_loads(snapshot.record)['state']
        principal = _indexes(state, self.binding.hub_id)['identities'].get(_key(operation['effectiveActorRef']))
        if (principal is None or contract in ('federation-message-deliver', 'federation-message-finding') and (
                principal['kind'] != 'service' or actor.caller != 'federation')
                or contract == 'federation-message-approve' and (
                    principal['kind'] != 'human' or actor.caller != 'operator')
                or contract == 'federation-message-send' and actor.caller == 'federation'):
            raise ContractError('capability_access_refused')
        if contract in ('federation-message-inspect', 'federation-message-outcome'):
            if contract == 'federation-message-outcome':
                original_contract = payload['input']['contractId']
                selected_grant = grants.get(original_contract)
                current_grant = (None if selected_grant is None else
                    _indexes(state, self.binding.hub_id)['grants'].get(_key(selected_grant)))
                if (current_grant is None or not _active(current_grant, now)
                        or current_grant['decision'] != 'allowed' or current_grant['delegationRef'] is not None
                        or current_grant['callerRef'] != operation['effectiveActorRef']
                        or current_grant['actorRef'] != operation['effectiveActorRef']
                        or current_grant['scope'] != operation['scope']
                        or current_grant['resourceId'] != self.binding.entity_id
                        or current_grant['contractId'] != original_contract):
                    raise ContractError('capability_access_refused')
        elif contract == 'federation-message-finding':
            if payload['attribution'] != 'federation':
                raise ContractError('capability_access_refused')
        else:
            value, attribution = payload['input'], payload['attribution']
            env = value['envelope']
            federation_envelope.validate(env)
            outgoing = contract == 'federation-message-send'
            sender, recipient = (self._owner.me, self.peer) if outgoing else (self.peer, self._owner.me)
            if (env['type'] not in ('message', 'handoff') or env.get('rid') != self.repository_id
                    or env['from'] != sender or env['to'] != recipient
                    or value['subject'] != federation_envelope.subject('msg', sender, recipient)
                    or value['localNode'] != self._owner.node):
                raise ContractError('capability_access_refused')
            federation_envelope.validate_route(value['subject'], env)
            if outgoing:
                if actor.caller not in ('operator', 'virtual:operator') and attribution != actor.caller:
                    raise ContractError('capability_access_refused')
                sender = {k:v for k,v in self._owner.sender_of(attribution).items() if k != 'repo'}
                if env['node'] != self._owner.node or env['data'].get('sender') != sender:
                    raise ContractError('capability_access_refused')
            elif attribution != actor.caller:
                raise ContractError('capability_access_refused')
        checked = object.__new__(_LegacyMessageAdmission)
        for name, value in (('resource', self), ('original', raw), ('actor', actor),
                ('valid_until', decision.valid_until), ('snapshot', snapshot)):
            object.__setattr__(checked, name, value)
        return checked

    def _finding_source(self, value):
        self._current()
        env, recipient = value['envelope'], value['recipient']
        federation_envelope.validate(env)
        if (self.repository is None or env['type'] != 'knowledge' or env['from'] != self.peer
                or env['rid'] != self.repository_id or env['to'] != '*' or value['localNode'] != self._owner.node
                or names.split_session(recipient)[0] != self.repository):
            raise ContractError('capability_access_refused')
        current = guard.inbound(self._owner.policy,
            federation_envelope.subject('know', self.peer, self.repository_id), env)
        row = self._store.q1('SELECT * FROM p_knowledge_items WHERE id=? AND repo=? AND rid=? AND from_peer=?',
            (env['id'], self.repository, self.repository_id, self.peer))
        data = env['data']
        expected = {'title': data.get('title') or '(untitled)', 'body': data.get('body') or '',
            'author': data.get('author'), 'tags': ' '.join(data.get('tags') or []), 'ref': data.get('ref'),
            'source': data.get('source') or 'explicit'}
        if (current.action != 'deliver' or current.local_repo != self.repository or row is None
                or row['withdrawn'] is not None or row['untrusted'] not in (0, 1)
                or any(row[key] != field for key, field in expected.items())):
            raise ContractError('capability_access_refused')
        return row

    def _post_finding(self, value, selected, bindings):
        row = self._finding_source(value)
        recipient, env = value['recipient'], value['envelope']
        agent = self._store.agent(recipient)
        result = None
        if self._owner.fcfg.get('notify_findings', True) and agent is not None and agent['state'] != 'dead':
            target = 'agent:' + recipient
            if selected != target:
                raise ContractError('capability_resource_stale')
            note = (f"[fed] finding from {self.peer} on {self.repository}: {(env['data'].get('title') or '')[:100]}"
                f"{' (untrusted data)' if row['untrusted'] else ''}\n  agentmux hub fed know show {env['id']}")
            try:
                recipients = self._store.recipients(target)
                self._store._check_identity_bindings(target, recipients, bindings, False)
                result = self._store.post(f'peer:{self.peer}', target, 'finding', note,
                    env['data'].get('ref'), None, f"know:{env['id']}:{recipient}", meta=None,
                    identity_bindings=bindings)
            except HubError:
                # Preserve the existing best-effort finding notification. An
                # identity failure never redirects to another inbox.
                result = None
        if result is None:
            return {'deliveryOutcome': 'not_hosted'}, self._journal.current()['source']
        return {'id': result['id'], 'deliveryOutcome': 'delivered'}, {'kind': 'message', 'id': result['id']}

    async def legacy(self, authority, raw):
        """The enrolled legacy adapter shares the original owner and SQL journal."""
        async with self._lock:
            checked = await self.authorize_legacy(authority, raw)
            original = strict_loads(raw)
            contract, payload = original['contractId'], original['payload']
            if contract in ('federation-message-inspect', 'federation-message-outcome'):
                def load():
                    self._current()
                    self._journal._deadline(checked.valid_until)
                    current = self._journal.current()
                    reference = {'id': self.binding.entity_id, 'ownerHubId': self.binding.hub_id,
                        'revision': current['revision']}
                    if contract == 'federation-message-inspect':
                        return {'resourceRef': reference}
                    query = payload['input']
                    stored = self._journal.outcome(query['operationId'], query['payloadDigest'])
                    if stored is None:
                        return {'outcome': 'absent', 'resourceRef': None, 'receiptRef': None, 'result': None,
                            **query}
                    if (stored['envelope']['contractId'] != query['contractId']
                            or stored['envelope']['operation']['effectiveActorRef'] != original['operation']['effectiveActorRef']):
                        raise ContractError('capability_access_refused')
                    return {**query, **stored['reply'], 'result': stored['result']}
                result = await self._owner.db(load)
                await self.authorize_legacy(authority, raw)
                return result
            value = payload['input']
            if contract == 'federation-message-finding':
                target, bindings = 'agent:' + value['recipient'], ()
                hub = getattr(self._owner, 'hub', None)
                if hub is not None and getattr(hub, '_legacy_identity', None) is not None:
                    selected, bindings = await hub._current_identity_target(target)
                    if selected != target:
                        raise ContractError('capability_resource_stale')
                checked = await self.authorize_legacy(authority, raw)
                stored = await self._owner.db(self._journal.commit, original,
                    payload['resourceRef']['revision'], checked.valid_until,
                    lambda: self._post_finding(value, target, bindings))
                return {**stored['reply'], 'result': stored['result']}
            env = value['envelope']
            target, bindings = None, ()
            if contract != 'federation-message-send':
                target, _ = await self._owner.db(self._target, env)
                hub = getattr(self._owner, 'hub', None)
                if hub is not None and getattr(hub, '_legacy_identity', None) is not None:
                    selected, bindings = await hub._current_identity_target(target)
                    if selected != target:
                        raise ContractError('capability_resource_stale')
            checked = await self.authorize_legacy(authority, raw)
            def effect():
                if contract == 'federation-message-send':
                    result, source = self._publish(env)
                    return {'id': result['envelope']['id'], 'redacted': result['redacted']}, source
                if target == 'virtual:operator' and not self._owner.fcfg.get('primary', True):
                    return {'deliveryOutcome': 'not_hosted'}, self._journal.current()['source']
                return self._post(env, target, bindings, legacy=checked)
            stored = await self._owner.db(self._journal.commit, original,
                payload['resourceRef']['revision'], checked.valid_until, effect)
            return {**stored['reply'], 'result': stored['result']}

    async def read(self, revision):
        def load():
            self._current()
            state = self._journal.current()
            if state['revision'] != revision:
                raise ContractError('capability_resource_stale')
            source = state['source']
            if source is None:
                value = {'formatVersion': 1, 'source': None}
            elif source['kind'] == 'message':
                value = self._store.q1('SELECT * FROM messages WHERE id=?', (source['id'],))
            elif source['kind'] == 'publication':
                value = self._store.q1('SELECT * FROM fed_outbox WHERE msg_id=?', (source['id'],))
            else:
                raise ContractError('capability_resource_stale')
            if value is None:
                raise ContractError('capability_resource_stale')
            raw = canonical_bytes(value)
            if len(raw) > 45000:
                raise ContractError('capability_service_unavailable')
            return raw
        return await self._owner.db(load)

    async def reconcile(self, raw):
        original = strict_loads(raw)
        query = original['payload']['input']
        def load():
            self._current()
            result = {'operationId': query['operationId'], 'payloadDigest': query['payloadDigest'],
                'recordRef': None, 'outcome': 'absent', 'contractId': 'capability-storage-write', 'resourceRef': None}
            stored = self._journal.outcome(query['operationId'], query['payloadDigest'])
            if stored is not None:
                if (stored['envelope']['contractId'] != query['contractId'] or stored['envelope']['contractId'] != 'capability-storage-write'
                        or stored['envelope']['operation']['effectiveActorRef'] != original['operation']['effectiveActorRef']):
                    raise ContractError('capability_access_refused')
                result.update(contractId=stored['envelope']['contractId'], recordRef=stored['reply']['receiptRef'],
                    resourceRef=stored['reply']['resourceRef'],
                    outcome='committed' if stored['reply']['outcome'] == 'applied' else 'rejected')
            return result
        return await self._owner.db(load)
