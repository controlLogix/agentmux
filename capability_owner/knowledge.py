"""Knowledge storage preserves original IDs, FTS and staged publications."""
from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed import envelope, guard
from hub.fed.knowledge_services import KnowledgeOwner
from .federated_storage import FederatedStorageResource


class KnowledgeStorageResource(FederatedStorageResource):
    domain = 'knowledge'

    def __init__(self, binding, federation, *, legacy_actors=(), message_sources=(), work_sources=(), **kwargs):
        from .messages import MessageStorageResource
        from hub.fed.message_storage import MessageStorageJournal
        if legacy_actors:
            from .knowledge_legacy import LegacyKnowledgeActor
        if (type(legacy_actors) is not tuple or any(type(a) is not LegacyKnowledgeActor for a in legacy_actors)
                or len({(a.identity_ref, a.transport_ref) for a in legacy_actors}) != len(legacy_actors)
                or type(message_sources) is not tuple
                or any(type(source) is not MessageStorageResource for source in message_sources)
                or len({source.binding.entity_id for source in message_sources}) != len(message_sources)):
            raise ContractError('capability_owner_configuration')
        self._legacy_actors, self._message_sources = legacy_actors, message_sources
        self._work_source_declarations = work_sources
        self._knowledge = KnowledgeOwner(federation)
        super().__init__(binding, federation, **kwargs)
        from .work_capture import bind_sources
        self._work_capture_sources = bind_sources(self, work_sources)
        del self._work_source_declarations
        if any(source._store is not self._store or source.binding.scope != binding.scope for source in message_sources):
            raise ContractError('capability_owner_configuration')
        if legacy_actors or self._work_capture_sources:
            descriptor = strict_loads(self._journal.binding)
            descriptor['legacyActors'] = [{'identityRef': strict_loads(a.identity_ref),
                'transportRef': strict_loads(a.transport_ref), 'caller': a.caller,
                'grants': strict_loads(a.grants)} for a in legacy_actors]
            descriptor['messageSources'] = [source.binding.entity_id for source in message_sources]
            if self._work_capture_sources:
                from agentmux_contracts import payload_digest
                descriptor['workSources'] = [{'resourceRef': {'id': pin.resource.binding.entity_id,
                    'ownerHubId': pin.resource.binding.hub_id},
                    'bindingDigest': payload_digest(strict_loads(pin.resource._journal.binding))}
                    for pin in self._work_capture_sources]
            self._journal = MessageStorageJournal(self._store, canonical_bytes(descriptor),
                kwargs.get('initial_source'), namespace=self.domain)

    async def authorize_legacy(self, authority, raw):
        from .knowledge_legacy import authorize
        return await authorize(self, authority, raw)

    async def legacy(self, authority, raw):
        from .knowledge_legacy import apply
        return await apply(self, authority, raw)

    def _value(self, original):
        value = original['payload']['input']['value']
        if (type(value) is not dict or type(value.get('formatVersion')) is not int
                or value['formatVersion'] != 1):
            raise ContractError('capability_service_unavailable')
        if value.get('command') == 'withdraw':
            if (set(value) != {'formatVersion', 'command', 'peer'} or type(value['peer']) is not str
                    or envelope.TOKEN.fullmatch(value['peer']) is None or value['peer'] == self._peer):
                raise ContractError('capability_access_refused')
            return value
        if (set(value) != {'formatVersion', 'command', 'envelope'}
                or value['command'] not in ('publish', 'index')):
            raise ContractError('capability_service_unavailable')
        env = value['envelope']
        self._validate_item(env, incoming=value['command'] == 'index')
        if value['command'] == 'publish':
            self._check_publication_author(env, self._actor(original).caller)
        if value['command'] == 'index' and env['from'] == self._peer:
            raise ContractError('capability_access_refused')
        return value

    def _validate_item(self, env, *, incoming=False):
        envelope.validate(env)
        data = env['data']
        if incoming:
            if (any(data.get(key) is not None and type(data[key]) is not str
                    for key in ('title', 'body', 'ref', 'author', 'source'))
                    or data.get('tags') is not None and (type(data['tags']) not in (list, str)
                        or any(type(tag) is not str for tag in data['tags']))):
                raise ContractError('capability_service_unavailable')
        elif (type(data) is not dict or set(data) != {'title', 'body', 'tags', 'ref', 'author', 'source'}
                or type(data['title']) is not str or type(data['body']) is not str
                or type(data['author']) is not str
                or type(data['tags']) is not list or any(type(tag) is not str for tag in data['tags'])
                or data['ref'] is not None and type(data['ref']) is not str
                or data['source'] not in ('explicit', 'auto:work', 'auto:handoff', 'auto:result')):
            raise ContractError('capability_service_unavailable')
        if env['type'] != 'knowledge' or env['rid'] != self.repository_id or env['to'] != '*':
            raise ContractError('capability_access_refused')

    def _check_publication_author(self, env, caller):
        sender = self._owner.sender_of(caller)
        author = 'operator' if sender.get('operator') else f"{sender['role']}/{sender['agent']}"
        if (env['from'] != self._peer or env['node'] != self._node
                or env['data'].get('author') != author):
            raise ContractError('capability_access_refused')

    def _effect(self, value, *, approval=None):
        if value['command'] == 'withdraw':
            if 'control' in value:
                from .knowledge_control import stage_withdrawal
                return stage_withdrawal(self, value, approval)
            peer = value['peer']
            if self._owner.policy.known_peer(peer) and self._owner.policy.trust(peer) != 'deny':
                raise ContractError('capability_access_refused')
            count = self._knowledge.stage_withdrawal(peer, self.repository)
            return {'withdrawn': count}, self._journal.current()['source']
        env = value['envelope']
        if value['command'] == 'index':
            subject = envelope.subject('know', env['from'], self.repository_id)
            decision = guard.inbound(self._owner.policy, subject, env)
            if approval is not None:
                from .knowledge_legacy import _Admission, check_approval
                if (type(approval) is not _Admission or approval.resource is not self
                        or strict_loads(approval.original)['contractId'] != 'federation-knowledge-approve'
                        or strict_loads(approval.original)['payload']['input']['envelope'] != env):
                    raise ContractError('capability_access_refused')
                decision = check_approval(self, strict_loads(approval.original))
            if decision.action == 'quarantine':
                rows = self._store.q('SELECT envelope FROM fed_quarantine WHERE state=? AND peer=? AND plane=? AND subject=?',
                    ('approved', env['from'], 'know', subject))
                if not any(canonical_bytes(strict_loads(row['envelope'])) == canonical_bytes(env) for row in rows):
                    raise ContractError('capability_access_refused')
                decision = guard.Decision('deliver', 'approved by operator', decision.trust,
                    untrusted=True, local_repo=decision.local_repo, approved=True)
            if decision.action != 'deliver' or decision.local_repo != self.repository:
                raise ContractError('capability_access_refused')
            outcome = self._knowledge.stage_received(env, decision)
            if outcome != 'delivered':
                raise ContractError('capability_access_refused')
            row = self._read_source({'kind': self.domain, 'id': env['id']})
            data = env['data']
            expected = {'from_peer': env['from'], 'author': data.get('author'),
                'title': data.get('title') or '(untitled)', 'body': data.get('body') or '',
                'tags': ' '.join(data.get('tags') or []), 'ref': data.get('ref'),
                'source': data.get('source') or 'explicit', 'at': env.get('at') or row['at']}
            if row is None or any(row[key] != value for key, value in expected.items()):
                raise ContractError('capability_outcome_conflict')
            return {'id': env['id']}, {'kind': self.domain, 'id': env['id']}
        result = self._knowledge.stage_share(env, self.repository)
        if result is None:
            raise ContractError('capability_service_unavailable')
        clean, kinds = result
        row = self._read_source({'kind': self.domain, 'id': clean['id']})
        data = clean['data']
        expected = {'rid': self.repository_id, 'repo': self.repository, 'from_peer': self._peer,
            'author': data['author'], 'title': data['title'] or '(untitled)', 'body': data['body'] or '',
            'tags': ' '.join(data['tags']), 'ref': data['ref'], 'source': data['source'],
            'trust': 'self', 'untrusted': 0, 'at': clean['at']}
        staged = self._store.q1('SELECT payload FROM fed_outbox WHERE msg_id=?', (clean['id'],))
        if (row is None or any(row[key] != value for key, value in expected.items())
                or row['withdrawn'] is not None or staged is None
                or canonical_bytes(strict_loads(staged['payload'])) != canonical_bytes(clean)):
            raise ContractError('capability_outcome_conflict')
        return {'id': clean['id'], 'redacted': sorted(set(kinds))}, {'kind': self.domain, 'id': clean['id']}

    def _read_source(self, source):
        if source['kind'] != self.domain:
            raise ContractError('capability_resource_stale')
        row = self._store.q1('SELECT * FROM p_knowledge_items WHERE id=?', (source['id'],))
        if row is not None and (row['rid'] != self.repository_id or row['repo'] != self.repository):
            raise ContractError('capability_access_refused')
        return row
