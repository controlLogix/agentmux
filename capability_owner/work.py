"""Bounded work commands over the original Store transactions and retained outcomes."""
import asyncio
import json
import re
import sqlite3

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub import names
from hub.fed import envelope, guard
from hub.fed.message_storage import MessageStorageJournal
from hub.fed.session import FederationSession
from hub.fed.work_services import _WorkTransactions, offer_digest, valid_work_data
from hub.store import Store
from state_owner.ledger import OwnerBinding
from .federated_storage import FederatedStorageResource
from .messages import MessageActor
from .policy import _reference


class LocalWorkDomain:
    """Borrow one concrete Hub's Store and worker without starting federation."""
    def __init__(self, hub):
        from hub.server import Hub
        if type(hub) is not Hub or type(hub.store) is not Store:
            raise ContractError('capability_owner_configuration')
        self._hub, self._store, self._connection = hub, hub.store, hub.store.db
        self._worker, self._stop, self.node = hub.dbx, hub.stop, hub.cfg['node']
        self._closed, self._pending = False, set()
        self._current()

    def __repr__(self):
        return '<LocalWorkDomain private>'

    @property
    def store(self):
        self._current()
        return self._store

    def _current(self):
        if (self._closed or self._hub.store is not self._store
                or self._store.db is not self._connection or self._hub.dbx is not self._worker
                or self._hub.stop is not self._stop or self._stop.is_set()
                or self._hub.cfg['node'] != self.node):
            raise ContractError('capability_resource_stale')
        try:
            self._connection.in_transaction
        except sqlite3.Error:
            raise ContractError('capability_resource_stale') from None
        if hasattr(self._store, '_selected_custody'):
            self._store.check_existing()

    async def db(self, function, *args, **kwargs):
        self._current()
        from hub.server import Hub
        original = asyncio.create_task(Hub.db(self._hub, function, *args, **kwargs))
        self._pending.add(original)
        try:
            await asyncio.wait({original})
            return original.result()
        except asyncio.CancelledError:
            while not original.done():
                try:
                    await asyncio.wait({original})
                except asyncio.CancelledError:
                    continue
            if not original.cancelled():
                original.exception()
            raise
        finally:
            self._pending.discard(original)

    async def close(self):
        self._closed = True
        while self._pending:
            await asyncio.wait(tuple(self._pending))

    def sender_of(self, caller):
        from hub.server import Hub
        self._current()
        return Hub.sender_of(self._hub, caller)


class WorkStorageResource(FederatedStorageResource):
    """Host-private work owner; plugins receive the common StorageHandle only."""
    domain = 'work'
    _local_commands = frozenset(('create', 'claim', 'heartbeat', 'release', 'cancel', 'claim-path', 'select'))
    _federated_commands = frozenset(('offer', 'ingest', 'claim-envelope', 'grant-envelope',
        'result-envelope', 'stage-result', 'revoke'))

    def __init__(self, binding, owner, *, repository, actors, plugin_identity_ref,
                 instance_id, initial_source=None, legacy_actors=(), legacy_authority=None, _bootstrap=None,
                 first_worker=None):
        from .work_host import SelectedWorkDomain
        from .work_legacy import LegacyWorkActor
        from identity.authority import LedgerAuthorityReader
        selected = type(owner) is SelectedWorkDomain
        if selected and legacy_authority is None:
            legacy_authority = owner._identity_reader
        local = type(owner) is LocalWorkDomain or selected and owner.session is None
        if (type(binding) is not OwnerBinding or binding.owner_domain != 'federation-work'
                or binding.entity_kind != 'work-channel' or type(owner.store) is not Store
                or not local and type(owner.session) is not FederationSession
                or repository is not None and (type(repository) is not str or not repository)
                or (repository is None) != (strict_loads(binding.scope)['projectId'] is None)
                or type(actors) is not tuple or not actors or any(type(a) is not MessageActor for a in actors)
                or len({(a.identity_ref, a.transport_ref) for a in actors}) != len(actors)
                or type(legacy_actors) is not tuple
                or any(type(actor) is not LegacyWorkActor for actor in legacy_actors)
                or len({(actor.identity_ref, actor.transport_ref) for actor in legacy_actors}) != len(legacy_actors)
                or legacy_actors and not isinstance(legacy_authority, LedgerAuthorityReader)
                or legacy_authority is not None and (not isinstance(legacy_authority, LedgerAuthorityReader)
                    or legacy_authority._hub != binding.hub_id)
                or not _reference(plugin_identity_ref) or type(instance_id) is not str
                or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', instance_id) is None
                or initial_source is not None and (type(initial_source) is not dict
                    or set(initial_source) != {'kind', 'id'} or initial_source['kind'] != 'work'
                    or not self._identifier(initial_source['id']))):
            raise ContractError('capability_owner_configuration')
        if selected and (owner._scope != binding.scope
                or owner._identity_reader._hub != binding.hub_id
                or legacy_authority is not owner._identity_reader
                or (None if strict_loads(owner._bound_repository) is None else
                    strict_loads(owner._bound_repository)['localName']) != repository):
            raise ContractError('capability_owner_configuration')
        self._first_worker = None
        if first_worker is not None:
            from .first_worker import declaration
            if not selected:
                raise ContractError('capability_owner_configuration')
            channels = owner._bound_selection.policy['storage']['work']['channels']
            matched = [channel for channel in channels if channel['resourceRef']['id'] == binding.entity_id]
            if len(matched) != 1 or matched[0].get('firstWorker') != first_worker:
                raise ContractError('capability_owner_configuration')
            self._first_worker = declaration(first_worker, repository, legacy_actors)
        self.binding, self.repository, self.actors = binding, repository, actors
        self._local, self._owner, self._store = local, owner, owner.store
        self._connection, self._db = self._store.db, owner.db
        self._source = getattr(owner, '_source', None)
        self._source_worker = getattr(self._source, '_executor', None)
        self._hub = None if local else getattr(owner, 'hub', None)
        self._hub_worker = getattr(self._hub, 'dbx', None)
        self._session = None if local else owner.session
        self._peer, self._node = (None if local else owner.me), owner.node
        if _bootstrap is not None:
            from .policy_bootstrap import PolicyResourceBootstrap
            if type(_bootstrap) is not PolicyResourceBootstrap or local:
                raise ContractError('capability_owner_configuration')
            self.repository_id = _bootstrap.repository_id(owner, repository)
        else:
            self.repository_id = None if local or repository is None else owner.policy.rid_of(repository)
        # A federated domain may also serve an existing unshared local repository.
        self.plugin_identity, self.instance_id = canonical_bytes(plugin_identity_ref), instance_id
        descriptor = {'hubId': binding.hub_id, 'entityId': binding.entity_id,
            'scope': strict_loads(binding.scope), 'repository': repository, 'repositoryId': self.repository_id,
            'domain': self.domain, 'localPeer': self._peer, 'localNode': self._node,
            'pluginIdentityRef': plugin_identity_ref, 'instanceId': instance_id,
            'actors': [{'identityRef': strict_loads(a.identity_ref), 'transportRef': strict_loads(a.transport_ref),
                'caller': a.caller} for a in actors], 'initialSource': initial_source}
        self._actor_generations = {}
        for actor in actors:
            if actor.caller != 'operator':
                row = self._store.q1('SELECT generation, repo, state FROM agents WHERE session=?', (actor.caller,))
                if row is None or row['state'] == 'dead':
                    raise ContractError('capability_owner_configuration')
                self._actor_generations[actor.caller] = row['generation']
        descriptor['actorGenerations'] = self._actor_generations
        self._legacy_actors, self._legacy_actor_generations = legacy_actors, {}
        self._legacy_authority = legacy_authority
        if legacy_authority is not None:
            descriptor['authorityProfile'] = {'hubId': legacy_authority._hub,
                'profileId': legacy_authority._profile, 'authorityId': legacy_authority._entity}
        for actor in legacy_actors:
            if actor.caller not in ('operator', 'federation'):
                if self._first_worker is not None and actor.caller == first_worker['caller']:
                    self._legacy_actor_generations[actor.caller] = 1
                    continue
                row = self._store.q1('SELECT generation, state FROM agents WHERE session=?', (actor.caller,))
                if row is None or row['state'] == 'dead':
                    raise ContractError('capability_owner_configuration')
                self._legacy_actor_generations[actor.caller] = row['generation']
        if legacy_actors:
            descriptor['legacyActors'] = [{'identityRef': strict_loads(actor.identity_ref),
                'transportRef': strict_loads(actor.transport_ref), 'caller': actor.caller,
                'grants': strict_loads(actor.grants)} for actor in legacy_actors]
            descriptor['legacyActorGenerations'] = self._legacy_actor_generations
        if self._first_worker is not None:
            descriptor['firstWorker'] = strict_loads(self._first_worker)
        source = {'kind': 'query', 'query': {'kind': 'list', 'state': None}} if repository is None else initial_source
        self._journal = MessageStorageJournal(self._store, canonical_bytes(descriptor), source, namespace='work')
        self._lock, self._transactions = asyncio.Lock(), _WorkTransactions()
        if _bootstrap is None:
            self._current()
        else:
            from .policy_bootstrap import check_bootstrap
            check_bootstrap(_bootstrap, self)

    def __repr__(self):
        return '<WorkStorageResource private>'

    @staticmethod
    def _identifier(value):
        return type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value) is not None

    def _current(self):
        if (self._owner.store is not self._store or self._store.db is not self._connection
                or self._owner.db != self._db or self._owner.node != self._node
                or getattr(self._owner, '_source', None) is not self._source
                or getattr(self._source, '_executor', None) is not self._source_worker
                or not self._local and (getattr(self._owner, 'hub', None) is not self._hub
                    or getattr(self._hub, 'dbx', None) is not self._hub_worker)):
            raise ContractError('capability_resource_stale')
        try:
            self._connection.in_transaction
        except sqlite3.Error:
            raise ContractError('capability_resource_stale') from None
        if hasattr(self._store, '_selected_custody'):
            self._store.check_existing()
        pin = getattr(self, '_work_source_pin', None)
        if pin is not None:
            if pin.store is not self._store or pin.connection is not self._connection:
                raise ContractError('capability_resource_stale')
            pin.check()
        if self._local:
            self._owner._current()
        else:
            if (self._owner.session is not self._session or self._owner.me != self._peer
                    or self.repository is not None and self._owner.policy.rid_of(self.repository) != self.repository_id
                    or self.repository_id is not None and self._owner.policy.local_of(self.repository_id) != self.repository):
                raise ContractError('capability_resource_stale')
            self._session.check_open()

    async def authorize(self, authority, raw, service_raw):
        decision = await super().authorize(authority, raw, service_raw)
        original = strict_loads(raw)
        if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(original['operation'])
                or canonical_bytes(original['operation']['scope']) != self.binding.scope):
            raise ContractError('capability_access_refused')
        actor = self._actor(original)
        await self._owner.db(self._check_caller, actor.caller)
        return decision

    async def authorize_legacy(self, authority, raw, *, source_expectation=None):
        from .work_legacy import authorize
        return await authorize(self, authority, raw, source_expectation=source_expectation)

    async def legacy(self, authority, raw, *, source_expectation=None):
        from identity.work_client import WORK_LIFECYCLE_COMMANDS
        if strict_loads(raw)['contractId'] in WORK_LIFECYCLE_COMMANDS:
            from .work_lifecycle import WorkLifecycleOwner
            owner = getattr(self, '_lifecycle_owner', None)
            if type(owner) is not WorkLifecycleOwner:
                raise ContractError('capability_access_refused')
            return await owner.apply(self, authority, raw, source_expectation=source_expectation)
        from .work_legacy import apply
        return await apply(self, authority, raw, source_expectation=source_expectation)

    def _check_caller(self, caller):
        self._current()
        if caller != 'operator':
            agent = self._agent(caller)
            if self._actor_generations.get(caller) != agent['generation']:
                raise ContractError('capability_access_refused')

    async def check_disclosure(self, raw):
        """Recheck the original actor after the service's final authority await."""
        actor = self._actor(strict_loads(raw))
        await self._owner.db(self._check_caller, actor.caller)
        self._current()

    async def write(self, authority, raw, service_raw):
        async with self._lock:
            await self.authorize(authority, raw, service_raw)
            original = strict_loads(raw)
            actor = self._actor(original)
            value = self._value(original)
            decision = await self.authorize(authority, raw, service_raw)
            def effect():
                self._current()
                return self._effect(value, actor.caller)
            def commit():
                self._current()
                with self._store.tx():
                    # Replays also cross this fence after waiting for the worker.
                    self._check_caller(actor.caller)
                    return self._journal.commit(original, original['payload']['resourceRef']['revision'],
                        decision.valid_until, effect)
            stored = await self._owner.db(commit)
            return stored['reply']

    def _value(self, original):
        value = original['payload']['input']['value']
        if (type(value) is not dict or type(value.get('formatVersion')) is not int
                or value['formatVersion'] != 1 or type(value.get('command')) is not str):
            raise ContractError('capability_service_unavailable')
        command = value['command']
        fields = {
            'create': ({'target', 'title'}, {'body', 'taskKey', 'requirements', 'priority', 'parentId', 'maxAttempts', 'federate'}),
            'offer': ({'target', 'title'}, {'body', 'taskKey', 'requirements', 'priority'}),
            'claim': (set(), {'workId', 'leaseSeconds'}),
            'heartbeat': (set(), {'leaseSeconds'}),
            'release': ({'workId', 'outcome'}, {'result'}),
            'cancel': ({'workId', 'reason'}, set()),
            'claim-path': ({'path'}, {'workId', 'leaseSeconds'}),
            'select': ({'query'}, set()),
            'ingest': ({'envelope'}, set()), 'claim-envelope': ({'envelope'}, set()),
            'grant-envelope': ({'envelope'}, set()), 'result-envelope': ({'envelope'}, set()),
            'stage-result': ({'workId'}, set()), 'revoke': ({'peer'}, set()),
        }
        if command not in fields:
            raise ContractError('capability_service_unavailable')
        required, optional = fields[command]
        keys = set(value) - {'formatVersion', 'command'}
        if not required <= keys or not keys <= required | optional:
            raise ContractError('capability_service_unavailable')
        for key in ('target', 'title', 'path', 'reason', 'peer'):
            if key in value and (type(value[key]) is not str or not value[key].strip()):
                raise ContractError('capability_service_unavailable')
        for key in ('body', 'taskKey', 'result'):
            if key in value and value[key] is not None and type(value[key]) is not str:
                raise ContractError('capability_service_unavailable')
        for key in ('workId', 'parentId'):
            if key in value and value[key] is not None and not self._identifier(value[key]):
                raise ContractError('capability_service_unavailable')
        if 'priority' in value and type(value['priority']) is not int:
            raise ContractError('capability_service_unavailable')
        for key in ('leaseSeconds', 'maxAttempts'):
            if key in value and value[key] is not None and (type(value[key]) is not int or not 1 <= value[key] <= 2147483647):
                raise ContractError('capability_service_unavailable')
        if 'requirements' in value and value['requirements'] is not None and type(value['requirements']) is not dict:
            raise ContractError('capability_service_unavailable')
        if 'federate' in value and type(value['federate']) is not bool:
            raise ContractError('capability_service_unavailable')
        if command == 'release' and value['outcome'] not in ('done', 'failed', 'returned', 'blocked'):
            raise ContractError('capability_service_unavailable')
        if command in ('release', 'cancel', 'stage-result') and not self._identifier(value['workId']):
            raise ContractError('capability_service_unavailable')
        if command == 'select':
            self._query(value['query'])
        if command in self._federated_commands:
            if self._local or self.repository_id is None:
                raise ContractError('capability_access_refused')
            if 'envelope' in value:
                env = value['envelope']
                envelope.validate(env)
                expected = {'ingest': 'work', 'claim-envelope': 'work_claim',
                    'grant-envelope': 'work_grant', 'result-envelope': 'result'}[command]
                if env['v'] != 3 or env['type'] != expected or env['rid'] != self.repository_id or not valid_work_data(env):
                    raise ContractError('capability_access_refused')
                if command == 'ingest' and env['data']['offer_digest'] != offer_digest(env):
                    raise ContractError('capability_access_refused')
        return value

    def _named_repo(self):
        if self.repository is None or self._store.q1('SELECT repo FROM repos WHERE repo=?', (self.repository,)) is None:
            raise ContractError('capability_access_refused')

    def _row(self, work_id):
        row = self._store.q1('SELECT * FROM work_items WHERE id=?', (work_id,))
        if row is None or self.repository is not None and row['repo'] != self.repository:
            raise ContractError('capability_access_refused')
        return row

    def _agent(self, caller):
        agent = self._store.q1('SELECT * FROM agents WHERE session=?', (caller,))
        if agent is None or agent['state'] == 'dead':
            raise ContractError('capability_access_refused')
        return agent

    def _target(self, target):
        addr = names.parse_address(target)
        if addr.kind == 'agent':
            if self._agent(addr.name)['repo'] != self.repository:
                raise ContractError('capability_access_refused')
        elif addr.kind == 'role':
            if addr.scope not in (self.repository, '*') and not addr.scope.startswith('team:' + self.repository + '/'):
                if not addr.scope.startswith('group:') or self._store.q1(
                        'SELECT 1 FROM groups WHERE repo=? AND grp=?', (self.repository, addr.scope[6:])) is None:
                    raise ContractError('capability_access_refused')
        elif addr.kind == 'team':
            if addr.scope != self.repository:
                raise ContractError('capability_access_refused')
        else:
            raise ContractError('capability_access_refused')

    @staticmethod
    def _operator(caller):
        if caller != 'operator':
            raise ContractError('capability_access_refused')

    def _query(self, query):
        if type(query) is not dict or type(query.get('kind')) is not str:
            raise ContractError('capability_service_unavailable')
        fields = {'show': {'kind', 'workId'}, 'list': {'kind', 'state'},
            'claimable': {'kind'}, 'active': {'kind'}, 'claims': {'kind'},
            'federated': {'kind'}, 'pending-results': {'kind'}, 'readiness': {'kind', 'session'}}
        kind = query['kind']
        if kind not in fields or set(query) != fields[kind]:
            raise ContractError('capability_service_unavailable')
        if kind == 'show' and not self._identifier(query['workId']):
            raise ContractError('capability_service_unavailable')
        if kind == 'readiness' and not self._identifier(query['session']):
            raise ContractError('capability_service_unavailable')
        if kind == 'list' and query['state'] not in (None, 'ready', 'claimed', 'waiting_children', 'done', 'failed', 'blocked', 'cancelled'):
            raise ContractError('capability_service_unavailable')
        return query

    def _select(self, query, caller, *, _admission=None):
        kind = self._query(query)['kind']
        if kind == 'readiness':
            from .work_legacy import _Admission, check_actor
            if (type(_admission) is not _Admission or _admission.resource is not self
                    or _admission.actor.caller != caller or _admission.target is None
                    or _admission.target[0] != query['session']):
                raise ContractError('capability_access_refused')
            self._named_repo()
            check_actor(self, _admission.actor)
            self._journal._deadline(_admission.valid_until)
            target = self._agent(query['session'])
            if target['generation'] != _admission.target[1]:
                raise ContractError('capability_access_refused')
            maximum = int(json.loads(target['role_snapshot']).get('max_active', 1))
            count = self._store.q1("SELECT count(*) n FROM work_items WHERE claimed_by=? AND state='claimed'",
                (query['session'],))['n']
            return {'claimable': self._store.claimable(query['session'], repository=self.repository),
                'active': self._store.q("SELECT id, title, lease_until FROM work_items WHERE claimed_by=? "
                    "AND repo=? AND state IN ('claimed','waiting_children')", (query['session'], self.repository)),
                'capacity': {'atCapacity': count >= maximum, 'available': max(0, maximum - count)}}
        if kind == 'show':
            self._row(query['workId'])
            result = self._store.work(query['workId'])
            if self.repository is not None and any(self._row(child['id'])['repo'] != self.repository for child in result['children']):
                raise ContractError('capability_access_refused')
            return result
        if kind == 'list':
            return self._store.work(state=query['state'], repo=self.repository)
        if kind in ('claimable', 'active'):
            self._agent(caller)
            if kind == 'claimable':
                return self._store.claimable(caller, repository=self.repository)
            return self._store.q("SELECT id, title, lease_until FROM work_items WHERE claimed_by=? "
                "AND repo=? AND state IN ('claimed','waiting_children')", (caller, self.repository))
        if kind == 'claims':
            return self._store.q('SELECT * FROM claims WHERE (? IS NULL OR repo=?)', (self.repository, self.repository))
        if kind == 'pending-results':
            return self._store.q("SELECT id FROM work_items WHERE repo=? AND origin_peer IS NOT NULL "
                "AND state IN ('done','failed') AND json_extract(fed_flags,'$.result_pending')=1 "
                "AND json_extract(fed_flags,'$.grant_id') IS NOT NULL", (self.repository,))
        return self._store.q("SELECT id, title, state, claimed_by, origin_peer, task_key, target, result, updated "
            "FROM work_items WHERE (? IS NULL OR repo=?) AND (origin_peer IS NOT NULL OR claimed_by=? "
            "OR claimed_by LIKE 'peer:%') ORDER BY updated DESC LIMIT 50", (self.repository, self.repository, 'fed:pending'))

    def _admission(self, env):
        plane = envelope.PLANE_OF[env['type']]
        tail = [env['rid'], env['data']['role']] if plane == 'work' else [env['to']]
        subject = envelope.subject(plane, env['from'], *tail)
        decision = guard.inbound(self._owner.policy, subject, env)
        if decision.action == 'quarantine':
            approved = self._store.q('SELECT envelope FROM fed_quarantine WHERE state=? AND peer=? AND plane=? AND subject=?',
                ('approved', env['from'], plane, subject))
            if any(canonical_bytes(strict_loads(row['envelope'])) == canonical_bytes(env) for row in approved):
                # Approval comes from the owner's retained exact envelope.
                decision = guard.Decision('deliver', 'approved by operator', decision.trust,
                    untrusted=True, local_repo=decision.local_repo, approved=True)
        if decision.action != 'deliver' or decision.local_repo != self.repository:
            raise ContractError('capability_access_refused')
        return decision

    def _effect(self, value, caller, *, _admission=None):
        command = value['command']
        if _admission is None:
            self._check_caller(caller)
        else:
            from .work_legacy import _Admission, check_actor, effect_caller
            if (type(_admission) is not _Admission or _admission.resource is not self
                    or _admission.actor.caller != caller):
                raise ContractError('capability_access_refused')
            self._journal._deadline(_admission.valid_until)
            check_actor(self, _admission.actor)
            caller = effect_caller(self, _admission)
        if command == 'select':
            result = self._select(value['query'], caller)
            return result, {'kind': 'result', 'value': result}
        self._named_repo()
        result, work_id = None, value.get('workId')
        if command in ('create', 'offer'):
            self._target(value['target'])
            parent = value.get('parentId')
            if parent is not None:
                self._row(parent)
                if caller != 'operator' and self._row(parent)['claimed_by'] != caller:
                    raise ContractError('capability_access_refused')
            if command == 'offer':
                addr = names.parse_address(value['target'])
                if addr.kind != 'role' or addr.scope != self.repository:
                    raise ContractError('capability_access_refused')
                result = self._transactions.stage_offer(self._owner, self._owner.hub.sender_of(caller),
                    self._owner.sender_of(caller), self.repository, addr.name, self.repository_id,
                    value['target'], value['title'], value.get('body'), value.get('taskKey'),
                    value.get('requirements'), value.get('priority', 100))
            else:
                sender = self._owner.sender_of(caller) if self._local else self._owner.hub.sender_of(caller)
                result = self._store.work_create(sender, self.repository, value['target'], value['title'], value.get('body'),
                    value.get('taskKey'), value.get('requirements'), value.get('priority', 100), parent,
                    value.get('maxAttempts', 3), federate=value.get('federate', False), node=self._node)
            work_id = result['id']
        elif command == 'claim':
            self._agent(caller)
            if work_id is not None:
                self._row(work_id)
            result = self._store.claim(caller, value.get('leaseSeconds'), work_id, repository=self.repository)
            work_id = (result.get('claimed') or {}).get('id')
        elif command == 'heartbeat':
            self._agent(caller)
            result = {'renewed': self._store.heartbeat(caller, value.get('leaseSeconds'), repository=self.repository)}
        elif command == 'release':
            self._agent(caller)
            self._row(work_id)
            result = self._store.release(caller, work_id, value['outcome'], value.get('result'), self._node)
        elif command == 'cancel':
            self._operator(caller)
            self._row(work_id)
            for row in self._store.q('SELECT id FROM work_items WHERE parent_id=?', (work_id,)):
                self._row(row['id'])
            result = {'cancelled': self._store.cancel(work_id, value['reason'])}
        elif command == 'claim-path':
            self._agent(caller)
            if work_id is not None:
                row = self._row(work_id)
                if row['claimed_by'] != caller or row['state'] not in ('claimed', 'waiting_children'):
                    raise ContractError('capability_access_refused')
            result = self._store.claim_path(caller, self.repository, value['path'], work_id, value.get('leaseSeconds') or 1800)
        elif command == 'stage-result':
            self._row(work_id)
            self._transactions._stage_result(self._owner, work_id)
            result = self._row(work_id)
        elif command == 'revoke':
            self._operator(caller)
            peer = value['peer']
            if envelope.TOKEN.fullmatch(peer) is None or peer == self._peer or self._owner.policy.known_peer(peer) and self._owner.policy.trust(peer) != 'deny':
                raise ContractError('capability_access_refused')
            result = {'cancelled': self._transactions._revoke(self._owner, peer, self.repository)}
        else:
            env = value['envelope']
            dec = self._admission(env)
            if command == 'ingest':
                if env['from'] == self._peer and env['node'] == self._node:
                    self._row(env['data']['origin_id'])
                result = self._transactions._ingest(self._owner, env, dec, self.repository)
                row = (self._store.q1('SELECT id FROM work_items WHERE id=?', (env['data']['origin_id'],))
                    if env['from'] == self._peer and env['node'] == self._node else self._store.q1(
                    "SELECT id FROM work_items WHERE origin_peer=? AND json_extract(fed_flags,'$.origin_node')=? "
                    "AND json_extract(fed_flags,'$.env')=?", (env['from'], env['node'], env['id'])))
                work_id = None if row is None else self._row(row['id'])['id']
            elif command == 'claim-envelope':
                self._row(env['data']['origin_id'])
                result = self._transactions._claim(self._owner, env, dec)
                work_id = env['data']['origin_id']
            elif command == 'grant-envelope':
                result = self._transactions._grant(self._owner, env, dec)
                row = self._store.q1("SELECT id FROM work_items WHERE origin_peer=? AND json_extract(fed_flags,'$.env')=? "
                    "AND json_extract(fed_flags,'$.execution_id')=?",
                    (env['from'], env['data']['offer_id'], env['data']['execution_id']))
                work_id = None if row is None else self._row(row['id'])['id']
            elif command == 'result-envelope':
                self._row(env['data']['origin_id'])
                outcome, row = self._transactions._result(self._owner, env, dec)
                result = {'outcome': outcome, 'work': None if row is None else self._row(row['id'])}
                work_id = None if row is None else row['id']
            else:
                raise ContractError('capability_service_unavailable')
        source = {'kind': 'result', 'value': result} if work_id is None else {'kind': 'work', 'id': work_id}
        return result, source

    def _read_source(self, source):
        if source['kind'] == 'query':
            return self._select(source['query'], 'operator')
        if source['kind'] == 'result':
            return source['value']
        if source['kind'] != 'work':
            raise ContractError('capability_resource_stale')
        return self._row(source['id'])

    def _return_leases(self, session, why):
        """Service-only primitive for the existing death/reregistration transaction."""
        self._current()
        self._named_repo()
        agent = self._store.q1('SELECT repo FROM agents WHERE session=?', (session,))
        if agent is None:
            raise ContractError('capability_access_refused')
        with self._store.tx():
            return self._store._return_leases(session, why, repository=self.repository)

    def _sweep_leases(self):
        """Service-only lease expiry inside the caller's retained transaction."""
        self._current()
        self._named_repo()
        return self._store.sweep_leases(repository=self.repository)

    def _ingest_legacy(self, env):
        """Service-only bridge ingest; this is never a native work command."""
        self._current()
        self._named_repo()
        if env['work']['repo'] != self.repository:
            raise ContractError('capability_access_refused')
        self._target(env['work']['target'])
        with self._store.tx():
            prior = self._store.q1('SELECT id FROM work_items WHERE origin=?', (env['origin'],))
            if prior is not None:
                self._row(prior['id'])
            row = self._store.ingest_work(env)
            return self._row(row['id'])

    def _result_legacy(self, env):
        """Service-only completion using the existing bridge placeholder rules."""
        self._current()
        self._named_repo()
        self._row(env['origin_id'])
        return self._store.ingest_result(env)
