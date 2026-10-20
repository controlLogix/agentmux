"""Retain an authorized self-revoke before its protected external publication."""
import asyncio
from datetime import datetime, timezone
import hashlib

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.authority import _active, _indexes, _key, approval_reason, evaluate_snapshot
from identity.peer_control import check_authority, control_storage, selected_route
from identity.peer_control_commands import COMMANDS
from hub.fed import envelope
from hub.fed.peer_control import PeerControlPublisher


class PeerControlCommandOwner:
    """Borrow exact selected publishers and existing Store custody; own attempts."""
    def __init__(self, selection, identity, source, publishers):
        from identity.application_service_selection import ApplicationServiceSelection
        from .knowledge_host import KnowledgeStoreHost
        from .messages_host import MessageStoreHost
        from .selected_storage import BoardAuditMirrorHost
        from .work_host import WorkStoreHost
        from .code_host import CodeStoreHost
        if (type(selection) is not ApplicationServiceSelection
                or type(publishers) is not tuple or not publishers
                or any(type(p) is not PeerControlPublisher or p._selection is not selection for p in publishers)
                or len({p._route_id for p in publishers}) != len(publishers)):
            raise ContractError('peer_control_command_configuration')
        routes, declarations = {}, {}
        for publisher in publishers:
            route = selected_route(selection, publisher._route_id)
            domain, selected = control_storage(selection.policy, route)
            allowed = ((WorkStoreHost, KnowledgeStoreHost, MessageStoreHost, BoardAuditMirrorHost,
                CodeStoreHost) if domain == 'work' else
                (KnowledgeStoreHost, MessageStoreHost, BoardAuditMirrorHost))
            if (type(source) not in allowed or publisher._identity is not identity
                    or publisher._pin != route or source._pins != selected['source']
                    or source._peer != route['localPeer'] or source._repository is None
                    or any(source._repository.get(k) != v for k, v in route['repository'].items())):
                raise ContractError('peer_control_command_configuration')
            routes[publisher._route_id] = strict_loads(canonical_bytes(route))
            declarations[publisher._route_id] = (domain, canonical_bytes(selected))
        self._selection, self._identity, self._source = selection, identity, source
        self._routes, self._declarations = routes, declarations
        self._custody, self._db = source, source.db
        self._source_binding = canonical_bytes([source._pins, source._repository, source._peer])
        self._original_publishers = {p._route_id: p for p in publishers}
        self._store, self._executor = source._store, source._executor
        self._authority, self._ingress = selection.check_storage_identity_source(identity)
        self._publishers = {p._route_id: p for p in publishers}
        self._locks = {key: asyncio.Lock() for key in self._publishers}
        self._closed, self._closing = False, None
        self._active, self._workers = set(), set()

    def __repr__(self):
        return '<PeerControlCommandOwner private>'

    def check(self):
        if self._closed:
            raise ContractError('peer_control_command_unavailable')
        self._source.check_health()
        if (self._source is not self._custody or self._source.db != self._db
                or canonical_bytes([self._source._pins, self._source._repository,
                    self._source._peer]) != self._source_binding
                or self._source._store is not self._store or self._source._executor is not self._executor
                or any(selected_route(self._selection, key) != route
                    or self._publishers[key] is not self._original_publishers[key]
                    or self._publishers[key]._identity is not self._identity
                    or self._publishers[key]._selection is not self._selection
                    or self._publishers[key]._pin != route for key, route in self._routes.items())):
            raise ContractError('peer_control_command_unavailable')
        for key, route in self._routes.items():
            domain, declaration = control_storage(self._selection.policy, route)
            if (domain, canonical_bytes(declaration)) != self._declarations[key]:
                raise ContractError('peer_control_command_unavailable')
        authority, ingress = self._selection.check_storage_identity_source(self._identity)
        if authority is not self._authority or ingress is not self._ingress:
            raise ContractError('peer_control_command_unavailable')

    async def authorize(self, raw):
        self.check()
        original = strict_loads(raw)
        validate('message-envelope', original)
        contract, payload = original['contractId'], original['payload']
        if canonical_bytes(original) != raw or contract not in COMMANDS:
            raise ContractError('peer_control_command_refused')
        validate(contract, payload)
        route_id = payload['input']['routeId']
        route = selected_route(self._selection, route_id)
        if (route_id not in self._publishers or route.get('operators') is None
                or payload['resourceRef'] != route['resourceRef']):
            raise ContractError('peer_control_command_refused')
        # Publication and outcome disclosure require both the current operator
        # permission and this exact selected publisher's current authority.
        snapshot = await check_authority(self._selection, self._identity,
            route_id=route_id, publisher=True)
        self.check()
        decision = evaluate_snapshot(snapshot, raw, audience={'hubId': self._authority._hub,
            'serviceId': 'storage-owner'}, now=datetime.now(timezone.utc))
        operation = original['operation']
        transport = original['ingressAttestation']['claims']['authenticatedTransportRef']
        actors = [actor for actor in route['operators'] if actor['identityRef'] == operation['effectiveActorRef']
            and actor['transportRef'] == transport]
        index = _indexes(strict_loads(snapshot.record)['state'], self._authority._hub)
        principal = index['identities'].get(_key(operation['effectiveActorRef']))
        if (decision.outcome != 'allowed' or decision.valid_until is None or len(actors) != 1
                or principal is None or principal['kind'] != 'human'
                or operation['caller']['authenticatedIdentityRef'] != principal['ref']
                or operation['delegationRef'] is not None or operation['scope'] != route['scope']
                or actors[0]['grants'][contract] != operation['grantRef']
                or operation['expectedVersion'] != route['resourceRef']['revision']):
            raise ContractError('peer_control_command_refused')
        if contract == 'federation-peer-revoke':
            item = payload['input']['envelope']
            envelope.validate_route('am.ctl.' + route['localPeer'], item)
            if (item['type'] != 'revoke' or item['from'] != route['localPeer']
                    or item['node'] != route['localNode'] or item['rid'] is not None or item['to'] != '*'):
                raise ContractError('peer_control_command_refused')
        return snapshot, decision, route

    def _key(self, route, operation_id):
        binding = {'hubId': self._authority._hub, 'scope': route['scope'],
            'resourceRef': route['resourceRef'], 'routeId': route['routeId']}
        return 'peer-control-command:' + hashlib.sha256(canonical_bytes(binding)).hexdigest() + ':' + \
            hashlib.sha256(operation_id.encode()).hexdigest()

    def _record(self, route, original):
        self._source._check_files()
        operation = original['operation']
        row = self._source._store.q1('SELECT v FROM fed_state WHERE k=?',
            (self._key(route, operation['operationId']),))
        if row is None:
            return None
        value = strict_loads(row['v'])
        if (type(value) is not dict or set(value) != {'formatVersion', 'route', 'original', 'result'}
                or type(value['formatVersion']) is not int or value['formatVersion'] != 1
                or value['route'] != route or value['original']['operation']['operationId'] != operation['operationId']):
            raise ContractError('peer_control_command_conflict')
        retained = value['original']
        validate('message-envelope', retained)
        validate('federation-peer-revoke', retained['payload'])
        validate('federation-peer-revoke-result', value['result'])
        result = value['result']
        item = retained['payload']['input']['envelope']
        if (retained['contractId'] != 'federation-peer-revoke'
                or result['operationId'] != retained['operation']['operationId']
                or result['payloadDigest'] != payload_digest(retained['payload'])
                or retained['operation']['payloadDigest'] != result['payloadDigest']
                or result['eventId'] != item['id'] or result['eventDigest'] != payload_digest(item)
                or retained['payload']['input']['routeId'] != route['routeId']
                or retained['payload']['resourceRef'] != route['resourceRef']):
            raise ContractError('peer_control_command_conflict')
        return value

    def _reserve(self, route, original, valid_until):
        self._source._check_files()
        if datetime.now(timezone.utc) >= valid_until:
            raise ContractError('peer_control_command_refused')
        with self._source._store.tx():
            previous = self._record(route, original)
            if previous is not None:
                preserved = ('operationId', 'payloadDigest', 'caller', 'effectiveActorRef', 'scope',
                    'taskId', 'runId', 'attemptId', 'delegationRef', 'grantRef', 'expectedVersion')
                if (any(previous['original']['operation'][k] != original['operation'][k] for k in preserved)
                        or previous['original']['payload'] != original['payload']):
                    raise ContractError('peer_control_command_conflict')
                return previous, False
            operation, payload = original['operation'], original['payload']
            item = payload['input']['envelope']
            value = {'formatVersion': 1, 'route': route, 'original': original, 'result': {
                'operationId': operation['operationId'], 'payloadDigest': payload_digest(payload),
                'eventId': item['id'], 'eventDigest': payload_digest(item), 'outcome': 'uncertain'}}
            raw = canonical_bytes(value)
            if len(raw) > 65536:
                raise ContractError('peer_control_command_capacity')
            self._source._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                (self._key(route, operation['operationId']), raw.decode()))
            return value, True

    def _published(self, route, value, sent):
        self._source._check_files()
        original, result = value['original'], value['result']
        if sent != {'eventId': result['eventId'], 'eventDigest': result['eventDigest']}:
            raise ContractError('peer_control_command_unconfirmed')
        with self._source._store.tx():
            current = self._record(route, original)
            if current != value:
                raise ContractError('peer_control_command_conflict')
            current['result']['outcome'] = 'published'
            self._source._store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                (canonical_bytes(current).decode(), self._key(route, result['operationId'])))
            return current['result']

    def _query(self, route, original, snapshot):
        request = original['payload']['input']
        selector = {**original, 'operation': {**original['operation'], 'operationId': request['operationId']}}
        value = self._record(route, selector)
        if value is None or value['result']['payloadDigest'] != request['payloadDigest']:
            # A new call cannot turn an unknown original into an absent effect.
            raise ContractError('peer_control_command_unconfirmed')
        retained = value['original']
        current_actor = original['operation']['effectiveActorRef']
        if retained['operation']['effectiveActorRef'] != current_actor:
            raise ContractError('peer_control_command_refused')
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], self._authority._hub)
        now = datetime.now(timezone.utc)
        operation = retained['operation']
        grants = [g for g in index['grants'].values() if _active(g, now)
            and g['callerRef'] == current_actor and g['actorRef'] == current_actor
            and g['scope'] == route['scope'] and g['resourceId'] == route['resourceRef']['id']
            and g['contractId'] == 'federation-peer-revoke']
        grant = index['grants'].get(_key(operation['grantRef']))
        if (grant not in grants or grant['delegationRef'] is not None
                or any(g['decision'] == 'denied' for g in grants)
                or approval_reason(index, grant, operation, audience={'hubId': self._authority._hub,
                    'serviceId': 'storage-owner'}, scope=route['scope'], contract='federation-peer-revoke', now=now) is not None):
            raise ContractError('peer_control_command_refused')
        return value['result']

    async def execute(self, raw):
        if self._closed:
            raise ContractError('peer_control_command_unavailable')
        worker = asyncio.create_task(self._execute(raw), name='peer-control-command:original')
        self._workers.add(worker)
        def finished(done):
            self._workers.discard(done)
            if not done.cancelled():
                done.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def _execute(self, raw):
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            _, _, route = await self.authorize(raw)
            async with self._locks[route['routeId']]:
                snapshot, decision, route = await self.authorize(raw)
                original = strict_loads(raw)
                if original['contractId'] == 'federation-peer-revoke-outcome':
                    result = await self._source.db(self._query, route, original, snapshot)
                else:
                    value, fresh = await self._source.db(self._reserve, route, original, decision.valid_until)
                    if fresh:
                        # Retention precedes this boundary. Any failure leaves
                        # the exact original uncertain and never dispatches it again.
                        await self.authorize(raw)
                        self.check()
                        publisher = self._publishers[route['routeId']]
                        sent = await publisher.publish_revoke(original['payload']['input']['envelope'])
                        result = await self._source.db(self._published, route, value, sent)
                    else:
                        result = value['result']
                await self.authorize(raw)
                self.check()
                return result
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('peer_control_command_cleanup_invalid')
        self._closed = True
        if self._closing is None:
            async def joined():
                if self._active or self._workers:
                    await asyncio.gather(*tuple(self._active | self._workers), return_exceptions=True)
            self._closing = asyncio.create_task(joined(), name='peer-control-command:cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('peer_control_command_cleanup_incomplete')
        self._closing.result()
