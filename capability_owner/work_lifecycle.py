"""Fixed agent lifecycle batches on one retained work Store transaction."""
import asyncio
from contextlib import AsyncExitStack
from datetime import datetime, timezone

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub import names
from identity.authority import _active, _indexes, _key, evaluate_snapshot
from .work import WorkStorageResource


LIFECYCLE_COMMANDS = frozenset('federation-work-' + action for action in
    ('register', 'state', 'sweep-global'))


def _refuse():
    raise ContractError('capability_access_refused')


def _session(original):
    value = original['payload']['input']
    if original['contractId'] == 'federation-work-register':
        return names.session_name(value['repo'], value['role'], value['agent'])
    return value.get('session')


def check_target(resource, original, snapshot=None):
    """Fence both initial effects and fresh original-outcome disclosure."""
    query = None
    if original['contractId'] == 'federation-work-outcome':
        query = original['payload']['input']
        stored = resource._journal.outcome(query['operationId'], query['payloadDigest'])
        if stored is None:
            if 'readyState' in query:
                _refuse()
            return
        original = stored['envelope']
        if 'readyState' in query and (query['contractId'] != 'federation-work-register'
                or original['contractId'] != query['contractId']):
            _refuse()
    if original['contractId'] not in LIFECYCLE_COMMANDS:
        return
    owner = getattr(resource, '_lifecycle_owner', None)
    if type(owner) is not WorkLifecycleOwner:
        _refuse()
    owner._current()
    value, operation = original['payload']['input'], original['operation']
    owner._descriptor(resource, original)
    stored = resource._journal.outcome(operation['operationId'], operation['payloadDigest'])
    session = _session(original)
    if session is not None:
        row = resource._store.q1('SELECT * FROM agents WHERE session=?', (session,))
        expected = value['generation']
        if original['contractId'] == 'federation-work-register' and stored is not None:
            expected = 1 if expected is None else expected + 1
        if (row is None) != (expected is None) or row is not None and row['generation'] != expected:
            _refuse()
    if stored is not None and snapshot is not None:
        deadline = owner._recovery_permission(original, snapshot)
        if query is not None and 'readyState' in query:
            ready = owner._ready_original(resource, stored, query['readyState'])
            deadline = min(deadline, check_target(resource, ready['envelope'], snapshot))
        return deadline


class WorkLifecycleOwner:
    """Borrow one exact source; never join independent connections by path."""
    def __init__(self, resources):
        if (type(resources) is not tuple or not 1 <= len(resources) <= 64
                or any(type(resource) is not WorkStorageResource or resource.repository is None
                    or not resource._legacy_actors for resource in resources)
                or len({resource.repository for resource in resources}) != len(resources)
                or len({resource.binding.entity_id for resource in resources}) != len(resources)):
            raise ContractError('capability_owner_configuration')
        self._resources = {resource.binding.entity_id: resource for resource in resources}
        first = resources[0]
        self._store, self._connection, self._db = first._store, first._connection, first._owner.db
        self._source, self._source_worker = first._source, first._source_worker
        self._hub_worker, self._node = first._hub_worker, first._node
        self._authority = first._legacy_authority
        self._profile = (self._authority._hub, self._authority._profile, self._authority._entity)
        self._pins = tuple((resource, resource._owner, resource._legacy_authority,
            resource.binding, resource.repository, resource._owner.db) for resource in resources)
        self._closed, self._batches, self._workers, self._installed = False, {}, set(), False
        self._current()
        if any(getattr(resource, '_lifecycle_owner', None) is not None for resource in resources):
            raise ContractError('capability_owner_configuration')
        for resource in resources:
            resource._lifecycle_owner = self
        self._installed = True

    def __repr__(self):
        return '<WorkLifecycleOwner private>'

    def _current(self):
        if self._closed:
            raise ContractError('capability_resource_stale')
        for resource, domain, authority, binding, repository, database in self._pins:
            resource._current()
            if (resource._owner is not domain or resource._store is not self._store
                    or resource._connection is not self._connection or resource._owner.db != database
                    or resource._source is not self._source or resource._source_worker is not self._source_worker
                    or resource._hub_worker is not self._hub_worker or resource._node != self._node
                    or resource._legacy_authority is not authority or authority is not self._authority
                    or (authority._hub, authority._profile, authority._entity) != self._profile
                    or resource.binding != binding or resource.repository != repository
                    or self._installed and getattr(resource, '_lifecycle_owner', None) is not self):
                raise ContractError('capability_resource_stale')

    def _descriptor(self, resource, original):
        if original['contractId'] not in LIFECYCLE_COMMANDS or resource not in self._resources.values():
            _refuse()
        validate(original['contractId'], original['payload'])
        value, operation = original['payload']['input'], original['operation']
        entries = value['repositories']
        if (value['batchId'] != operation['operationId'] or value['localNode'] != self._node
                or entries != sorted(entries, key=lambda entry: entry['repository'])
                or len({entry['repository'] for entry in entries}) != len(entries)
                or len({entry['resourceRef']['id'] for entry in entries}) != len(entries)):
            _refuse()
        for entry in entries:
            selected = self._resources.get(entry['resourceRef']['id'])
            if (selected is None or selected.repository != entry['repository']
                    or entry['resourceRef']['ownerHubId'] != selected.binding.hub_id
                    or entry['resourceRef']['revision'] < 1):
                _refuse()
        matches = [entry for entry in entries if entry['resourceRef']['id'] == resource.binding.entity_id]
        if len(matches) != 1 or original['payload']['resourceRef'] != matches[0]['resourceRef']:
            _refuse()
        if original['contractId'] == 'federation-work-register':
            if value['purpose'] != 'hub-registration':
                _refuse()
            for field in ('repo', 'role', 'agent'):
                names.check_part(value[field], field)
        elif original['contractId'] == 'federation-work-state':
            if (value['purpose'] not in ('hub-state', 'hub-observation')
                    or (value['purpose'] == 'hub-observation') != ('observation' in value)):
                _refuse()
        elif value['purpose'] != 'hub-lease-sweep':
            _refuse()
        return canonical_bytes({'contractId': original['contractId'], 'input': value})

    def _recovery_permission(self, original, snapshot):
        """A batch result needs every original permission under one fresh read."""
        from .work_legacy import check_actor, _permission
        now = datetime.now(timezone.utc)
        index = _indexes(strict_loads(snapshot.record)['state'], self._profile[0])
        ends, results = [], set()
        descriptor = canonical_bytes({'contractId': original['contractId'], 'input': original['payload']['input']})
        for entry in original['payload']['input']['repositories']:
            resource = self._resources[entry['resourceRef']['id']]
            payload = {**original['payload'], 'resourceRef': entry['resourceRef']}
            record = resource._journal.outcome(original['operation']['operationId'], payload_digest(payload))
            if record is None or record['reply']['outcome'] != 'applied':
                _refuse()
            retained, operation = record['envelope'], record['envelope']['operation']
            if (self._descriptor(resource, retained) != descriptor
                    or operation['effectiveActorRef'] != original['operation']['effectiveActorRef']
                    or operation['caller'] != original['operation']['caller']
                    or canonical_bytes(operation['scope']) != resource.binding.scope
                    or operation['delegationRef'] is not None):
                _refuse()
            claims = retained['ingressAttestation']['claims']
            matches = [actor for actor in resource._legacy_actors
                if actor.identity_ref == canonical_bytes(operation['effectiveActorRef'])
                and actor.transport_ref == canonical_bytes(claims['authenticatedTransportRef'])]
            if len(matches) != 1 or matches[0].caller != 'federation':
                _refuse()
            check_actor(resource, matches[0])
            grant = _permission(resource, index, matches[0], operation, retained['contractId'], now)
            identity = index['identities'].get(_key(operation['effectiveActorRef']))
            issuer = index['issuers'].get(_key(claims['signingKeyRef']))
            transport = index['transports'].get(_key(claims['authenticatedTransportRef']))
            issuer_identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
            if (grant['ref'] != operation['grantRef'] or identity is None or not _active(identity, now)
                    or issuer is None or not _active(issuer, now)
                    or issuer_identity is None or issuer_identity['kind'] != 'service' or not _active(issuer_identity, now)
                    or issuer['instanceId'] != claims['sourceInstanceId']
                    or claims['sourceHubId'] != resource.binding.hub_id
                    or transport is None or not _active(transport, now)
                    or transport['issuerRef'] != issuer['ref'] or transport['identityRef'] != identity['ref']
                    or transport['method'] != claims['authenticationMethod']
                    or not any(_active(item, now) and item['identityRef'] == identity['ref']
                        and item['scope'] == operation['scope'] for item in index['memberships'].values())):
                _refuse()
            ends.extend(datetime.fromisoformat(item['expiresAt']) for item in (grant, issuer, transport))
            results.add(canonical_bytes(record['result']))
        if len(results) != 1:
            raise ContractError('capability_outcome_conflict')
        return min(ends)

    def _ready_original(self, resource, registration, query):
        """Only an exact ready transition for this registration can be paired."""
        original = registration['envelope']
        ready = resource._journal.outcome(query['operationId'], query['payloadDigest'])
        if (original['contractId'] != 'federation-work-register'
                or registration['reply']['outcome'] != 'applied'
                or ready is None or ready['reply']['outcome'] != 'applied'
                or ready['envelope']['contractId'] != 'federation-work-state'):
            _refuse()
        retained = ready['envelope']
        value, state = original['payload']['input'], retained['payload']['input']
        generation = 1 if value['generation'] is None else value['generation'] + 1
        def repositories(descriptor):
            return [(entry['repository'], entry['resourceRef']['id'], entry['resourceRef']['ownerHubId'])
                for entry in descriptor['repositories']]
        if (state['state'] != 'ready' or state['note'] is not None
                or state['session'] != _session(original) or registration['result'] != state['session']
                or state['generation'] != generation or state['localNode'] != value['localNode']
                or repositories(state) != repositories(value)
                or original['operation']['operationId'] == retained['operation']['operationId']):
            _refuse()
        if state['purpose'] == 'hub-observation':
            observation = state['observation']
            row = self._store.agent(state['session'])
            # The exact True result retains the original state comparison. After
            # readiness, its physical target must still be this registration's.
            if (ready['result'] is not True or row is None
                    or observation['handle'] != value['handle'] or observation['panePid'] != value['panePid']
                    or any(row[field] != observation[key] for field, key in
                        (('handle', 'handle'), ('pane_pid', 'panePid'), ('created', 'created')))):
                _refuse()
        elif state['purpose'] != 'hub-state' or 'observation' in state or ready['result'] is not None:
            _refuse()
        if any(original['operation'][field] != retained['operation'][field] for field in
                ('effectiveActorRef', 'caller', 'scope', 'delegationRef')):
            _refuse()
        claims, other = original['ingressAttestation']['claims'], retained['ingressAttestation']['claims']
        if any(claims[field] != other[field] for field in
                ('authenticatedTransportRef', 'sourceHubId', 'sourceInstanceId', 'signingKeyRef')):
            _refuse()
        self._descriptor(resource, retained)
        # Every pair is checked, including repositories other than the request's.
        for entry, ready_entry in zip(value['repositories'], state['repositories']):
            selected = self._resources[entry['resourceRef']['id']]
            payload = {**original['payload'], 'resourceRef': entry['resourceRef']}
            ready_payload = {**retained['payload'], 'resourceRef': ready_entry['resourceRef']}
            left = selected._journal.outcome(original['operation']['operationId'], payload_digest(payload))
            right = selected._journal.outcome(retained['operation']['operationId'], payload_digest(ready_payload))
            if left is None or right is None:
                _refuse()
            left_operation, right_operation = left['envelope']['operation'], right['envelope']['operation']
            if (canonical_bytes(left_operation['scope']) != selected.binding.scope
                    or any(left_operation[field] != right_operation[field] for field in
                        ('effectiveActorRef', 'caller', 'scope', 'delegationRef'))
                    or any(left['envelope']['ingressAttestation']['claims'][field] !=
                        right['envelope']['ingressAttestation']['claims'][field] for field in
                        ('authenticatedTransportRef', 'sourceHubId', 'sourceInstanceId', 'signingKeyRef'))):
                _refuse()
        return ready

    async def _owned_db(self, function):
        original = asyncio.create_task(self._db(function))
        self._workers.add(original)
        try:
            return await asyncio.shield(original)
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
            if original.done():
                self._workers.discard(original)

    async def apply(self, resource, authority, raw, *, source_expectation=None):
        from .work_legacy import authorize
        self._current()
        if authority is not self._authority or type(raw) is not bytes or len(raw) > 1048576:
            _refuse()
        original = strict_loads(raw)
        descriptor = self._descriptor(resource, original)
        source_raw = None if source_expectation is None else canonical_bytes(source_expectation)
        admitted = await authorize(resource, authority, raw, source_expectation=source_expectation)
        if admitted.actor.caller != 'federation':
            _refuse()
        value = original['payload']['input']
        key = value['batchId']
        batch = self._batches.get(key)
        if batch is None:
            if len(self._batches) >= 32:
                raise ContractError('capability_service_unavailable')
            batch = {'descriptor': descriptor, 'requests': {}, 'sources': {}, 'futures': {}, 'task': None,
                'identity': admitted.actor.identity_ref, 'deadline': admitted.valid_until}
            self._batches[key] = batch
        if batch['descriptor'] != descriptor or batch['identity'] != admitted.actor.identity_ref:
            _refuse()
        entry = batch['requests'].get(resource.binding.entity_id)
        if entry is not None and (entry != (resource, raw)
                or batch['sources'][resource.binding.entity_id] != source_raw):
            _refuse()
        if entry is None and sum(len(item[1]) for item in batch['requests'].values()) + len(raw) > 1048576:
            raise ContractError('capability_service_unavailable')
        batch['requests'][resource.binding.entity_id] = (resource, raw)
        batch['sources'][resource.binding.entity_id] = source_raw
        batch['deadline'] = min(batch['deadline'], admitted.valid_until)
        future = batch['futures'].get(resource.binding.entity_id)
        if future is None:
            future = asyncio.get_running_loop().create_future()
            batch['futures'][resource.binding.entity_id] = future
        if len(batch['requests']) == len(value['repositories']) and batch['task'] is None:
            batch['task'] = asyncio.create_task(self._run(key, batch))
            self._workers.add(batch['task'])
            batch['task'].add_done_callback(self._workers.discard)
        remaining = (batch['deadline'] - datetime.now(timezone.utc)).total_seconds()
        try:
            async with asyncio.timeout(max(0, remaining)):
                return await asyncio.shield(future)
        except (TimeoutError, asyncio.CancelledError):
            if batch['task'] is None:
                if self._batches.get(key) is batch:
                    self._batches.pop(key)
                for pending in batch['futures'].values():
                    if not pending.done():
                        pending.cancel()
            else:
                while not batch['task'].done():
                    try:
                        await asyncio.wait({batch['task']})
                    except asyncio.CancelledError:
                        continue
            raise
        finally:
            # An incomplete collection has no effect. A started batch remains
            # owned until the one original transaction and every waiter join.
            if batch['task'] is None and datetime.now(timezone.utc) >= batch['deadline']:
                if self._batches.get(key) is batch:
                    self._batches.pop(key)
                for pending in batch['futures'].values():
                    if not pending.done():
                        pending.cancel()

    async def _run(self, key, batch):
        from .work_legacy import authorize
        try:
            requests = [batch['requests'][entry['resourceRef']['id']]
                for entry in strict_loads(batch['descriptor'])['input']['repositories']]
            async with AsyncExitStack() as locks:
                for resource, _ in sorted(requests, key=lambda item: item[0].binding.entity_id):
                    await locks.enter_async_context(resource._lock)
                checked = [(resource, raw, await authorize(resource, self._authority, raw,
                    source_expectation=(None if batch['sources'][resource.binding.entity_id] is None
                        else strict_loads(batch['sources'][resource.binding.entity_id]))))
                    for resource, raw in requests]
                self._current()
                deadline = min(batch['deadline'], *(admission.valid_until for _, _, admission in checked))
                result = await self._owned_db(lambda: self._commit(checked, deadline))
            for resource, _ in requests:
                future = batch['futures'][resource.binding.entity_id]
                if not future.done():
                    future.set_result(result[resource.binding.entity_id])
        except BaseException as error:
            for future in batch['futures'].values():
                if not future.done():
                    future.set_exception(error if isinstance(error, Exception) else
                        ContractError('capability_service_unavailable'))
                    future.exception()
        finally:
            self._batches.pop(key, None)

    def _coverage(self, original, cutoff):
        value, contract = original['payload']['input'], original['contractId']
        if contract == 'federation-work-sweep-global':
            rows = self._store.q("SELECT repo FROM work_items WHERE state='claimed' "
                "AND lease_until < ? UNION SELECT repo FROM claims WHERE lease_until < ?", (cutoff, cutoff))
            required = {row['repo'] for row in rows}
        else:
            session = _session(original)
            rows = []
            if contract == 'federation-work-register' or value['state'] == 'dead':
                rows = self._store.q("SELECT repo FROM work_items WHERE claimed_by=? AND state='claimed' "
                    "UNION SELECT repo FROM claims WHERE holder=?", (session, session))
            required = {row['repo'] for row in rows}
            current = self._store.q1('SELECT repo FROM agents WHERE session=?', (session,))
            if current is not None:
                required.add(current['repo'])
            if contract == 'federation-work-register':
                required.add(value['repo'])
        selected = {entry['repository'] for entry in value['repositories']}
        if not required <= selected or any(self._store.q1('SELECT 1 FROM repos WHERE repo=?', (repo,)) is None
                for repo in selected):
            _refuse()

    def _effect(self, original, cutoff):
        value, contract = original['payload']['input'], original['contractId']
        if contract == 'federation-work-register':
            session = self._store.register(value['repo'], value['role'], value['agent'], value['cli'],
                value['roleSnapshot'], transport=value['transport'], handle=value['handle'],
                pane_pid=value['panePid'], legacy=value['legacy'], token_sha=value['tokenSha'])
            if value['legacy'] is not None:
                # Publish the adopted terminal in the same owned transaction.
                # Liveness can observe this row before Hub.adopt receives its reply.
                self._store.db.execute('UPDATE agents SET term_name=? WHERE session=?',
                    (value['legacy'], session))
            return session
        if contract == 'federation-work-sweep-global':
            return self._store.sweep_leases(_cutoff=cutoff)
        observation = value.get('observation')
        if observation is not None:
            row = self._store.agent(value['session'])
            if any(row[field] != observation[key] for field, key in
                    (('handle', 'handle'), ('pane_pid', 'panePid'), ('created', 'created'), ('state', 'state'))):
                return False
        self._store.set_state(value['session'], value['state'], value['note'])
        return True if observation is not None else None

    def _commit(self, checked, deadline):
        from .work_legacy import check_actor, check_source_admission, _permission
        self._current()
        originals = [(resource, strict_loads(raw), admission) for resource, raw, admission in checked]
        snapshot = checked[-1][2].snapshot
        index = _indexes(strict_loads(snapshot.record)['state'], self._profile[0])
        with self._store.tx():
            previous = []
            for resource, original, admission in originals:
                check_actor(resource, admission.actor)
                source_deadline = check_source_admission(resource, admission, snapshot=snapshot)
                if source_deadline is not None:
                    deadline = min(deadline, source_deadline)
                now = datetime.now(timezone.utc)
                decision = evaluate_snapshot(snapshot, canonical_bytes(original),
                    audience={'hubId': resource.binding.hub_id, 'serviceId': 'storage-owner'}, now=now)
                if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(original['operation'])
                        or _permission(resource, index, admission.actor, original['operation'],
                            original['contractId'], now)['ref'] != original['operation']['grantRef']):
                    _refuse()
                deadline = min(deadline, decision.valid_until)
                resource._journal._deadline(deadline)
                check_target(resource, original)
                operation = original['operation']
                previous.append(resource._journal.outcome(operation['operationId'], operation['payloadDigest']))
            if any(record is not None for record in previous):
                if (not all(record is not None for record in previous)
                        or any(record['envelope']['operation'] != original['operation']
                            for record, (_, original, _) in zip(previous, originals))
                        or len({canonical_bytes(record['result']) for record in previous}) != 1):
                    raise ContractError('capability_outcome_conflict')
                return {resource.binding.entity_id: {**record['reply'], 'result': record['result']}
                    for record, (resource, _, _) in zip(previous, originals)}
            for resource, original, _ in originals:
                if resource._journal.current()['revision'] != original['payload']['resourceRef']['revision']:
                    raise ContractError('capability_outcome_conflict')
            cutoff = self._store.q1("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now') cutoff")['cutoff']
            self._coverage(originals[0][1], cutoff)
            result = self._effect(originals[0][1], cutoff)
            replies = {}
            for resource, original, _ in originals:
                stored = resource._journal.commit(original, original['payload']['resourceRef']['revision'],
                    deadline, lambda: (result, {'kind': 'result', 'value': result}))
                replies[resource.binding.entity_id] = {**stored['reply'], 'result': stored['result']}
            self._current()
            for resource, _, _ in originals:
                resource._journal._deadline(deadline)
            return replies

    async def close(self):
        self._closed = True
        for batch in self._batches.values():
            if batch['task'] is None:
                for future in batch['futures'].values():
                    if not future.done():
                        future.cancel()
        while self._workers:
            original = tuple(self._workers)
            try:
                await asyncio.wait(original)
            except asyncio.CancelledError:
                continue
        for resource in self._resources.values():
            if getattr(resource, '_lifecycle_owner', None) is self:
                resource._lifecycle_owner = None
