"""Initial selected declarations remain inactive without their original spawn."""
import asyncio
import base64
import copy
import hashlib
import unittest

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.test_authority import ref
from .first_worker import check_active, source_inspection
from .test_selected_work import SelectedWorkCompositionTests
from .work_legacy import check_actor
from .legacy_work_client import LegacyWorkCommandClient
from .test_hub_work_maintenance import HubWorkMaintenanceTests
from identity.authority import AuthoritySnapshot
from nacl.signing import SigningKey
from datetime import datetime, timedelta, timezone


class FirstWorkerTests(SelectedWorkCompositionTests):
    def setUp(self):
        super().setUp()
        self.declared = {'caller': 'falcon-worker-first', 'generation': 1,
            'spawnOperationId': 'first-spawn'}
        channel = self.value['storage']['work']['channels'][0]
        channel['firstWorker'] = self.declared
        channel['legacyActors'] = [{'caller': self.declared['caller'], 'identityRef': ref('human'),
            'transportRef': ref('first-worker-transport'),
            'grants': {'federation-work-' + action: ref('first-worker-' + action)
                for action in ('read', 'inspect', 'outcome', 'claim', 'heartbeat', 'release')}}]

    async def declared_resource(self):
        await self.replace_host()
        await self.host._work(self.selection.policy['storage']['work'])
        return self.work_resource()

    async def test_declared_construction_keeps_exact_generation_and_missing_worker_inactive(self):
        resource = await self.declared_resource()
        self.assertEqual(resource._legacy_actor_generations, {self.declared['caller']: 1})
        state = await resource._owner.db(resource._journal.current)
        self.assertEqual(state['binding']['firstWorker'], self.declared)
        self.assertIsNone(await resource._owner.db(resource._store.agent, self.declared['caller']))
        with self.assertRaisesRegex(ContractError, 'first_worker_inactive'):
            await resource._owner.db(check_actor, resource, resource._legacy_actors[0])

    async def test_pending_exception_is_only_source_inspection_for_declared_actor(self):
        resource = await self.declared_resource()
        actor = resource._legacy_actors[0]
        original = {'contractId': 'federation-work-inspect', 'payload': {'input': {'sourceBinding': {}}}}
        self.assertTrue(source_inspection(resource, actor, original))
        for contract, value in (('federation-work-read', {'sourceBinding': {}}),
                ('federation-work-inspect', {}), ('federation-work-outcome', {'sourceBinding': {}})):
            self.assertFalse(source_inspection(resource, actor,
                {'contractId': contract, 'payload': {'input': value}}))
        # The production caller validates the envelope/source schema before this predicate.
        await resource._owner.db(check_actor, resource, actor, original=original)
        self.assertEqual(await resource._owner.db(resource._store.q, 'SELECT * FROM agents'), [])

    async def test_reopening_pending_owner_preserves_declaration_and_generation(self):
        resource = await self.declared_resource()
        before = await resource._owner.db(resource._journal.current)
        reopened = await self.declared_resource()
        self.assertIsNot(resource, reopened)
        self.assertEqual(await reopened._owner.db(reopened._journal.current), before)
        self.assertEqual(reopened._legacy_actor_generations, {self.declared['caller']: 1})
        with self.assertRaises(ContractError):
            await reopened._owner.db(check_active, reopened, self.declared['caller'])

    async def test_selection_refuses_later_generation_foreign_worker_and_multiple_declarations(self):
        initial = copy.deepcopy(self.value)
        for changes in ({'generation': 2}, {'caller': 'other-worker-first'}, {'caller': 'operator'}):
            self.value = copy.deepcopy(initial)
            self.value['storage']['work']['channels'][0]['firstWorker'].update(changes)
            with self.assertRaises(ContractError):
                self.selected()
        self.value = copy.deepcopy(initial)
        second = copy.deepcopy(self.value['storage']['work']['channels'][0])
        second['resourceRef'] = ref('work-second')
        self.value['storage']['work']['channels'].append(second)
        with self.assertRaises(ContractError):
            self.selected()


class FirstWorkerSpawnTests(HubWorkMaintenanceTests):
    def sessions_for(self, resources):
        service_sessions = super().sessions_for(resources)
        resource = next(r for r in resources if r.repository == 'falcon')
        actor = next(a for a in resource._legacy_actors if a.caller == self.declared['caller'])
        self.worker_session = self.session_for(resource, actor=actor, seed=bytes([52]) * 32)
        return (*service_sessions, self.worker_session)

    def configure_channels(self, **kwargs):
        super().configure_channels(**kwargs)
        channel = self.value['storage']['work']['channels'][0]
        self.declared = {'caller': 'falcon-worker-spawned', 'generation': 1,
            'spawnOperationId': 'original-spawn'}
        channel['firstWorker'] = self.declared
        grants = {'federation-work-' + action: ref('first-worker-' + action)
            for action in ('read', 'inspect', 'outcome', 'claim', 'heartbeat', 'release')}
        channel['legacyActors'].append({'identityRef': ref('human'), 'transportRef': ref('first-transport'),
            'caller': self.declared['caller'], 'grants': grants})
        record = strict_loads(self.snapshot.record)
        transport = copy.deepcopy(next(t for t in record['state']['transports']
            if t['ref'] == ref('maintenance-transport')))
        transport.update(ref=ref('first-transport'), identityRef=ref('human'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(bytes([52]) * 32).verify_key)).decode().rstrip('='))
        record['state']['transports'].append(transport)
        for contract, grant in grants.items():
            record['state']['grants'].append({'ref': grant, 'callerRef': ref('human'),
                'actorRef': ref('human'), 'scope': copy.deepcopy(self.scope), 'contractId': contract,
                'resourceId': channel['resourceRef']['id'], 'decision': 'allowed', 'delegationRef': None,
                'definitionTarget': None, 'status': 'active', 'issuedAt': self.issuer_start,
                'expiresAt': self.issuer_end})
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence)
        self.selection = self.selected()

    async def test_pending_source_inspection_refuses_changed_original_source(self):
        resource = next(r for r in self.resources if r.repository == 'falcon')
        await resource._owner.db(resource._store.db.execute,
            'CREATE TABLE changed_pending_source (id TEXT)')
        with self.assertRaises(ContractError):
            await self.hub._work_storage_commands._call(self.worker_session,
                'federation-work-inspect', 'pending-changed-source',
                {'resourceRef': ref(resource.binding.entity_id), 'input': {
                    'sourceBinding': self.hub._work_source_binding.request('c' * 64)}},
                datetime.now(timezone.utc) + timedelta(seconds=4), _source_binding=True)

    async def test_pending_source_then_original_spawn_and_replacement(self):
        resource = next(r for r in self.resources if r.repository == 'falcon')
        with self.assertRaises(ContractError):
            await resource._owner.db(check_active, resource, self.declared['caller'])
        actor = next(a for a in resource._legacy_actors if a.caller == self.declared['caller'])
        session = self.worker_session
        commands = self.hub._work_storage_commands
        source = self.hub._work_source_binding
        expires = datetime.now(timezone.utc) + timedelta(seconds=4)
        response = await commands._call(session, 'federation-work-inspect', 'pending-source',
            {'resourceRef': ref(resource.binding.entity_id), 'input': {'sourceBinding': source.request('a' * 64)}},
            expires, _source_binding=True)
        self.assertEqual(set(response['result']), {'resourceRef', 'sourceBinding'})
        original_snapshot = self.snapshot
        revoked = strict_loads(original_snapshot.record)
        next(g for g in revoked['state']['grants']
            if g['ref'] == ref('first-worker-inspect'))['status'] = 'revoked'
        self.snapshot = AuthoritySnapshot(canonical_bytes(revoked), original_snapshot.sequence)
        try:
            with self.assertRaises(ContractError):
                await commands._call(session, 'federation-work-inspect', 'pending-revoked',
                    {'resourceRef': ref(resource.binding.entity_id),
                        'input': {'sourceBinding': source.request('b' * 64)}},
                    datetime.now(timezone.utc) + timedelta(seconds=4), _source_binding=True)
        finally:
            self.snapshot = original_snapshot
        for contract, value in (('federation-work-inspect', {}),
                ('federation-work-read', {'query': {'kind': 'list', 'state': None}})):
            with self.assertRaises(ContractError):
                await commands._call(session, contract, 'pending-refusal',
                    {'resourceRef': ref(resource.binding.entity_id), 'input': value},
                    datetime.now(timezone.utc) + timedelta(seconds=4), _source_binding=True)
        await self.test_actual_spawn_registers_through_owner_on_original_hub_source()
        await resource._owner.db(check_active, resource, self.declared['caller'])
        routes = commands._select(self.declared['caller'], 'read', 'falcon')
        value = await commands._read(routes, {'kind': 'readiness', 'session': self.declared['caller']},
            datetime.now(timezone.utc) + timedelta(seconds=4))
        self.assertIn('claimable', value)
        commands.finish_disclosure()
        before = await resource._owner.db(resource._journal.current)
        await resource._owner.db(check_active, resource, self.declared['caller'])
        self.assertEqual(await resource._owner.db(resource._journal.current), before)
        await resource._owner.db(self.assert_retained_activation_records, resource)
        from .local_work_client import LocalWorkClient
        client = LocalWorkClient(self.hub, commands)
        caller = self.declared['caller']
        row = await self.hub.db(self.hub.store.work_create, 'operator', 'falcon',
            'agent:' + caller, 'Declared worker assignment')
        claimed = await client.claim(caller, {'work_id': row['id']}, repository='falcon',
            intent_digest=payload_digest({'first-worker-claim': row['id']}))
        self.assertEqual(claimed['claimed']['id'], row['id'])
        await client.confirm_completion()
        client.finish_disclosure()
        renewed = await client.heartbeat(caller, {}, repository='falcon',
            intent_digest=payload_digest({'first-worker-heartbeat': row['id']}))
        self.assertEqual(renewed, {'renewed': 1})
        await client.confirm_completion()
        client.finish_disclosure()
        released = await client.release(caller, {'work_id': row['id'], 'outcome': 'done',
            'result': 'Fixture result'}, repository='falcon',
            intent_digest=payload_digest({'first-worker-release': row['id']}))
        self.assertEqual(released['id'], row['id'])
        await client.confirm_completion()
        client.finish_disclosure()
        # Controlled fixture replacement uses the existing registration owner.
        agent = await self.hub.db(self.hub.store.agent, self.declared['caller'])
        await self.hub._apply_observed_state(agent, 'dead')
        with self.assertRaises(ContractError):
            await resource._owner.db(check_active, resource, self.declared['caller'])
        await asyncio.create_task(self.maintenance.register('falcon', 'worker', 'spawned', 'codex', {},
            handle='%41', pane_pid=23456))
        with self.assertRaises(ContractError):
            await resource._owner.db(check_active, resource, self.declared['caller'])

    def assert_retained_activation_records(self, resource):
        """Corrupt only the fixture's original records, restoring each before continuing."""
        authority = resource._legacy_authority
        profile = {'hubId': authority._hub, 'profileId': authority._profile,
            'authorityId': authority._entity}
        prefix = 'hub-work-maintenance:' + hashlib.sha256(canonical_bytes(profile)).hexdigest() + ':'
        operation = self.declared['spawnOperationId']
        keys = {'request': prefix + 'request:' + hashlib.sha256(operation.encode()).hexdigest()}
        for phase in ('register', 'spawn-process', 'spawn-result'):
            keys[phase] = prefix + hashlib.sha256(canonical_bytes(
                {'operationId': operation, 'phase': phase})).hexdigest()
        for phase, key in keys.items():
            raw = resource._store.q1('SELECT v FROM fed_state WHERE k=?', (key,))['v']
            original = strict_loads(raw)
            variants = [None]
            if phase == 'request':
                variants += [{**original, 'operationId': 'another-spawn'},
                    {**original, 'requestDigest': 'f' * 64}]
            else:
                variants.append({**original, 'identity': {**original['identity'], 'requestDigest': 'f' * 64}})
                if phase == 'register':
                    variants.append({**original, 'completed': False})
                    for field, value in (('repo', 'other'), ('generation', 2)):
                        variants.append({**original, 'arguments': {**original['arguments'], field: value}})
                else:
                    variants.append({**original, 'state': 'uncertain'})
                    fields = (('returncode', 1),) if phase == 'spawn-process' else (
                        ('handle', '%42'), ('pane_pid', 99999), ('session', 'other-worker-spawned'))
                    for field, value in fields:
                        variants.append({**original, 'result': {**original['result'], field: value}})
            for variant in variants:
                with self.subTest(phase=phase, variant=variant):
                    try:
                        if variant is None:
                            resource._store.db.execute('DELETE FROM fed_state WHERE k=?', (key,))
                        else:
                            resource._store.db.execute('UPDATE fed_state SET v=? WHERE k=?',
                                (canonical_bytes(variant).decode(), key))
                        with self.assertRaises(ContractError):
                            check_active(resource, self.declared['caller'])
                    finally:
                        resource._store.db.execute('INSERT OR REPLACE INTO fed_state(k,v) VALUES (?,?)', (key, raw))
                    check_active(resource, self.declared['caller'])
