"""Actual signed service sessions drive one retained lifecycle batch."""
import asyncio
import copy
from datetime import timedelta
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.client_launch_session import ApplicationClientSession
from hub.store import HubError
from hub.tests.test_hub_offline import reg
from hub.tests.test_work_client_transport import material
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .legacy_work_client import LegacyWorkCommandClient
from .messages import MessageActor
from .test_work_bridge_owner import WorkBridgeFixture
from .work import WorkStorageResource
from .work_bridge_service import WorkBridgeService
from .work_legacy import LegacyWorkActor
from .work_lifecycle import WorkLifecycleOwner
from .work_lifecycle_client import WorkLifecycleClient


class WorkLifecycleClientTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.work_lifecycle', 'capability_owner.work_lifecycle_client',
                'capability_owner.legacy_work_client'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        record = strict_loads(self.js.messages[-1].data)
        self.other_scope = {**self.scope, 'projectId': 'project-other'}
        for membership in tuple(record['state']['memberships']):
            if membership['identityRef'] == ref('service'):
                record['state']['memberships'].append({**copy.deepcopy(membership),
                    'ref': ref('other-' + membership['ref']['id']), 'scope': self.other_scope})
        self.other_grants = {}
        for contract, reference in self.work_grants['service'].items():
            grant = copy.deepcopy(next(item for item in record['state']['grants'] if item['ref'] == reference))
            grant.update(ref=ref('other-' + reference['id']), resourceId='task-two', scope=self.other_scope)
            record['state']['grants'].append(grant)
            self.other_grants[contract] = grant['ref']
        self.js.messages[-1].data = canonical_bytes(record)
        actor = next(item for item in self.work_actors if item.caller == 'federation')
        other_actor = LegacyWorkActor(actor.identity_ref, actor.transport_ref, actor.caller, canonical_bytes(self.other_grants))
        self.other = WorkStorageResource(OwnerBinding('hub-one', 'federation-work', 'task-two', 'work-channel',
            canonical_bytes(self.other_scope)), self.local, repository='other',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-two', legacy_actors=(other_actor,),
            legacy_authority=self.service.reader)
        self.lifecycle = WorkLifecycleOwner((self.resource, self.other))
        self.addAsyncCleanup(self.lifecycle.close)
        self.other_endpoint = WorkBridgeService(self.service.ingress, resources=(self.other,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(self.other_endpoint.close, timeout=None)
        self.submitted, self.drop_before, self.drop_after = [], None, None
        self.sessions = (self.session_for(self.resource), self.session_for(self.other))
        self.commands = LegacyWorkCommandClient(self.hub, self.sessions)
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.client = WorkLifecycleClient(self.commands)
        self.addAsyncCleanup(self.client.close)
        self.expires = NOW + timedelta(seconds=4)

    def session_for(self, resource):
        selected = material()
        route = selected['workCommands']
        scope = strict_loads(resource.binding.scope)
        selected.update(scope=scope, callerRef=ref('service'))
        route.update(authenticatedCaller='federation', transportRef=ref('legacy-service-transport'),
            localPeer=None, localNode='mac', repository={'localName': resource.repository, 'repositoryId': None},
            resourceRef=ref(resource.binding.entity_id),
            grantRefs=self.work_grants['service'] if resource is self.resource else self.other_grants,
            subject='.'.join(('amx','v1','h','hub-one','o',scope['organizationId'],'p',scope['projectId'],
                'w',scope['workspaceId'] or '_','capability','storage-owner','command')))
        key = ApplicationClientKey(selected)
        session = object.__new__(ApplicationClientSession)
        session._stopped = session._terminal_enrolled = session._terminal_active = False
        session._closing = session._final_closing = None
        session._work_enrollment = canonical_bytes({
            **{name: key.selection[name] for name in ('hubId','profileId','authorityId','callerRef','scope')},
            'workCommands': key.selection['workCommands']})
        loop = asyncio.get_running_loop()
        def submit(*, contract_id, operation_id, payload, expires_at, deadline, include_valid_until=False):
            claims = {'purpose':'agentmux-client-possession-v1',
                **{name: key.selection[name] for name in ('hubId','profileId','authorityId')},
                'transportRef': route['transportRef'], 'grantRef': route['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': payload['resourceRef']['revision'],
                'contractId': contract_id, 'payload': payload, 'approvalRefs': [],
                'issuedAt': NOW.isoformat().replace('+00:00','Z'), 'expiresAt': expires_at,
                'replySubject':'_INBOX.work_lifecycle_actual_01'}
            self.submitted.append(copy.deepcopy(claims))
            raw = key.sign_command(claims, subject=route['subject'], now=NOW)
            if self.drop_before == contract_id:
                raise TimeoutError('controlled request loss')
            endpoint = self.endpoint if resource is self.resource else self.other_endpoint
            response = asyncio.run_coroutine_threadsafe(endpoint.handle(raw,
                received_reply_subject=claims['replySubject']), loop).result(timeout=6)
            if self.drop_after == contract_id:
                raise TimeoutError('controlled response loss')
            return key.verify_command_response(response, raw, subject=route['subject'], now=NOW,
                include_valid_until=include_valid_until)
        session.work_command = submit
        return session

    def arguments(self):
        session = reg(self.store, 'falcon', 'worker', 'one')
        return {'session':session,'generation':self.store.agent(session)['generation'],'state':'dead','note':'terminal gone'}

    def mutations(self):
        return [request for request in self.submitted if request['contractId'] == 'federation-work-state']

    async def restart(self):
        await self.client.close()
        await self.commands.close(timeout=None)
        self.commands = LegacyWorkCommandClient(self.hub, self.sessions)
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.client = WorkLifecycleClient(self.commands)
        self.addAsyncCleanup(self.client.close)

    async def test_descriptor_and_all_revisions_are_retained_before_first_submission(self):
        arguments = self.arguments()
        original = self.commands._call
        async def inspect_retention(session, contract, operation, payload, expires, **kwargs):
            if contract == 'federation-work-state':
                record = await self.commands._owned_db(self.client._load, operation, 'state', arguments)
                self.assertEqual(record['state'], 'uncertain')
                self.assertEqual(record['descriptor'], payload['input'])
                self.assertEqual(len(record['descriptor']['repositories']), 2)
            return await original(session, contract, operation, payload, expires, **kwargs)
        with patch.object(self.commands, '_call', inspect_retention):
            result = await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires)
        self.assertIsNone(result)
        mutations = self.mutations()
        self.assertEqual(len(mutations), 2)
        self.assertEqual(mutations[0]['payload']['input'], mutations[1]['payload']['input'])
        self.assertEqual({request['operationId'] for request in mutations}, {'batch-one'})
        self.assertEqual(self.client._active_ids(), [])
        self.assertEqual(self.store.agent(arguments['session'])['state'], 'dead')

    async def test_lost_reply_and_restart_query_original_without_second_effect(self):
        arguments = self.arguments()
        self.drop_after = 'federation-work-state'
        with self.assertRaises(TimeoutError):
            await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires)
        originals = copy.deepcopy(self.mutations())
        self.drop_after = None
        await self.restart()
        self.assertIsNone(await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires))
        self.assertEqual(self.mutations(), originals)
        self.assertEqual(self.client._active_ids(), [])
        self.assertEqual(self.store.agent(arguments['session'])['state'], 'dead')

    async def test_uncertain_absent_retains_original_without_resubmission(self):
        arguments = self.arguments()
        self.drop_before = 'federation-work-state'
        with self.assertRaises(TimeoutError):
            await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires)
        before = self.store.q1('SELECT v FROM fed_state WHERE k=?', (self.client._key('batch-one'),))['v']
        self.drop_before = None
        with self.assertRaisesRegex(HubError, 'original recovery is retained'):
            await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires)
        self.assertEqual(len(self.mutations()), 2)
        self.assertEqual(self.store.q1('SELECT v FROM fed_state WHERE k=?', (self.client._key('batch-one'),))['v'], before)
        self.assertEqual(self.store.agent(arguments['session'])['state'], 'ready')

    async def test_final_disclosure_checks_every_original_repository_grant(self):
        arguments = self.arguments()
        await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires)
        record = strict_loads(self.js.messages[-1].data)
        next(item for item in record['state']['grants']
            if item['ref'] == self.other_grants['federation-work-state'])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(record)
        with self.assertRaises(ContractError):
            await self.client.confirm_disclosure('batch-one', expires=self.expires)
        self.assertEqual(len(self.mutations()), 2)

    async def test_same_operation_cannot_change_arguments_or_rebuild_revisions(self):
        arguments = self.arguments()
        await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires)
        with self.assertRaises(ContractError):
            await self.client.set_state({**arguments,'state':'ready'}, operation_id='batch-one', expires=self.expires)
        self.assertEqual(len(self.mutations()), 2)
        await self.client.confirm_disclosure('batch-one', expires=self.expires, finish=True)
        self.assertEqual(len(self.mutations()), 2)

    async def test_cancelled_dispatch_joins_original_before_restart(self):
        arguments = self.arguments()
        entered, released = threading.Event(), threading.Event()
        original = self.store.set_state
        def held(*args):
            entered.set()
            if not released.wait(4):
                raise RuntimeError('controlled transaction not released')
            return original(*args)
        with patch.object(self.store, 'set_state', held):
            task = asyncio.create_task(self.client.set_state(arguments, operation_id='batch-one', expires=self.expires))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 4))
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                released.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            finally:
                released.set()
                await asyncio.gather(task, return_exceptions=True)
        await self.restart()
        await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires)
        self.assertEqual(len(self.mutations()), 2)
        self.assertEqual(self.commands._workers, set())

    async def test_initial_inspect_deadline_is_not_renewed_for_the_effect(self):
        arguments = self.arguments()
        record = strict_loads(self.js.messages[-1].data)
        end = NOW + timedelta(seconds=1)
        next(item for item in record['state']['grants']
            if item['ref'] == self.work_grants['service']['federation-work-inspect'])['expiresAt'] = end.isoformat().replace('+00:00','Z')
        self.js.messages[-1].data = canonical_bytes(record)
        await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires)
        self.assertEqual({request['expiresAt'] for request in self.mutations()},
            {end.isoformat(timespec='microseconds').replace('+00:00','Z')})
        self.assertEqual(self.commands._disclosures[asyncio.current_task()][1], end)

    async def test_changed_source_and_duplicate_live_driver_are_refused(self):
        with self.assertRaises(ContractError):
            WorkLifecycleClient(self.commands)
        arguments = self.arguments()
        original = self.hub.dbx
        self.hub.dbx = object()
        try:
            with self.assertRaises(ContractError):
                await self.client.set_state(arguments, operation_id='batch-one', expires=self.expires)
        finally:
            self.hub.dbx = original
        self.assertEqual(self.mutations(), [])

    async def capacity_resources(self):
        await self.client.close()
        await self.commands.close(timeout=None)
        await self.lifecycle.close()
        resources = [self.resource]
        for index in range(1, 64):
            repository = 'capacity_' + str(index)
            self.store.repo_add(repository)
            resources.append(WorkStorageResource(OwnerBinding('hub-one','federation-work',
                'capacity-' + str(index),'work-channel',canonical_bytes(self.scope)), self.local,
                repository=repository, actors=self.resource.actors, plugin_identity_ref=ref('plugin'),
                instance_id='capacity-' + str(index), legacy_actors=self.work_actors,
                legacy_authority=self.service.reader))
        self.lifecycle = WorkLifecycleOwner(tuple(resources))
        self.addAsyncCleanup(self.lifecycle.close)
        return resources

    async def test_owned_executor_starts_all_sixty_four_selected_calls_before_a_reply(self):
        resources = await self.capacity_resources()
        sessions = tuple(self.session_for(resource) for resource in resources)
        self.commands = LegacyWorkCommandClient(self.hub, sessions)
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.client = WorkLifecycleClient(self.commands)
        self.addAsyncCleanup(self.client.close)
        barrier, guard, started = threading.Barrier(64), threading.Lock(), set()
        def blocked_transport(**kwargs):
            with guard:
                started.add(threading.get_ident())
            barrier.wait(timeout=4)
            raise TimeoutError('controlled failure after every selected call started')
        for session in sessions:
            session.work_command = blocked_transport
        with self.assertRaises(TimeoutError):
            await self.client.sweep(operation_id='capacity-one', expires=self.expires)
        self.assertEqual(len(started), 64)
        self.assertEqual(self.commands._workers, set())
        self.assertEqual(self.client._active, set())

    async def test_same_endpoint_keeps_sixty_four_admissions_owned_until_cancelled(self):
        resources = await self.capacity_resources()
        endpoint = WorkBridgeService(self.service.ingress, resources=tuple(resources),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(endpoint.close, timeout=None)
        entered, release, count = asyncio.Event(), asyncio.Event(), 0
        async def pending_admission(raw, subject):
            nonlocal count
            count += 1
            if count == 64:
                entered.set()
            await release.wait()
            raise ContractError('controlled pending admission')
        with patch.object(endpoint, '_admit', pending_admission):
            tasks = [asyncio.create_task(endpoint.handle(b'', received_reply_subject='_INBOX.capacity_actual_01'))
                for _ in range(64)]
            try:
                await asyncio.wait_for(entered.wait(), 2)
                self.assertEqual(len(endpoint._active), 64)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        self.assertEqual(endpoint._active, set())
        self.assertEqual(endpoint._workers, set())
