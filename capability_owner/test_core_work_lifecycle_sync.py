"""Original signed lifecycle results join the selected role projection."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import unittest
import sys
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, payload_digest
from . import test_work_bridge_composition as composition
from . import test_core_work_owner as core_support
from . import test_selected_work as selected_support
from . import core_work
from .test_code_selection import SelectedCodeFixture
from .work_lifecycle_client import WorkLifecycleClient


class CoreWorkLifecycleSyncTests(composition.WorkBridgeCompositionTests):
    @staticmethod
    def arguments(agent):
        return {'generation': None, 'repo': 'falcon', 'role': 'worker', 'agent': agent,
            'cli': 'codex', 'roleSnapshot': {}, 'transport': 'tmux', 'handle': '%35',
            'panePid': 12359, 'legacy': None, 'tokenSha': '4' * 64}

    async def configured(self):
        hub = await self.protected_hub()
        await hub._work_source_binding.activate()
        owner, = self.host._core_work_owners
        resource = self.resources[0]
        endpoint = next(endpoint for endpoint in self.host._receivers
            if endpoint._service == 'storage-owner' and endpoint._scope == resource.binding.scope)
        client = WorkLifecycleClient(hub._work_storage_commands)
        self.addAsyncCleanup(client.close)
        return hub, owner, resource, endpoint._work_bridge, client

    @asynccontextmanager
    async def held_watcher(self, owner):
        original, sync = owner._roles_task, owner._roles.sync
        entered, release, completed = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def held():
            if asyncio.current_task() is not original:
                return await sync()
            entered.set()
            await release.wait()
            try:
                return await sync()
            finally:
                completed.set()
        with patch.object(owner._roles, 'sync', side_effect=held):
            try:
                await asyncio.wait_for(entered.wait(), 2)
                yield original
            finally:
                release.set()
                await asyncio.wait_for(completed.wait(), 2)

    def assert_subscription_custody(self, owner, resource):
        ingress = owner._ingresses[id(resource)]
        subscription = ingress._subscriptions['am.work.falcon.worker']
        self.assertIs(ingress._connection._subs[subscription._id], subscription)
        self.assertIs(ingress._session._resources[id(subscription)][1], subscription)
        self.assertIs(ingress._dispatch_tasks['am.work.falcon.worker'], subscription._wait_for_msgs_task)
        self.assertFalse(subscription._closed)
        self.assertFalse(subscription._wait_for_msgs_task.done())

    async def receipt(self, resource, operation):
        request = next(request for request in self.submitted
            if request['operationId'] == operation
            and request['payload']['resourceRef']['id'] == resource.binding.entity_id)
        receipt = await resource._owner.db(resource._journal.outcome,
            operation, payload_digest(request['payload']))
        self.assertEqual(receipt['reply']['outcome'], 'applied')
        return request, receipt

    async def assert_one_registration(self, resource, agent):
        row = await resource._owner.db(resource._store.agent, 'falcon-worker-' + agent)
        self.assertEqual(row['generation'], 1)
        self.assertEqual(await resource._owner.db(resource._store.q1,
            "SELECT count(*) n FROM events WHERE event='registered' AND entity_id=?",
            (row['session'],)), {'n': 1})

    async def test_direct_projection_owns_actual_subscription_before_original_result(self):
        hub, owner, resource, service, client = await self.configured()
        operation = 'role-sync-original-result'
        async with self.held_watcher(owner) as original:
            result = await client.register(self.arguments('direct'), operation_id=operation,
                expires=datetime.now(timezone.utc) + timedelta(seconds=4))
            self.assertEqual(result, 'falcon-worker-direct')
            self.assertIs(owner._roles_task, original)
            self.assertFalse(original.done())
            self.assert_subscription_custody(owner, resource)
            request, receipt = await self.receipt(resource, operation)
            self.assertEqual(receipt['result'], result)
            self.assertEqual(receipt['envelope']['operation']['operationId'], operation)
            self.assertEqual(receipt['envelope']['operation']['payloadDigest'], payload_digest(request['payload']))
            await self.assert_one_registration(resource, 'direct')
            self.assertFalse(service._workers)

    async def test_cancelled_original_reply_retains_projection_and_recovers_without_second_effect(self):
        hub, owner, resource, service, client = await self.configured()
        operation, arguments = 'role-sync-cancelled-result', self.arguments('cancelled')
        entered, release = asyncio.Event(), asyncio.Event()
        sync, original_projection = owner._roles._sync, []
        async def held():
            original_projection.append(asyncio.current_task())
            entered.set()
            await release.wait()
            return await sync()
        async with self.held_watcher(owner):
            with patch.object(owner._roles, '_sync', side_effect=held):
                caller = asyncio.create_task(client.register(arguments, operation_id=operation,
                    expires=datetime.now(timezone.utc) + timedelta(seconds=4)))
                try:
                    await asyncio.wait_for(entered.wait(), 2)
                    projection, = original_projection
                    self.assertIn(projection, service._workers)
                    request, original_receipt = await self.receipt(resource, operation)
                    original_reply, = service._active
                    original_reply.cancel()
                    await asyncio.gather(original_reply, return_exceptions=True)
                    with self.assertRaises(asyncio.CancelledError):
                        await caller
                    self.assertFalse(projection.done())
                    self.assertIn(projection, service._workers)
                finally:
                    release.set()
                    await asyncio.gather(*original_projection, return_exceptions=True)
                    await asyncio.gather(caller, return_exceptions=True)
            self.assert_subscription_custody(owner, resource)
            await client.close()
            recovered = WorkLifecycleClient(hub._work_storage_commands)
            self.addAsyncCleanup(recovered.close)
            before = len([request for request in self.submitted
                if request['contractId'] == 'federation-work-register'])
            result = await recovered.register(arguments, operation_id=operation,
                expires=datetime.now(timezone.utc) + timedelta(seconds=4))
            self.assertEqual(result, 'falcon-worker-cancelled')
            self.assertEqual(len([request for request in self.submitted
                if request['contractId'] == 'federation-work-register']), before)
            _, retained = await self.receipt(resource, operation)
            self.assertEqual(retained, original_receipt)
            await self.assert_one_registration(resource, 'cancelled')

    async def test_policy_pause_joins_original_projection_and_refuses_result(self):
        hub, owner, resource, service, client = await self.configured()
        operation = 'role-sync-paused-result'
        entered, release = asyncio.Event(), asyncio.Event()
        sync, projections = owner._roles._sync, []
        async def held():
            projections.append(asyncio.current_task())
            entered.set()
            await release.wait()
            return await sync()
        async with self.held_watcher(owner):
            with patch.object(owner._roles, '_sync', side_effect=held):
                caller = asyncio.create_task(client.register(self.arguments('paused'), operation_id=operation,
                    expires=datetime.now(timezone.utc) + timedelta(seconds=4)))
                pause = None
                try:
                    await asyncio.wait_for(entered.wait(), 2)
                    _, original = await self.receipt(resource, operation)
                    owner.begin_policy_pause()
                    pause = asyncio.create_task(owner.join_policy_pause())
                    await asyncio.sleep(0)
                    self.assertFalse(pause.done())
                    self.assertTrue(owner._roles._active)
                    release.set()
                    await pause
                    with self.assertRaises(ContractError):
                        await caller
                    self.assertFalse(owner._roles._active)
                    self.assertTrue(all(task.done() for task in projections))
                    _, retained = await self.receipt(resource, operation)
                    self.assertEqual(retained, original)
                    await self.assert_one_registration(resource, 'paused')
                finally:
                    release.set()
                    await asyncio.gather(caller, *projections, return_exceptions=True)
                    if pause is not None:
                        await asyncio.gather(pause, return_exceptions=True)
                    owner.end_policy_pause()

    async def test_service_close_joins_exact_direct_projection_before_releasing_source(self):
        hub, owner, resource, service, client = await self.configured()
        entered, release = asyncio.Event(), asyncio.Event()
        sync, projections = owner._roles._sync, []
        async def held():
            projections.append(asyncio.current_task())
            entered.set()
            await release.wait()
            return await sync()
        async with self.held_watcher(owner):
            with patch.object(owner._roles, '_sync', side_effect=held):
                caller = asyncio.create_task(client.register(self.arguments('closing'),
                    operation_id='role-sync-closing-result',
                    expires=datetime.now(timezone.utc) + timedelta(seconds=4)))
                cleanup = None
                try:
                    await asyncio.wait_for(entered.wait(), 2)
                    cleanup = asyncio.create_task(service.close(timeout=None))
                    await asyncio.sleep(0)
                    self.assertFalse(cleanup.done())
                    self.assertFalse(resource._source._closed)
                    self.assertFalse(resource._source_worker._shutdown)
                    projection, = projections
                    self.assertIn(projection, service._workers)
                    self.assertFalse(projection.done())
                    release.set()
                    await cleanup
                    self.assertTrue(projection.done())
                    self.assertFalse(service._workers)
                    self.assertFalse(resource._source._closed)
                    await self.assert_one_registration(resource, 'closing')
                finally:
                    release.set()
                    await asyncio.gather(caller, *projections, return_exceptions=True)
                    if cleanup is not None:
                        await asyncio.gather(cleanup, return_exceptions=True)

    async def test_local_only_registration_keeps_existing_mode_with_private_guard_diagnostic(self):
        guards, refuse = [], core_work.refused
        def observed():
            frame = sys._getframe(1)
            guards.append({'function': frame.f_code.co_name, 'line': frame.f_lineno})
            del frame
            return refuse()
        with patch.object(core_work, 'refused', new=observed):
            try:
                await super().test_actual_selected_mode_proves_transport_and_keeps_unshared_scope_local()
            except BaseException as error:
                error.add_note('Private local-only guard categories: ' + str(guards))
                raise


class CoreWorkProjectionOwnershipTests(SelectedCodeFixture, unittest.IsolatedAsyncioTestCase):
    setUp = selected_support.SelectedWorkCompositionTests.setUp
    start_host = selected_support.SelectedWorkCompositionTests.start_host
    core = core_support.CoreWorkOwnerTests.core

    async def test_queued_projection_reads_after_earlier_projection_installs(self):
        owner, resource, _, _ = await self.core()
        entered, release = asyncio.Event(), asyncio.Event()
        database, reads = owner._dispatcher._db, []
        async def held(*args):
            result = await database(*args)
            reads.append(result)
            if len(reads) == 1:
                entered.set()
                await release.wait()
            return result
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)), \
                patch.object(owner._dispatcher, '_db', side_effect=held), \
                patch.object(owner, 'set_work_subjects', AsyncMock()) as install:
            first = asyncio.create_task(owner._roles.sync())
            second = None
            try:
                await asyncio.wait_for(entered.wait(), 1)
                await resource._owner.db(resource._store.register,
                    'falcon', 'worker', 'queued', 'codex', {})
                second = asyncio.create_task(owner._roles.sync())
                await asyncio.sleep(0)
                self.assertEqual(len(owner._roles._active), 2)
                self.assertEqual(len(reads), 1)
                install.assert_not_awaited()
                release.set()
                await asyncio.gather(first, second)
                self.assertEqual([call.args[0] for call in install.await_args_list],
                    [set(), {'am.work.falcon.worker'}])
                self.assertFalse(owner._roles._active)
            finally:
                release.set()
                await asyncio.gather(first, *(() if second is None else (second,)), return_exceptions=True)

    async def test_policy_pause_joins_running_and_queued_projection(self):
        owner, resource, _, _ = await self.core()
        entered, release = asyncio.Event(), asyncio.Event()
        database = owner._dispatcher._db
        async def held(*args):
            result = await database(*args)
            entered.set()
            await release.wait()
            return result
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)), \
                patch.object(owner._dispatcher, '_db', side_effect=held), \
                patch.object(owner, 'set_work_subjects', AsyncMock()) as install:
            first = asyncio.create_task(owner._roles.sync())
            second = pause = None
            try:
                await asyncio.wait_for(entered.wait(), 1)
                second = asyncio.create_task(owner._roles.sync())
                await asyncio.sleep(0)
                self.assertEqual(len(owner._roles._active), 2)
                owner.begin_policy_pause()
                pause = asyncio.create_task(owner.join_policy_pause())
                await asyncio.sleep(0)
                self.assertFalse(pause.done())
                release.set()
                outcomes = await asyncio.gather(first, second, return_exceptions=True)
                self.assertTrue(all(isinstance(error, ContractError) for error in outcomes))
                await pause
                self.assertFalse(owner._roles._active)
                install.assert_not_awaited()
            finally:
                release.set()
                await asyncio.gather(first, *(() if second is None else (second,)), return_exceptions=True)
                if pause is not None:
                    await asyncio.gather(pause, return_exceptions=True)
                owner.end_policy_pause()

    async def test_core_close_joins_exact_projection_before_closing_ingress(self):
        owner, resource, ingress, _ = await self.core()
        entered, release = asyncio.Event(), asyncio.Event()
        database = owner._dispatcher._db
        async def held(*args):
            result = await database(*args)
            entered.set()
            await release.wait()
            return result
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.core_snapshot)), \
                patch.object(owner._dispatcher, '_db', side_effect=held):
            projection = asyncio.create_task(owner._roles.sync())
            cleanup = None
            try:
                await asyncio.wait_for(entered.wait(), 1)
                cleanup = asyncio.create_task(owner.close(timeout=None))
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                self.assertFalse(cleanup.done())
                self.assertFalse(projection.done())
                self.assertFalse(ingress._closed)
                self.assertFalse(resource._source._closed)
                release.set()
                with self.assertRaises(ContractError):
                    await projection
                await cleanup
                self.assertTrue(ingress._closed)
                self.assertFalse(owner._roles._active)
            finally:
                release.set()
                await asyncio.gather(projection, return_exceptions=True)
                if cleanup is not None:
                    await asyncio.gather(cleanup, return_exceptions=True)
