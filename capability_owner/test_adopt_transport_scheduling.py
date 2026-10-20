"""A background read must not split initial registration from its outcome."""
import asyncio
from contextvars import Context
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from hub import server
from .test_work_source import SelectedWorkSourceFixture
from . import test_hub_work_maintenance as maintenance_fixture
from . import test_hub_lifecycle_disclosure as disclosure_fixture


class AdoptTransportSchedulingTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    request = maintenance_fixture.HubWorkMaintenanceTests.request

    def configure_channels(self, **kwargs):
        maintenance_fixture.HubWorkMaintenanceTests.configure_channels(self, include_second=False, **kwargs)

    async def asyncSetUp(self):
        await maintenance_fixture.HubWorkMaintenanceTests.asyncSetUp(self)
        self.original_work = await self.hub.db(lambda: self.hub.store.work(repo='falcon'))

    async def test_initial_outcome_precedes_new_same_session_background_read(self):
        commands = self.hub._work_storage_commands
        exchange, call, read = commands._exchange_command, commands._call, commands._read
        read_queued, outcome_requested = asyncio.Event(), asyncio.Event()
        tasks, order, registrations, outcomes = [], [], [], []
        read_task = None
        registration_session = None
        original_expiry = None

        async def observe_read(routes, query, expires, **kwargs):
            if asyncio.current_task() is read_task:
                self.assertEqual(len(routes), 1)
                self.assertIs(routes[0][0], registration_session)
                read_queued.set()
            return await read(routes, query, expires, **kwargs)

        async def observe_call(session, contract, operation, payload, expires, **kwargs):
            if contract == 'federation-work-outcome' and not outcomes:
                self.assertIs(session, registration_session)
                self.assertLessEqual(expires, original_expiry)
                outcomes.append((operation, payload))
                outcome_requested.set()
            return await call(session, contract, operation, payload, expires, **kwargs)

        async def observe_exchange(session, contract, operation, payload, expires, **kwargs):
            nonlocal read_task, registration_session, original_expiry
            if contract == 'federation-work-read' and asyncio.current_task() is read_task:
                self.assertIs(session, registration_session)
                order.append('background-read')
                # This releases only when the real original outcome attempts
                # its call; the read still executes its original exchange.
                await asyncio.wait_for(outcome_requested.wait(), 3)
            elif (contract == 'federation-work-outcome' and registrations
                    and payload['input']['operationId'] == registrations[0][0]
                    and 'original-outcome' not in order):
                order.append('original-outcome')
            result = await exchange(session, contract, operation, payload, expires, **kwargs)
            if contract == 'federation-work-register':
                self.assertIsNone(read_task)
                self.assertTrue(commands._locks[id(session)].locked())
                registrations.append((operation, payload))
                registration_session, original_expiry = session, expires
                read_task = asyncio.create_task(
                    self.hub._local_work_commands.list('federation'), context=Context())
                tasks.append(read_task)
                # Observe read entry before its scheduling guard so the test
                # does not require that queued work enter the transport.
                await asyncio.wait_for(read_queued.wait(), 3)
            return result

        arguments = {'legacy': 'transport-pane', 'repo': 'falcon', 'role': 'worker',
            'agent': 'transport', 'cli': 'shell'}
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.hub.tp, 'handle', return_value=('%91', 23901)), \
                patch.object(commands, '_read', side_effect=observe_read), \
                patch.object(commands, '_call', side_effect=observe_call), \
                patch.object(commands, '_exchange_command', side_effect=observe_exchange):
            try:
                foreground = asyncio.create_task(self.request('adopt', arguments, 'transport-original'))
                tasks.append(foreground)
                result = await asyncio.wait_for(asyncio.shield(foreground), 8)
                await asyncio.wait_for(asyncio.shield(read_task), 5)
                self.assertEqual(len(registrations), 1)
                self.assertEqual(outcomes[0][1]['input']['operationId'], registrations[0][0])
                row = await self.hub.db(self.hub.store.agent, result['session'])
                self.assertEqual((row['generation'], row['state']), (1, 'ready'))
                events = await self.hub.db(self.hub.store.q,
                    "SELECT event FROM events WHERE entity_id=? AND event='registered'", (result['session'],))
                self.assertEqual(events, [{'event': 'registered'}])
                self.assertEqual(order[:2], ['original-outcome', 'background-read'],
                    'same-session read entered before the final original outcome')
                mutations = [r for r in self.submitted if r['contractId'] in
                    ('federation-work-register', 'federation-work-state')]
                self.assertEqual(await self.request('adopt', arguments, 'transport-original'), result)
                self.assertEqual([r for r in self.submitted if r['contractId'] in
                    ('federation-work-register', 'federation-work-state')], mutations)
                self.assertEqual(await self.hub.db(self.hub.store.agent, result['session']), row)
            finally:
                outcome_requested.set()
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 10)

    async def queued_read(self, mode):
        commands = self.hub._work_storage_commands
        read = commands._read
        entered = asyncio.Event()
        original_expiries = []
        held_path = None
        original_snapshot = self.snapshot
        original_read_count = len([r for r in self.submitted if r['contractId'] == 'federation-work-read'])
        task = None

        async def observe_read(routes, query, expires, **kwargs):
            original_expiries.append(expires)
            entered.set()
            return await read(routes, query, expires, **kwargs)

        with patch.object(commands, '_read', side_effect=observe_read):
            try:
                async with self.maintenance._serialized():
                    task = asyncio.create_task(self.hub._local_work_commands.list('federation'), context=Context())
                    await asyncio.wait_for(entered.wait(), 3)
                    self.assertFalse(task.done())
                    if mode == 'expiry':
                        expired = asyncio.Event()
                        remaining = (original_expiries[0] - datetime.now(timezone.utc)).total_seconds()
                        timer = asyncio.get_running_loop().call_later(max(0, remaining) + .02, expired.set)
                        try:
                            await asyncio.wait_for(expired.wait(), 6)
                        finally:
                            timer.cancel()
                    elif mode == 'source':
                        held_path = self.database.with_name('original-held.db')
                        self.database.rename(held_path)
                    elif mode == 'authority':
                        disclosure_fixture.HubLifecycleDisclosureTests.revoke(self, 'read')
                    elif mode == 'cancel':
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                        self.assertTrue(self.maintenance._lock.locked())
                        self.assertNotIn(task, commands._active)
                if mode == 'cancel':
                    self.assertEqual(await self.hub._local_work_commands.list('federation'), self.original_work)
                elif mode == 'expiry':
                    with self.assertRaisesRegex(ContractError, '^legacy_work_client_expired$'):
                        await asyncio.wait_for(asyncio.shield(task), 5)
                    self.assertEqual(len([r for r in self.submitted
                        if r['contractId'] == 'federation-work-read']), original_read_count)
                else:
                    with self.assertRaises((ContractError, server.HubError)):
                        await asyncio.wait_for(asyncio.shield(task), 5)
                self.assertFalse(self.maintenance._lock.locked())
                self.assertIsNone(self.maintenance._turn_owner)
            finally:
                if task is not None and not task.done():
                    task.cancel()
                if task is not None:
                    await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 8)
                if held_path is not None:
                    held_path.rename(self.database)
                self.snapshot = original_snapshot

    async def test_queued_read_preserves_original_expiry(self):
        await self.queued_read('expiry')

    async def test_queued_read_rechecks_source(self):
        await self.queued_read('source')

    async def test_queued_read_rechecks_authority(self):
        await self.queued_read('authority')

    async def test_cancelled_queued_read_leaves_holder_owned_and_later_read_progresses(self):
        await self.queued_read('cancel')

    async def test_same_adoption_task_can_read_federation_list_without_deadlock(self):
        register = self.maintenance.register
        nested = []

        async def register_original(*args, **kwargs):
            result = await register(*args, **kwargs)
            self.assertIs(self.maintenance._turn_owner, asyncio.current_task())
            nested.append(await self.hub._local_work_commands.list('federation'))
            return result

        arguments = {'legacy': 'nested-pane', 'repo': 'falcon', 'role': 'worker',
            'agent': 'nested', 'cli': 'shell'}
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.hub.tp, 'handle', return_value=('%92', 23902)), \
                patch.object(self.maintenance, 'register', side_effect=register_original):
            task = asyncio.create_task(self.request('adopt', arguments, 'nested-original'))
            try:
                result = await asyncio.wait_for(asyncio.shield(task), 8)
                self.assertEqual(nested, [self.original_work])
                self.assertEqual(result['session'], 'falcon-worker-nested')
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 10)

    async def test_same_adoption_task_can_read_actual_readiness_projection(self):
        register = self.maintenance.register
        nested = []

        async def register_original(*args, **kwargs):
            result = await register(*args, **kwargs)
            self.assertIs(self.maintenance._turn_owner, asyncio.current_task())
            nested.append(await self.hub._local_work_commands.readiness(
                'federation', target=result[0], repository='falcon'))
            return result

        arguments = {'legacy': 'readiness-pane', 'repo': 'falcon', 'role': 'worker',
            'agent': 'readiness', 'cli': 'shell'}
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.hub.tp, 'handle', return_value=('%93', 23903)), \
                patch.object(self.maintenance, 'register', side_effect=register_original):
            task = asyncio.create_task(self.request('adopt', arguments, 'readiness-original'))
            try:
                await asyncio.wait_for(asyncio.shield(task), 8)
                self.assertEqual(len(nested), 1)
                self.assertEqual(nested[0]['claimable'], [
                    {key: row[key] for key in ('id', 'priority', 'target', 'title')}
                    for row in self.original_work])
                self.assertEqual(nested[0]['active'], [])
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 10)
