"""Adoption keeps its original turn while selected background work stays queued."""
import asyncio
from contextvars import Context
import unittest
from unittest.mock import patch

from hub import server
from .test_work_source import SelectedWorkSourceFixture
from . import test_hub_work_maintenance as maintenance_fixture


class AdoptSchedulingTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    request = maintenance_fixture.HubWorkMaintenanceTests.request

    def configure_channels(self, **kwargs):
        maintenance_fixture.HubWorkMaintenanceTests.configure_channels(self, include_second=False, **kwargs)

    async def asyncSetUp(self):
        await maintenance_fixture.HubWorkMaintenanceTests.asyncSetUp(self)
        self.enterContext(patch.object(self.hub, 'resolve_role', return_value={}))
        self.enterContext(patch.object(self.hub.tp, 'handle', return_value=('%81', 23801)))
        self.arguments = {'legacy': 'scheduled-pane', 'repo': 'falcon',
            'role': 'worker', 'agent': 'scheduled', 'cli': 'shell'}

    async def test_background_cannot_split_registration_from_ready_and_confirmation(self):
        first_entered, release_first = asyncio.Event(), asyncio.Event()
        admitted, second_queued = asyncio.Event(), asyncio.Event()
        confirmed = asyncio.Event()
        order, tasks = [], []
        execute = self.maintenance._client.execute
        admit = self.maintenance.admit
        register = self.maintenance.register
        confirm = self.maintenance.confirm_result
        first = second = None

        async def execute_original(*args, **kwargs):
            task = asyncio.current_task()
            if task is first:
                first_entered.set()
                await release_first.wait()
            elif task is second:
                order.append(('background', confirmed.is_set()))
            return await execute(*args, **kwargs)

        async def admit_original(*args, **kwargs):
            result = await admit(*args, **kwargs)
            admitted.set()
            return result

        async def background():
            second_queued.set()
            return await self.maintenance.sweep()

        async def register_original(*args, **kwargs):
            nonlocal second
            result = await register(*args, **kwargs)
            if second is None:
                second = asyncio.create_task(background(), context=Context())
                tasks.append(second)
                # The background coroutine runs into the actual maintenance lock
                # before this event wait resumes; no timing delay selects the order.
                await second_queued.wait()
            return result

        async def confirm_original(*args, **kwargs):
            result = await confirm(*args, **kwargs)
            confirmed.set()
            order.append(('confirmed', True))
            return result

        with patch.object(self.maintenance._client, 'execute', side_effect=execute_original), \
                patch.object(self.maintenance, 'admit', side_effect=admit_original), \
                patch.object(self.maintenance, 'register', side_effect=register_original), \
                patch.object(self.maintenance, 'confirm_result', side_effect=confirm_original):
            try:
                first = asyncio.create_task(self.maintenance.sweep(), context=Context())
                tasks.append(first)
                await asyncio.wait_for(first_entered.wait(), 3)
                foreground = asyncio.create_task(self.request('adopt', self.arguments, 'scheduled-original'))
                tasks.append(foreground)
                await asyncio.wait_for(admitted.wait(), 3)
                release_first.set()
                result = await asyncio.wait_for(asyncio.shield(foreground), 8)
                await asyncio.wait_for(asyncio.gather(first, second), 5)
                self.assertEqual(order, [('confirmed', True), ('background', True)],
                    'background maintenance entered between registration and confirmation')
                mutations = [r for r in self.submitted if r['contractId'] in
                    ('federation-work-register', 'federation-work-state')]
                self.assertEqual(await self.request('adopt', self.arguments, 'scheduled-original'), result)
                self.assertEqual([r for r in self.submitted if r['contractId'] in
                    ('federation-work-register', 'federation-work-state')], mutations)
                row = await self.hub.db(self.hub.store.agent, result['session'])
                self.assertEqual((row['generation'], row['state']), (1, 'ready'))
                events = await self.hub.db(self.hub.store.q,
                    "SELECT event FROM events WHERE entity_id=? AND event='registered'", (result['session'],))
                self.assertEqual(events, [{'event': 'registered'}])
            finally:
                release_first.set()
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 10)

    async def queued_adoption(self, action):
        entered, release, inherited = asyncio.Event(), asyncio.Event(), asyncio.Event()
        execute = self.maintenance._client.execute
        inherit = self.maintenance.inherit
        tasks, originals = [], []
        holder = None

        async def held_execute(*args, **kwargs):
            if asyncio.current_task() is holder:
                entered.set()
                await release.wait()
            return await execute(*args, **kwargs)

        def capture_original(task):
            inherit(task)
            originals.append(task)
            inherited.set()

        with patch.object(self.maintenance._client, 'execute', side_effect=held_execute), \
                patch.object(self.maintenance, 'inherit', side_effect=capture_original):
            try:
                holder = asyncio.create_task(self.maintenance.sweep(), context=Context())
                tasks.append(holder)
                await asyncio.wait_for(entered.wait(), 3)
                foreground = asyncio.create_task(self.request('adopt', self.arguments, 'queued-original'))
                tasks.append(foreground)
                await asyncio.wait_for(inherited.wait(), 3)
                original = originals[0]
                self.assertFalse(original.done())
                await action(foreground, original, release)
            finally:
                release.set()
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 10)
                self.assertTrue(all(task.done() for task in originals))
                self.assertIsNone(self.maintenance._turn_owner)
                self.assertFalse(self.maintenance._lock.locked())

    async def test_cancellation_while_queued_joins_original_without_releasing_holder(self):
        async def cancel(foreground, original, release):
            foreground.cancel()
            cancellation_delivered = asyncio.Event()
            asyncio.get_running_loop().call_soon(cancellation_delivered.set)
            await cancellation_delivered.wait()
            self.assertFalse(foreground.done())
            self.assertFalse(original.done())
            self.assertTrue(self.maintenance._lock.locked())
            self.assertIsNone(self.maintenance._turn_owner)
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(foreground), 8)
            self.assertTrue(original.done())
            original.result()
            row = await self.hub.db(self.hub.store.agent, 'falcon-worker-scheduled')
            self.assertEqual((row['generation'], row['state']), (1, 'ready'))
        await self.queued_adoption(cancel)

    async def test_original_deadline_expires_while_queued_before_any_adoption_effect(self):
        async def expire(foreground, original, release):
            deadline = self.maintenance._requests[original]['expires']
            elapsed = asyncio.Event()
            loop = asyncio.get_running_loop()
            timer = loop.call_later(max(0, deadline - server.time.monotonic()) + .02, elapsed.set)
            try:
                await asyncio.wait_for(elapsed.wait(), 6)
            finally:
                timer.cancel()
            self.assertGreaterEqual(server.time.monotonic(), deadline)
            release.set()
            with self.assertRaisesRegex(server.HubError, 'authenticated lifecycle request expired'):
                await asyncio.wait_for(asyncio.shield(foreground), 5)
            self.assertFalse(any(r['contractId'] == 'federation-work-register' for r in self.submitted))
            self.assertIsNone(await self.hub.db(self.hub.store.agent, 'falcon-worker-scheduled'))
        await self.queued_adoption(expire)

    async def test_source_path_lost_while_queued_refuses_before_adoption_effect(self):
        async def lose_source(foreground, original, release):
            held = self.database.with_name('retained-original.db')
            self.database.rename(held)
            try:
                release.set()
                with self.assertRaisesRegex(server.HubError, 'selected hub database is unavailable'):
                    await asyncio.wait_for(asyncio.shield(foreground), 5)
                self.assertFalse(any(r['contractId'] == 'federation-work-register' for r in self.submitted))
            finally:
                held.rename(self.database)
        await self.queued_adoption(lose_source)

    async def test_background_recovery_waits_until_confirmation_then_runs(self):
        register = self.maintenance.register
        confirm = self.maintenance.confirm_result
        owned_db = self.maintenance._commands._owned_db
        queued, confirmed = asyncio.Event(), asyncio.Event()
        observations, tasks = [], []
        recovery = None

        async def recover():
            queued.set()
            await self.maintenance.recover_pending()

        async def register_original(*args, **kwargs):
            nonlocal recovery
            result = await register(*args, **kwargs)
            recovery = asyncio.create_task(recover(), context=Context())
            tasks.append(recovery)
            await queued.wait()
            return result

        async def confirm_original(*args, **kwargs):
            result = await confirm(*args, **kwargs)
            confirmed.set()
            return result

        async def observe_db(function, *args, **kwargs):
            if asyncio.current_task() is recovery and function == self.maintenance._pending_recovery:
                observations.append(confirmed.is_set())
            return await owned_db(function, *args, **kwargs)

        with patch.object(self.maintenance, 'register', side_effect=register_original), \
                patch.object(self.maintenance, 'confirm_result', side_effect=confirm_original), \
                patch.object(self.maintenance._commands, '_owned_db', side_effect=observe_db):
            try:
                foreground = asyncio.create_task(self.request('adopt', self.arguments, 'recovery-original'))
                tasks.append(foreground)
                await asyncio.wait_for(asyncio.shield(foreground), 8)
                await asyncio.wait_for(asyncio.shield(recovery), 5)
                self.assertEqual(observations, [True])
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 10)
