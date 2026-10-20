"""Keep native kill admission together without holding physical work."""
import asyncio
from dataclasses import replace
import json
import threading
import time
import unittest
from unittest.mock import Mock, patch

from .test_native_kill_preflight import NativeKillPreflightTests
from .test_work_source import SelectedWorkSourceFixture


class KillAdmissionTurnTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = NativeKillPreflightTests.configure_channels
    asyncSetUp = NativeKillPreflightTests.asyncSetUp
    join_tasks = NativeKillPreflightTests.join_tasks
    task = NativeKillPreflightTests.task
    gate = NativeKillPreflightTests.gate
    framed_connection = NativeKillPreflightTests.framed_connection
    registered = NativeKillPreflightTests.registered

    async def prepare(self):
        agent = await self.registered()
        self.hub._native_core = object()
        return {'verb': 'kill', 'args': {'session': agent['session']},
                'operationId': 'reserved-kill'}

    async def test_release_before_physical_child_and_callback_with_same_id_replay(self):
        request = await self.prepare()
        auth = self.hub.authenticate_caller
        kill = self.hub._kill_agent
        apply = self.hub._apply_kill
        background_done = self.gate()
        queued = self.gate()
        events = []
        background_tasks = []
        async def background():
            queued.set()
            async with self.maintenance.observation_read_turn():
                events.append('background')
                background_done.set()
        async def authenticated(*args, **kwargs):
            proof = await auth(*args, **kwargs)
            token = self.maintenance._kill_admission_turn
            self.assertIs(token['owner'], asyncio.current_task())
            self.assertEqual(token['request'], self.hub._authenticated_callers[proof].request)
            events.append('authenticated')
            background_tasks.append(self.task(background()))
            await queued.wait()
            await asyncio.sleep(0)
            self.assertFalse(background_done.is_set())
            return proof
        async def physical_child(*args):
            self.assertIsNone(self.maintenance._kill_admission_turn)
            events.append('child')
            await asyncio.wait_for(background_done.wait(), 2)
            return await kill(*args)
        async def callback(*args):
            self.assertIsNone(self.maintenance._kill_admission_turn)
            async with self.maintenance.observation_read_turn():
                events.append('callback')
            return await apply(*args)
        with patch.object(self.hub, 'authenticate_caller', side_effect=authenticated), \
                patch.object(self.hub, '_kill_agent', side_effect=physical_child), \
                patch.object(self.hub, '_apply_kill', side_effect=callback), \
                patch.object(self.hub, 'harness', return_value=True) as effect:
            result = await self.framed_connection(request)
            self.assertTrue(result['ok'], result)
            rows = await self.hub.db(self.hub.store.q,
                "SELECT k,v FROM fed_state WHERE json_extract(v,'$.identity.operationId')=? ORDER BY k",
                (request['operationId'],))
            background_done.clear(); queued.clear()
            replay = await self.framed_connection(request)
            self.assertEqual(replay, result)
            self.assertEqual(await self.hub.db(self.hub.store.q,
                "SELECT k,v FROM fed_state WHERE json_extract(v,'$.identity.operationId')=? ORDER BY k",
                (request['operationId'],)), rows)
            effect.assert_called_once()
        await asyncio.gather(*background_tasks)
        self.assertEqual(events.count('callback'), 1)
        self.assertIsNone(self.maintenance._kill_admission_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_request_and_digest_mismatch_release_without_effect(self):
        request = await self.prepare()
        auth = self.hub.authenticate_caller
        for mismatch in ('request', 'digest'):
            async def changed(req, *args, **kwargs):
                if mismatch == 'request':
                    req = {**req, 'args': {**req['args'], 'reason': 'changed'}}
                proof = await auth(req, *args, **kwargs)
                if mismatch == 'digest':
                    self.hub._authenticated_callers[proof] = replace(
                        self.hub._authenticated_callers[proof], request_digest='0' * 64)
                return proof
            with self.subTest(mismatch=mismatch), \
                    patch.object(self.hub, 'authenticate_caller', side_effect=changed), \
                    patch.object(self.hub, 'harness', return_value=True) as physical:
                result = await self.framed_connection(request)
                self.assertFalse(result['ok'], result)
                self.assertIn('authenticated kill request does not match', result['error'])
                physical.assert_not_called()
                self.assertIsNone(self.maintenance._kill_admission_turn)
                self.assertFalse(self.maintenance._lock.locked())

    async def test_target_refusal_releases_admission(self):
        request = await self.prepare()
        request['args']['session'] = 'missing-target'
        with patch.object(self.hub, 'harness', return_value=True) as physical:
            result = await self.framed_connection(request)
            self.assertFalse(result['ok'], result)
            self.assertIn('selected repository does not match', result['error'])
            physical.assert_not_called()
        self.assertIsNone(self.maintenance._kill_admission_turn)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_parent_reentry_excludes_unrelated_tasks_and_old_finally_keeps_new_owner(self):
        encoded = b'{"args":{},"verb":"kill"}'
        first = self.maintenance.kill_admission_turn(encoded)
        await first.__aenter__()
        token = self.maintenance._kill_admission_turn
        async with self.maintenance.native_check_turn():
            async with self.maintenance.source_read_turn():
                pass
        entered = []
        async def unrelated(kind):
            turn = (self.maintenance.native_check_turn if kind == 'native'
                    else self.maintenance.source_read_turn)
            async with turn():
                entered.append(kind)
        tasks = [self.task(unrelated(kind)) for kind in ('native', 'source')]
        await asyncio.sleep(0)
        self.assertEqual(entered, [])
        self.maintenance._release_kill_admission(token)
        await asyncio.gather(*tasks)
        self.assertEqual(entered, ['native', 'source'])
        async with self.maintenance.kill_admission_turn(encoded):
            second = self.maintenance._kill_admission_turn
            self.assertIsNot(second, token)
            await first.__aexit__(None, None, None)
            self.assertIs(self.maintenance._kill_admission_turn, second)
            self.assertTrue(self.maintenance._lock.locked())
        self.assertFalse(self.maintenance._lock.locked())

    async def test_queued_cancel_does_not_authenticate_or_release_holder(self):
        request = await self.prepare()
        await self.maintenance._lock.acquire()
        try:
            with patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as auth:
                connection = self.task(self.framed_connection(request))
                for _ in range(100):
                    if self.maintenance._lock._foreground:
                        break
                    await asyncio.sleep(.01)
                self.assertTrue(self.maintenance._lock._foreground)
                connection.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await connection
                auth.assert_not_awaited()
                self.assertTrue(self.maintenance._lock.locked())
                self.assertIsNone(self.maintenance._kill_admission_turn)
        finally:
            self.maintenance._lock.release()

    async def test_original_envelope_expiring_in_queue_never_authenticates(self):
        request = await self.prepare()
        clock = [time.monotonic()]
        timer = Mock(wraps=time)
        timer.monotonic.side_effect = lambda: clock[0]
        await self.maintenance._lock.acquire()
        released = False
        try:
            with patch('hub.server.time', timer), patch('hub.core_endpoint.time', timer), \
                    patch.object(self.hub, 'authenticate_caller', wraps=self.hub.authenticate_caller) as auth, \
                    patch.object(self.hub, 'harness', return_value=True) as physical:
                connection = self.task(self.framed_connection(request, expires=clock[0] + 10))
                for _ in range(100):
                    if self.maintenance._lock._foreground:
                        break
                    await asyncio.sleep(.01)
                self.assertTrue(self.maintenance._lock._foreground)
                clock[0] += 11
                self.maintenance._lock.release()
                released = True
                with self.assertRaisesRegex(AssertionError, 'closed without a response'):
                    await connection
                auth.assert_not_awaited()
                physical.assert_not_called()
                self.assertIsNone(self.maintenance._kill_admission_turn)
                self.assertFalse(self.maintenance._lock.locked())
        finally:
            if not released:
                self.maintenance._lock.release()

    async def cancelled_original(self, stage):
        request = await self.prepare()
        entered = self.gate()
        release = threading.Event() if stage != 'source' else self.gate()
        completed = []
        loop = asyncio.get_running_loop()
        if stage == 'source':
            original = self.binding._prove
            async def held(*args):
                entered.set()
                await release.wait()
                try:
                    return await original(*args)
                finally:
                    completed.append('source')
            target, name = self.binding, '_prove'
        else:
            target, name = ((self.hub, 'identify_qualified') if stage == 'native'
                            else (self.maintenance, '_admit_request'))
            original = getattr(target, name)
            def held(*args):
                loop.call_soon_threadsafe(entered.set)
                if not release.wait(8):
                    raise AssertionError('original DB worker was not released')
                try:
                    return original(*args)
                finally:
                    completed.append(stage)
        with patch.object(target, name, side_effect=held), \
                patch.object(self.hub, 'harness', return_value=True) as physical:
            connection = self.task(self.framed_connection(request))
            try:
                await asyncio.wait_for(entered.wait(), 5)
                token = self.maintenance._kill_admission_turn
                owner = token['owner']
                for _ in range(2):
                    owner.cancel()
                    await asyncio.sleep(.02)
                    self.assertFalse(owner.done())
                    self.assertIs(self.maintenance._kill_admission_turn, token)
                    self.assertTrue(self.maintenance._lock.locked())
                    self.assertFalse(completed)
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await connection
            finally:
                release.set()
                await asyncio.gather(connection, return_exceptions=True)
            self.assertTrue(completed)
            physical.assert_not_called()
            self.assertIsNone(self.maintenance._kill_admission_turn)
            self.assertFalse(self.maintenance._lock.locked())
            self.assertFalse(self.binding.pending)
            self.assertFalse(self.maintenance._commands._workers)

    async def test_repeated_cancel_joins_native_classification(self):
        await self.cancelled_original('native')

    async def test_repeated_cancel_joins_source_fanout(self):
        await self.cancelled_original('source')

    async def test_repeated_cancel_joins_admission_db(self):
        await self.cancelled_original('admit')
