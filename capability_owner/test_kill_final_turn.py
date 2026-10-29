"""Final native kill checks keep their original validity while readers progress."""
import asyncio
import json
import time
import unittest
from unittest.mock import Mock, patch

from .test_kill_admission_turn import KillAdmissionTurnTests
from .test_work_source import SelectedWorkSourceFixture


class KillFinalTurnTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = KillAdmissionTurnTests.configure_channels
    asyncSetUp = KillAdmissionTurnTests.asyncSetUp
    join_tasks = KillAdmissionTurnTests.join_tasks
    task = KillAdmissionTurnTests.task
    gate = KillAdmissionTurnTests.gate
    framed_connection = KillAdmissionTurnTests.framed_connection
    registered = KillAdmissionTurnTests.registered
    prepare = KillAdmissionTurnTests.prepare

    async def test_final_check_precedes_queued_readers_without_starving_them(self):
        request = await self.prepare()
        with patch.object(self.hub, 'harness', return_value=True) as physical:
            query = "SELECT k,v FROM fed_state WHERE json_extract(v,'$.identity.operationId')=? ORDER BY k"
            saved = []
            clock = [time.monotonic()]
            timer = Mock(wraps=time)
            timer.monotonic.side_effect = lambda: clock[0]
            checked = self.hub._check_work_targets
            current = self.hub._check_work_request_current
            entered, release = self.gate(), self.gate()
            tasks, events = [], []

            async def holder():
                async with self.maintenance.observation_read_turn():
                    entered.set()
                    await release.wait()

            async def reader(index):
                async with self.maintenance.observation_read_turn():
                    events.append('reader-' + str(index))
                    clock[0] += 2

            async def release_when_final_queued():
                lock = self.maintenance._lock
                while len(lock._ordinary) + len(lock._foreground) < 4:
                    await asyncio.sleep(0)
                release.set()

            async def checking(*args, **kwargs):
                saved.extend(await self.hub.db(self.hub.store.q, query, (request['operationId'],)))
                tasks.append(self.task(holder()))
                await entered.wait()
                tasks.extend(self.task(reader(index)) for index in range(3))
                while len(self.maintenance._lock._ordinary) < 3:
                    await asyncio.sleep(0)
                tasks.append(self.task(release_when_final_queued()))
                return await checked(*args, **kwargs)

            def current_check(targets, identity):
                events.append('final')
                return current(targets, identity)

            with patch.object(self.hub, '_check_work_targets', side_effect=checking), \
                    patch.object(self.hub, '_check_work_request_current', side_effect=current_check), \
                    patch('hub.server.time', timer), patch('hub.core_endpoint.time', timer):
                result = await asyncio.wait_for(self.framed_connection(request, expires=clock[0]+10), 10)
                await asyncio.gather(*tasks)
            self.assertTrue(result['ok'], result)
            self.assertEqual(events, ['final', 'reader-0', 'reader-1', 'reader-2'])
            self.assertEqual(await self.hub.db(self.hub.store.q, query, (request['operationId'],)), saved)
            physical.assert_called_once()
            self.assertFalse(self.maintenance._lock.locked())

    async def final_wait(self, cancel):
        request = await self.prepare()
        with patch.object(self.hub, 'harness', return_value=True) as physical:
            clock = [time.monotonic()]
            timer = Mock(wraps=time)
            timer.monotonic.side_effect = lambda: clock[0]
            checked = self.hub._check_work_targets
            entered, release = self.gate(), self.gate()
            tasks, owners = [], []

            async def holder():
                async with self.maintenance.observation_read_turn():
                    entered.set()
                    await release.wait()

            async def checking(*args, **kwargs):
                owners.append(asyncio.current_task())
                tasks.append(self.task(holder()))
                await entered.wait()
                return await checked(*args, **kwargs)

            with patch.object(self.hub, '_check_work_targets', side_effect=checking), \
                    patch('hub.server.time', timer), patch('hub.core_endpoint.time', timer), \
                    patch.object(self.hub, 'identify_qualified', wraps=self.hub.identify_qualified) as identify:
                connection = self.task(self.framed_connection(request, expires=clock[0]+10))
                try:
                    await asyncio.wait_for(entered.wait(), 5)
                    for _ in range(1000):
                        if self.maintenance._lock._foreground:
                            break
                        await asyncio.sleep(.001)
                    self.assertTrue(self.maintenance._lock._foreground)
                    self.assertTrue(self.maintenance._lock.locked())
                    if cancel:
                        owners[0].cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await connection
                        self.assertTrue(self.maintenance._lock.locked())
                        self.assertFalse(self.maintenance._lock._foreground)
                    else:
                        clock[0] += 6
                        release.set()
                        result = await connection
                        self.assertFalse(result['ok'], result)
                        self.assertIn('authenticated work request changed or expired', result['error'])
                    self.assertEqual(identify.call_count, 1)
                finally:
                    release.set()
                    await asyncio.gather(connection, *tasks, return_exceptions=True)
            physical.assert_called_once()
            self.assertFalse(self.maintenance._lock.locked())
            self.assertFalse(self.hub._kill_reply_timings)

    async def test_foreground_turn_inside_held_turn_does_not_wait_on_itself(self):
        await self.prepare()
        task = asyncio.current_task()
        await self.maintenance._lock.acquire()
        self.maintenance._turn_owner = task
        try:
            async with asyncio.timeout(2):
                async with self.maintenance.native_check_turn(foreground=True):
                    entered = True
        finally:
            self.maintenance._turn_owner = None
            self.maintenance._lock.release()
        self.assertTrue(entered)
        self.assertFalse(self.maintenance._lock.locked())

    async def test_cancelled_final_wait_preserves_active_reader(self):
        await self.final_wait(True)

    async def test_expiry_during_active_reader_still_refuses(self):
        await self.final_wait(False)
