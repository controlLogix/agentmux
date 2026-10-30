"""Physical spawn keeps the original caller deadline across IO scheduling."""
import asyncio
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import strict_loads
from hub import server
from .test_hub_work_maintenance import HubWorkMaintenanceTests
from .test_work_source import SelectedWorkSourceFixture


class HubSpawnExpiryTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    configure_channels = HubWorkMaintenanceTests.configure_channels
    asyncSetUp = HubWorkMaintenanceTests.asyncSetUp
    request = HubWorkMaintenanceTests.request

    async def prepare_checkout(self):
        await self.hub.db(self.hub.store.db.execute,
            'INSERT INTO repo_paths(repo,path,kind) VALUES (?,?,?)',
            ('falcon', str(self.database.parent / 'checkout'), 'local'))

    async def spawn_records(self):
        rows = await self.hub.db(self.hub.store.q,
            "SELECT v FROM fed_state WHERE json_valid(v) AND json_extract(v,'$.identity.phase')='spawn-process'")
        return [strict_loads(row['v']) for row in rows]

    async def test_original_expiry_while_io_queued_refuses_and_retains_uncertainty(self):
        await self.prepare_checkout()
        arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'queued', 'cli': 'codex'}
        release = threading.Event()
        entered = [threading.Event() for _ in range(self.hub.io._max_workers)]
        submit = self.hub.io.submit
        queued = asyncio.Event()
        captured = {}
        original_request = self.maintenance.spawn_request

        def hold(event):
            event.set()
            if not release.wait(25):
                raise AssertionError('original IO queue was not released')

        def observe_submit(fn, *args, **kwargs):
            future = submit(fn, *args, **kwargs)
            if fn.__name__ == 'launch_original':
                queued.set()
            return future

        def capture_request():
            value = original_request()
            captured.update(value)
            return value

        blockers = [submit(hold, event) for event in entered]
        request = None
        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(self.maintenance, 'spawn_request', side_effect=capture_request), \
                patch.object(self.hub.io, 'submit', side_effect=observe_submit), \
                patch.object(server.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout='controlled provider result', stderr='')) as launch:
            try:
                for event in entered:
                    self.assertTrue(await asyncio.to_thread(event.wait, 5))
                request = asyncio.create_task(self.request('spawn', arguments, 'io-queued-expiry'))
                await asyncio.wait_for(queued.wait(), 10)
                remaining = captured['expires'] - server.time.monotonic()
                self.assertGreater(remaining, 0, 'caller must be live when physical submission queues')
                await asyncio.sleep(remaining + 0.02)
                self.assertGreaterEqual(server.time.monotonic(), captured['expires'])
                release.set()
                with self.assertRaisesRegex(server.HubError, 'request expired'):
                    await request
                self.assertEqual(launch.call_count, 0)
                records = await self.spawn_records()
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]['state'], 'uncertain')
                self.assertIsNone(records[0]['result'])
                self.assertEqual(records[0]['identity']['requestDigest'], captured['requestDigest'])
                token_path = Path(server.ROOT) / 'repos/falcon/agents/worker-queued/run/token'
                original_token = token_path.read_bytes()
                with self.assertRaisesRegex(server.HubError, 'will not be repeated'):
                    await self.request('spawn', arguments, 'io-queued-expiry')
                self.assertEqual(launch.call_count, 0)
                self.assertEqual(token_path.read_bytes(), original_token)
                agent = await self.hub.db(self.hub.store.agent, 'falcon-worker-queued')
                self.assertEqual(agent['generation'], 1)
                self.assertIsNone(agent['handle'])
                events = await self.hub.db(self.hub.store.q,
                    "SELECT * FROM events WHERE entity_id=? AND event='registered'", (agent['session'],))
                self.assertEqual(len(events), 1)
            finally:
                release.set()
                await asyncio.gather(*(asyncio.wrap_future(future) for future in blockers))
                if request is not None:
                    await asyncio.gather(request, return_exceptions=True)

    async def test_cancelled_caller_and_close_join_original_physical_result(self):
        await self.prepare_checkout()
        arguments = {'repo': 'falcon', 'role': 'worker', 'agent': 'cancelled', 'cli': 'codex'}
        entered, release = threading.Event(), threading.Event()
        finished = asyncio.Event()
        original_finish = self.maintenance.finish_spawn

        def launch(*args, **kwargs):
            entered.set()
            if not release.wait(10):
                raise AssertionError('original physical spawn was not released')
            return SimpleNamespace(returncode=0, stdout='controlled provider result', stderr='')

        async def finish(result):
            await original_finish(result)
            finished.set()

        with patch.object(self.hub, 'resolve_role', return_value={}), \
                patch.object(server.subprocess, 'run', side_effect=launch) as physical, \
                patch.object(self.maintenance, 'finish_spawn', side_effect=finish), \
                patch.object(self.hub.tp, 'handle', return_value=('%44', 23459)):
            request = asyncio.create_task(self.request('spawn', arguments, 'cancelled-original-spawn'))
            close = None
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 10))
                request.cancel()
                request.cancel()
                close = asyncio.create_task(self.hub._close_work_maintenance())
                await asyncio.sleep(0)
                self.assertFalse(close.done())
                self.assertFalse(self.maintenance._closed)
                self.assertFalse(finished.is_set())
            finally:
                release.set()
                await asyncio.gather(request, return_exceptions=True)
                if close is not None:
                    await close
            self.assertTrue(request.cancelled())
            self.assertEqual(physical.call_count, 1)
        self.assertTrue(finished.is_set())
        self.assertTrue(self.maintenance._closed)
        self.assertFalse(self.hub._maintenance_calls)
        records = await asyncio.wrap_future(self.hub.dbx.submit(self.hub.store.q,
            "SELECT v FROM fed_state WHERE json_valid(v) AND json_extract(v,'$.identity.phase')='spawn-process'"))
        self.assertEqual(len(records), 1)
        self.assertEqual(strict_loads(records[0]['v'])['state'], 'completed')
