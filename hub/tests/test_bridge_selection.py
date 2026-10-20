"""Check legacy subscription ownership and joined connection cleanup."""
import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from hub.bridge import Bridge


class Connection:
    def __init__(self):
        self.subscriptions = {}
        self.unsubscribed = []
        self.closed = False
        self.reading = asyncio.Event()
        self.reader_finishing = asyncio.Event()
        self.finish_reader = asyncio.Event()
        self.socket_finishing = asyncio.Event()
        self.finish_socket = asyncio.Event()
        self.writer = SimpleNamespace(wait_closed=self.wait_closed)

    async def connect(self):
        pass

    async def sub(self, subject, handler, queue=None):
        sid = len(self.subscriptions) + 1
        self.subscriptions[sid] = (subject, handler, queue)
        return sid

    async def unsub(self, sid):
        self.unsubscribed.append(sid)

    async def read_loop(self):
        self.reading.set()
        try:
            await asyncio.Future()
        finally:
            self.reader_finishing.set()
            await self.finish_reader.wait()

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self.socket_finishing.set()
        await self.finish_socket.wait()


class BridgeSelectionTests(unittest.IsolatedAsyncioTestCase):
    def hub(self, qualified):
        store = SimpleNamespace(agents=object(), eligible_targets=object(), outbox_pending=object())
        async def db(function, *args, **kwargs):
            if function is store.outbox_pending:
                return []
            if qualified:
                self.fail('qualified legacy Bridge queried raw role interests')
            if function is store.agents:
                return [{'session': 'falcon-worker-one'}]
            if function is store.eligible_targets:
                return ['role:falcon/worker', 'agent:falcon/worker/one']
            self.fail('unexpected database read')
        return SimpleNamespace(stop=asyncio.Event(), db=db, store=store,
            _work_storage_commands=object() if qualified else None,
            ingest_message=AsyncMock(return_value={'duplicate': False}))

    async def started(self, hub, connection):
        bridge = Bridge(hub, 'nats://unused:4222', 'mac', lambda *args: None)
        patcher = patch('hub.bridge.NatsClient', return_value=connection)
        patcher.start()
        self.addCleanup(patcher.stop)
        task = asyncio.create_task(bridge.run())
        async def cleanup():
            hub.stop.set()
            connection.finish_reader.set()
            connection.finish_socket.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.addAsyncCleanup(cleanup)
        await asyncio.wait_for(connection.reading.wait(), 1)
        return bridge, task

    async def test_selected_mode_leaves_all_work_and_result_subscriptions_with_owner(self):
        connection = Connection()
        bridge, task = await self.started(self.hub(True), connection)
        self.assertEqual([row[0] for row in connection.subscriptions.values()], ['am.agent.>'])
        self.assertEqual(bridge.role_subs, {})
        # A cancelled observer must still join the original callback and socket.
        task.cancel()
        await asyncio.wait_for(connection.reader_finishing.wait(), 1)
        self.assertTrue(connection.closed)
        self.assertFalse(task.done())
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        connection.finish_reader.set()
        await asyncio.wait_for(connection.socket_finishing.wait(), 1)
        self.assertFalse(task.done())
        connection.finish_socket.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(bridge.connected)

    async def test_unqualified_mode_preserves_legacy_role_result_and_message_handlers(self):
        connection = Connection()
        hub = self.hub(False)
        bridge, _ = await self.started(hub, connection)
        subscriptions = {row[0]: row for row in connection.subscriptions.values()}
        self.assertEqual(set(subscriptions), {'am.agent.>', 'am.result.mac', 'am.work.falcon.worker'})
        self.assertEqual(subscriptions['am.result.mac'][1], bridge.on_result)
        self.assertEqual(subscriptions['am.work.falcon.worker'][1:],
            (bridge.on_work, 'am_work_falcon_worker'))
        await subscriptions['am.agent.>'][1]('am.agent.falcon.worker.one', b'{"origin":"other"}')
        hub.ingest_message.assert_awaited_once_with({'origin': 'other'})

    async def test_selected_role_sync_removes_retained_raw_queue_subscription(self):
        hub = self.hub(True)
        bridge = Bridge(hub, 'nats://unused:4222', 'mac', lambda *args: None)
        bridge.nc = Connection()
        bridge.role_subs = {'am.work.falcon.worker': 17}
        await bridge.sync_role_subs()
        self.assertEqual(bridge.nc.unsubscribed, [17])
        self.assertEqual(bridge.role_subs, {})
        self.assertEqual(bridge.nc.subscriptions, {})
