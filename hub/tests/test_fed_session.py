"""Legacy federation joins its own consumers before reconnect and shutdown."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from hub.fed.board_services import build_board_context
from hub.fed.work_services import build_work_context
from hub.fed import conn
from hub.fed.plugins.board import PLUGIN as BOARD
from hub.fed.plugins.work import PLUGIN as WORK
from hub.fed.runtime import Federation
from hub.fed.session import FederationSession, SessionCleanupFailure


class Watcher:
    def __init__(self):
        self.reading = asyncio.Event()
        self.stopped = 0

    async def updates(self, timeout):
        self.reading.set()
        await asyncio.Event().wait()

    async def stop(self):
        self.stopped += 1


def runtime():
    fed = Federation.__new__(Federation)
    fed.session = None
    fed.connection_cleanup = None
    fed.nc = fed.js = None
    fed.cfg = {"federation": {"url": "nats://fixture", "peer": "fixture"}}
    fed.node = "fixture"
    fed.log = Mock()
    return fed


class SessionOwnership(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_setup_caller_does_not_log_later_private_failure(self):
        session = FederationSession()
        began, finish = asyncio.Event(), asyncio.Event()
        diagnostics = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: diagnostics.append(context))

        async def setup():
            began.set()
            await finish.wait()
            raise OSError("private setup failure")

        try:
            caller = asyncio.create_task(session.acquire(setup(), session.own_watcher))
            await began.wait()
            caller.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await caller
            owned, = session._acquisitions
            finish.set()
            await asyncio.wait({owned})
            await session.close()
            self.assertEqual(diagnostics, [])
        finally:
            finish.set()
            loop.set_exception_handler(previous)

    async def test_completed_setup_retries_do_not_accumulate_tasks(self):
        session = FederationSession()

        async def refused():
            raise OSError("private setup refusal")

        for _ in range(100):
            with self.assertRaises(OSError):
                await session.acquire(refused(), session.own_subscription)
        self.assertEqual(session._acquisitions, set())
        self.assertEqual(session._resources, {})

        watcher = Watcher()

        async def success():
            return watcher

        self.assertIs(await session.acquire(success(), session.own_watcher), watcher)
        self.assertEqual(session._acquisitions, set())
        await session.close()
        self.assertEqual(watcher.stopped, 1)

    async def test_cancelled_caller_keeps_only_unfinished_setup(self):
        session = FederationSession()
        began, finish = asyncio.Event(), asyncio.Event()
        watcher = Watcher()

        async def setup():
            began.set()
            await finish.wait()
            return watcher

        caller = asyncio.create_task(session.acquire(setup(), session.own_watcher))
        await began.wait()
        caller.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await caller
        owned, = session._acquisitions
        self.assertFalse(owned.done())
        finish.set()
        await owned
        self.assertEqual(session._acquisitions, set())
        await session.close()
        self.assertEqual(watcher.stopped, 1)

    async def test_board_singleton_has_separate_watchers_for_each_federation(self):
        contexts, watchers = [], []
        for _ in range(2):
            watcher = Watcher()
            kv = SimpleNamespace(watch=AsyncMock(return_value=watcher))
            ctx = SimpleNamespace(session=FederationSession(), js=SimpleNamespace(key_value=AsyncMock(return_value=kv)))
            contexts.append(ctx)
            watchers.append(watcher)
            await BOARD.on_connect(build_board_context(ctx))
            await watcher.reading.wait()
        try:
            await contexts[0].session.close()
            self.assertEqual([w.stopped for w in watchers], [1, 0])
            self.assertTrue(all(t.done() for t in contexts[0].session.tasks()))
            self.assertFalse(any(t.done() for t in contexts[1].session.tasks()))
            await contexts[0].session.close()
            self.assertEqual(watchers[0].stopped, 1)
        finally:
            await contexts[1].session.close()
        self.assertEqual(watchers[1].stopped, 1)

    async def test_close_joins_exact_callback_and_heartbeat_tasks(self):
        began, stopping, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def callback():
            began.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopping.set()
                await finish.wait()

        task = asyncio.create_task(callback())
        heartbeat = asyncio.create_task(asyncio.Event().wait())
        flow_control = asyncio.create_task(asyncio.Event().wait())
        await began.wait()
        watcher = Watcher()
        watcher._sub = SimpleNamespace(_sub=SimpleNamespace(
            _wait_for_msgs_task=task, _jsi=SimpleNamespace(_hbtask=heartbeat, _fctask=flow_control)))
        session = FederationSession()
        session.own_watcher(watcher)
        close = asyncio.create_task(session.close())
        await stopping.wait()
        self.assertFalse(close.done())
        finish.set()
        await close
        self.assertTrue(all(t.done() for t in (task, heartbeat, flow_control)))
        self.assertEqual(watcher.stopped, 1)

    async def test_late_acquisition_remains_owned_while_creator_is_joined(self):
        began, cancelled, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
        watcher = Watcher()
        session = FederationSession()

        async def acquire():
            began.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                await finish.wait()
            session.own_watcher(watcher)

        original = session.start_task("board", acquire())
        await began.wait()
        close = asyncio.create_task(session.close())
        await cancelled.wait()
        self.assertFalse(close.done())
        finish.set()
        await close
        self.assertTrue(original.done())
        self.assertEqual(watcher.stopped, 1)

    async def test_timeout_blocks_reconnect_and_rejoins_the_same_cleanup(self):
        began, finish = asyncio.Event(), asyncio.Event()
        closes = []

        async def stop():
            closes.append("stop")
            began.set()
            await finish.wait()

        fed = runtime()
        old = SimpleNamespace(close=AsyncMock())
        fed.nc, fed.js = old, object()
        session = fed.session = FederationSession()
        session.own_watcher(SimpleNamespace(stop=stop))
        with patch("hub.fed.session.SESSION_CLOSE_TIMEOUT", 0.01):
            await fed._close_session_owned()
            await began.wait()
            original = session.close_task
            self.assertIs(fed.nc, old)
            old.close.assert_not_awaited()
            with patch.object(conn, "connect", AsyncMock(return_value="replacement")) as connect:
                with self.assertRaises(SessionCleanupFailure):
                    await fed._connect_owned()
                connect.assert_not_awaited()
                self.assertIs(session.close_task, original)
                self.assertFalse(original.done())
                finish.set()
                self.assertEqual(await fed._connect_owned(), "replacement")
                connect.assert_awaited_once()
        old.close.assert_awaited_once()
        self.assertEqual(closes, ["stop"])
        self.assertIsNone(fed.session)

    async def test_cancelled_wait_keeps_original_cleanup_and_does_not_stop_twice(self):
        began, finish = asyncio.Event(), asyncio.Event()

        async def stop():
            began.set()
            await finish.wait()

        watcher = SimpleNamespace(stop=AsyncMock(side_effect=stop))
        session = FederationSession()
        session.own_watcher(watcher)
        caller = asyncio.create_task(session.close())
        await began.wait()
        original = session.close_task
        caller.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await caller
        self.assertFalse(original.done())
        finish.set()
        await session.close()
        self.assertIs(session.close_task, original)
        watcher.stop.assert_awaited_once()

    async def test_failed_stop_is_retained_after_other_resources_are_closed(self):
        failure = OSError("private stop failure")
        broken = SimpleNamespace(stop=AsyncMock(side_effect=failure))
        other = SimpleNamespace(unsubscribe=AsyncMock())
        session = FederationSession()
        session.own_watcher(broken)
        session.own_subscription(other)
        with self.assertRaises(SessionCleanupFailure) as first:
            await session.close()
        with self.assertRaises(SessionCleanupFailure) as second:
            await session.close()
        self.assertIs(first.exception, second.exception)
        self.assertNotIn("private", str(first.exception))
        broken.stop.assert_awaited_once()
        other.unsubscribe.assert_awaited_once()

    async def test_closed_connection_still_joins_subscription_tasks(self):
        from nats.errors import ConnectionClosedError
        task = asyncio.create_task(asyncio.Event().wait())
        resource = SimpleNamespace(_wait_for_msgs_task=task, unsubscribe=AsyncMock(side_effect=ConnectionClosedError))
        session = FederationSession()
        session.own_subscription(resource)
        await session.close()
        self.assertTrue(task.done())
        resource.unsubscribe.assert_awaited_once()


class RuntimeResources(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_plain_client_close_keeps_the_client_owner(self):
        fed = runtime()
        client = SimpleNamespace(close=AsyncMock(side_effect=[asyncio.CancelledError(), None]))
        session = fed.session = FederationSession()
        js = fed.js = object()
        fed.nc = client
        with self.assertRaises(asyncio.CancelledError):
            await fed._close_session_owned()
        self.assertIs(fed.nc, client)
        self.assertIs(fed.js, js)
        self.assertIs(fed.session, session)
        await fed.finish_cleanup()
        self.assertEqual(client.close.await_count, 2)
        self.assertIsNone(fed.nc)
        self.assertIsNone(fed.session)

    async def test_work_singleton_uses_each_session_cache_and_keeps_durable_consumer(self):
        import nats.errors
        contexts, subscriptions = [], []
        for _ in range(2):
            subscription = SimpleNamespace(fetch=AsyncMock(side_effect=nats.errors.TimeoutError), unsubscribe=AsyncMock())
            store = SimpleNamespace(q=Mock(return_value=[]), q1=Mock(return_value={"n": 0}), agents=Mock(return_value=[
                {"repo": "repo", "state": "idle", "session": "worker", "role": "worker",
                 "role_snapshot": json.dumps({"max_active": 1})}]))

            async def db(fn, *args, **kwargs):
                return fn(*args, **kwargs)

            ctx = SimpleNamespace(session=FederationSession(), store=store, db=db, me="me", peer_ids=set(),
                policy=SimpleNamespace(shared=lambda: {"repo": "rid"}, rid_of=lambda repo: "rid"),
                js=SimpleNamespace(pull_subscribe=AsyncMock(return_value=subscription)))
            await WORK.on_connect(build_work_context(ctx))
            await WORK.on_tick(build_work_context(ctx))
            await WORK.on_tick(build_work_context(ctx))
            ctx.js.pull_subscribe.assert_awaited_once()
            args, kwargs = ctx.js.pull_subscribe.call_args
            self.assertEqual(args, ("am.work.me.rid.worker.v3",))
            self.assertEqual((kwargs["durable"], kwargs["stream"]), ("work3_me_rid_worker", "AM_WORK"))
            contexts.append(ctx)
            subscriptions.append(subscription)
        await contexts[0].session.close()
        subscriptions[0].unsubscribe.assert_awaited_once()
        subscriptions[1].unsubscribe.assert_not_awaited()
        self.assertEqual(len(contexts[1].session.work_subscriptions), 1)
        await contexts[1].session.close()
        subscriptions[1].unsubscribe.assert_awaited_once()

    async def test_partial_core_binding_keeps_first_subscription_until_cleanup(self):
        fed = runtime()
        first = SimpleNamespace(unsubscribe=AsyncMock())
        fed.session = FederationSession()
        fed.nc = SimpleNamespace(close=AsyncMock(), subscribe=AsyncMock())
        fed.js = SimpleNamespace(pull_subscribe=AsyncMock(side_effect=[first, RuntimeError("bind failure")]))
        client = fed.nc
        with self.assertRaisesRegex(RuntimeError, "bind failure"):
            await fed._bind_core()
        await fed._close_session_owned()
        first.unsubscribe.assert_awaited_once()
        client.close.assert_awaited_once()

    async def test_run_cancellation_keeps_unfinished_session_for_hub_shutdown(self):
        started, stopping, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
        fed = runtime()
        fed.cfg["federation"]["enabled"] = True
        fed.hub = SimpleNamespace(stop=asyncio.Event(), store=object())
        fed.plugin_adapters = {}
        fed.db = AsyncMock(return_value=None)
        fed._drain_outbox = AsyncMock()
        fed._presence = AsyncMock()
        client = SimpleNamespace(jetstream=lambda: object(), is_closed=False, is_connected=True, close=AsyncMock())

        async def consumer():
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopping.set()
                await finish.wait()

        async def bind():
            fed.session.start_task("messages", consumer())

        fed._bind_core = bind
        with patch.object(conn, "connect", AsyncMock(return_value=client)), \
                patch("hub.fed.session.SESSION_CLOSE_TIMEOUT", 0.01):
            task = asyncio.create_task(fed.run())
            await started.wait()
            task.cancel()
            await stopping.wait()
            with self.assertRaises(asyncio.CancelledError):
                await task
            session = fed.session
            self.assertFalse(session.close_task.done())
            client.close.assert_not_awaited()
            cleanup = asyncio.create_task(fed.finish_cleanup())
            finish.set()
            await cleanup
        self.assertTrue(all(t.done() for t in session.tasks()))
        self.assertTrue(session.close_task.done())
        client.close.assert_awaited_once()
        self.assertIsNone(fed.session)


class HubShutdown(unittest.IsolatedAsyncioTestCase):
    def test_process_boundary_prints_no_private_cleanup_cause_or_traceback(self):
        code = '''
import asyncio
import sys
from hub import server
from hub.fed.conn import ConnectionCleanupFailure
from hub.fed.session import FederationSession, SessionCleanupFailure
from hub.transport import TmuxTransport, TmuxBufferCleanupFailure

class BrokenHub:
    def __init__(self, *, profile_context=None, legacy_identity=None,
                 authority_switch_recovery=None, message_sessions=None,
                 knowledge_sessions=None, peer_control_sessions=None, policy_sessions=None):
        pass

    async def main(self):
        secret = OSError("private-cleanup-marker")
        if sys.argv[1] == "session":
            raise SessionCleanupFailure(FederationSession(), secret) from BaseExceptionGroup("private-group-marker", [secret])
        if sys.argv[1] == "terminal":
            raise TmuxBufferCleanupFailure(TmuxTransport(socket="fixture"), "fixture", "original") from secret
        class Client:
            async def close(self):
                raise secret
        owned = ConnectionCleanupFailure(Client(), secret)
        await owned._wait()

server.Hub = BrokenHub
raise SystemExit(server.main())
'''
        for kind in ("session", "connection", "terminal"):
            with self.subTest(kind=kind):
                result = subprocess.run([sys.executable, "-c", code, kind], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                owner = "terminal" if kind == "terminal" else "federation"
                self.assertEqual(result.stderr, f"hub shutdown could not complete owned {owner} cleanup\n")

    async def test_hub_down_waits_for_original_federation_task_and_retained_cleanup(self):
        from hub import server
        started, stopping, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()
        events = []

        async def loop():
            await asyncio.Event().wait()

        async def federation():
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopping.set()
                await finish.wait()
                events.append("federation joined")

        async def cleanup():
            events.append("cleanup joined")

        async def db(fn, *args):
            return fn(*args)

        class Server:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        hub = server.Hub.__new__(server.Hub)
        hub.stop, hub.cfg, hub.started, hub.bridge = asyncio.Event(), {}, {}, None
        hub._message_commands = None
        hub._knowledge_commands = None
        hub._peer_control_commands = None
        hub._policy_commands = None
        hub.rings = {}
        hub.tp = server.TmuxTransport(socket="fixture")
        hub.db = db
        hub.store = SimpleNamespace(path="fixture", agents=lambda live: [], checkpoint=lambda: events.append("checkpoint"))
        hub.bell_loop = hub.live_loop = hub.lease_loop = hub.receipt_loop = loop
        hub.fed = SimpleNamespace(run=federation, finish_cleanup=cleanup)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(server, "HUBDIR", directory), patch.object(server, "SOCK", os.path.join(directory, "hub.sock")), \
                patch.object(asyncio, "start_unix_server", AsyncMock(return_value=Server())), \
                patch.object(asyncio.get_running_loop(), "add_signal_handler"), \
                patch.object(server, "log", side_effect=lambda *args: events.append(args[0])):
            main = asyncio.create_task(hub.main())
            await started.wait()
            hub.stop.set()
            await stopping.wait()
            self.assertFalse(main.done())
            self.assertNotIn("checkpoint", events)
            self.assertNotIn("hub down", events)
            finish.set()
            await main
        self.assertLess(events.index("federation joined"), events.index("cleanup joined"))
        self.assertLess(events.index("cleanup joined"), events.index("checkpoint"))
        self.assertLess(events.index("checkpoint"), events.index("hub down"))


class PinnedNatsOwnership(unittest.IsolatedAsyncioTestCase):
    def client(self):
        import nats
        client = conn._new_client(nats, False)
        client._status = client.CONNECTED
        client._send_command = AsyncMock()
        client._flush_pending = AsyncMock()
        client._error_cb = AsyncMock()
        return client

    def jetstream(self, client, session, manager):
        from hub.fed.owned_nats import OwnedJetStream

        class TestJetStream(OwnedJetStream):
            @property
            def _jsm(self):
                return manager

        client._agentmux_session = session
        return TestJetStream(client, session)

    def test_adapter_matches_the_prepared_client_binding_contract(self):
        import importlib.metadata
        import inspect
        from hub.fed.owned_nats import OwnedJetStream
        from nats.js.client import JetStreamContext
        self.assertEqual(importlib.metadata.version("nats-py"), "2.16.0")
        expected = inspect.signature(JetStreamContext.subscribe_bind).parameters
        actual = inspect.signature(OwnedJetStream.subscribe_bind).parameters
        self.assertEqual(list(actual), list(expected))
        for name in expected:
            self.assertEqual((actual[name].kind, actual[name].default), (expected[name].kind, expected[name].default))

    async def test_cancelled_kv_setup_joins_returned_watcher_and_exact_client_tasks(self):
        from nats.js.kv import KeyValue
        from hub.fed.owned_nats import _OwnedJSI
        setup, finish = asyncio.Event(), asyncio.Event()
        watchers = []

        async def info(*args, **kwargs):
            setup.set()
            await finish.wait()
            return SimpleNamespace(num_pending=0)

        class ObservedKV(KeyValue):
            async def watch(self, *args, **kwargs):
                watcher = await super().watch(*args, **kwargs)
                watcher.stop = AsyncMock(wraps=watcher.stop)
                watchers.append(watcher)
                return watcher

        client, session = self.client(), FederationSession()
        manager = SimpleNamespace(add_consumer=AsyncMock(return_value=SimpleNamespace(name="watcher")), consumer_info=info)
        js = self.jetstream(client, session, manager)
        kv = ObservedKV("am_board", "KV_am_board", "$KV.am_board.", js, False)
        caller = asyncio.create_task(session.acquire(kv.watch("*.card.*"), session.own_watcher))
        await setup.wait()
        base = next(iter(client._subs.values()))
        self.assertIsInstance(base._jsi, _OwnedJSI)
        self.assertIn(id(base), session._resources)
        exact_tasks = (base._wait_for_msgs_task, base._jsi._hbtask, base._jsi._fctask)
        caller.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await caller
        close = asyncio.create_task(session.close())
        await asyncio.sleep(0)
        self.assertFalse(close.done())
        finish.set()
        await close
        self.assertEqual(len(watchers), 1)
        watchers[0].stop.assert_awaited_once()
        self.assertTrue(all(task.done() for task in exact_tasks))
        self.assertTrue(all(task.done() for task in session._acquisitions))
        self.assertEqual(client._subs, {})

    async def test_failed_kv_setup_keeps_and_joins_already_unsubscribed_tasks(self):
        from nats.js.kv import KeyValue
        client, session = self.client(), FederationSession()
        tasks = []

        async def fail_info(*args, **kwargs):
            base = next(iter(client._subs.values()))
            tasks.extend((base._wait_for_msgs_task, base._jsi._hbtask, base._jsi._fctask))
            raise OSError("private setup failure")

        manager = SimpleNamespace(add_consumer=AsyncMock(return_value=SimpleNamespace(name="watcher")), consumer_info=fail_info)
        js = self.jetstream(client, session, manager)
        kv = KeyValue("am_board", "KV_am_board", "$KV.am_board.", js, False)
        with self.assertRaisesRegex(OSError, "setup failure"):
            await session.acquire(kv.watch("*.card.*"), session.own_watcher)
        await session.close()
        self.assertEqual(len(tasks), 3)
        self.assertTrue(all(task.done() for task in tasks))
        self.assertEqual(client._subs, {})

    async def test_subscribe_send_failure_cannot_lose_the_created_callback(self):
        client, session = self.client(), FederationSession()
        client._agentmux_session = session
        client._send_command.side_effect = [OSError("private subscribe failure"), None]
        with self.assertRaisesRegex(OSError, "subscribe failure"):
            await session.acquire(client.subscribe("am.fixture", cb=AsyncMock()), session.own_subscription)
        base = next(iter(client._subs.values()))
        task = base._wait_for_msgs_task
        self.assertIn(id(base), session._resources)
        await session.close()
        self.assertTrue(task.done())
        self.assertEqual(client._subs, {})

    async def test_ordered_reset_returns_before_rpc_and_cleanup_joins_recreation(self):
        from nats.js import api
        client, session = self.client(), FederationSession()
        started, cancelling, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def recreate(*args, **kwargs):
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelling.set()
                await finish.wait()
            return SimpleNamespace(name="late-replacement")

        manager = SimpleNamespace(add_consumer=AsyncMock(side_effect=recreate))
        js = self.jetstream(client, session, manager)
        config = api.ConsumerConfig(deliver_subject="_INBOX.original", ack_policy=api.AckPolicy.NONE, idle_heartbeat=5)
        psub = await js.subscribe_bind("KV_am_board", config, "original", cb=AsyncMock(), ordered_consumer=True)
        state, old_id = psub._sub._jsi, psub._sub._id
        self.assertTrue(await state.reset_ordered_consumer(9))
        await started.wait()
        self.assertEqual(config.opt_start_seq, 9)
        self.assertEqual(config.deliver_policy, api.DeliverPolicy.BY_START_SEQUENCE)
        self.assertEqual(state._dseq, 1)
        self.assertNotEqual(psub._sub._id, old_id)
        commands = [call.args[0] for call in client._send_command.call_args_list]
        self.assertTrue(commands[1].startswith(b"UNSUB "))
        self.assertTrue(commands[2].startswith(b"SUB "))
        owned = tuple(session._client_tasks)
        close = asyncio.create_task(session.close())
        await cancelling.wait()
        self.assertFalse(close.done())
        self.assertEqual(psub._consumer, "original")
        finish.set()
        await close
        self.assertTrue(all(task.done() for task in owned))
        self.assertEqual(psub._consumer, "original")
        self.assertFalse(await state.reset_ordered_consumer(10))
        self.assertEqual(manager.add_consumer.await_count, 1)
        self.assertEqual(client._subs, {})
