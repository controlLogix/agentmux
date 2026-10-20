"""Offline checks for restricted plugin dispatch and joined database cancellation."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from hub.fed.plugin import Plugin, Verb
from hub.fed.plugin_adapter import HOOKS, TrustedPluginAdapter, builtin_context_factory
from hub.fed.runtime import Federation, BUILTIN
from hub.server import Hub


class RecordingPlugin(Plugin):
    name = "test"
    handles = ("test",)

    def __init__(self):
        self.calls = []
        self.command = Verb(self.command_call, "record a call")

    async def command_call(self, ctx, args, caller):
        self.calls.append(("verb", ctx, args, caller))
        return ctx

    def verbs(self):
        return {"record": self.command}

    async def start(self, ctx):
        self.calls.append(("start", ctx))

    async def on_connect(self, ctx):
        self.calls.append(("on_connect", ctx))

    async def on_tick(self, ctx):
        self.calls.append(("on_tick", ctx))

    async def on_envelope(self, ctx, env, decision):
        self.calls.append(("on_envelope", ctx, env, decision))

    async def on_local_event(self, ctx, kind, data):
        self.calls.append(("on_local_event", ctx, kind, data))

    async def on_revoke(self, ctx, peer):
        self.calls.append(("on_revoke", ctx, peer))

    def panel(self, ctx):
        self.calls.append(("panel", ctx))
        return {"title": "Test"}


class RestrictedPluginCalls(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.plugin = RecordingPlugin()
        self.fed = object.__new__(Federation)
        self.contexts = []

        def factory(fed):
            self.assertIs(fed, self.fed)
            ctx = SimpleNamespace(sequence=len(self.contexts))
            self.contexts.append(ctx)
            return ctx

        self.adapter = TrustedPluginAdapter(self.plugin, factory)

    async def test_every_hook_verb_and_panel_uses_fresh_factory_context(self):
        env, decision, data = {}, object(), {}
        hook_args = {"start": (), "on_connect": (), "on_tick": (),
                     "on_envelope": (env, decision), "on_local_event": ("event", data),
                     "on_revoke": ("alice",)}
        for hook in HOOKS:
            await getattr(self.adapter, hook)(self.fed, *hook_args[hook])
        await self.adapter.invoke(self.fed, "record", {}, "operator")
        self.adapter.panel(self.fed)
        self.assertEqual(len(self.contexts), 8)
        self.assertEqual(len({id(ctx) for ctx in self.contexts}), 8)
        for call, ctx in zip(self.plugin.calls, self.contexts):
            self.assertIs(call[1], ctx)
            self.assertIsNot(ctx, self.fed)
        received = next(c for c in self.plugin.calls if c[0] == "on_envelope")
        self.assertIs(received[2], env)
        self.assertIs(received[3], decision)
        self.assertIs(self.adapter.verbs()["record"], self.plugin.command)
        self.assertIs(self.adapter.verbs()["record"].fn, self.plugin.command.fn)
        self.adapter.contribution()
        self.assertIs(self.adapter.verbs()["record"].fn, self.plugin.command.fn)

    async def test_runtime_command_and_local_event_use_adapter(self):
        self.fed.verbs = {"fed_test_record": self.plugin.command}
        self.fed.plugin_verbs = {"fed_test_record": (self.adapter, "record")}
        self.fed.plugin_adapters = {"test": self.adapter}
        self.fed.log = lambda *args: self.fail("unexpected event failure")
        result = await self.fed.dispatch("fed_test_record", {"value": 1}, "operator")
        self.assertIs(result, self.contexts[0])
        await self.fed.local_event("event", {"value": 2})
        self.assertIs(self.plugin.calls[1][1], self.contexts[1])

    async def test_hub_peer_post_and_work_add_use_restricted_runtime_helpers(self):
        self.plugin.send = AsyncMock(return_value={"sent": True})
        self.plugin.add = AsyncMock(return_value={"work": True})
        self.fed.plugin_adapters = {"messages": self.adapter, "work": self.adapter}
        self.fed.cfg = {"federation": {"enabled": True, "peer": "nick", "url": "nats://unused"}}
        hub = object.__new__(Hub)
        hub.store = object()
        hub.fed = self.fed
        self.assertEqual(await hub.dispatch("post", {
            "to": "peer:alice", "body": "hello", "kind": "note", "ref": "ref1"
        }, "operator"), {"sent": True})
        self.assertIs(self.plugin.send.call_args.args[0], self.contexts[0])
        self.assertEqual(await hub.dispatch("work_add", {
            "federate": True, "to": "peer:alice", "title": "Task", "priority": 7
        }, "operator"), {"work": True})
        self.assertIs(self.plugin.add.call_args.args[0], self.contexts[1])
        self.assertEqual(self.plugin.add.call_args.args[-1], 7)

    def test_builtins_register_factories_and_custom_extensions_remain_explicit(self):
        self.fed.cfg = {"federation": {"plugins": list(BUILTIN)}}
        self.fed.plugins, self.fed.plugin_adapters, self.fed.routes = {}, {}, {}
        self.fed._load_plugins()
        for name in BUILTIN:
            self.assertIs(self.fed.plugin_adapters[name]._context_factory, builtin_context_factory(name))
        custom = TrustedPluginAdapter(self.plugin)
        self.assertIs(custom.context(self.fed), self.fed)
        self.assertEqual(custom.contribution()["context"], "legacy-federation")


class FederationDatabaseCancellation(unittest.IsolatedAsyncioTestCase):
    async def check_join(self, fail):
        loop = asyncio.get_running_loop()
        diagnostics = []
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: diagnostics.append(context))
        entered = asyncio.Event()
        release = threading.Event()
        completed = threading.Event()
        pool = ThreadPoolExecutor(max_workers=1)
        calls = []
        hub = object.__new__(Hub)
        hub.dbx = pool
        fed = object.__new__(Federation)
        fed.hub = hub

        def operation():
            calls.append(threading.get_ident())
            loop.call_soon_threadsafe(entered.set)
            release.wait()
            completed.set()
            if fail:
                raise ValueError("database operation failed")
            return "committed"

        task = asyncio.create_task(fed.db(operation))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertFalse(completed.is_set())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
            self.assertTrue(completed.is_set())
            self.assertEqual(len(calls), 1)
            await asyncio.sleep(0)
            self.assertEqual(len(diagnostics), 0, "cancelled database work leaked a private exception")
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
            pool.shutdown(wait=True)
            loop.set_exception_handler(previous_handler)

    async def test_cancellation_joins_original_executor_success_and_stays_cancelled(self):
        await self.check_join(False)

    async def test_cancellation_joins_original_executor_failure_and_stays_cancelled(self):
        await self.check_join(True)

    async def test_uncancelled_database_result_and_failure_are_preserved(self):
        fed = object.__new__(Federation)
        fed.hub = SimpleNamespace(db=AsyncMock(return_value="result"))
        self.assertEqual(await fed.db(lambda: None), "result")
        fed.hub.db.side_effect = ValueError("database operation failed")
        with self.assertRaisesRegex(ValueError, "database operation failed"):
            await fed.db(lambda: None)
