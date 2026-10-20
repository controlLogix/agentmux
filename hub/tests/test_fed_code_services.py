"""Offline checks for the restricted legacy Code services."""
import sqlite3
import unittest
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from hub.fed import envelope
from hub.fed.code_services import Checkout, GitOperations, build_code_context
from hub.fed.plugins.code import PLUGIN
from hub.fed.policy import Policy, rid_for_remote
from hub.store import HubError


class CodeServices(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute(PLUGIN.tables[0])
        self.db.execute("CREATE TABLE outbox (id TEXT)")
        cfg = {"federation": {"peer": "alice"}, "repos": {"repo": {"remote": "https://example.test/repo"}},
               "peers": {"bob": {"trust": "auto"}}}
        self.fed = SimpleNamespace(me="alice", node="one", fcfg=cfg["federation"], policy=Policy(cfg, {}),
                                   hub=SimpleNamespace(io=None), store=SimpleNamespace(db=self.db, tx=lambda: self.db))
        async def db(fn, *args):
            return fn(*args)
        self.fed.db = db
        def stage(env, *args):
            self.db.execute("INSERT INTO outbox VALUES (?)", (env["id"],))
            return env, []
        self.fed.stage = stage
        self.ctx = build_code_context(self.fed)
        self.rid = rid_for_remote("https://example.test/repo")
        self.checkout = Checkout("repo", self.rid, "/fixture", "origin", "https://example.test/repo")

    def test_context_is_frozen_and_has_no_raw_service_handles(self):
        for name in ("hub", "store", "db", "nc", "js", "plugins", "fcfg"):
            self.assertFalse(hasattr(self.ctx, name))
        with self.assertRaises(FrozenInstanceError):
            self.ctx.me = "other"
        with self.assertRaises(TypeError):
            self.ctx.policy._shared["repo"] = "other"
        self.fed.fcfg["code_remote"] = "new"
        self.fed.policy._rid.clear()
        self.assertEqual(self.ctx.settings.code_remote, "origin")
        self.assertEqual(self.ctx.policy.rid_of("repo"), self.rid)

    async def test_policy_change_blocks_git_push_from_old_snapshot(self):
        self.fed.policy._rid.clear()
        with patch.object(GitOperations, "_run", new_callable=AsyncMock) as run:
            with self.assertRaises(HubError):
                await self.ctx.git.push(self.checkout, "a" * 40, "refs/agentmux/alice/wip")
            run.assert_not_awaited()

    async def test_remote_lookup_rechecks_policy_before_push(self):
        async def changed(*args):
            self.fed.policy._rid.clear()
            return self.checkout.url
        with patch.object(GitOperations, "_run", new=AsyncMock(side_effect=changed)) as run:
            with self.assertRaises(HubError):
                await self.ctx.git.push(self.checkout, "a" * 40, "refs/agentmux/alice/wip")
            self.assertEqual(run.await_count, 1)

    async def test_fetch_sha_mismatch_does_not_mark_fetched(self):
        share = {"ref": "refs/agentmux/bob/wip", "sha": "a" * 40, "from_peer": "bob", "repo": "repo", "rid": self.rid}
        ctx = SimpleNamespace(shares=SimpleNamespace(get=AsyncMock(return_value=share), mark_fetched=AsyncMock()),
                              repositories=SimpleNamespace(checkout=AsyncMock(return_value=self.checkout)), git=self.ctx.git)
        with patch.object(GitOperations, "_run", new=AsyncMock(side_effect=[self.checkout.url, "", "b" * 40])):
            with self.assertRaisesRegex(HubError, "sha mismatch"):
                await PLUGIN.v_fetch(ctx, {"id": "share"}, "operator")
        ctx.shares.mark_fetched.assert_not_awaited()

    async def test_share_and_outbox_roll_back_together(self):
        env = envelope.make("code", "alice", "one", self.rid, "*",
                            {"ref": "refs/agentmux/alice/wip", "sha": "a" * 40})
        self.db.execute("CREATE TRIGGER reject_share BEFORE INSERT ON p_code_shares BEGIN SELECT RAISE(ABORT, 'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            await self.ctx.shares.publish(env, "repo")
        self.assertEqual(self.db.execute("SELECT count(*) FROM outbox").fetchone()[0], 0)
        self.db.execute("DROP TRIGGER reject_share")
        await self.ctx.shares.publish(env, "repo")
        self.assertEqual(self.db.execute("SELECT count(*) FROM outbox").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT ref,sha FROM p_code_shares").fetchone(),
                         ("refs/agentmux/alice/wip", "a" * 40))

    async def test_receive_rechecks_current_policy(self):
        env = envelope.make("code", "bob", "two", self.rid, "*",
                            {"ref": "refs/agentmux/bob/wip", "sha": "a" * 40})
        self.fed.policy.cfg["peers"]["bob"]["trust"] = "deny"
        self.assertEqual(await PLUGIN.on_envelope(self.ctx, env, SimpleNamespace()), "dropped")
        self.assertEqual(self.db.execute("SELECT count(*) FROM p_code_shares").fetchone()[0], 0)

    async def test_runtime_approval_and_original_framing_are_preserved(self):
        from hub.fed.guard import Decision
        env = envelope.make("code", "bob", "two", self.rid, "*",
                            {"ref": "refs/agentmux/bob/wip", "sha": "a" * 40})
        approved = Decision("deliver", trust="approve", untrusted=True, local_repo="repo", approved=True)
        current = Decision("quarantine", trust="approve", untrusted=True, local_repo="repo")
        with patch("hub.fed.code_services.guard.inbound", return_value=current):
            self.assertEqual(await self.ctx.shares.receive(env, approved), "delivered")
        self.assertEqual(self.db.execute("SELECT untrusted FROM p_code_shares").fetchone()[0], 1)
        current = Decision("deliver", trust="auto", untrusted=False, local_repo="repo")
        with patch("hub.fed.code_services.guard.inbound", return_value=current):
            self.assertEqual(await self.ctx.shares.receive({**env, "id": "another"}, approved), "delivered")
        self.assertEqual(self.db.execute("SELECT untrusted FROM p_code_shares WHERE id='another'").fetchone()[0], 1)

    async def test_approval_cannot_override_removed_or_remapped_scope(self):
        from hub.fed.guard import Decision
        env = envelope.make("code", "bob", "two", self.rid, "*",
                            {"ref": "refs/agentmux/bob/wip", "sha": "a" * 40})
        approved = Decision("deliver", trust="approve", untrusted=True, local_repo="old", approved=True)
        self.assertEqual(await self.ctx.shares.receive(env, approved), "dropped")
        self.fed.policy._local.clear()
        self.assertEqual(await self.ctx.shares.receive(env, approved), "dropped")
        self.assertEqual(self.db.execute("SELECT count(*) FROM p_code_shares").fetchone()[0], 0)

    def test_context_repr_omits_private_owner_contents(self):
        self.fed.private_fixture = "private-owner-marker"
        self.assertNotIn("private-owner-marker", repr(self.ctx))
        self.assertNotIn("_owner=", repr(self.ctx))

    async def test_cancelled_git_call_joins_original_executor_success_and_failure(self):
        import asyncio
        from concurrent.futures import Executor, Future

        class PendingExecutor(Executor):
            def __init__(self):
                self.started = asyncio.Event()
                self.worker = Future()
                self.calls = 0

            def submit(self, fn, *args, **kwargs):
                self.calls += 1
                self.worker.set_running_or_notify_cancel()
                self.started.set()
                return self.worker

        for failure in (False, True):
            with self.subTest(failure=failure):
                executor = PendingExecutor()
                self.fed.hub.io = executor
                caller = asyncio.create_task(self.ctx.git._run("/fixture", "push"))
                await executor.started.wait()
                caller.cancel()
                await asyncio.sleep(0)
                self.assertFalse(caller.done())
                self.assertFalse(executor.worker.cancelled())
                caller.cancel()
                await asyncio.sleep(0)
                self.assertFalse(caller.done())
                if failure:
                    executor.worker.set_exception(HubError("private git failure fixture"))
                else:
                    executor.worker.set_result("pushed")
                with self.assertRaises(asyncio.CancelledError):
                    await caller
                self.assertTrue(executor.worker.done())
                self.assertEqual(executor.calls, 1)
