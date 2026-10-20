"""Offline checks for the Knowledge service boundary and its SQLite transaction."""
from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from hub.fed import envelope
from hub.fed.knowledge_services import build_knowledge_context
from hub.fed.plugins.knowledge import Knowledge
from hub.fed.runtime import Federation
from hub.store import Store, HubError
from hub.tests.test_fed_unit import policy


class KnowledgeServices(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(str(Path(self.temp.name) / "hub.db"))
        self.addCleanup(self.store.db.close)
        self.plugin = Knowledge()
        for sql in self.plugin.tables:
            self.store.db.execute(sql)
        self.fed = object.__new__(Federation)
        self.fed.cfg = {"federation": {"peer": "nick", "capture": True, "notify_findings": True}}
        self.fed.hub = SimpleNamespace(store=self.store, db=self.db)
        self.fed.node = "local"
        self.fed.policy = policy()
        self.fed.loop = self.fed.wake = None
        self.ctx = build_knowledge_context(self.fed)

    async def db(self, fn, *args, **kwargs):
        return fn(*args, **kwargs)

    async def share(self):
        return await self.plugin.v_share(self.ctx, {
            "repo": "falcon", "title": "Parser finding", "body": "tokenizing BOM", "tags": ["parser"]
        }, "operator")

    async def test_share_commits_outbox_audit_index_and_fts(self):
        result = await self.share()
        row = await self.plugin.v_show(self.ctx, {"id": result["id"]}, "operator")
        self.assertEqual(row["body"], "tokenizing BOM")
        self.assertEqual(row["author"], "operator")
        self.assertEqual(len(self.store.q("SELECT * FROM fed_outbox")), 1)
        self.assertEqual(len(self.store.q("SELECT * FROM fed_audit")), 1)
        hits = await self.plugin.v_search(self.ctx, {"query": "BOM"}, "operator")
        self.assertEqual([r["id"] for r in hits], [result["id"]])
        self.assertEqual(len(self.plugin.panel(self.ctx)["rows"]), 1)

    async def test_index_failure_rolls_back_outbox_and_audit(self):
        self.store.db.execute("CREATE TRIGGER reject_knowledge BEFORE INSERT ON p_knowledge_items "
                              "BEGIN SELECT RAISE(ABORT, 'test index failure'); END")
        with self.assertRaisesRegex(Exception, "test index failure"):
            await self.share()
        for table in ("fed_outbox", "fed_audit", "p_knowledge_items"):
            self.assertEqual(self.store.q(f"SELECT * FROM {table}"), [])

    async def test_settings_snapshot_and_current_capture_recheck(self):
        self.fed.fcfg["capture"] = False
        self.assertTrue(self.ctx.settings.capture)
        await self.plugin.on_local_event(self.ctx, "fed_result", {
            "repo": "falcon", "result": "done", "from_peer": "alice", "title": "task", "id": "w1"
        })
        self.assertEqual(self.store.q("SELECT * FROM fed_outbox"), [])
        # Explicit sharing remains available when automatic capture is disabled.
        self.assertIsNotNone(await self.share())

    async def test_share_rechecks_repository_after_db_dispatch(self):
        async def revoke_before_db(fn, *args, **kwargs):
            self.fed.policy = policy(repos={})
            return fn(*args, **kwargs)
        self.fed.hub.db = revoke_before_db
        with self.assertRaisesRegex(HubError, "sharing changed"):
            await self.share()
        self.assertEqual(self.store.q("SELECT * FROM fed_outbox"), [])

    async def test_inbound_index_dedup_revoke_and_notification(self):
        env = envelope.make("knowledge", "alice", "remote", self.fed.policy.rid_of("falcon"), "*",
                            {"title": "Parser BOM", "body": "private finding body", "author": "author"})
        decision = SimpleNamespace(local_repo="falcon", trust="flag", untrusted=True)
        self.store.post = Mock()
        await self.ctx.knowledge.index_received(env, decision)
        await self.ctx.knowledge.index_received(env, decision)
        await self.ctx.messages.finding(env, decision, "session")
        args = self.store.post.call_args.args
        self.assertNotIn("private finding body", args[3])
        self.assertIn("untrusted data", args[3])
        self.assertEqual(args[6], f"know:{env['id']}:session")
        self.fed.fcfg["notify_findings"] = False
        await self.ctx.messages.finding(env, decision, "session")
        self.assertEqual(self.store.post.call_count, 1)
        await self.plugin.on_revoke(self.ctx, "alice")
        rows = await self.plugin.v_recent(self.ctx, {}, "operator")
        self.assertEqual(len(rows), 1)
        self.assertIn("alice revoked", rows[0]["withdrawn"])
        self.assertEqual(len(await self.ctx.knowledge.search({"query": "BOM"})), 1)

    async def test_notification_rechecks_settings_after_database_dispatch(self):
        env = envelope.make("knowledge", "alice", "remote", self.fed.policy.rid_of("falcon"), "*",
                            {"title": "Finding"})
        decision = SimpleNamespace(local_repo="falcon", untrusted=False)
        self.store.post = Mock()
        async def disable_before_db(fn, *args, **kwargs):
            self.fed.fcfg["notify_findings"] = False
            return fn(*args, **kwargs)
        self.fed.hub.db = disable_before_db
        await self.ctx.messages.finding(env, decision, "session")
        self.store.post.assert_not_called()

    async def test_incoming_effects_recheck_peer_and_sharing_after_dispatch(self):
        env = envelope.make("knowledge", "alice", "remote", self.fed.policy.rid_of("falcon"), "*",
                            {"title": "Finding"})
        decision = SimpleNamespace(local_repo="falcon", trust="approve", untrusted=True, approved=True)
        self.store.post = Mock()
        for changed, expected in (
            (policy(peers={"alice": {"trust": "deny"}}), "denied"),
            (policy(repos={"falcon": {"peers": ["bob"]}}), "not_shared"),
            (policy(repos={}), "not_shared"),
        ):
            with self.subTest(expected=expected):
                self.fed.policy = policy()
                async def change_before_db(fn, *args, **kwargs):
                    self.fed.policy = changed
                    return fn(*args, **kwargs)
                self.fed.hub.db = change_before_db
                self.assertEqual(await self.plugin.on_envelope(self.ctx, env, decision), expected)
                self.assertEqual(self.store.q("SELECT * FROM p_knowledge_items"), [])
                await self.ctx.messages.finding(env, decision, "session")
                self.store.post.assert_not_called()

    async def test_runtime_approved_decision_is_preserved_when_current_scope_allows(self):
        env = envelope.make("knowledge", "alice", "remote", self.fed.policy.rid_of("falcon"), "*",
                            {"title": "Finding"})
        self.fed.policy = policy(peers={"alice": {"trust": "approve"}})
        decision = SimpleNamespace(local_repo="falcon", trust="approve", untrusted=True, approved=True)
        self.assertEqual(await self.ctx.knowledge.index_received(env, decision), "delivered")
        row = await self.ctx.knowledge.show({"id": env["id"]})
        self.assertEqual(row["trust"], "approve")
        self.assertEqual(row["untrusted"], 1)

    async def test_capture_sources_and_remote_work_exclusion(self):
        events = [
            ("work_released", {"repo": "falcon", "state": "done", "result": "work result",
                               "title": "task", "id": "w1", "claimed_by": "operator"}),
            ("handoff_sent", {"repo": "falcon", "by": "operator", "to": "agent", "body": "handoff result"}),
            ("fed_result", {"repo": "falcon", "result": "peer result", "from_peer": "alice",
                            "title": "task", "id": "w2"}),
        ]
        for kind, data in events:
            await self.plugin.on_local_event(self.ctx, kind, data)
        await self.plugin.on_local_event(self.ctx, "work_released", {
            **events[0][1], "claimed_by": "fed:alice"
        })
        rows = await self.ctx.knowledge.recent({})
        self.assertEqual({row["source"] for row in rows}, {"auto:work", "auto:handoff", "auto:result"})
        self.assertEqual(len(rows), 3)

    async def test_redacted_finding_is_identical_in_outbox_and_index(self):
        import json
        result = await self.plugin.v_share(self.ctx, {
            "repo": "falcon", "title": "Finding", "body": "DB_PASSWORD=supersecret1"
        }, "operator")
        row = await self.ctx.knowledge.show({"id": result["id"]})
        sent = json.loads(self.store.q1("SELECT payload FROM fed_outbox")["payload"])
        self.assertEqual(sent["data"]["body"], row["body"])
        self.assertNotIn("supersecret1", row["body"])
        self.assertTrue(result["redacted"])

    def test_context_has_only_read_only_named_services(self):
        for value in (self.ctx, self.ctx.knowledge, self.ctx.agents, self.ctx.messages):
            for name in ("hub", "store", "db", "nc", "js", "federation", "stage", "publish"):
                self.assertFalse(hasattr(value, name), name)
        with self.assertRaises(FrozenInstanceError):
            self.ctx.settings.capture = False
        with self.assertRaises(FrozenInstanceError):
            self.ctx.knowledge = None
        sender = self.ctx.agents.sender_of("operator")
        with self.assertRaises(TypeError):
            sender["operator"] = False
