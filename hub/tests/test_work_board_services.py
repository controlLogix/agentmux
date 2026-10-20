"""Offline compatibility checks for restricted work and board services."""
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from hub.fed import ledger
from hub.fed.board_services import build_board_context
from hub.fed.plugins.board import Board
from hub.fed.plugins.work import Work
from hub.fed.runtime import Federation
from hub.fed.session import FederationSession
from hub.fed.work_services import build_work_context
from hub.store import HubError, Store
from hub.tests.test_fed_unit import policy


class WorkBoardServices(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(str(Path(self.tmp.name) / "hub.db"))
        self.store.repo_add("falcon")
        for sql in Board.tables:
            self.store.db.execute(sql)

        async def db(fn, *args, **kwargs):
            return fn(*args, **kwargs)

        self.owner = SimpleNamespace(me="nick", node="mac", store=self.store, db=db,
                                     policy=policy(), presence={}, session=FederationSession(),
                                     hub=SimpleNamespace(sender_of=lambda caller: caller), kick=lambda: None)
        for name in ("sender_of", "resolve_repo", "address_of", "stage", "publish"):
            setattr(self.owner, name, getattr(Federation, name).__get__(self.owner))

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    async def test_contexts_are_frozen_without_raw_runtime_access(self):
        for ctx in (build_work_context(self.owner), build_board_context(self.owner)):
            for name in ("hub", "store", "db", "js", "nc", "session", "policy"):
                self.assertFalse(hasattr(ctx, name), name)
            field = next(iter(ctx.__dataclass_fields__))
            with self.assertRaises(FrozenInstanceError):
                setattr(ctx, field, None)

    async def test_stale_consumer_and_projection_refuse_replaced_session(self):
        work, board = build_work_context(self.owner), build_board_context(self.owner)
        self.owner.session = FederationSession()
        with self.assertRaisesRegex(HubError, "stale"):
            await work.consumer.poll()
        with self.assertRaisesRegex(HubError, "stale"):
            await board.projection.connect()

    async def test_work_add_commits_placeholder_and_outbox_together(self):
        result = await Work().add(build_work_context(self.owner), "operator", "role:falcon/worker", "test")
        row = self.store.work(result["id"])
        self.assertEqual((row["state"], row["claimed_by"]), ("claimed", "fed:pending"))
        self.assertEqual(len(ledger.outbox_pending(self.store)), 1)
        flags = json.loads(row["fed_flags"])
        self.assertEqual(flags["env"], result["federated"])
        self.assertEqual(flags["protocol"], 3)

    async def test_failed_work_staging_rolls_back_placeholder_and_outbox(self):
        stage = self.owner.stage

        def fail_after_stage(*args):
            stage(*args)
            raise HubError("staging failed")

        self.owner.stage = fail_after_stage
        with self.assertRaisesRegex(HubError, "staging failed"):
            await Work().add(build_work_context(self.owner), "operator", "role:falcon/worker", "test")
        self.assertEqual(self.store.q("SELECT * FROM work_items"), [])
        self.assertEqual(ledger.outbox_pending(self.store), [])
        self.assertEqual(ledger.audit_tail(self.store), [])

    async def test_board_conflict_rereads_card_and_preserves_other_writer(self):
        from nats.js.errors import KeyWrongLastSequenceError
        rid = self.owner.policy.rid_of("falcon")
        base = {"key": "SH-1", "rid": rid, "title": "original", "status": "todo", "history": []}
        entries = [SimpleNamespace(value=json.dumps(base).encode(), revision=1),
                   SimpleNamespace(value=json.dumps({**base, "title": "other writer"}).encode(), revision=2)]
        kv = SimpleNamespace(get=AsyncMock(side_effect=entries),
                             update=AsyncMock(side_effect=[KeyWrongLastSequenceError(), 3]))
        self.owner.kv = AsyncMock(return_value=kv)
        with patch("hub.fed.board_services.asyncio.sleep", new_callable=AsyncMock):
            result = await Board().v_move(build_board_context(self.owner),
                                          {"key": "SH-1", "repo": "falcon", "status": "doing"}, "operator")
        self.assertEqual((result["title"], result["status"], result["rev"], result["attempts"]),
                         ("other writer", "doing", 3, 2))
        self.assertEqual([c.kwargs["last"] for c in kv.update.await_args_list], [1, 2])
        row = self.store.q1("SELECT card, rev FROM p_board_cards")
        self.assertEqual((json.loads(row["card"])["title"], row["rev"]), ("other writer", 3))
        self.assertEqual(len(ledger.audit_tail(self.store)), 1)

    async def test_board_policy_change_during_get_blocks_update(self):
        rid = self.owner.policy.rid_of("falcon")
        card = {"key": "SH-1", "rid": rid, "title": "original", "status": "todo", "history": []}

        async def get(key):
            self.owner.policy = policy(repos={})
            return SimpleNamespace(value=json.dumps(card).encode(), revision=1)

        kv = SimpleNamespace(get=AsyncMock(side_effect=get), update=AsyncMock())
        self.owner.kv = AsyncMock(return_value=kv)
        with self.assertRaisesRegex(HubError, "sharing changed"):
            await Board().v_move(build_board_context(self.owner),
                                 {"key": "SH-1", "repo": "falcon", "status": "doing"}, "operator")
        kv.update.assert_not_awaited()
        self.assertEqual(self.store.q("SELECT * FROM p_board_cards"), [])
        self.assertEqual(ledger.audit_tail(self.store), [])

    async def test_work_repository_remapped_while_db_queued_creates_nothing(self):
        from hub.fed.policy import Policy, normalize_remote
        changed = Policy({"federation": {"peer": "nick"}, "repos": {"falcon": {"peers": ["*"]}},
                          "peers": {}}, {"falcon": normalize_remote("https://github.com/adag/other.git")})
        self.assertNotEqual(changed.rid_of("falcon"), self.owner.policy.rid_of("falcon"))

        async def queued_db(fn, *args, **kwargs):
            self.owner.policy = changed
            return fn(*args, **kwargs)

        self.owner.db = queued_db
        with self.assertRaisesRegex(HubError, "sharing changed"):
            await Work().add(build_work_context(self.owner), "operator", "role:falcon/worker", "test")
        self.assertEqual(self.store.q("SELECT * FROM work_items"), [])
        self.assertEqual(ledger.outbox_pending(self.store), [])
        self.assertEqual(ledger.audit_tail(self.store), [])

    async def test_session_replaced_during_recovery_cannot_subscribe(self):
        first_js = SimpleNamespace(pull_subscribe=AsyncMock())
        replacement_js = SimpleNamespace(pull_subscribe=AsyncMock())
        self.owner.js, self.owner.peer_ids = first_js, set()

        async def recover(operations, owner):
            owner.session, owner.js = FederationSession(), replacement_js

        async def db(fn, *args, **kwargs):
            if fn == self.store.agents:
                return [{"repo": "falcon", "role": "worker", "state": "idle", "session": "falcon-worker-one",
                         "role_snapshot": '{"max_active":1}'}]
            return fn(*args, **kwargs)

        self.owner.db = db
        with patch("hub.fed.work_services._WorkTransactions.recover_results", new=recover):
            with self.assertRaisesRegex(HubError, "stale"):
                await build_work_context(self.owner).consumer.poll()
        first_js.pull_subscribe.assert_not_awaited()
        replacement_js.pull_subscribe.assert_not_awaited()

    async def test_session_replaced_during_fetch_does_not_dispatch_message(self):
        rid = self.owner.policy.rid_of("falcon")
        self.owner.js = SimpleNamespace(pull_subscribe=AsyncMock())
        self.owner.peer_ids = set()
        self.owner.receive = AsyncMock()

        async def fetch(*args, **kwargs):
            self.owner.session = FederationSession()
            return [SimpleNamespace(subject="unused", data=b"unused")]

        subscription = SimpleNamespace(fetch=AsyncMock(side_effect=fetch))
        self.owner.session.work_subscriptions[("nick", rid, "worker")] = subscription

        async def db(fn, *args, **kwargs):
            if fn == self.store.agents:
                return [{"repo": "falcon", "role": "worker", "state": "idle", "session": "falcon-worker-one",
                         "role_snapshot": '{"max_active":1}'}]
            return fn(*args, **kwargs)

        self.owner.db = db
        with self.assertRaisesRegex(HubError, "stale"):
            await build_work_context(self.owner).consumer.poll()
        subscription.fetch.assert_awaited_once()
        self.owner.receive.assert_not_awaited()
        self.owner.js.pull_subscribe.assert_not_awaited()

    async def test_incoming_work_denied_while_db_queued_has_no_effect(self):
        from hub.fed import envelope, guard
        from hub.fed.work_services import offer_digest
        rid = self.owner.policy.rid_of("falcon")
        env = envelope.make("work", "alice", "sender", rid, "*",
                            {"origin_id": "W-original", "title": "test", "role": "worker"})
        env["data"]["offer_digest"] = offer_digest(env)
        decision = guard.Decision("deliver", local_repo="falcon")

        async def queued_db(fn, *args, **kwargs):
            self.owner.policy = policy(peers={"alice": {"trust": "deny"}})
            return fn(*args, **kwargs)

        self.owner.db = queued_db
        result = await Work().on_envelope(build_work_context(self.owner), env, decision)
        self.assertEqual(result, "dropped")
        self.assertEqual(self.store.q("SELECT * FROM work_items"), [])
        self.assertEqual(ledger.outbox_pending(self.store), [])
        self.assertEqual(ledger.audit_tail(self.store), [])

    async def test_policy_withdrawn_during_subscription_setup_prevents_fetch(self):
        subscription = SimpleNamespace(fetch=AsyncMock(), unsubscribe=AsyncMock())
        session = self.owner.session

        async def subscribe(*args, **kwargs):
            self.owner.policy = policy(repos={})
            return subscription

        self.owner.js = SimpleNamespace(pull_subscribe=AsyncMock(side_effect=subscribe))
        self.owner.peer_ids = set()

        async def db(fn, *args, **kwargs):
            if fn == self.store.agents:
                return [{"repo": "falcon", "role": "worker", "state": "idle", "session": "falcon-worker-one",
                         "role_snapshot": '{"max_active":1}'}]
            return fn(*args, **kwargs)

        self.owner.db = db
        try:
            await build_work_context(self.owner).consumer.poll()
            self.owner.js.pull_subscribe.assert_awaited_once()
            subscription.fetch.assert_not_awaited()
        finally:
            await session.close()
        subscription.unsubscribe.assert_awaited_once()

    async def test_board_policy_change_after_mirror_blocks_notification(self):
        from hub.fed.board_services import _BoardOperations
        for changed in (policy(repos={}), policy(peers={"alice": {"trust": "deny"}})):
            with self.subTest(policy=changed):
                self.owner.policy = policy()
                self.store.db.execute("DELETE FROM p_board_cards")
                rid = self.owner.policy.rid_of("falcon")
                card = {"key": "SH-1", "rid": rid, "title": "assignment", "status": "todo",
                        "updated_by": "peer:alice", "assignee": "peer:nick/falcon/worker", "history": []}
                entry = SimpleNamespace(key=f"{rid}.card.SH-1", value=json.dumps(card).encode(),
                                        revision=1, operation=None)
                calls = 0

                async def db(fn, *args, **kwargs):
                    nonlocal calls
                    calls += 1
                    result = fn(*args, **kwargs)
                    if calls == 3:  # Projection and its audit committed before the policy changed.
                        self.owner.policy = changed
                    return result

                self.owner.db = db
                await _BoardOperations()._on_entry(self.owner, entry)
                self.assertEqual(len(self.store.q("SELECT * FROM p_board_cards")), 1)
                self.assertEqual(self.store.q("SELECT * FROM messages"), [])

    async def test_board_queued_purge_rechecks_current_sharing(self):
        from hub.fed.board_services import _BoardOperations
        operations = _BoardOperations()
        rid = self.owner.policy.rid_of("falcon")
        card = {"key": "SH-1", "updated_by": "peer:alice"}
        operations._mirror(self.owner, rid, "SH-1", card, 1)

        async def db(fn, *args, **kwargs):
            self.owner.policy = policy(repos={})
            return fn(*args, **kwargs)

        self.owner.db = db
        await operations._on_entry(self.owner, SimpleNamespace(key=f"{rid}.card.SH-1", operation="PURGE"))
        self.assertEqual(self.store.q1("SELECT deleted FROM p_board_cards")["deleted"], 0)

    async def test_board_delete_is_refused_after_legacy_writer_fence(self):
        from hub.fed.board_services import _BoardOperations
        operations = _BoardOperations()
        rid = self.owner.policy.rid_of("falcon")
        operations._mirror(self.owner, rid, "SH-1", {"key": "SH-1", "updated_by": "peer:alice"}, 1)
        self.store.fence_legacy_writer()
        with self.assertRaisesRegex(HubError, '^legacy writer is fenced for migration$'):
            await operations._on_entry(self.owner,
                SimpleNamespace(key=f"{rid}.card.SH-1", operation="DEL"))
        self.assertEqual(self.store.q1("SELECT deleted FROM p_board_cards")["deleted"], 0)
