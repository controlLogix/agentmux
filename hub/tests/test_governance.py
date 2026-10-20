"""Regression evidence for AMX-BASE-001 through AMX-BASE-006.

Use temporary stores and injected failures; never touch a user's running hub.
"""
from hub.fed.work_services import build_work_context

import asyncio
from contextlib import closing
import concurrent.futures
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from hub.fed import envelope, guard
from hub.store import Store
from hub.tests.test_fed_unit import policy


class AuthorizationBinding(unittest.TestCase):
    def test_work_cannot_enter_through_information_plane(self):
        p = policy()
        rid = p.rid_of("falcon")
        e = envelope.make("work", "mallory", "remote", rid, "*",
                          {"origin_id": "W-example", "role": "worker", "title": "review"})
        for subject in (f"am.know.mallory.{rid}", f"am.code.mallory.{rid}"):
            with self.subTest(subject=subject):
                self.assertEqual(guard.inbound(p, subject, e).action, "drop")

    def test_subject_destination_repository_and_role_match(self):
        p = policy()
        rid = p.rid_of("falcon")
        work = envelope.make("work", "alice", "remote", rid, "*", {"role": "worker", "title": "review"})
        msg = envelope.make("message", "alice", "remote", None, "nick", {"body": "hi"})
        for subject, env in [(f"am.work.alice.r000000000000.worker.v3", work),
                             (f"am.work.alice.{rid}.lead.v3", work),
                             (f"am.msg.alice.mallory", msg),
                             (f"am.msg.alice.nick.extra", msg),
                             (f"am.msg.alice.nick", {**msg, "to": "mallory"})]:
            with self.subTest(subject=subject, env=env):
                self.assertEqual(guard.inbound(p, subject, env).action, "drop")


class BackupIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="amx-gov-")
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "hub.db"))
        self.addCleanup(self.store.db.close)
        self.store.repo_add("fixture")
        self.dest = os.path.join(self.tmp.name, "backups")

    def test_frozen_clock_keeps_distinct_restorable_snapshots(self):
        paths = []
        with patch("hub.store.time.time", return_value=1_700_000_000.123):
            for i in range(5):
                self.store.repo_add("fixture", title=f"revision {i}")
                paths.append(self.store.backup_to(self.dest, keep=10))
        self.assertEqual(len(set(paths)), 5)
        for i, path in enumerate(paths):
            with closing(sqlite3.connect(path)) as restored:
                self.assertEqual(restored.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(restored.execute("SELECT title FROM repos").fetchone()[0], f"revision {i}")

    def test_second_boundary_uses_one_timestamp_for_backup_rotation(self):
        # A previous gmtime() sample followed by the next second's milliseconds
        # can sort the newest backup before the old one and prune it immediately.
        real_gmtime = __import__('time').gmtime
        before = 1_700_000_000.999
        after = 1_700_000_001.001
        def clock_gmtime(value=None):
            return real_gmtime(before if value is None else value)
        with patch("hub.store.time.gmtime", side_effect=clock_gmtime):
            with patch("hub.store.time.time", return_value=before):
                first = self.store.backup_to(self.dest, keep=1)
            self.store.repo_add("fixture", title="newest")
            with patch("hub.store.time.time", return_value=after):
                newest = self.store.backup_to(self.dest, keep=1)
        self.assertFalse(Path(first).exists())
        self.assertTrue(Path(newest).exists())
        self.assertEqual([p.name for p in Path(self.dest).iterdir()], [Path(newest).name])
        with closing(sqlite3.connect(newest)) as restored:
            self.assertEqual(restored.execute("SELECT title FROM repos").fetchone()[0], "newest")

    def test_failed_copy_does_not_publish_or_prune_a_snapshot(self):
        good = self.store.backup_to(self.dest, keep=1)
        original = Path(good).read_bytes()
        with patch.object(self.store, "backup", side_effect=OSError("injected disk failure")):
            with self.assertRaises(OSError):
                self.store.backup_to(self.dest, keep=1)
        self.assertEqual(Path(good).read_bytes(), original)
        self.assertEqual([p.name for p in Path(self.dest).iterdir()], [Path(good).name])

    def test_concurrent_stores_do_not_replace_snapshots(self):
        def backup(i):
            s = Store(os.path.join(self.tmp.name, f"source{i}.db"))
            try:
                s.repo_add("fixture", title=str(i))
                return i, s.backup_to(self.dest, keep=20)
            finally:
                s.db.close()
        with patch("hub.store.time.time", return_value=1_700_000_000.123):
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                result = list(pool.map(backup, range(8)))
        self.assertEqual(len({p for _, p in result}), 8)
        for i, path in result:
            with closing(sqlite3.connect(path)) as restored:
                self.assertEqual(restored.execute("SELECT title FROM repos").fetchone()[0], str(i))


class LocalContext:
    """Real store and guard/outbox boundaries with an in-process scheduler."""
    def __init__(self, directory, peer="nick", node="origin"):
        from hub.fed import ledger
        self.me, self.node = peer, node
        self.store = Store(os.path.join(directory, "hub.db"))
        self.store.repo_add("falcon")
        self.policy = policy(me=peer, peers={"nick": {"trust": "auto"}, "alice": {"trust": "auto"}, "bob": {"trust": "auto"}})
        self.hub = SimpleNamespace(sender_of=lambda caller: caller, _notify_work_owner=self._notify_work_owner)
        self.notifications = []
        self.peer_ids = {"nick", "alice", "bob"} - {peer}

    async def db(self, fn, *a, **kw):
        return fn(*a, **kw)

    def sender_of(self, caller):
        return {"operator": True}

    def address_of(self, peer, sender):
        return f"peer:{peer}"

    def stage(self, env, subject, local_repo=None, to_peer=None):
        from hub.fed import ledger
        clean, kinds = guard.outbound(self.policy, env, local_repo, to_peer)
        ledger.outbox_add(self.store, clean["id"], subject, clean)
        return clean, kinds

    async def publish(self, env, subject, local_repo=None, to_peer=None):
        with self.store.tx():
            return self.stage(env, subject, local_repo, to_peer)

    async def local_event(self, *args):
        pass

    async def _notify_work_owner(self, *args):
        self.notifications.append(args)

    def log(self, *args):
        pass


class WorkRecovery(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from hub.fed.plugins.work import Work
        self.tmp = tempfile.TemporaryDirectory(prefix="amx-work-")
        self.addCleanup(self.tmp.cleanup)
        self.ctx = LocalContext(self.tmp.name, peer="alice", node="receiver")
        self.addCleanup(self.ctx.store.db.close)
        self.plugin = Work()
        self.rid = self.ctx.policy.rid_of("falcon")

    def offer(self, node="origin"):
        from hub.fed.plugins.work import offer_digest
        env = envelope.make("work", "nick", node, self.rid, "*",
                            {"origin_id": "W-original", "title": "review fixture", "role": "worker"})
        env["data"]["offer_digest"] = offer_digest(env)
        return env

    async def test_incoming_creation_rolls_back_when_attribution_fails(self):
        # A SQLite trigger injects failure exactly where the old second transaction ran.
        self.ctx.store.db.execute("CREATE TRIGGER fail_attribution BEFORE UPDATE OF origin_peer ON work_items "
                                  "BEGIN SELECT RAISE(ABORT, 'injected attribution failure'); END")
        env = self.offer()
        with self.assertRaises(sqlite3.IntegrityError):
            await self.plugin.on_envelope(build_work_context(self.ctx), env, guard.Decision("deliver", local_repo="falcon"))
        self.assertEqual(self.ctx.store.q("SELECT * FROM work_items"), [])

    async def test_same_peer_other_node_is_not_discarded(self):
        self.ctx.me = "nick"
        self.ctx.policy = policy(me="nick")
        env = self.offer()
        outcome = await self.plugin.on_envelope(build_work_context(self.ctx), env, guard.Decision("deliver", local_repo="falcon"))
        self.assertNotEqual(outcome, "stale")
        self.assertEqual(len(self.ctx.store.q("SELECT * FROM work_items")), 1)

    async def test_wrong_peer_result_does_not_complete_origin(self):
        from hub.fed.plugins.work import PENDING
        w = self.ctx.store.work_create("operator", "falcon", "role:falcon/worker", "review")
        flags = {"outgoing": True, "env": "original-offer", "rid": self.rid,
                 "executor": {"peer": "nick", "node": "selected", "execution_id": "execution"}}
        self.ctx.store.db.execute("UPDATE work_items SET state='claimed', claimed_by=?, fed_flags=? WHERE id=?",
                                  (PENDING, json.dumps(flags), w["id"]))
        env = envelope.make("result", "bob", "unselected", self.rid, "alice",
                             {"origin_id": w["id"], "state": "done", "result": "forged"})
        await self.plugin.on_envelope(build_work_context(self.ctx), env, guard.Decision("deliver", local_repo="falcon"))
        self.assertEqual(self.ctx.store.work(w["id"])["claimed_by"], PENDING)

    async def test_completion_keeps_durable_return_intent_without_callback(self):
        w = self.ctx.store.work_create("peer:nick", "falcon", "role:falcon/worker", "review")
        flags = {"origin_id": "W-original", "env": "offer", "rid": self.rid}
        self.ctx.store.db.execute("UPDATE work_items SET state='claimed', claimed_by='worker', origin_peer='nick', "
                                  "fed_flags=? WHERE id=?", (json.dumps(flags), w["id"]))
        self.ctx.store.release("worker", w["id"], "done", "fixture verified", "receiver")
        # No callback was delivered; only committed store state may establish the obligation.
        row = self.ctx.store.work(w["id"])
        self.assertTrue(json.loads(row["fed_flags"]).get("result_pending"))
        self.assertTrue(json.loads(row["fed_flags"]).get("result_id"))


class WorkProtocol(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from hub.fed.plugins.work import Work
        self.tmp = tempfile.TemporaryDirectory(prefix="amx-protocol-")
        self.addCleanup(self.tmp.cleanup)
        self.origin = LocalContext(os.path.join(self.tmp.name, "origin"), "nick", "origin")
        self.a = LocalContext(os.path.join(self.tmp.name, "a"), "alice", "a")
        self.b = LocalContext(os.path.join(self.tmp.name, "b"), "bob", "b")
        for ctx in [self.origin, self.a, self.b]: self.addCleanup(ctx.store.db.close)
        self.p = Work()
        self.w = await self.p.add(build_work_context(self.origin), "operator", "role:falcon/worker", "Read fixture", "report checksum")
        self.offer = self.outbox(self.origin, "work")[0]

    def outbox(self, ctx, kind):
        return [json.loads(r["payload"]) for r in ctx.store.q("SELECT payload FROM fed_outbox ORDER BY seq")
                if json.loads(r["payload"])["type"] == kind]

    async def deliver(self, ctx, env):
        plane = envelope.PLANE_OF[env["type"]]
        tail = [env["rid"], env["data"]["role"]] if plane == "work" else [env["to"]]
        dec = guard.inbound(ctx.policy, envelope.subject(plane, env["from"], *tail), env)
        self.assertEqual(dec.action, "deliver", dec.reason)
        return await self.p.on_envelope(build_work_context(ctx), env, dec)

    async def grant(self, receiver):
        await self.deliver(receiver, self.offer)
        claim = self.outbox(receiver, "work_claim")[0]
        await self.deliver(self.origin, claim)
        grant = [e for e in self.outbox(self.origin, "work_grant") if e["to"] == receiver.me][-1]
        await self.deliver(receiver, grant)
        return receiver.store.q("SELECT * FROM work_items")[0]

    async def complete(self, receiver):
        w = await self.grant(receiver)
        session = receiver.store.register("falcon", "worker", "one", "codex", {"capabilities": [], "max_active": 1})
        receiver.store.set_state(session, "ready")
        self.assertIsNotNone(receiver.store.claim(session, work_id=w["id"])["claimed"])
        receiver.store.release(session, w["id"], "done", "checksum verified", receiver.node)
        return w

    async def test_two_receivers_only_origin_selected_one_becomes_ready(self):
        await self.grant(self.a)
        await self.grant(self.b)
        self.assertEqual(self.a.store.q1("SELECT state FROM work_items")["state"], "ready")
        self.assertEqual(self.b.store.q1("SELECT state FROM work_items")["state"], "cancelled")
        flags = json.loads(self.origin.store.work(self.w["id"])["fed_flags"])
        self.assertEqual(flags["executor"]["peer"], "alice")
        # Redelivery after origin reserved work cannot reopen its own placeholder.
        await self.deliver(self.origin, self.offer)
        self.assertEqual(self.origin.store.work(self.w["id"])["claimed_by"], "fed:pending")

    async def test_receive_is_atomic_with_claim_and_retry_after_injected_crash(self):
        with patch.object(self.a, "stage", side_effect=OSError("crash before claim commit")):
            with self.assertRaises(OSError): await self.deliver(self.a, self.offer)
        self.assertEqual(self.a.store.q("SELECT * FROM work_items"), [])
        await self.deliver(self.a, self.offer)
        await self.deliver(self.a, self.offer)
        self.assertEqual(len(self.a.store.q("SELECT * FROM work_items")), 1)
        self.assertEqual(len(self.outbox(self.a, "work_claim")), 1)
        self.assertEqual(self.a.store.q1("SELECT state FROM work_items")["state"], "blocked")

    async def test_completion_recovers_after_restart_and_failed_staging(self):
        w = await self.complete(self.a)
        identity = json.loads(self.a.store.work(w["id"])["fed_flags"])["result_id"]
        # Close and reopen the store, without ever delivering the release callback.
        self.a.store.db.close()
        self.a.store = Store(self.a.store.path)
        self.addCleanup(self.a.store.db.close)
        with patch.object(self.a, "stage", side_effect=OSError("publish staging unavailable")):
            await self.p.recover_results(build_work_context(self.a))
        self.assertTrue(json.loads(self.a.store.work(w["id"])["fed_flags"])["result_pending"])
        await self.p.recover_results(build_work_context(self.a))
        await self.p.recover_results(build_work_context(self.a))
        results = self.outbox(self.a, "result")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], identity)
        await self.deliver(self.origin, results[0])
        await self.deliver(self.origin, results[0])
        done = self.origin.store.work(self.w["id"])
        self.assertEqual((done["state"], done["result"]), ("done", "checksum verified"))
        self.assertEqual(len(self.origin.notifications), 1)

    async def test_result_binds_peer_node_attempt_task_repo_grant_and_evidence(self):
        import copy
        w = await self.complete(self.a)
        await self.p.recover_results(build_work_context(self.a))
        valid = self.outbox(self.a, "result")[0]
        changes = [('from', 'bob'), ('node', 'wrong'), ('rid', 'r000000000000'),
                   ('origin_node', 'other'), ('origin_id', 'W-other'), ('offer_id', 'wrong'),
                   ('offer_digest', 'wrong'), ('execution_id', 'wrong'), ('grant_id', 'wrong'),
                   ('result', 'tampered'), ('result_digest', 'wrong'), ('state', 'nonsense')]
        for field, value in changes:
            invalid = copy.deepcopy(valid)
            (invalid if field in ['from', 'node', 'rid'] else invalid['data'])[field] = value
            with self.subTest(field=field):
                await self.p.on_envelope(build_work_context(self.origin), invalid, guard.Decision("deliver", local_repo="falcon"))
                self.assertEqual(self.origin.store.work(self.w["id"])["claimed_by"], "fed:pending")
        await self.deliver(self.origin, valid)
        self.assertEqual(self.origin.store.work(self.w["id"])["state"], "done")

    async def test_same_peer_other_node_completes_without_confusing_origin_rows(self):
        self.a.me = "nick"
        self.a.policy = policy(me="nick")
        await self.complete(self.a)
        await self.p.recover_results(build_work_context(self.a))
        result = self.outbox(self.a, "result")[0]
        await self.deliver(self.origin, result)
        self.assertEqual(self.origin.store.work(self.w["id"])["state"], "done")

    async def test_origin_reservation_and_grant_rollback_together(self):
        await self.deliver(self.a, self.offer)
        claim = self.outbox(self.a, "work_claim")[0]
        with patch.object(self.origin, "stage", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError): await self.deliver(self.origin, claim)
        self.assertNotIn("executor", json.loads(self.origin.store.work(self.w["id"])["fed_flags"]))
        await self.deliver(self.origin, claim)
        await self.deliver(self.origin, claim)
        self.assertEqual(len(self.outbox(self.origin, "work_grant")), 1)

    async def test_exhausted_lease_also_records_return_obligation(self):
        w = await self.grant(self.a)
        self.a.store.db.execute("UPDATE work_items SET state='claimed', claimed_by='lost', attempts=max_attempts, "
                               "lease_until='2000-01-01T00:00:00Z' WHERE id=?", (w['id'],))
        self.a.store.sweep_leases()
        self.assertEqual(self.a.store.work(w['id'])['state'], 'failed')
        self.assertTrue(json.loads(self.a.store.work(w['id'])['fed_flags'])['result_pending'])
        await self.p.recover_results(build_work_context(self.a))
        await self.deliver(self.origin, self.outbox(self.a, 'result')[0])
        self.assertEqual(self.origin.store.work(self.w['id'])['state'], 'failed')


    async def test_abrupt_process_exit_after_completion_still_returns_result(self):
        import subprocess
        import sys
        w = await self.grant(self.a)
        session = self.a.store.register("falcon", "worker", "crash", "codex", {"capabilities": [], "max_active": 1})
        self.a.store.set_state(session, "ready")
        self.assertTrue(self.a.store.claim(session, work_id=w["id"])["claimed"])
        code = "from hub.store import Store; import os,sys; s=Store(sys.argv[1]); s.release(sys.argv[2],sys.argv[3],'done','survived process exit','a'); os._exit(73)"
        proc = subprocess.run([sys.executable, "-c", code, self.a.store.path, session, w["id"]], timeout=15)
        self.assertEqual(proc.returncode, 73)
        await self.p.recover_results(build_work_context(self.a))
        await self.deliver(self.origin, self.outbox(self.a, "result")[0])
        self.assertEqual(self.origin.store.work(self.w["id"])["result"], "survived process exit")

    async def test_malformed_claim_cannot_reserve_an_origin_task(self):
        import copy
        await self.deliver(self.a, self.offer)
        valid = self.outbox(self.a, "work_claim")[0]
        for key, value in [('execution_id', []), ('origin_node', {}), ('offer_digest', 5)]:
            env = copy.deepcopy(valid)
            env['data'][key] = value
            self.assertEqual(await self.p.on_envelope(build_work_context(self.origin), env, guard.Decision('deliver')), 'invalid_work')
            self.assertNotIn('executor', json.loads(self.origin.store.work(self.w['id'])['fed_flags']))

    async def test_late_grant_cannot_revive_cancelled_execution(self):
        await self.deliver(self.a, self.offer)
        await self.deliver(self.origin, self.outbox(self.a, "work_claim")[0])
        item = self.a.store.q1("SELECT id FROM work_items")
        self.a.store.cancel(item['id'], 'operator stopped it')
        await self.deliver(self.a, self.outbox(self.origin, "work_grant")[0])
        self.assertEqual(self.a.store.work(item['id'])['state'], 'cancelled')

    async def test_legacy_work_stays_quarantined_and_cannot_be_auto_approved(self):
        legacy = {**self.offer, 'v': 2}
        subject = f"am.work.{legacy['from']}.{legacy['rid']}.{legacy['data']['role']}"
        decision = guard.inbound(self.a.policy, subject, legacy)
        self.assertEqual(decision.action, 'quarantine')
        from hub.store import HubError
        with self.assertRaises(HubError):
            await self.p.on_envelope(build_work_context(self.a), legacy, guard.Decision('deliver', approved=True))
        self.assertEqual(self.a.store.q("SELECT * FROM work_items"), [])
