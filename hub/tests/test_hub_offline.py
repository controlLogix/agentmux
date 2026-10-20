"""Offline tier: protocol semantics and delivery guards, no tmux, no agent CLI.

Run (WSL):  python3 -m unittest discover -s hub/tests -v     from the repo root
Each test names the failure class (C#) or requirement (R-*) it pins.
"""
import json
import asyncio
import concurrent.futures
from contextlib import nullcontext
import multiprocessing as mp
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import stat
import sys
import tempfile
import time
import unittest
import uuid
from threading import Event
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from hub import deliver, names, profiles  # noqa: E402
from hub.store import HubError, Store  # noqa: E402
from hub.transport import FakeTransport, TmuxTransport, TmuxBufferCleanupFailure  # noqa: E402

ROLE = {"capabilities": ["python"], "max_active": 1, "lease_s": 900}
LEAD = {"capabilities": ["plan"], "max_active": 3, "lease_s": 900}


def fresh_store():
    d = tempfile.mkdtemp(prefix="hubtest-", dir="/tmp")
    s = Store(os.path.join(d, "hub.db"))
    s.repo_add("alpha", paths=["/tmp/alpha"], groups=["g1"])
    s.repo_add("beta", paths=["/tmp/beta"], groups=["g1"])
    return s


def reg(s, repo, role, agent, snap=ROLE, cli="codex"):
    sess = s.register(repo, role, agent, cli, snap)
    s.set_state(sess, "ready")
    return sess


class Names(unittest.TestCase):
    def test_normalize_and_refuse(self):  # R-NAME-1
        self.assertEqual(names.normalize("Agora Rev #2"), "agora_rev_2")
        self.assertEqual(names.normalize("TM-210", "team"), "tm_210")
        with self.assertRaises(names.NameError_) as e:
            names.check_part("my-repo", "repo")
        self.assertEqual(e.exception.suggestion, "my_repo")
        self.assertEqual(names.check_part("my-repo", "repo", accept_normalized=True), "my_repo")

    def test_session_roundtrip(self):
        s = names.session_name("agora", "reviewer", "codex_1")
        self.assertEqual(s, "agora-reviewer-codex_1")
        self.assertEqual(names.split_session(s), ("agora", "reviewer", "codex_1"))
        with self.assertRaises(ValueError):
            names.split_session("agora-web-reviewer-x")

    def test_addresses_and_subjects(self):
        a = names.parse_address("role:group:g1/reviewer")
        self.assertEqual(str(a), "role:group:g1/reviewer")
        self.assertEqual(names.nats_subject(names.parse_address("agent:alpha/worker/w1"), "n1"), "am.agent.alpha.worker.w1")
        self.assertEqual(names.nats_subject(a, "n1"), "am.work.g_g1.reviewer")
        with self.assertRaises(ValueError):
            names.parse_address("nobody")

    def test_all_address_forms_roundtrip(self):
        cases = [
            ("agent:alpha/worker/w1", "agent:alpha-worker-w1", "am.agent.alpha.worker.w1"),
            ("agent:alpha-worker-w1", "agent:alpha-worker-w1", "am.agent.alpha.worker.w1"),
            ("virtual:operator", "virtual:operator", "am.n1.virtual.operator"),
            ("team:alpha/t1", "team:alpha/t1", "am.team.alpha.t1"),
            ("role:alpha/worker", "role:alpha/worker", "am.work.alpha.worker"),
            ("role:group:g1/worker", "role:group:g1/worker", "am.work.g_g1.worker"),
            ("role:team:alpha/t1/worker", "role:team:alpha/t1/worker", "am.work.t_alpha.t1.worker"),
            ("role:*/worker", "role:*/worker", "am.work.all.worker"),
        ]
        for raw, canonical, subject in cases:
            with self.subTest(address=raw):
                parsed = names.parse_address(raw)
                self.assertEqual(str(parsed), canonical)
                self.assertEqual(names.parse_address(str(parsed)), parsed)
                self.assertEqual(names.nats_subject(parsed, "n1"), subject)

    def test_malformed_addresses_rejected(self):
        cases = ["", "nobody", "unknown:alpha", "agent:alpha/worker", "agent:alpha-worker",
                 "agent:alpha-worker-w1-extra", "team:alpha", "team:alpha/t1/extra",
                 "virtual:", "role:worker", "role:team:alpha/worker"]
        for invalid in ("*", ">", "a.b", "a b", "a\nb", "a\r", "a\t", "a\n", "A", "é"):
            cases.extend((f"agent:alpha/worker/{invalid}", f"agent:alpha-worker-{invalid}",
                          f"virtual:{invalid}", f"team:alpha/{invalid}", f"role:alpha/{invalid}",
                          f"role:group:{invalid}/worker", f"role:team:alpha/{invalid}/worker"))
        for raw in cases:
            with self.subTest(address=raw), self.assertRaises(ValueError):
                names.parse_address(raw)

    def test_session_spellings_enforce_same_length_limits(self):
        parts = ["r" * names.LIMITS["repo"], "w" * names.LIMITS["role"], "a" * names.LIMITS["agent"]]
        self.assertEqual(names.split_session(names.session_name(*parts)), tuple(parts))
        for index in range(3):
            oversized = list(parts)
            oversized[index] += "x"
            for separator in ("/", "-"):
                with self.subTest(part=index, separator=separator), self.assertRaises(ValueError):
                    names.parse_address("agent:" + separator.join(oversized))


class Messaging(unittest.TestCase):
    def setUp(self):
        self.s = fresh_store()
        self.w1 = reg(self.s, "alpha", "worker", "w1")
        self.w2 = reg(self.s, "alpha", "worker", "w2")
        self.r1 = reg(self.s, "beta", "reviewer", "r1")

    def test_duplicate_live_name_refused(self):  # R-NAME-2 / C8
        with self.assertRaises(HubError):
            self.s.register("alpha", "worker", "w1", "codex", ROLE)

    def test_legacy_names_resolve(self):  # TM-214 AC2
        leg = self.s.adopt("nfl-lead", "alpha", "lead", "nfl_lead", "claude", LEAD, "%9", 4242)
        self.assertEqual(leg, "alpha-lead-nfl_lead")
        self.assertEqual(self.s.agent("nfl-lead")["session"], leg)
        self.assertEqual(self.s.agent(leg)["term_name"], "nfl-lead")
        self.assertEqual(self.s.canonical_target("nfl-lead"), f"agent:{leg}")
        self.assertEqual(self.s.canonical_target(self.w1), f"agent:{self.w1}")
        self.assertEqual(self.s.canonical_target("orchestrator"), "virtual:orchestrator")
        self.assertEqual(self.s.canonical_target("role:alpha/worker"), "role:alpha/worker")
        with self.assertRaises(HubError):
            self.s.canonical_target("nobody-here")
        r = self.s.post("virtual:operator", self.s.canonical_target("nfl-lead"), "status", "to the legacy name")
        self.assertEqual(r["recipients"], [leg])

    def test_courier_kinds_accepted(self):  # TM-214: every `agentmux post --kind` still works
        for k in ("plan", "status", "finding", "error", "request", "reply", "claim", "release"):
            self.s.post("virtual:operator", f"agent:{self.w1}", k, k)

    def test_reregistered_name_does_not_inherit_mail(self):  # R-NAME-2
        self.s.post("virtual:operator", f"agent:{self.w1}", "request", "for the old one")
        self.s.set_state(self.w1, "dead", "terminal gone")
        again = reg(self.s, "alpha", "worker", "w1")
        self.assertEqual(again, self.w1)
        self.assertEqual(self.s.inbox(self.w1), [])
        self.assertEqual(self.s.status()["dead"][0]["last_error"], "recipient re-registered")

    def test_direct_inbox_ack(self):  # R-DLV-1
        r = self.s.post("virtual:operator", f"agent:{self.w1}", "request", "hello")
        self.assertEqual(r["recipients"], [self.w1])
        box = self.s.inbox(self.w1)
        self.assertEqual([m["body"] for m in box], ["hello"])
        self.assertEqual(self.s.pending_for(self.w1)[0]["state"], "received")
        self.s.ack(self.w1, [r["id"]])
        self.assertEqual(self.s.inbox(self.w1), [])

    def test_idempotent_post(self):  # R-MSG-1 / C1 re-sends
        a = self.s.post("virtual:operator", f"agent:{self.w1}", "note", "x", idem_key="k1")
        b = self.s.post("virtual:operator", f"agent:{self.w1}", "note", "x", idem_key="k1")
        self.assertEqual(a["id"], b["id"])
        self.assertTrue(b["duplicate"])
        self.assertEqual(len(self.s.inbox(self.w1)), 1)

    def test_order_preserved(self):  # R-DLV-4 / C9 ordering
        ids = [self.s.post("virtual:operator", f"agent:{self.w1}", "note", f"m{i}")["id"] for i in range(50)]
        self.assertEqual([m["id"] for m in self.s.inbox(self.w1, limit=100)], ids)

    def test_role_broadcast_and_cross_repo_group(self):
        r = self.s.post("virtual:operator", "role:alpha/worker", "note", "all workers")
        self.assertEqual(sorted(r["recipients"]), sorted([self.w1, self.w2]))
        r = self.s.post("virtual:operator", "role:group:g1/reviewer", "note", "cross-repo")
        self.assertEqual(r["recipients"], [self.r1])

    def test_unknown_kind_lists_known(self):  # R-MSG-2 / C9 bug #38
        with self.assertRaises(HubError) as e:
            self.s.post("virtual:operator", f"agent:{self.w1}", "bogus", "x")
        self.assertIn("request", str(e.exception))

    def test_no_live_recipient_refused(self):  # C4: never queue into the void silently
        self.s.set_state(self.r1, "dead")
        with self.assertRaises(HubError):
            self.s.post("virtual:operator", "role:beta/reviewer", "note", "nobody home")

    def test_virtual_operator_inbox(self):  # C9: a recipient with no pane
        self.s.post(f"agent:{self.w1}", "virtual:operator", "reply", "done")
        self.assertEqual(self.s.inbox("virtual:operator")[0]["body"], "done")

    def test_attempts_to_dead(self):
        self.s.post("virtual:operator", f"agent:{self.w1}", "note", "x")
        dead = []
        for _ in range(3):
            dead = self.s.bump_attempt(self.w1, "not acked", max_attempts=3)
        self.assertEqual(len(dead), 1)
        self.assertEqual(self.s.status()["deliveries"].get("dead"), 1)

    def test_events_tail_returns_newest_oldest_first(self):
        # The 2026-10-02 smoke failure: forward paging from 0 returned the oldest rows,
        # so a fresh ack past the first page was invisible to `hub events`.
        for i in range(30):
            self.s.post("virtual:operator", f"agent:{self.w1}", "note", f"m{i}")
        seqs = [e["seq"] for e in self.s.events(since=0, limit=1000)]
        head = [e["seq"] for e in self.s.events(limit=5)]
        tail = [e["seq"] for e in self.s.events(limit=5, tail=True)]
        self.assertEqual(head, seqs[:5])
        self.assertEqual(tail, seqs[-5:])
        since = [e["seq"] for e in self.s.events(since=seqs[-8], limit=5, tail=True)]
        self.assertEqual(since, seqs[-5:])

    def test_fts_and_audit(self):
        self.s.post("virtual:operator", f"agent:{self.w1}", "note", "the quick brown fox")
        hits = self.s.q("SELECT rowid FROM messages_fts WHERE messages_fts MATCH 'brown'")
        self.assertEqual(len(hits), 1)
        self.assertTrue(any(e["entity"] == "delivery" for e in self.s.events()))
        # Local traffic never enters the NATS outbox; only remote-bound rows do (TM-218).
        self.assertEqual(len(self.s.q("SELECT * FROM nats_outbox")), 0)
        r = self.s.post("virtual:operator", "agent:beta-reviewer-elsewhere", "note", "x", remote_ok=True, node="n1")
        self.assertTrue(r["remote"])
        out = self.s.outbox_pending()
        self.assertEqual([o["subject"] for o in out], ["am.agent.beta.reviewer.elsewhere"])
        with self.assertRaises(HubError):                  # without the bridge it is still refused
            self.s.post("virtual:operator", "agent:beta-reviewer-elsewhere", "note", "x")


def _claimer(path, session, q):
    s = Store(path)
    time.sleep(0.05)
    q.put((session, (s.claim(session) or {}).get("claimed")))


class Work(unittest.TestCase):
    def setUp(self):
        self.s = fresh_store()
        self.ws = [reg(self.s, "alpha", "worker", f"w{i}") for i in range(8)]

    def test_first_claim_wins_across_processes(self):  # role pickup, BEGIN IMMEDIATE
        self.s.work_create("virtual:operator", "alpha", "role:alpha/worker", "only one")
        q = mp.Queue()
        ps = [mp.Process(target=_claimer, args=(self.s.path, w, q)) for w in self.ws]
        [p.start() for p in ps]
        [p.join() for p in ps]
        got = [q.get() for _ in ps]
        winners = [g for g in got if g[1]]
        self.assertEqual(len(winners), 1, got)

    def test_capacity_and_lease_expiry(self):  # R-LIVE-2
        w = self.ws[0]
        self.s.work_create("virtual:operator", "alpha", "role:alpha/worker", "a")
        self.s.work_create("virtual:operator", "alpha", "role:alpha/worker", "b")
        c = self.s.claim(w, lease_s=0)["claimed"]
        self.assertIsNotNone(c)
        self.assertIsNone(self.s.claim(w)["claimed"])            # max_active 1
        time.sleep(0.05)
        back = self.s.sweep_leases()
        self.assertEqual([b["id"] for b in back], [c["id"]])
        self.assertEqual(self.s.work(c["id"])["state"], "ready")

    def test_dead_agent_returns_leases(self):  # C4
        self.s.work_create("virtual:operator", "alpha", "role:alpha/worker", "a")
        c = self.s.claim(self.ws[1])["claimed"]
        self.s.set_state(self.ws[1], "dead", "terminal gone")
        self.assertEqual(self.s.work(c["id"])["state"], "ready")
        self.assertIsNotNone(self.s.claim(self.ws[2])["claimed"])

    def test_direct_to_dead_refused(self):
        self.s.set_state(self.ws[3], "dead")
        with self.assertRaises(HubError):
            self.s.work_create("virtual:operator", "alpha", f"agent:{self.ws[3]}", "x")

    def test_requirements(self):
        self.s.work_create("virtual:operator", "alpha", "role:alpha/worker", "needs codesys",
                           requirements={"capabilities": ["codesys"]})
        self.assertIsNone(self.s.claim(self.ws[0])["claimed"])
        self.s.work_create("virtual:operator", "alpha", "role:alpha/worker", "needs python",
                           requirements={"capabilities": ["python"], "cli": ["codex"]})
        self.assertEqual(self.s.claim(self.ws[0])["claimed"]["title"], "needs python")

    def test_team_lead_decomposes(self):
        lead = reg(self.s, "alpha", "lead", "l1", LEAD)
        self.s.team_add("alpha", "t1", [lead, self.ws[0], self.ws[1]])
        parent = self.s.work_create("virtual:operator", "alpha", "team:alpha/t1", "feature")
        self.assertIsNone(self.s.claim(self.ws[0])["claimed"])      # workers cannot take team items
        p = self.s.claim(lead)["claimed"]
        self.assertEqual(p["id"], parent["id"])
        kid = self.s.work_create(f"agent:{lead}", "alpha", "role:team:alpha/t1/worker", "part 1", parent_id=p["id"])
        self.assertEqual(self.s.work(p["id"])["state"], "waiting_children")
        self.assertIsNone(self.s.claim(self.ws[5])["claimed"])      # not on the team
        k = self.s.claim(self.ws[1])["claimed"]
        self.assertEqual(k["id"], kid["id"])
        with self.assertRaises(HubError):
            self.s.release(lead, p["id"], "done")                   # open child
        self.s.release(self.ws[1], k["id"], "done", "ok")
        self.assertEqual(self.s.release(lead, p["id"], "done", "shipped")["state"], "done")

    def test_cancel_takes_open_children(self):
        p = self.s.work_create("virtual:operator", "alpha", "role:alpha/worker", "parent")
        k = self.s.work_create("virtual:operator", "alpha", "role:alpha/worker", "kid", parent_id=p["id"])
        self.assertEqual(sorted(self.s.cancel(p["id"], "orphaned")), sorted([p["id"], k["id"]]))
        self.assertIsNone(self.s.claim(self.ws[0])["claimed"])

    def test_path_claims_are_per_repo(self):  # R-HOME-2
        self.s.claim_path(self.ws[0], "alpha", "README.md")
        self.s.claim_path(self.ws[1], "beta", "README.md")          # same path, other repo: fine
        with self.assertRaises(HubError):
            self.s.claim_path(self.ws[1], "alpha", "README.md")


def screen(prompt="› ", above="codex ready"):
    return f"{above}\n\n{prompt}"


class Deliver(unittest.TestCase):
    def setUp(self):
        self.t = FakeTransport()
        self.p = profiles.get("codex")

    def run_line(self, sess, **kw):
        return deliver.deliver_line(self.t, self.p, sess, sess, "[hub] 1 new message(s). Run: agentmux hub inbox --ack",
                                    pane_pid=1000, **kw)

    def keys(self, sess):
        return [x[2] for x in self.t.sent if x[0] == sess and x[1] == "key"]

    def test_clean_submit(self):
        self.t.add("a", screen())
        rc = self.run_line("a")
        self.assertEqual(rc.outcome, "submitted", rc.as_dict())
        self.assertEqual(rc.stages["typed"], "ok")

    def test_windows_claude_idle_hint_receives_notice(self):
        # Observed native Windows Claude prompt, not a permission menu.
        self.p = profiles.get("claude")
        self.t.add("a", '>\u00a0Try "edit <filepath>"\n  bypass permissions on')
        rc = self.run_line("a")
        self.assertEqual(rc.outcome, "submitted", rc.as_dict())
        self.assertEqual(self.keys("a")[0], "C-u")
        self.assertTrue(any(kind == "text" and "[hub]" in text
                            for _, kind, text in self.t.sent))

    def test_windows_claude_choice_is_not_an_idle_prompt(self):
        self.p = profiles.get("claude")
        for choice in ("> 1. No, exit", "> Yes", "> No"):
            with self.subTest(choice=choice):
                self.t = FakeTransport()
                self.t.add("a", choice)
                self.assertFalse(self.p.is_ready(choice))
                rc = self.run_line("a")
                self.assertEqual(rc.outcome, "blocked", rc.as_dict())
                self.assertEqual(self.t.sent, [])

    def test_windows_claude_busy_prompt_defers_notice(self):
        self.p = profiles.get("claude")
        self.t.add("a", "Working (12s · esc to interrupt)\n>\u00a0")
        rc = self.run_line("a")
        self.assertEqual(rc.outcome, "deferred", rc.as_dict())
        self.assertEqual(self.t.sent, [])

    def test_update_modal_answered_safely(self):  # C2: never Enter on 'Update now'
        self.t.add("a", "✨ Update available! 0.159 -> 0.160\n› 1. Update now (runs `npm install -g @openai/codex`)\n  2. Skip\n")
        s = self.t.sessions["a"]

        orig = self.t.send_key

        def key(h, k):
            orig(h, k)
            if k == "2":
                s["screen"] = screen()
        self.t.send_key = key
        rc = self.run_line("a")
        self.assertEqual(self.keys("a")[0], "2", self.t.sent)
        self.assertNotEqual(self.keys("a")[0], "Enter")
        self.assertEqual(rc.outcome, "submitted", rc.as_dict())

    def test_update_banner_is_not_the_update_menu(self):
        """codex 0.159.2 (2026-09-30): every pane shows this NON-modal banner. It must be
        rung normally - no '2', no block."""
        banner = ("╭─────────────────────────────────────────────────╮\n"
                  "│ ✨ Update available! 0.159.0 -> 0.159.2         │\n"
                  "│ Run npm install -g @openai/codex to update.     │\n"
                  "│ See full release notes:                         │\n"
                  "╰─────────────────────────────────────────────────╯\n"
                  "  >_ OpenAI Codex (v0.159.0)\n     ~/hubdemo/calc\n")
        self.t.add("a", banner + "› Ask Codex to do anything")
        rc = self.run_line("a")
        self.assertEqual(rc.outcome, "submitted", rc.as_dict())
        self.assertNotIn("2", self.keys("a"))
        self.assertEqual(rc.modal_answers, [])

    def test_login_modal_blocks_without_keys(self):  # C2
        self.t.add("a", "Welcome to Codex\nSign in with ChatGPT\n› 1. Sign in with ChatGPT\n")
        rc = self.run_line("a")
        self.assertEqual(rc.outcome, "blocked")
        self.assertEqual(self.t.sent, [])

    def test_unknown_prompt_blocks(self):  # C2: generic guard
        self.t.add("a", "Something new?\nPress enter to continue\n")
        rc = self.run_line("a")
        self.assertEqual(rc.outcome, "blocked")
        self.assertEqual(self.t.sent, [])

    def test_copy_mode_left_first(self):  # C7 / D02
        self.t.add("a", screen(), mode="copy")
        rc = self.run_line("a")
        self.assertEqual(self.t.sent[0][2], "cancel-mode")
        self.assertEqual(rc.outcome, "submitted", rc.as_dict())

    def test_busy_defers_without_keys(self):
        self.t.add("a", "Working (12s • esc to interrupt)\n› ")
        rc = self.run_line("a")
        self.assertEqual(rc.outcome, "deferred")
        self.assertEqual(self.t.sent, [])

    def test_booting_defers(self):  # C5
        self.t.add("a", screen())
        rc = self.run_line("a", started_at=time.time())
        self.assertEqual((rc.outcome, rc.reason), ("deferred", "booting"))
        self.assertEqual(self.t.sent, [])

    def test_placeholder_gets_second_enter(self):  # C1
        self.t.add("a", screen())
        s = self.t.sessions["a"]
        n = {"enter": 0}

        def on_submit(scr):
            n["enter"] += 1
            return "› [Pasted Content 1024 chars]" if n["enter"] == 1 else "working (esc to interrupt)\n› "
        s["on_submit"] = on_submit
        rc = self.run_line("a")
        self.assertEqual(rc.outcome, "submitted", rc.as_dict())
        self.assertGreaterEqual(rc.enters, 2)

    def test_stale_line_resubmitted_not_retyped(self):  # C1 recovery
        self.t.add("a", "› [hub] 1 new message(s). Run: agentmux hub inbox --ack")
        rc = self.run_line("a")
        self.assertEqual(rc.outcome, "submitted", rc.as_dict())
        self.assertFalse(any(k == "text" for _, k, _p in self.t.sent))

    def test_handle_mismatch_refused(self):  # R-ID-2 / C8
        self.t.add("a", screen())
        rc = deliver.deliver_line(self.t, self.p, "a", "%99", "x", pane_pid=1000)
        self.assertEqual(rc.outcome, "failed")
        self.assertEqual(self.t.sent, [])

    def test_hint_text_cleared_first(self):
        self.t.add("a", "› Ask Codex to do anything")
        rc = self.run_line("a")
        self.assertEqual(self.keys("a")[0], "C-u")
        self.assertEqual(rc.outcome, "submitted", rc.as_dict())


class DeliveryOwnership(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.transport.add("target", screen())
        self.cancel = Event()
        sleeping = patch("hub.deliver.time.sleep")
        sleeping.start()
        self.addCleanup(sleeping.stop)

    def send(self, pane_pid=1000):
        return deliver.deliver_line(self.transport, profiles.get("codex"),
                                    "target", "target", "owned notice", pane_pid=pane_pid,
                                    cancel=self.cancel)

    def test_missing_or_changed_registered_pid_refuses_without_input(self):
        for pid in (None, True, 0, -1, 2000):
            with self.subTest(pid=pid):
                receipt = self.send(pid)
                self.assertEqual(receipt.outcome, "failed")
                self.assertEqual(self.transport.sent, [])

    def test_replacement_during_screen_read_refuses_before_input(self):
        capture = self.transport.capture

        def replaced(handle):
            value = capture(handle)
            self.transport.sessions["target"]["pid"] = 2000
            return value

        self.transport.capture = replaced
        receipt = self.send()
        self.assertEqual(receipt.outcome, "failed")
        self.assertEqual(self.transport.sent, [])

    def test_cancel_during_identity_query_refuses_before_input(self):
        handle = self.transport.handle

        def cancelled(session):
            value = handle(session)
            self.cancel.set()
            return value

        self.transport.handle = cancelled
        receipt = self.send()
        self.assertEqual((receipt.outcome, receipt.reason), ("deferred", "delivery cancelled"))
        self.assertEqual(self.transport.sent, [])

    def test_cancel_after_typing_prevents_enter(self):
        send = self.transport.send_text

        def typed(handle, text):
            send(handle, text)
            self.cancel.set()

        self.transport.send_text = typed
        receipt = self.send()
        self.assertEqual(receipt.outcome, "deferred")
        self.assertEqual(self.transport.sent, [("target", "text", "owned notice")])
        self.assertNotIn("submitted", receipt.stages)

    def test_cancel_after_submit_prevents_retry_and_success_claim(self):
        self.transport.sessions["target"]["on_submit"] = lambda _: "› [Pasted Content 20 chars]"
        send = self.transport.send_key

        def submitted(handle, key):
            send(handle, key)
            if key == "Enter":
                self.cancel.set()

        self.transport.send_key = submitted
        receipt = self.send()
        self.assertEqual(receipt.outcome, "deferred")
        self.assertEqual([entry[2] for entry in self.transport.sent if entry[1] == "key"], ["Enter"])
        self.assertEqual(receipt.enters, 1)
        self.assertNotIn("submitted", receipt.stages)

    def test_replacement_before_modal_answer_does_not_answer(self):
        self.transport.sessions["target"]["screen"] = "› 1. Update now (runs npm install)\n  2. Skip"
        capture = self.transport.capture

        def replaced(handle):
            value = capture(handle)
            self.transport.sessions["target"]["pid"] = 2000
            return value

        self.transport.capture = replaced
        receipt = self.send()
        self.assertEqual(receipt.outcome, "failed")
        self.assertEqual(self.transport.sent, [])

    def test_unchanged_target_keeps_submission_receipt(self):
        receipt = self.send()
        self.assertEqual(receipt.outcome, "submitted")
        self.assertEqual(receipt.stages["typed"], "ok")
        self.assertEqual(receipt.stages["submitted"], "ok")

    def test_cancel_after_modal_navigation_preserves_incomplete_answer(self):
        self.transport.sessions["target"]["screen"] = (
            "Do you trust the files in this folder?\n> No, exit\n  Yes, I trust")
        send = self.transport.send_key

        def navigated(handle, key):
            send(handle, key)
            self.cancel.set()

        self.transport.send_key = navigated
        receipt = deliver.deliver_line(self.transport, profiles.get("claude"),
                                       "target", "target", "notice", pane_pid=1000,
                                       cancel=self.cancel)
        self.assertEqual(receipt.outcome, "deferred")
        self.assertEqual(receipt.modal_answers, [{"kind": "trust", "keys": ["Down"], "complete": False}])
        self.assertEqual(self.transport.sent, [("target", "key", "Down")])

    def test_cancel_or_replacement_during_buffer_load_prevents_paste_and_reclaims_buffer(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                transport, cancel, pid = TmuxTransport(), Event(), [1000]
                buffers, operations = {"sentinel": "unrelated"}, []

                def command(*args, input_=None):
                    operations.append(args)
                    if args[0] == "load-buffer":
                        buffers[args[2]] = input_
                        if replacement:
                            pid[0] = 2000
                        else:
                            cancel.set()
                    elif args[0] == "list-buffers":
                        return "\n".join(buffers)
                    elif args[0] == "delete-buffer":
                        del buffers[args[2]]
                    return ""

                with patch.object(transport, "handle", side_effect=lambda _: ("target", pid[0])), \
                        patch.object(transport, "mode", return_value="normal"), \
                        patch.object(transport, "capture", return_value=screen()), \
                        patch.object(transport, "_tm", side_effect=command):
                    receipt = deliver.deliver_line(transport, profiles.get("codex"), "target", "target",
                                                   "notice", pane_pid=1000, cancel=cancel, strategy="buffer")
                self.assertEqual(receipt.outcome, "failed" if replacement else "deferred")
                self.assertFalse(any(args[0] == "paste-buffer" for args in operations))
                self.assertEqual(buffers, {"sentinel": "unrelated"})
                self.assertEqual(sum(args[0] == "delete-buffer" for args in operations), 1)

    def test_uncertain_buffer_load_reply_still_reclaims_only_original_allocation(self):
        transport, buffers = TmuxTransport(), {"sentinel": "unrelated"}
        failure = RuntimeError("load reply lost")

        def command(*args, input_=None):
            if args[0] == "load-buffer":
                buffers[args[2]] = input_
                raise failure
            if args[0] == "list-buffers":
                return "\n".join(buffers)
            if args[0] == "delete-buffer":
                del buffers[args[2]]
            return ""

        with patch.object(transport, "_tm", side_effect=command):
            with self.assertRaises(RuntimeError) as raised:
                transport.send_buffer("target", "notice")
        self.assertIs(raised.exception, failure)
        self.assertEqual(buffers, {"sentinel": "unrelated"})

    def test_uncertain_buffer_cleanup_preserves_operation_and_cleanup_failures(self):
        transport = TmuxTransport()
        failure, cleanup = RuntimeError("load reply lost"), RuntimeError("cleanup unavailable")
        with patch.object(transport, "_tm", side_effect=[failure, cleanup]):
            with self.assertRaises(TmuxBufferCleanupFailure) as raised:
                transport.send_buffer("target", "notice")
        owner = raised.exception
        self.assertEqual(owner.__cause__.exceptions, (failure, cleanup))
        self.assertIs(owner.operation_failure, failure)
        self.assertIs(owner.cleanup_failure, cleanup)
        self.assertIs(transport._buffers[owner.name], owner)
        self.assertEqual((owner.socket, owner.state), (transport.socket, "cleanup_uncertain"))
        with self.assertRaises(TmuxBufferCleanupFailure) as retained:
            transport.require_buffer_cleanup()
        self.assertIs(retained.exception, owner)
        with patch.object(transport, "_tm", side_effect=[owner.name, ""]) as command:
            owner.retry_cleanup()
        self.assertEqual(command.call_args_list[-1].args, ("delete-buffer", "-b", owner.name))
        self.assertEqual(owner.state, "closed")
        self.assertEqual(transport._buffers, {})
        transport.require_buffer_cleanup()

    def test_buffer_cleanup_retains_original_socket_and_failure_on_retry(self):
        transport, first, second = TmuxTransport(), RuntimeError("first"), RuntimeError("retry")
        with patch.object(transport, "_tm", side_effect=[first, first]):
            with self.assertRaises(TmuxBufferCleanupFailure) as raised:
                transport.send_buffer("target", "notice")
        owner = raised.exception
        with patch.object(transport, "_tm", side_effect=second):
            with self.assertRaises(TmuxBufferCleanupFailure) as retried:
                owner.retry_cleanup()
        self.assertIs(retried.exception, owner)
        self.assertIs(owner.cleanup_failure, first)
        self.assertIs(owner.retry_failure, second)
        transport.socket = "replacement"
        with patch.object(transport, "_tm", return_value="agentmux-kill-confirmed\n") as command:
            with self.assertRaises(TmuxBufferCleanupFailure):
                owner.retry_cleanup()
        command.assert_not_called()
        self.assertIs(transport._buffers[owner.name], owner)

    def test_socket_change_during_absence_query_cannot_close_original_buffer_owner(self):
        transport = TmuxTransport(socket="original")

        def command(*args, **kwargs):
            if args[0] == "load-buffer":
                raise RuntimeError("load reply lost")
            transport.socket = "replacement"
            return ""

        with patch.object(transport, "_tm", side_effect=command):
            with self.assertRaises(TmuxBufferCleanupFailure) as raised:
                transport.send_buffer("target", "notice")
        owner = raised.exception
        self.assertEqual(owner.socket, "original")
        self.assertEqual(owner.state, "cleanup_uncertain")
        self.assertIs(transport._buffers[owner.name], owner)


class RingOwnership(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from hub.server import Hub
        self.hub = Hub.__new__(Hub)
        self.hub.stop = asyncio.Event()
        self.hub.rings, self.hub.inflight = {}, set()
        self.hub.bell = {"target": {}}
        self.hub.started = {}
        self.hub.tp = FakeTransport()
        self.hub.io = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.hub.io.shutdown, wait=True)
        self.agent = {"session": "target", "cli": "codex", "handle": "%1", "pane_pid": 1000,
                      "created": "original"}
        self.current = dict(self.agent)
        self.events = []
        self.hub.store = SimpleNamespace(agent=lambda _: self.current,
                                         event=lambda *args: self.events.append(args), tx=nullcontext)

        async def db(function, *args):
            return function(*args)

        self.hub.db = db
        self.entered, self.release, self.joined = Event(), Event(), Event()
        self.addCleanup(self.release.set)

    def worker(self, *args, **kwargs):
        self.assertEqual(kwargs["pane_pid"], 1000)
        self.cancellation = kwargs["cancel"]
        self.entered.set()
        try:
            if not self.release.wait(5):
                raise RuntimeError("test did not release its delivery worker")
            return deliver.Receipt(outcome="deferred", reason="delivery cancelled")
        finally:
            self.joined.set()

    async def start(self):
        self.patched = patch("hub.deliver.deliver_line", side_effect=self.worker)
        self.patched.start()
        self.addCleanup(self.patched.stop)
        task = self.hub._start_ring(self.agent, 1, 0, (None, ()))
        entered = await asyncio.get_running_loop().run_in_executor(None, self.entered.wait, 2)
        self.assertTrue(entered)
        return task

    async def test_repeated_task_cancel_retains_original_worker_until_joined(self):
        task = await self.start()
        for _ in range(2):
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertFalse(self.joined.is_set())
            self.assertIn("target", self.hub.rings)
            self.assertIn("target", self.hub.inflight)
        self.assertTrue(self.cancellation.is_set())
        self.release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        self.assertTrue(self.joined.is_set())
        self.assertEqual(self.hub.rings, {})
        self.assertEqual(self.hub.inflight, set())
        self.assertEqual(self.events, [])

    async def test_shutdown_cancel_does_not_abandon_original_delivery(self):
        task = await self.start()
        finish = asyncio.create_task(self.hub.finish_deliveries())
        await asyncio.sleep(0)
        self.assertTrue(self.cancellation.is_set())
        self.assertFalse(finish.done())
        self.assertIsNone(self.hub._start_ring(self.agent, 1, 0, (None, ())))
        for _ in range(2):
            finish.cancel()
            await asyncio.sleep(0)
            self.assertFalse(finish.done())
        self.release.set()
        with self.assertRaises(asyncio.CancelledError):
            await finish
        await task
        await asyncio.sleep(0)
        self.assertTrue(self.joined.is_set())
        self.assertEqual(self.hub.rings, {})

    async def test_changed_registration_cannot_receive_old_receipt(self):
        task = await self.start()
        self.current["created"] = "replacement"
        self.release.set()
        await task
        self.assertTrue(self.joined.is_set())
        self.assertEqual(self.events, [])
        self.assertEqual(self.hub.bell["target"], {})

    async def test_registration_replacement_at_db_await_cannot_take_old_receipt(self):
        task = await self.start()
        self.hub.store.agent = lambda _: dict(self.current)
        self.hub.store.event = lambda *args: self.events.append((self.current["created"], args))
        replaced = False

        async def db(function, *args):
            nonlocal replaced
            value = function(*args)
            if not replaced:
                replaced = True
                self.current = {**self.current, "created": "replacement"}
            return value

        self.hub.db = db
        self.release.set()
        await task
        self.assertTrue(replaced)
        self.assertTrue(self.joined.is_set())
        self.assertTrue(self.events)
        self.assertTrue(all(generation == "original" for generation, _ in self.events))

    async def test_cancel_before_task_start_releases_retained_slot(self):
        task = self.hub._start_ring(self.agent, 1, 0, (None, ()))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        self.assertEqual(self.hub.rings, {})
        self.assertEqual(self.hub.inflight, set())

    async def test_worker_cancelled_error_finishes_original_wait_without_spinning(self):
        def cancelled(*args, **kwargs):
            self.cancellation = kwargs["cancel"]
            self.entered.set()
            self.joined.set()
            raise asyncio.CancelledError

        self.worker = cancelled
        task = await self.start()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        self.assertTrue(self.joined.is_set())
        self.assertEqual(self.hub.rings, {})
        self.assertEqual(self.hub.inflight, set())

    async def test_shutdown_refuses_unresolved_original_buffer_owner(self):
        transport = TmuxTransport(socket="original")
        with patch.object(transport, "_tm", side_effect=RuntimeError("unavailable")):
            with self.assertRaises(TmuxBufferCleanupFailure) as raised:
                transport.send_buffer("target", "notice")
        owner = raised.exception
        self.hub.tp = transport
        with self.assertRaises(TmuxBufferCleanupFailure) as refused:
            await self.hub.finish_deliveries()
        self.assertIs(refused.exception, owner)
        self.assertIs(transport._buffers[owner.name], owner)
        with patch.object(transport, "_tm", return_value=""):
            owner.retry_cleanup()
        await self.hub.finish_deliveries()
        self.assertEqual(transport._buffers, {})

    async def test_main_joins_delivery_before_cleanup_checkpoint_and_hub_down(self):
        from hub import server
        task = await self.start()
        events, ready = [], asyncio.Event()
        federation_started, draining, finish_federation = asyncio.Event(), asyncio.Event(), asyncio.Event()
        self.addCleanup(finish_federation.set)

        async def loop():
            await asyncio.Event().wait()

        async def cleanup():
            self.assertTrue(self.joined.is_set())
            events.append("cleanup")

        async def federation():
            federation_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                draining.set()
                await finish_federation.wait()

        self.hub.cfg, self.hub.bridge = {}, None
        self.hub._work_source_binding = self.hub._work_start_cleanup = None
        self.hub._selected_endpoint = self.hub._legacy_work_notices = None
        self.hub._work_maintenance = None
        self.hub._peer_control_commands = None
        self.hub._policy_commands = None
        self.hub._knowledge_commands = self.hub._message_commands = None
        self.hub._work_rpc = self.hub._work_storage_commands = None
        self.hub._code_commands = None
        self.hub.bell_loop = self.hub.live_loop = self.hub.lease_loop = self.hub.receipt_loop = loop
        self.hub.fed = SimpleNamespace(run=federation, finish_cleanup=cleanup)
        self.hub.store.path = "fixture"
        self.hub.store.agents = lambda live: []
        self.hub.store.checkpoint = lambda: events.append("checkpoint")
        self.hub.store.db = SimpleNamespace(close=lambda: events.append('database close'))
        self.hub.dbx = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.hub.dbx.shutdown, wait=True)

        def logged(*args):
            events.append(args[0])
            if args[0] == "hub up":
                ready.set()

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(server, "HUBDIR", directory), \
                patch.object(server, "SOCK", os.path.join(directory, "hub.sock")), \
                patch.object(asyncio.get_running_loop(), "add_signal_handler"), \
                patch.object(asyncio.get_running_loop(), "remove_signal_handler"), \
                patch.object(server, "log", side_effect=logged):
            main = asyncio.create_task(self.hub.main())
            await asyncio.wait_for(ready.wait(), 2)
            await asyncio.wait_for(federation_started.wait(), 2)
            self.hub.stop.set()
            await asyncio.wait_for(draining.wait(), 2)
            self.assertTrue(self.cancellation.is_set(), "delivery must stop before federation drain joins")
            self.assertFalse(main.done())
            self.assertNotIn("checkpoint", events)
            self.assertNotIn("hub down", events)
            self.release.set()
            finish_federation.set()
            await main
        await task
        self.assertLess(events.index("cleanup"), events.index("checkpoint"))
        self.assertLess(events.index("checkpoint"), events.index("hub down"))


class RingReceiptStore(unittest.TestCase):
    def setUp(self):
        from hub.server import Hub
        self.hub = Hub.__new__(Hub)
        self.hub.store = fresh_store()
        self.addCleanup(shutil.rmtree, os.path.dirname(self.hub.store.path), ignore_errors=True)
        self.addCleanup(self.hub.store.db.close)
        self.hub.cfg = {"max_attempts": 12}
        self.session = reg(self.hub.store, "alpha", "worker", "target")
        self.hub.store.set_handle(self.session, "%1", 1000)
        self.agent = self.hub.store.agent(self.session)
        self.message = self.hub.store.post("virtual:operator", f"agent:{self.session}", "note", "original")

    def record(self, outcome, rering=False):
        return self.hub._record_ring(self.agent, deliver.Receipt(outcome=outcome, reason="test"),
                                      (self.message["id"], ()), rering, None)

    def test_submitted_receipt_preserves_original_message_cutoff(self):
        time.sleep(0.002)
        newer = self.hub.store.post("virtual:operator", f"agent:{self.session}", "note", "newer")
        self.assertGreater(newer["id"], self.message["id"])
        self.record("submitted", rering=True)
        pending = {row["message_id"]: row for row in self.hub.store.pending_for(self.session)}
        self.assertEqual(pending[self.message["id"]]["state"], "submitted")
        self.assertEqual(pending[newer["id"]]["state"], "queued")
        self.assertEqual(pending[self.message["id"]]["attempts"], 1)
        self.assertEqual(self.hub.store.agent(self.session)["state"], "busy")

    def test_deferred_receipt_does_not_spend_attempt_or_change_state(self):
        self.record("deferred")
        self.assertEqual(self.hub.store.pending_for(self.session)[0]["attempts"], 0)
        self.assertEqual(self.hub.store.agent(self.session)["state"], "ready")

    def test_blocked_receipt_preserves_blocked_state_and_no_attempt(self):
        self.record("blocked")
        self.assertEqual(self.hub.store.agent(self.session)["state"], "blocked")
        self.assertEqual(self.hub.store.pending_for(self.session)[0]["attempts"], 0)

    def test_failed_receipt_spends_one_attempt(self):
        self.record("failed")
        self.assertEqual(self.hub.store.pending_for(self.session)[0]["attempts"], 1)
        self.assertEqual(self.hub.store.agent(self.session)["state"], "ready")

    def test_replaced_registration_refuses_all_old_receipt_writes(self):
        self.hub.store.set_handle(self.session, "%2", 2000)
        before = self.hub.store.q("SELECT * FROM events")
        self.assertIsNone(self.record("submitted", rering=True))
        self.assertEqual(self.hub.store.q("SELECT * FROM events"), before)
        self.assertEqual(self.hub.store.pending_for(self.session)[0]["state"], "queued")
        self.assertEqual(self.hub.store.pending_for(self.session)[0]["attempts"], 0)


def _node_identity(value):
    return value.st_dev, value.st_ino, value.st_uid, value.st_mode


def _unlink_owned_tmux_socket(root, parent, name, root_identity, parent_identity, socket_identity):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root_fd = os.open(root, flags)
    try:
        current_root = os.fstat(root_fd)
        if (_node_identity(current_root) != root_identity
                or current_root.st_uid != os.getuid() or stat.S_IMODE(current_root.st_mode) != 0o700):
            raise AssertionError("owned tmux fixture directory changed")
        parent_fd = os.open(parent, flags, dir_fd=root_fd)
        try:
            current_parent = os.fstat(parent_fd)
            if (_node_identity(current_parent) != parent_identity
                    or current_parent.st_uid != os.getuid() or stat.S_IMODE(current_parent.st_mode) != 0o700):
                raise AssertionError("owned tmux socket directory changed")
            try:
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if (_node_identity(current) != socket_identity or not stat.S_ISSOCK(current.st_mode)
                    or current.st_uid != os.getuid()):
                raise AssertionError("owned tmux socket node changed")
            os.unlink(name, dir_fd=parent_fd)
            return True
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


class NativeSocketCleanup(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="amux-socket-", dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.parent = self.root / "owned"
        self.parent.mkdir(mode=0o700)
        self.path = self.parent / "socket"
        self.bind(self.path)
        self.root_identity = _node_identity(os.lstat(self.root))
        self.parent_identity = _node_identity(os.lstat(self.parent))
        self.socket_identity = _node_identity(os.lstat(self.path))

    def bind(self, path):
        # Leave a node without a listener, client or background process.
        with socket.socket(socket.AF_UNIX) as owned:
            owned.bind(str(path))

    def remove(self):
        return _unlink_owned_tmux_socket(self.root, self.parent.name, self.path.name,
                                         self.root_identity, self.parent_identity, self.socket_identity)

    def test_only_original_socket_is_removed(self):
        sentinel = self.parent / "sentinel"
        sentinel.write_text("keep")
        self.assertTrue(self.remove())
        self.assertFalse(self.path.exists())
        self.assertEqual(sentinel.read_text(), "keep")

    def test_replaced_socket_is_refused(self):
        original = self.parent / "original"
        self.path.rename(original)
        self.bind(self.path)
        with self.assertRaises(AssertionError):
            self.remove()
        self.assertTrue(self.path.exists())
        self.assertTrue(original.exists())

    def test_socket_symlink_is_refused(self):
        self.path.unlink()
        sentinel = self.root / "sentinel"
        sentinel.write_text("keep")
        self.path.symlink_to(sentinel)
        with self.assertRaises(AssertionError):
            self.remove()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(sentinel.read_text(), "keep")

    def test_changed_parent_is_not_followed(self):
        original = self.root / "original"
        self.parent.rename(original)
        self.parent.symlink_to(original, target_is_directory=True)
        with self.assertRaises(OSError):
            self.remove()
        self.assertTrue((original / "socket").exists())

    def test_nonprivate_root_refuses_cleanup(self):
        self.root.chmod(0o755)
        with self.assertRaises(AssertionError):
            self.remove()
        self.assertTrue(self.path.exists())

    def test_already_absent_socket_is_not_replaced_or_adopted(self):
        self.path.unlink()
        self.assertFalse(self.remove())


@unittest.skipUnless(os.environ.get("AGENTMUX_TEST_NATIVE_TMUX") == "1"
                     and sys.platform == "darwin" and platform.machine() == "arm64",
                     "requires explicit native macOS ARM64 tmux qualification")
class NativeDeliveryOwnership(unittest.TestCase):
    def setUp(self):
        # Darwin's sockaddr_un path holds 104 bytes, including the terminator.
        # Retain this private fixture and the original server diagnostics.
        self.root = Path(tempfile.mkdtemp(prefix="amux-delivery-", dir="/tmp"))
        self.root_identity = _node_identity(os.lstat(self.root))
        self.socket = "delivery-" + uuid.uuid4().hex
        self.socket_path = self.root / f"tmux-{os.getuid()}" / self.socket
        self.assertLess(len(os.fsencode(self.socket_path.resolve())), 104)
        self.startup_completed = False
        self.binary = shutil.which("tmux")
        self.assertIsNotNone(self.binary)
        environment = patch.dict(os.environ, TMUX_TMPDIR=str(self.root), TMUX="",
                                 ENV="/dev/null", BASH_ENV="/dev/null", PS1="amux> ")
        environment.start()
        self.addCleanup(environment.stop)
        self.server = subprocess.Popen(
            [self.binary, "-D", "-f", "/dev/null", "-L", self.socket],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(self.close_server)
        for _ in range(100):
            if self.socket_path.exists() or self.server.poll() is not None:
                break
            time.sleep(0.02)
        self.assertIsNone(self.server.poll(), "owned foreground tmux server exited during startup")
        self.assertEqual(int(self.tm("display-message", "-p", "#{pid}")), self.server.pid)
        self.parent_identity = _node_identity(os.lstat(self.socket_path.parent))
        socket_node = os.lstat(self.socket_path)
        self.assertTrue(stat.S_ISSOCK(socket_node.st_mode))
        self.socket_identity = _node_identity(socket_node)
        identity_file = self.root / "socket-identity.private.json"
        identity_file.write_text(json.dumps({"root": self.root_identity, "parent": self.parent_identity,
                                             "socket": self.socket_identity, "name": self.socket}) + "\n")
        identity_file.chmod(0o600)
        self.startup_completed = True
        for session in ("target", "sentinel"):
            self.tm("new-session", "-d", "-s", session, "-x", "120", "-y", "24", "/bin/sh", "-i")
        self.transport = TmuxTransport(socket=self.socket)
        self.original = self.transport.handle("target")
        self.assertIsNotNone(self.original)
        self.sentinel = self.transport.handle("sentinel")
        self.profile = profiles.Profile(cli="shell-fixture", ready=re.compile(r"^amux> "),
                                        busy=None, placeholder=re.compile(r"(?!)"), boot_s=0,
                                        pre_enter_s=0.01, submit_timeout_s=1)
        for _ in range(100):
            if self.profile.is_ready(self.transport.capture(self.original[0])):
                break
            time.sleep(0.02)
        self.assertTrue(self.profile.is_ready(self.transport.capture(self.original[0])))
        self.marker = self.root / "submitted"

    def tm(self, *args):
        self.assertIsNone(self.server.poll(), "original foreground tmux server exited")
        child = subprocess.Popen([self.binary, "-N", "-L", self.socket, *args],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = child.communicate()
        self.assertEqual(child.returncode, 0, "owned tmux command failed")
        return stdout.decode().strip()

    def close_server(self):
        # Signal only this original foreground child, never a server found by name.
        if self.server.poll() is None:
            self.server.terminate()
        stdout, stderr = self.server.communicate()
        for name, value in (("server.stdout.private", stdout), ("server.stderr.private", stderr)):
            path = self.root / name
            path.write_bytes(value)
            path.chmod(0o600)
        result = self.root / "server-exit.private.txt"
        result.write_text(f"exitCode={self.server.returncode}\nwaitJoined=true\n"
                          f"stdoutComplete=true\nstderrComplete=true\n"
                          f"socketRemainsAfterServerExit={self.socket_path.exists()}\n")
        result.chmod(0o600)
        print(f"retained native tmux fixture: {self.root}", file=sys.stderr)
        if self.startup_completed:
            self.assertEqual(self.server.returncode, 0, "owned tmux server did not close normally")
            removed = _unlink_owned_tmux_socket(self.root, self.socket_path.parent.name, self.socket,
                                                 self.root_identity, self.parent_identity, self.socket_identity)
            result.write_text(result.read_text() + f"ownedSocketRemoved={removed}\n"
                              f"socketRemainsAfterCleanup={self.socket_path.exists()}\n")
            self.assertFalse(self.socket_path.exists(), "owned tmux socket survived joined shutdown")

    def send(self, cancel=None, strategy="type"):
        return deliver.deliver_line(
            self.transport, self.profile, "target", self.original[0],
            "printf '%s' delivered > " + shlex.quote(str(self.marker)),
            pane_pid=self.original[1], cancel=cancel, auto_modals=False, submit_timeout_s=1,
            strategy=strategy,
        )

    def test_unchanged_native_shell_submits_once(self):
        receipt = self.send()
        self.assertEqual(receipt.outcome, "submitted", receipt.as_dict())
        self.assertEqual(self.marker.read_text(), "delivered")
        self.assertEqual(receipt.enters, 1)
        self.assertEqual(self.transport.handle("sentinel"), self.sentinel)

    def test_native_termination_confirms_original_session(self):
        target = self.transport.termination_target("target")
        self.assertTrue(self.transport.kill("target", expected=target))
        self.assertIsNone(self.transport.handle("target"))
        self.assertEqual(self.transport.handle("sentinel"), self.sentinel)

    def changed_roster_before_termination(self, mutation):
        target = self.transport.termination_target("target")
        command = self.transport._tm
        changed = False

        def race(*args, **kwargs):
            nonlocal changed
            if args[0] == "if-shell":
                self.tm(*mutation)
                changed = True
            return command(*args, **kwargs)

        with patch.object(self.transport, "_tm", side_effect=race):
            with self.assertRaisesRegex(RuntimeError, "termination unconfirmed"):
                self.transport.kill("target", expected=target)
        self.assertTrue(changed)
        self.assertIsNotNone(self.transport.handle("target"))
        self.assertNotEqual(self.transport.termination_target("target"), target)
        self.assertEqual(self.transport.handle("sentinel"), self.sentinel)

    def test_native_termination_refuses_last_moment_pane_replacement(self):
        self.changed_roster_before_termination(
            ("respawn-pane", "-k", "-t", self.original[0], "/bin/sh", "-i"))

    def test_native_termination_refuses_last_moment_added_pane(self):
        self.changed_roster_before_termination(
            ("split-window", "-d", "-t", self.original[0], "/bin/sh", "-i"))

    def native_named_kill(self, replace=False):
        source = Path(__file__).resolve().parents[2] / "agentmux.sh"
        harness = self.root / "harness.sh"
        harness.write_text(source.read_text().replace(
            '\ncase "${1:-}" in\n', '\nreturn 0 # stop fixture dispatch\n'))
        home = self.root / "home"
        (home / "run").mkdir(parents=True)
        (home / "run/target.started").write_text("original")
        (home / "run/target.task").write_text("SYNTHETIC-1")
        script = '''
source "$1" || exit 2
SOCKET="$2"
tm() {
  if [ "$1" = if-shell ] && [ "$REPLACE" = 1 ]; then
    command tmux -N -L "$SOCKET" respawn-pane -k -t "$ORIGINAL_PANE" /bin/sh -i || return 1
  fi
  command tmux -N -L "$SOCKET" "$@"
}
task_cli() { return 0; }
claim_reported() { return 0; }
task_try() { printf '%s\\n' "$1" >> "$ROOT/closeout"; }
claude_credentials_sync() { echo synchronized > "$ROOT/sync"; }
stop_courier_if_idle() { :; }
stop_idle_watchdog_if_no_agents() { :; }
cmd_kill target
'''
        result = subprocess.run([shutil.which("bash"), "-c", script, "kill-test", str(harness), self.socket],
                                env=dict(os.environ, AGENTMUX_HOME=str(home), AGENTMUX_NO_COURIER="1",
                                         AGENTMUX_IDLE_MINUTES="0", ORIGINAL_PANE=self.original[0],
                                         REPLACE=str(int(replace))),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual((home / "closeout").read_text(), "done\nreport\n")
        self.assertEqual(self.transport.handle("sentinel"), self.sentinel)
        if replace:
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNotNone(self.transport.handle("target"))
            self.assertEqual((home / "run/target.started").read_text(), "original")
            self.assertEqual((home / "run/target.task").read_text(), "SYNTHETIC-1")
            self.assertFalse((home / "sync").exists())
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIsNone(self.transport.handle("target"))
            self.assertFalse((home / "run/target.started").exists())
            self.assertEqual((home / "sync").read_text(), "synchronized\n")

    def test_native_named_kill_cleans_only_confirmed_target(self):
        self.native_named_kill()

    def test_native_named_kill_retains_state_for_changed_pane(self):
        self.native_named_kill(replace=True)

    def test_native_same_name_spawn_waits_for_kill_cleanup(self):
        source = Path(__file__).resolve().parents[2] / "agentmux.sh"
        harness = self.root / "spawn-kill.sh"
        harness.write_text(source.read_text().replace(
            '\ncase "${1:-}" in\n', '\nreturn 0 # stop fixture dispatch\n'))
        home = self.root / "spawn-home"
        home.mkdir()
        environment = dict(os.environ, HOME=str(home), AGENTMUX_HOME=str(home),
                           AGENTMUX_NO_COURIER="1", AGENTMUX_IDLE_MINUTES="0", SHELL="/bin/sh")
        script = '''
source "$1" || exit 2
SOCKET="$2"
tm() { command tmux -N -L "$SOCKET" "$@"; }
task_cli() { return 1; }
claude_credentials_sync() { :; }
claude_config_gc() { :; }
start_idle_watchdog() { :; }
stop_courier_if_idle() { :; }
stop_idle_watchdog_if_no_agents() { :; }
node_bin() { printf '/usr/bin\\n'; }
archive_log() {
  python3 - "$ROOT/.spawn.lock" <<'PYLOCK'
import fcntl, sys
with open(sys.argv[1], "a") as stream:
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(0)
    sys.exit(1)
PYLOCK
  [ "$?" = 0 ] || exit 91
  return 1
}
if [ "$3" = kill ]; then
  sweep_sidecars() {
    touch "$ROOT/cleanup-entered"
    python3 - "$ROOT/cleanup-release" <<'PYWAIT'
import pathlib, sys, time
path = pathlib.Path(sys.argv[1])
deadline = time.monotonic() + 10
while not path.exists():
    if time.monotonic() > deadline:
        sys.exit(1)
    time.sleep(.01)
PYWAIT
    [ "$?" = 0 ] || exit 92
    rm -f "$RUNDIR/$1".*
  }
  cmd_kill worker
else
  have() {
    touch "$ROOT/spawn-attempted"
    tm has-session -t "=$1" 2>/dev/null
  }
  cmd_spawn worker --cli shell --cwd "$ROOT"
fi
'''
        children = []

        def start(mode):
            child = subprocess.Popen([shutil.which("bash"), "-c", script, "race-test",
                                      str(harness), self.socket, mode], env=environment,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            children.append(child)
            return child

        def join(child):
            stdout, stderr = child.communicate(timeout=12)
            self.assertEqual(child.returncode, 0, stderr.decode())

        def wait_marker(name, child):
            deadline = time.monotonic() + 5
            while not (home / name).exists():
                self.assertIsNone(child.poll(), "fixture exited before coordination point")
                self.assertLess(time.monotonic(), deadline, "fixture coordination timed out")
                time.sleep(.01)

        try:
            join(start("spawn"))
            original = self.transport.termination_target("worker")
            (home / "spawn-attempted").unlink()
            killer = start("kill")
            wait_marker("cleanup-entered", killer)
            replacement = start("spawn")
            wait_marker("spawn-attempted", replacement)
            self.assertIsNone(replacement.poll())
            self.assertIsNone(self.transport.handle("worker"))
            (home / "cleanup-release").touch()
            join(killer)
            join(replacement)
            self.assertNotEqual(self.transport.termination_target("worker"), original)
            self.assertEqual((home / "run/worker.cli").read_text(), "shell\n")
            self.assertTrue((home / "run/worker.started").read_text().strip())
            self.assertEqual((home / "run/worker.pane").read_text().strip(), self.transport.handle("worker")[0])
            self.assertEqual(self.transport.handle("sentinel"), self.sentinel)
        finally:
            (home / "cleanup-release").touch()
            for child in children:
                if child.poll() is None:
                    child.terminate()
                child.communicate(timeout=12)

    def test_cancel_after_native_capture_sends_no_input(self):
        cancel, capture = Event(), self.transport.capture

        def cancelled(handle):
            value = capture(handle)
            cancel.set()
            return value

        self.transport.capture = cancelled
        receipt = self.send(cancel)
        self.assertEqual(receipt.outcome, "deferred")
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.transport.handle("target"), self.original)
        self.assertEqual(self.transport.handle("sentinel"), self.sentinel)

    def test_native_pane_pid_change_refuses_before_input(self):
        capture, replaced = self.transport.capture, False

        def replacement(handle):
            nonlocal replaced
            value = capture(handle)
            if not replaced:
                self.assertEqual(int(self.tm("display-message", "-p", "#{pid}")), self.server.pid)
                self.tm("respawn-pane", "-k", "-t", self.original[0], "/bin/sh", "-i")
                replaced = True
            return value

        self.transport.capture = replacement
        receipt = self.send()
        current = self.transport.handle("target")
        self.assertEqual(current[0], self.original[0])
        self.assertNotEqual(current[1], self.original[1])
        self.assertEqual(receipt.outcome, "failed")
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.transport.handle("sentinel"), self.sentinel)

    def test_native_buffer_submission_reclaims_only_its_buffer(self):
        self.tm("set-buffer", "-b", "sentinel", "unrelated")
        receipt = self.send(strategy="buffer")
        self.assertEqual(receipt.outcome, "submitted", receipt.as_dict())
        self.assertEqual(self.marker.read_text(), "delivered")
        self.assertEqual(self.tm("list-buffers", "-F", "#{buffer_name}"), "sentinel")
        self.assertEqual(self.tm("show-buffer", "-b", "sentinel"), "unrelated")
        self.assertEqual(self.transport.handle("sentinel"), self.sentinel)

    def buffer_interruption(self, replace):
        self.tm("set-buffer", "-b", "sentinel", "unrelated")
        cancel, command, operations = Event(), self.transport._tm, []

        def interrupted(*args, **kwargs):
            operations.append(args[0])
            value = command(*args, **kwargs)
            if args[0] == "load-buffer":
                if replace:
                    self.assertEqual(int(self.tm("display-message", "-p", "#{pid}")), self.server.pid)
                    self.tm("respawn-pane", "-k", "-t", self.original[0], "/bin/sh", "-i")
                else:
                    cancel.set()
            return value

        self.transport._tm = interrupted
        receipt = self.send(cancel, strategy="buffer")
        self.assertEqual(receipt.outcome, "failed" if replace else "deferred")
        self.assertNotIn("paste-buffer", operations)
        self.assertNotIn("printf", self.transport.capture(self.original[0]))
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.tm("list-buffers", "-F", "#{buffer_name}"), "sentinel")
        self.assertEqual(self.tm("show-buffer", "-b", "sentinel"), "unrelated")
        self.assertEqual(self.transport.handle("sentinel"), self.sentinel)

    def test_cancel_during_native_buffer_load_prevents_paste(self):
        self.buffer_interruption(False)

    def test_replacement_during_native_buffer_load_prevents_paste(self):
        self.buffer_interruption(True)


class CliReceipts(unittest.TestCase):  # TM-213 / C15
    BELL = "[hub] 1 new message(s), 0 claimable work item(s) for calc-worker-codex_1. Run: agentmux hub inbox --ack"

    def setUp(self):
        from hub.receipts import ReceiptScanner
        self.d = tempfile.mkdtemp(prefix="hubrcpt-", dir="/tmp")
        self.files = {"codex": os.path.join(self.d, "codex", "sessions", "2026", "rollout-a.jsonl"),
                      "claude": os.path.join(self.d, "claude", "projects", "p", "s.jsonl"),
                      "grok": os.path.join(self.d, "grok", "sessions", "x", "y", "updates.jsonl")}
        for f in self.files.values():
            os.makedirs(os.path.dirname(f), exist_ok=True)
            open(f, "w").write(json.dumps({"type": "old history, " + self.BELL}) + "\n")
        self.sc = ReceiptScanner({
            "codex": [os.path.join(self.d, "codex", "sessions", "**", "*.jsonl")],
            "claude": [os.path.join(self.d, "claude", "projects", "*", "*.jsonl")],
            "grok": [os.path.join(self.d, "grok", "sessions", "*", "*", "updates.jsonl")]})
        self.assertEqual(self.sc.scan(), [])            # primes at EOF: history is not a receipt

    def append(self, cli, obj):
        with open(self.files[cli], "a") as f:
            f.write(json.dumps(obj) + "\n")

    def test_each_cli_format(self):
        self.append("codex", {"type": "event_msg", "payload": {"type": "item_completed", "item": {
            "type": "UserMessage", "content": [{"type": "input_text", "text": self.BELL}]}}})
        self.append("claude", {"type": "user", "message": {"content": self.BELL.replace("codex_1", "claude_1")}})
        self.append("grok", {"params": {"update": {"sessionUpdate": "user_message_chunk",
                                                   "content": {"type": "text", "text": self.BELL.replace("codex_1", "grok_1")}}}})
        got = sorted((s, c) for s, c, _ref in self.sc.scan())
        self.assertEqual(got, [("calc-worker-claude_1", "claude"), ("calc-worker-codex_1", "codex"),
                               ("calc-worker-grok_1", "grok")])
        self.assertEqual(self.sc.scan(), [])            # incremental: nothing new, nothing reported

    def test_assistant_text_and_partial_lines_are_not_receipts(self):
        self.append("claude", {"type": "assistant", "message": {"content": self.BELL}})
        with open(self.files["codex"], "a") as f:
            f.write('{"type": "event_msg", "payload"')     # no newline yet: a write in progress
        self.assertEqual(self.sc.scan(), [])

    def test_grok_bell_split_across_chunks(self):
        for part in (self.BELL[:20], self.BELL[20:]):
            self.append("grok", {"params": {"update": {"sessionUpdate": "user_message_chunk",
                                                       "content": {"type": "text", "text": part}}}})
        self.assertEqual([s for s, _c, _r in self.sc.scan()], ["calc-worker-codex_1"])

    def test_hold_alert_fires_once(self):
        import asyncio
        from hub import server as srv
        s = fresh_store()
        w = reg(s, "alpha", "worker", "g1", cli="grok")
        mid = s.post("virtual:operator", f"agent:{w}", "request", "held")["id"]
        notes = []

        class Stub:
            store, cfg = s, {"hold_alert_s": 300}
            awaiting = {w: {"at": 1000.0, "upto": mid, "alerted": False}}

            async def db(self, fn, *a, **kw):
                return fn(*a, **kw)

            async def _tell_operator(self, body, idem):
                notes.append(body)
        stub = Stub()
        asyncio.run(srv.Hub.check_holds(stub, 1000.0 + 299))
        self.assertEqual(notes, [])
        asyncio.run(srv.Hub.check_holds(stub, 1000.0 + 301))
        asyncio.run(srv.Hub.check_holds(stub, 1000.0 + 900))
        self.assertEqual(len(notes), 1)
        self.assertIn("holding input (C15)", notes[0])
        s.inbox(w)
        s.ack(w, [mid])
        asyncio.run(srv.Hub.check_holds(stub, 1000.0 + 901))
        self.assertNotIn(w, stub.awaiting)               # acked means received: stop watching

    def test_mark_received(self):
        s = fresh_store()
        w = reg(s, "alpha", "worker", "c1")
        a = s.post("virtual:operator", f"agent:{w}", "note", "one")["id"]
        s.delivery_report(a, w, "submitted")
        b = s.post("virtual:operator", f"agent:{w}", "note", "two")["id"]  # after the bell
        self.assertEqual(s.mark_received(w, a, {"cli_receipt": "x"}), [a])
        states = {p["message_id"]: p["state"] for p in s.pending_for(w)}
        self.assertEqual(states, {a: "received", b: "queued"})


class BackupsAndRetention(unittest.TestCase):  # TM-217
    def setUp(self):
        self.s = fresh_store()
        self.w = reg(self.s, "alpha", "worker", "w1")

    def test_rotation_keeps_newest_and_copy_restores(self):
        d = tempfile.mkdtemp(prefix="hubbk-", dir="/tmp")
        self.s.post("virtual:operator", f"agent:{self.w}", "note", "keep me")
        paths = [self.s.backup_to(d, keep=3) for _ in range(5)]
        left = sorted(os.listdir(d))
        self.assertEqual(len(left), 3)
        self.assertEqual(left[-1], os.path.basename(paths[-1]))
        restored = Store(os.path.join(d, left[-1]))
        self.assertEqual(restored.q1("SELECT body FROM messages")["body"], "keep me")

    def test_prune_never_touches_undelivered_mail(self):
        done = self.s.post("virtual:operator", f"agent:{self.w}", "note", "acked, old")["id"]
        live = self.s.post("virtual:operator", f"agent:{self.w}", "note", "unacked, old")["id"]
        self.s.ack(self.w, [done])
        self.s.db.execute("UPDATE messages SET created='2020-01-01T00:00:00.000Z'")
        self.s.db.execute("UPDATE events SET at='2020-01-01T00:00:00.000Z'")
        n = self.s.prune(events_days=14, messages_days=30)
        self.assertEqual(n["messages"], 1)
        left = [m["id"] for m in self.s.q("SELECT id FROM messages")]
        self.assertEqual(left, [live])
        self.assertEqual([m["id"] for m in self.s.inbox(self.w)], [live])
        self.assertGreater(n["events"], 0)

    def test_migration_takes_a_backup_first(self):
        from hub import store as store_mod
        path = self.s.path
        self.s.db.close()
        current = len(store_mod.MIGRATIONS)
        store_mod.MIGRATIONS.append("CREATE TABLE migration_probe (x INTEGER) STRICT;")
        try:
            s2 = Store(path)
            self.assertEqual(s2.q1("PRAGMA user_version")["user_version"], len(store_mod.MIGRATIONS))
            bk = os.listdir(os.path.join(os.path.dirname(path), "backups"))
            self.assertTrue(any(b.startswith(f"hub-premigrate-v{current}-") for b in bk), bk)
        finally:
            store_mod.MIGRATIONS.pop()


class LegacyLifecycle(unittest.TestCase):
    """Compare the real legacy lifecycle without starting agents or providers."""

    def test_failed_unix_connection_closes_its_exact_socket(self):
        import socket
        from pathlib import Path
        from unittest.mock import patch
        from hub import cli

        with tempfile.TemporaryDirectory(prefix="hubconnect-", dir="/tmp") as directory:
            original_socket = socket.socket
            owned = []

            def retain_actual_socket(*args, **kwargs):
                result = original_socket(*args, **kwargs)
                owned.append(result)
                self.addCleanup(result.close)
                return result

            with patch.dict(os.environ, {}, clear=True), patch.object(cli, "SOCK", str(Path(directory) / "absent.sock")), \
                    patch.object(socket, "socket", retain_actual_socket):
                for timeout, failure in ((1, FileNotFoundError), (-1, ValueError)):
                    with self.subTest(timeout=timeout):
                        with self.assertRaises(failure):
                            cli.connect(timeout)
                        self.assertEqual(len(owned), 1)
                        self.assertEqual(owned.pop().fileno(), -1, "the failed socket must already be closed")

    def test_real_legacy_start_reuse_stop_preserves_selected_store(self):
        import contextlib
        import io
        import sqlite3
        import subprocess
        import rfc8785
        from pathlib import Path
        from unittest.mock import patch
        from hub import cli

        root = Path(__file__).resolve().parents[2]
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "the existing harness needs bash")
        with tempfile.TemporaryDirectory(prefix="hublegacy-", dir="/tmp") as directory:
            private = Path(directory)
            home, selected = private / "home", private / "selected"
            home.mkdir()
            (selected / "hub").mkdir(parents=True)
            (selected / "hub" / "config.toml").write_text('tcp_port = 0\nnats_url = ""\n')
            env = {
                "HOME": str(home), "AGENTMUX_HOME": str(selected),
                "AGENTMUX_PYTHON": sys.executable, "AGENTMUX_BIN": str(root / "agentmux.sh"),
                "AGENTMUX_REPO": str(root), "AGENTMUX_NO_COURIER": "1",
                "AGENTMUX_SOCKET": private.name + "-unused",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": os.pathsep.join((str(root / "sdk" / "python"),
                    str(Path(rfc8785.__file__).resolve().parent.parent))),
                "PATH": os.pathsep.join(dict.fromkeys((str(Path(sys.executable).parent),
                                                       str(Path(bash).parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin"))),
            }
            children, logfiles = [], []
            original_popen = subprocess.Popen

            def retain_actual_child(*args, **kwargs):
                process = original_popen(*args, **kwargs)
                children.append(process)
                logfiles.append(kwargs["stdout"])
                return process

            def frontend(*args):
                return subprocess.run([bash, str(root / "agentmux.sh"), "hub", *args],
                                      env=env, cwd=str(home), capture_output=True, text=True, timeout=10)

            def stop_exact_children():
                for child in children:
                    if child.poll() is None:
                        child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
                for logfile in logfiles:
                    logfile.close()

            try:
                # Delegate the actual creation unchanged and retain its original
                # Popen owner. No PID lookup or reconstructed process handle is used.
                with patch.dict(os.environ, env, clear=True), patch.object(cli, "ROOT", str(selected)), \
                        patch.object(cli, "SOCK", str(selected / "hub" / "hub.sock")), \
                        patch.object(subprocess, "Popen", retain_actual_child), contextlib.redirect_stdout(io.StringIO()):
                    cli.start()
                self.assertEqual(len(children), 1)
                child = children[0]
                for logfile in logfiles:
                    logfile.close()
                pidfile = selected / "hub" / "hub.pid"
                self.assertEqual(pidfile.read_text(), str(child.pid))
                self.assertIsNone(child.poll())
                warm = frontend("start")
                self.assertEqual(warm.returncode, 0, warm.stderr)
                self.assertIn("hub already running", warm.stdout)
                self.assertIsNone(child.poll(), "the hub must survive the warm frontend's exit")
                self.assertEqual(pidfile.read_text(), str(child.pid))
                status = frontend("status", "--json")
                self.assertEqual(status.returncode, 0, status.stderr)
                observed = json.loads(status.stdout)
                self.assertEqual(set(observed), {"agents", "deliveries", "work", "dead", "repos", "teams"})
                self.assertEqual(observed["agents"], [])
                posted = frontend("post", "--to", "virtual:operator", "--kind", "note", "legacy lifecycle record")
                self.assertEqual(posted.returncode, 0, posted.stderr)
                stopped = frontend("stop")
                self.assertEqual(stopped.returncode, 0, stopped.stderr)
                self.assertEqual(child.wait(timeout=10), 0)
                self.assertFalse((selected / "hub" / "hub.sock").exists())
                database = selected / "hub" / "hub.db"
                with contextlib.closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as stored:
                    self.assertEqual(stored.execute("SELECT body FROM messages").fetchall(),
                                     [("legacy lifecycle record",)])
                failed = frontend("status", "--json")
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("hub is not reachable", failed.stderr)
                self.assertIn("agentmux hub start", failed.stderr)
                self.assertEqual(failed.stdout, "")
                self.assertFalse((home / ".agentmux").exists(), "explicit selection must not use the default home")
            finally:
                stop_exact_children()


class ServerAPI(unittest.TestCase):
    """The socket API end to end, against a real hub process on a throwaway home.
    Added after `return r` in two verbs was silently truncated to `return` (a bad
    sed): the store tests all passed while `repo_add` and `post` answered null."""

    @classmethod
    def setUpClass(cls):
        import subprocess
        cls.home = tempfile.mkdtemp(prefix="hubapi-", dir="/tmp")
        os.makedirs(os.path.join(cls.home, "repoA"))
        import socket as _s
        probe = _s.socket()
        probe.bind(("127.0.0.1", 0))
        cls.port = probe.getsockname()[1]
        probe.close()
        os.makedirs(os.path.join(cls.home, "hub"))
        with open(os.path.join(cls.home, "hub", "config.toml"), "w") as f:
            f.write(f"tcp_port = {cls.port}\n")
        env = {**os.environ, "AGENTMUX_HOME": cls.home, "AGENTMUX_SOCKET": "hubapi-test-none",
               "AGENTMUX_BIN": shutil.which("true")}  # harness calls (courier stop) succeed, touch nothing;
                                                        # /usr/bin/true on macOS, /bin/true on Linux
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cls.proc = subprocess.Popen([sys.executable, os.path.join(root, "hub", "server.py")], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        cls.sock = os.path.join(cls.home, "hub", "hub.sock")
        for _ in range(50):
            if os.path.exists(cls.sock):
                break
            time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.call("shutdown", {})
        except Exception:
            pass
        cls.proc.wait(timeout=10)

    @classmethod
    def call(cls, verb, args):
        import socket
        s = socket.socket(socket.AF_UNIX)
        s.connect(cls.sock)
        s.sendall((json.dumps({"verb": verb, "args": args}) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf)

    def test_every_write_verb_returns_a_result(self):
        r = self.call("repo_add", {"repo": "repo_a", "paths": [os.path.join(self.home, "repoA")]})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["result"]["repo"], "repo_a")
        p = self.call("post", {"to": "virtual:operator", "kind": "note", "body": "api check"})
        self.assertTrue(p["ok"], p)
        self.assertTrue(p["result"]["id"])
        w = self.call("work_add", {"to": "role:repo_a/worker", "title": "api item"})
        self.assertTrue(w["result"]["id"].startswith("W-"), w)
        box = self.call("inbox", {"ack": True})
        self.assertEqual(box["result"]["messages"][0]["body"], "api check")
        self.assertEqual(self.call("work_cancel", {"work_id": w["result"]["id"]})["result"]["cancelled"],
                         [w["result"]["id"]])

    def test_unknown_verb_is_an_error_not_null(self):
        r = self.call("no_such_verb", {})
        self.assertFalse(r["ok"])

    # -- TM-215: TCP + tokens + subscribe -------------------------------------------------
    def tcp(self, req):
        import socket
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf)

    def op_token(self):
        with open(os.path.join(self.home, "hub", "operator.token")) as f:
            return f.read().strip()

    def test_tcp_requires_a_valid_token(self):
        self.assertIn("token required", self.tcp({"verb": "ping"})["error"])
        self.assertIn("invalid", self.tcp({"verb": "ping", "token": "nope"})["error"])
        ok = self.tcp({"verb": "ping", "token": self.op_token()})
        self.assertEqual(ok["caller"], "operator")

    def test_tcp_ignores_as(self):  # nothing the caller claims is an identity over TCP
        r = self.tcp({"verb": "whoami", "token": self.op_token(), "as": "alpha-worker-w1"})
        self.assertEqual(r["caller"], "operator")

    def test_tcp_post_and_read(self):
        tok = self.op_token()
        p = self.tcp({"verb": "post", "token": tok, "args": {"to": "virtual:operator", "body": "via tcp"}})
        self.assertTrue(p["result"]["id"])
        box = self.tcp({"verb": "inbox", "token": tok, "args": {"ack": True}})
        self.assertIn("via tcp", [m["body"] for m in box["result"]["messages"]])

    def test_retire_courier_imports_only_the_undelivered_backlog_once(self):  # TM-214 AC1
        q, c = os.path.join(self.home, "queue"), os.path.join(self.home, "courier")
        os.makedirs(q, exist_ok=True)
        os.makedirs(c, exist_ok=True)
        line1 = json.dumps({"sender": "bob", "recipient": "orchestrator", "kind": "status", "body": "already sent"}) + "\n"
        line2 = json.dumps({"sender": "bob", "recipient": "orchestrator", "kind": "status", "body": "still queued"}) + "\n"
        line3 = json.dumps({"sender": "bob", "recipient": "ghost", "kind": "status", "body": "nobody"}) + "\n"
        with open(os.path.join(q, "bob.jsonl"), "w") as f:
            f.write(line1 + line2 + line3)
        st = os.stat(os.path.join(q, "bob.jsonl"))
        with open(os.path.join(c, "bob.cursor"), "w") as f:
            json.dump({"dev": st.st_dev, "ino": st.st_ino, "offset": len(line1)}, f)
        r = self.call("retire_courier", {})["result"]
        self.assertEqual((r["imported"], r["unresolved"]), (1, ["bob->ghost"]))
        self.assertTrue(r["courier_stopped"])
        self.assertTrue(os.path.exists(os.path.join(self.home, "hub", "courier-retired")))
        again = self.call("retire_courier", {})["result"]
        self.assertEqual((again["imported"], again["duplicate"]), (0, 1))
        box = [m for m in self.call("inbox", {"session": "virtual:orchestrator"})["result"]["messages"]
               if m["sender"] == "virtual:legacy_bob"]              # the inbox is shared with other tests
        self.assertEqual([m["body"] for m in box], ["still queued"])  # once, and "already sent" not replayed

    def test_agentmux_post_goes_through_the_hub(self):  # TM-214 AC1, from bash
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        env = {k: v for k, v in os.environ.items() if k != "AGENTMUX_AGENT"}
        env.update(AGENTMUX_HOME=self.home, AGENTMUX_REPO=root, AGENTMUX_SOCKET="hubapi-test-none")
        cmd = f"bash <(tr -d '\\r' < '{root}/agentmux.sh') post orchestrator --kind finding via-bash-hub-path"
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("posted", r.stdout)
        box = self.call("inbox", {"session": "virtual:orchestrator"})["result"]["messages"]
        self.assertIn("via-bash-hub-path", [m["body"] for m in box])
        self.assertFalse(os.path.exists(os.path.join(self.home, "queue", "orchestrator.jsonl")))

    def test_token_file_is_private(self):
        st = os.stat(os.path.join(self.home, "hub", "operator.token"))
        self.assertEqual(st.st_mode & 0o077, 0)

    def test_subscribe_streams_new_mail_and_events(self):
        import socket
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(10)
        s.connect(self.sock)
        s.sendall(b'{"verb": "subscribe", "args": {"stream": "mail"}}\n')
        f = s.makefile("r")
        self.assertEqual(json.loads(f.readline())["subscribed"], "mail")
        self.call("post", {"to": "virtual:operator", "body": "pushed"})
        got = None
        for _ in range(20):
            line = json.loads(f.readline())
            if "message" in line and line["message"]["body"] == "pushed":
                got = line
                break
        self.assertIsNotNone(got)
        s.close()
        e = socket.socket(socket.AF_UNIX)
        e.settimeout(10)
        e.connect(self.sock)
        e.sendall(b'{"verb": "subscribe", "args": {"stream": "events", "since": 0}}\n')
        ef = e.makefile("r")
        self.assertEqual(json.loads(ef.readline())["subscribed"], "events")
        self.assertIn("event", json.loads(ef.readline()))
        e.close()


class Profiles(unittest.TestCase):
    def test_claude_idle_prompt_is_not_a_modal(self):
        p = profiles.get("claude")
        idle = "────────\n❯ \n────────\n  ⏵⏵ bypass permissions on (shift+tab to cycle)"
        self.assertIsNone(p.modal(idle))
        self.assertTrue(p.is_ready(idle))

    def test_claude_bypass_consent_answer(self):
        p = profiles.get("claude")
        m = p.modal("WARNING: Claude Code running in Bypass Permissions mode\n❯ 1. No, exit\n  2. Yes, I accept")
        self.assertEqual(m.kind, "bypass")
        self.assertEqual(m.answer, {"select": r"^Yes, I accept"})


class MenuByLabel(unittest.TestCase):
    """C2, measured 2026-09-29: claude 2.1.285's folder-trust dialog preselects 'No, exit'.
    A positional Enter killed a team lead 9 s after spawn. Answers go by label."""

    def menu(self, opts, sel):
        head = ("Accessing workspace:\n /home/nick/hubdemo/calc\n Quick safety check: Is this a project you "
                "created or one you trust?\n")
        body = "\n".join((" ❯ " if i == sel else "   ") + o for i, o in enumerate(opts))
        return head + body + "\n Enter to confirm · Esc to cancel"

    def test_trust_selects_yes_even_when_no_is_preselected(self):
        t = FakeTransport()
        opts, state = ["No, exit", "Yes, I trust this folder"], {"sel": 0, "chosen": None}
        t.add("c", self.menu(opts, 0))
        orig = t.send_key

        def key(h, k):
            t.sent.append((h, "key", k))
            if k == "Down":
                state["sel"] = min(state["sel"] + 1, len(opts) - 1)
            elif k == "Up":
                state["sel"] = max(state["sel"] - 1, 0)
            elif k == "Enter" and state["chosen"] is None:
                state["chosen"] = opts[state["sel"]]
                t.sessions[h]["screen"] = "────\n❯ \n────\n  ⏵⏵ bypass permissions on"
                return
            elif k == "Enter":
                return orig(h, k)
            t.sessions[h]["screen"] = self.menu(opts, state["sel"])
        t.send_key = key
        rc = deliver.deliver_line(t, profiles.get("claude"), "c", "c", "[hub] 1 new message(s). Run: agentmux hub inbox --ack", pane_pid=1000)
        self.assertEqual(state["chosen"], "Yes, I trust this folder", t.sent)
        self.assertEqual(rc.modal_answers[0]["keys"], ["Down", "Enter"])

    def test_missing_safe_option_blocks(self):
        t = FakeTransport()
        t.add("c", self.menu(["No, exit", "Maybe later"], 0))
        rc = deliver.deliver_line(t, profiles.get("claude"), "c", "c", "x", pane_pid=1000)
        self.assertEqual(rc.outcome, "blocked")
        self.assertNotIn("Enter", [k for _, kind, k in t.sent if kind == "key"])


class BridgeConnectBounded(unittest.TestCase):
    def test_silent_endpoint_times_out_instead_of_hanging(self):  # a black-holed NATS must not stall the outbox
        import asyncio
        from hub.bridge import NatsClient

        async def go():
            held = []                                          # keep the socket open: silent, not closed

            async def silent(r, w):
                held.append(w)
                await asyncio.sleep(10)

            server = await asyncio.start_server(silent, "127.0.0.1", 0)  # accepts, never sends INFO
            port = server.sockets[0].getsockname()[1]
            nc = NatsClient(f"nats://127.0.0.1:{port}", "t")
            t0 = time.monotonic()
            try:
                with self.assertRaises(TimeoutError):  # an OSError, so run()'s retry loop catches it
                    await nc.connect(timeout=0.3)
            finally:
                if nc.writer:
                    nc.writer.close()
                for w in held:
                    w.close()
                server.close()
            return time.monotonic() - t0

        self.assertLess(asyncio.run(go()), 5)


class NamedTermination(unittest.TestCase):
    original = "101|12|$3|13|%4|105"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        source = Path(__file__).resolve().parents[2] / "agentmux.sh"
        self.harness = self.root / "harness.sh"
        self.harness.write_text(source.read_text().replace(
            '\ncase "${1:-}" in\n', '\nreturn 0 # stop offline test dispatch\n'))
        (self.root / "run").mkdir()
        (self.root / "roster").write_text(self.original + "\n")
        (self.root / "run/target.started").write_text("original")
        (self.root / "run/target.task").write_text("SYNTHETIC-1")
        self.environment = dict(os.environ, AGENTMUX_HOME=str(self.root),
                                AGENTMUX_NO_COURIER="1", AGENTMUX_IDLE_MINUTES="0")

    def invoke(self, mutation="", kill_status=0, expected=""):
        # Only the real harness functions under test run. No native tmux, Jira,
        # provider, credential file or shared home is used by these stubs.
        script = '''
source "$1" || exit 2
tm() {
  case "$1" in
    list-panes) cat "$ROOT/roster" ;;
    if-shell)
      printf '%s\\n' "$*" > "$ROOT/killed"
      [ "$KILL_STATUS" = 0 ] || return "$KILL_STATUS"
      printf 'agentmux-kill-confirmed\\n' ;;
    *) return 2 ;;
  esac
}
task_cli() { return 0; }
claim_reported() { printf 'claimed\\n' >> "$ROOT/order"; }
task_try() {
  printf '%s\\n' "$*" >> "$ROOT/order"
  if [ "$1" = done ]; then eval "$MUTATION"; fi
}
claude_credentials_sync_locked() { echo unexpected-relock > "$ROOT/sync"; return 1; }
claude_credentials_sync() {
  python3 - "$ROOT/.spawn.lock" <<'PYLOCK'
import fcntl, sys
with open(sys.argv[1], "a") as stream:
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit(0)
    sys.exit(1)
PYLOCK
  [ "$?" = 0 ] || return 1
  echo synchronized > "$ROOT/sync"
}
stop_courier_if_idle() { :; }
stop_idle_watchdog_if_no_agents() { :; }
cmd_kill target
'''
        env = dict(self.environment, MUTATION=mutation, KILL_STATUS=str(kill_status),
                   AGENTMUX_KILL_EXPECTED_TARGET=expected)
        return subprocess.run([shutil.which("bash"), "-c", script, "kill-test", str(self.harness)],
                              env=env, capture_output=True, text=True, timeout=10)

    def test_confirmed_original_kill_sweeps_and_syncs_under_same_lock(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kill-session -t $3 ; display-message -p agentmux-kill-confirmed", (self.root / "killed").read_text())
        self.assertFalse((self.root / "run/target.started").exists())
        self.assertEqual((self.root / "sync").read_text(), "synchronized\n")
        self.assertEqual((self.root / "order").read_text().splitlines(), [
            "claimed", "done SYNTHETIC-1 --from-log target",
            "report target --title agentmux run - target - SYNTHETIC-1"])

    def test_replacement_during_closeout_keeps_sidecars_and_never_kills(self):
        result = self.invoke("printf '101|12|$8|13|%%9|110\\n' > \"$ROOT/roster\"")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "killed").exists())
        self.assertEqual((self.root / "run/target.started").read_text(), "original")

    def test_changed_run_metadata_refuses_kill(self):
        result = self.invoke('echo replacement > "$RUNDIR/target.started"')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "killed").exists())

    def test_unknown_final_query_refuses_kill(self):
        result = self.invoke('rm "$ROOT/roster"')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "killed").exists())
        self.assertTrue((self.root / "run/target.task").exists())

    def test_failed_kill_preserves_run_metadata(self):
        result = self.invoke(kill_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / "run/target.task").exists())
        self.assertFalse((self.root / "sync").exists())

    def test_hub_expected_target_refused_before_any_closeout(self):
        result = self.invoke(expected=self.original.replace("%4", "%9"))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "order").exists())
        self.assertFalse((self.root / "killed").exists())

    def test_linked_run_metadata_is_unknown(self):
        (self.root / "run/target.task").unlink()
        (self.root / "run/target.task").symlink_to(self.root / "roster")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "order").exists())

    def test_transport_target_roster_is_canonical_and_complete(self):
        transport = TmuxTransport("offline")
        other = self.original.replace("%4|105", "%6|107")
        with patch.object(transport, "_tm", return_value=other + "\n" + self.original + "\n"):
            self.assertEqual(transport.termination_target("target"), self.original + "\n" + other)
        for invalid in ("", self.original + "\n" + self.original, "bad", other.replace("$3", "$8") + "\n" + self.original):
            with self.subTest(invalid=invalid), patch.object(transport, "_tm", return_value=invalid):
                with self.assertRaises(RuntimeError):
                    transport.termination_target("target")

    def test_transport_refuses_changed_target_and_checks_kill_result(self):
        transport = TmuxTransport("offline")
        with patch.object(transport, "termination_target", return_value=self.original), patch.object(transport, "_tm", return_value="agentmux-kill-confirmed\n") as command:
            with self.assertRaises(RuntimeError):
                transport.kill("target", expected="changed")
            command.assert_not_called()
            self.assertTrue(transport.kill("target", expected=self.original))
            self.assertEqual(command.call_args.args[:4], ("if-shell", "-F", "-t", "$3"))
            self.assertIn("#{==:#{pid},101}", command.call_args.args[4])

    def test_transport_requires_explicit_termination_confirmation(self):
        transport = TmuxTransport("offline")
        for reply in ("", "agentmux-kill-refused\n", "unexpected\n"):
            with self.subTest(reply=reply), patch.object(transport, "termination_target", return_value=self.original), patch.object(transport, "_tm", return_value=reply):
                with self.assertRaisesRegex(RuntimeError, "termination unconfirmed"):
                    transport.kill("target", expected=self.original)


class HubTermination(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from hub.server import Hub
        self.hub = Hub.__new__(Hub)
        self.hub.rings, self.hub.kills, self.hub.terminating = {}, set(), set()
        self.hub.io = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.hub.io.shutdown)
        self.hub.db = AsyncMock(return_value=True)
        self.agent = {"session": "target", "handle": "%4", "pane_pid": 105, "created": 1}

    async def test_failed_kill_never_records_dead(self):
        self.hub.harness = lambda *a, **kw: False
        with self.assertRaisesRegex(HubError, "unconfirmed"):
            await self.hub._kill_agent(self.agent, "test")
        self.hub.db.assert_not_awaited()
        self.assertFalse(self.hub.terminating)

    async def test_repeated_cancellation_joins_worker_and_records_result(self):
        entered, release = Event(), Event()
        def harness(*a, **kw):
            entered.set()
            release.wait(3)
            return True
        self.hub.harness = harness
        task = asyncio.create_task(self.hub._kill_agent(self.agent, "test"))
        self.hub.kills.add(task)
        while not entered.is_set():
            await asyncio.sleep(0.001)
        try:
            for _ in range(2):
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                self.assertIn("target", self.hub.terminating)
            shutdown = asyncio.create_task(self.hub.finish_kills())
            await asyncio.sleep(0)
            self.assertFalse(shutdown.done())
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await shutdown
        self.hub.db.assert_awaited_once()
        self.assertFalse(self.hub.terminating)

    async def test_stale_registration_not_marked_dead(self):
        self.hub.store = SimpleNamespace(agent=lambda sess: {**self.agent, "created": 2},
                                         set_state=unittest.mock.Mock(), event=unittest.mock.Mock(), tx=nullcontext)
        self.assertFalse(self.hub._record_kill(self.agent, "test"))
        self.hub.store.set_state.assert_not_called()
        self.hub.store.event.assert_not_called()

    async def test_harness_failure_and_timeout_never_fall_back(self):
        self.hub.tp = FakeTransport()
        self.hub.tp.add("target", pid=105)
        original = self.hub.tp.termination_target("target")
        self.agent["handle"] = "target"
        with patch("hub.server.subprocess.run", return_value=SimpleNamespace(returncode=1)):
            self.assertFalse(self.hub.harness("kill", "target", expected_agent=self.agent))
        with patch("hub.server.subprocess.run", side_effect=subprocess.TimeoutExpired("synthetic", 120)):
            self.assertFalse(self.hub.harness("kill", "target", expected_agent=self.agent))
        self.assertEqual(self.hub.tp.termination_target("target"), original)

    async def test_missing_harness_refuses_contended_spawn_lock(self):
        import fcntl
        self.hub.tp = FakeTransport()
        self.hub.tp.add("target", pid=105)
        self.agent["handle"] = "target"
        original = self.hub.tp.termination_target("target")
        with tempfile.TemporaryDirectory() as directory, open(Path(directory) / ".spawn.lock", "a") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            with patch("hub.server.ROOT", directory), patch("hub.server.subprocess.run", side_effect=FileNotFoundError):
                self.assertFalse(self.hub.harness("kill", "target", expected_agent=self.agent))
        self.assertEqual(self.hub.tp.termination_target("target"), original)

    async def test_old_liveness_result_cannot_change_replacement_state(self):
        original = {**self.agent, "state": "ready"}
        replacement = {**original, "created": 2, "state": "starting"}
        self.hub.store = SimpleNamespace(agent=lambda sess: replacement,
                                         set_state=unittest.mock.Mock())
        self.assertFalse(self.hub._set_observed_state(original, "dead", "terminal gone"))
        self.hub.store.set_state.assert_not_called()
        self.assertTrue(self.hub._set_observed_state(replacement, "ready"))
        self.hub.store.set_state.assert_called_once_with("target", "ready", None)

    async def test_delayed_liveness_preserves_replacement_and_its_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(str(Path(directory) / "hub.db"))
            self.addCleanup(store.db.close)
            store.repo_add("alpha", paths=[directory])
            session = store.register("alpha", "worker", "one", "shell", ROLE,
                                     handle="%4", pane_pid=105)
            store.set_state(session, "ready")
            original = store.agent(session)
            self.hub.store = store
            self.hub.stop = asyncio.Event()
            entered, release = Event(), Event()
            applied = asyncio.Event()

            def delayed_alive(_):
                entered.set()
                if not release.wait(3):
                    raise RuntimeError("fixture observation was not released")
                return False

            async def database(fn, *args):
                result = fn(*args)
                if fn == self.hub._set_observed_state:
                    applied.set()
                return result

            self.hub.db = database
            self.hub.tp = SimpleNamespace(alive=delayed_alive)
            self.hub.harness = unittest.mock.Mock()
            self.hub._tell_operator = AsyncMock()
            task = asyncio.create_task(self.hub.live_loop())
            try:
                async with asyncio.timeout(3):
                    while not entered.is_set():
                        await asyncio.sleep(0.001)
                self.assertTrue(self.hub._record_kill(original, "fixture"))
                store.register("alpha", "worker", "one", "shell", ROLE,
                               handle="%9", pane_pid=106)
                store.set_state(session, "ready")
                store.work_create("virtual:operator", "alpha", "role:alpha/worker", "replacement work")
                claimed = store.claim(session)["claimed"]
                self.assertIsNotNone(claimed)
                release.set()
                await asyncio.wait_for(applied.wait(), 3)
                self.assertEqual(store.agent(session)["state"], "ready")
                self.assertEqual(store.agent(session)["handle"], "%9")
                self.assertEqual(store.work(claimed["id"])["claimed_by"], session)
                self.assertEqual(store.work(claimed["id"])["state"], "claimed")
                self.hub.harness.assert_not_called()
                self.hub._tell_operator.assert_not_awaited()
            finally:
                release.set()
                self.hub.stop.set()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()


class HubLifetimeCleanup(unittest.IsolatedAsyncioTestCase):
    """Real local listeners; controlled domain owners, no agent or shared service."""
    async def asyncSetUp(self):
        from hub import server
        from unittest.mock import Mock
        self.server = server
        self.temporary = tempfile.TemporaryDirectory(prefix='a709-')
        self.addCleanup(self.temporary.cleanup)
        root = str(Path(self.temporary.name).resolve())
        self.path = os.path.join(root, 'hub.sock')
        for name, value in (('HUBDIR', root), ('SOCK', self.path)):
            patcher = patch.object(server, name, value)
            patcher.start(); self.addCleanup(patcher.stop)
        loop = asyncio.get_running_loop()
        for name in ('add_signal_handler', 'remove_signal_handler'):
            patcher = patch.object(loop, name)
            patcher.start(); self.addCleanup(patcher.stop)
        hub = self.hub = server.Hub.__new__(server.Hub)
        hub.stop = asyncio.Event()
        hub.rings, hub.kills, hub.started = {}, set(), {}
        hub.tp = SimpleNamespace(require_buffer_cleanup=Mock())
        hub.cfg = {'tcp_port': 0}
        hub._work_source_binding = hub._work_start_cleanup = None
        hub._selected_endpoint = None
        hub._legacy_work_notices = hub._work_maintenance = None
        hub.bridge = None
        for name in ('_work_rpc', '_work_storage_commands', '_peer_control_commands',
                     '_policy_commands', '_knowledge_commands', '_code_commands', '_message_commands'):
            setattr(hub, name, None)
        hub.store = SimpleNamespace(path='controlled', agents=Mock(return_value=[]),
            checkpoint=Mock(), db=SimpleNamespace(close=Mock()))
        hub.dbx = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        hub.io = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.addCleanup(hub.dbx.shutdown, wait=True)
        self.addCleanup(hub.io.shutdown, wait=True)
        self.ready = asyncio.Event()
        async def idle():
            self.ready.set()
            await asyncio.Event().wait()
        hub.bell_loop = hub.live_loop = hub.lease_loop = hub.receipt_loop = idle
        hub.fed = SimpleNamespace(run=idle, finish_cleanup=AsyncMock())

    async def test_tcp_start_failure_closes_published_endpoint_listener_and_store(self):
        from unittest.mock import Mock
        endpoint = self.hub._selected_endpoint = SimpleNamespace(
            publish=AsyncMock(), drain=AsyncMock(), close=Mock())
        original = OSError('controlled TCP bind failure')
        self.hub.cfg['tcp_port'] = 12345
        with patch('asyncio.start_server', side_effect=original):
            with self.assertRaises(OSError) as caught: await self.hub._main()
        self.assertIs(caught.exception, original)
        endpoint.publish.assert_awaited_once_with(self.hub)
        endpoint.drain.assert_awaited_once(); endpoint.close.assert_called_once()
        self.assertFalse(os.path.lexists(self.path))
        self.assertTrue(self.hub.dbx._shutdown)
        self.hub.store.db.close.assert_called_once()

    async def test_repeated_stop_wait_cancellation_joins_same_cleanup(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def deliveries():
            entered.set(); await release.wait()
        self.hub.finish_deliveries = AsyncMock(side_effect=deliveries)
        task = asyncio.create_task(self.hub._main())
        await asyncio.wait_for(self.ready.wait(), 2)
        task.cancel()
        await asyncio.wait_for(entered.wait(), 2)
        original = self.hub._work_start_cleanup
        task.cancel(); await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.assertFalse(self.hub.dbx._shutdown)
        release.set()
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertIs(self.hub._work_start_cleanup, original)
        self.assertTrue(original.done())
        self.hub.finish_deliveries.assert_awaited_once()
        self.assertTrue(self.hub.dbx._shutdown)

    async def test_owner_close_failure_attempts_independent_owners_and_retains_store(self):
        from unittest.mock import Mock
        original = OSError('controlled client cleanup failure')
        self.hub._peer_control_commands = SimpleNamespace(close=AsyncMock(side_effect=original))
        self.hub._policy_commands = SimpleNamespace(close=AsyncMock())
        endpoint = self.hub._selected_endpoint = SimpleNamespace(
            publish=AsyncMock(), drain=AsyncMock(), close=Mock())
        task = asyncio.create_task(self.hub._main())
        await asyncio.wait_for(self.ready.wait(), 2)
        self.hub.stop.set()
        with self.assertRaises(self.server.HubCleanupFailure) as caught: await task
        self.assertIs(caught.exception.owner, self.hub)
        self.assertIn(original, caught.exception.__cause__.exceptions)
        self.hub._policy_commands.close.assert_awaited_once()
        self.hub.fed.finish_cleanup.assert_awaited_once()
        endpoint.close.assert_called_once()
        self.hub.store.db.close.assert_not_called()
        self.assertFalse(self.hub.dbx._shutdown)
        self.assertFalse(self.hub._hub_borrowers_joined)
        with self.assertRaises(self.server.HubCleanupFailure):
            await self.hub._close_failed_work_start()
        self.hub._peer_control_commands.close.assert_awaited_once()

    async def test_replaced_socket_is_preserved_on_ordinary_stop(self):
        task = asyncio.create_task(self.hub._main())
        await asyncio.wait_for(self.ready.wait(), 2)
        os.unlink(self.path)
        replacement = socket.socket(socket.AF_UNIX)
        self.addCleanup(replacement.close)
        replacement.bind(self.path)
        identity = os.lstat(self.path).st_ino
        self.hub.stop.set()
        with self.assertRaises(self.server.HubCleanupFailure): await task
        self.assertEqual(os.lstat(self.path).st_ino, identity)
        self.hub.store.checkpoint.assert_called_once()

    async def test_retained_federation_cleanup_precedes_shared_client_release(self):
        entered, release = asyncio.Event(), asyncio.Event()
        self.hub._message_commands = SimpleNamespace(close=AsyncMock())
        async def federation_cleanup():
            entered.set()
            await release.wait()
        self.hub.fed.finish_cleanup.side_effect = federation_cleanup
        task = asyncio.create_task(self.hub._main())
        await asyncio.wait_for(self.ready.wait(), 2)
        self.hub.stop.set()
        await asyncio.wait_for(entered.wait(), 2)
        self.hub._message_commands.close.assert_not_awaited()
        self.hub.store.db.close.assert_not_called()
        release.set()
        await asyncio.wait_for(task, 2)
        self.hub._message_commands.close.assert_awaited_once()
        self.hub.store.db.close.assert_called_once()

    async def test_unresolved_federation_cleanup_retains_shared_clients(self):
        original = RuntimeError('retained federation cleanup failed')
        self.hub.fed.finish_cleanup.side_effect = original
        self.hub._message_commands = SimpleNamespace(close=AsyncMock())
        task = asyncio.create_task(self.hub._main())
        await asyncio.wait_for(self.ready.wait(), 2)
        self.hub.stop.set()
        with self.assertRaises(self.server.HubCleanupFailure) as caught: await task
        self.assertIn(original, caught.exception.__cause__.exceptions)
        self.hub._message_commands.close.assert_not_awaited()
        self.hub.store.db.close.assert_not_called()
        self.assertFalse(self.hub._hub_borrowers_joined)

    async def test_plain_connection_is_joined_before_database_close(self):
        entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def handler(reader, writer, tcp=False):
            entered.set()
            try: await asyncio.Event().wait()
            finally:
                await release.wait(); finished.set()
        self.hub.handle_conn = handler
        task = asyncio.create_task(self.hub._main())
        await asyncio.wait_for(self.ready.wait(), 2)
        reader, writer = await asyncio.open_unix_connection(self.path)
        await asyncio.wait_for(entered.wait(), 2)
        self.hub.stop.set(); await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.hub.store.db.close.assert_not_called()
        release.set()
        await asyncio.wait_for(task, 2)
        self.assertTrue(finished.is_set())
        self.assertFalse(self.hub._hub_connections)
        self.hub.store.db.close.assert_called_once()
        writer.close(); await writer.wait_closed()
