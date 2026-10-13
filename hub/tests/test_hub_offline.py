"""Offline tier: protocol semantics and delivery guards, no tmux, no agent CLI.

Run (WSL):  python3 -m unittest discover -s hub/tests -v     from the repo root
Each test names the failure class (C#) or requirement (R-*) it pins.
"""
import json
import multiprocessing as mp
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from hub import deliver, names, profiles  # noqa: E402
from hub.store import HubError, Store  # noqa: E402
from hub.transport import FakeTransport  # noqa: E402

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
        return deliver.deliver_line(self.t, self.p, sess, sess, "[hub] 1 new message(s). Run: agentmux hub inbox --ack", **kw)

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
        rc = deliver.deliver_line(self.t, self.p, "a", "%99", "x")
        self.assertEqual(rc.outcome, "failed")
        self.assertEqual(self.t.sent, [])

    def test_hint_text_cleared_first(self):
        self.t.add("a", "› Ask Codex to do anything")
        rc = self.run_line("a")
        self.assertEqual(self.keys("a")[0], "C-u")
        self.assertEqual(rc.outcome, "submitted", rc.as_dict())


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
        rc = deliver.deliver_line(t, profiles.get("claude"), "c", "c", "[hub] 1 new message(s). Run: agentmux hub inbox --ack")
        self.assertEqual(state["chosen"], "Yes, I trust this folder", t.sent)
        self.assertEqual(rc.modal_answers[0]["keys"], ["Down", "Enter"])

    def test_missing_safe_option_blocks(self):
        t = FakeTransport()
        t.add("c", self.menu(["No, exit", "Maybe later"], 0))
        rc = deliver.deliver_line(t, profiles.get("claude"), "c", "c", "x")
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


if __name__ == "__main__":
    unittest.main()
