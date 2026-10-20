#!/usr/bin/env python3
"""Roster contract through an isolated store and port-0 HTTP server."""
import json
from contextlib import closing
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from dataclasses import replace

TEMP = tempfile.TemporaryDirectory(prefix="boardteams-suite-")
BASE = Path(TEMP.name)
os.environ["AGENTMUX_HOME"] = str(BASE / ".agentmux")
os.environ["HOME"] = str(BASE)
os.environ.pop("CC_ENFORCE", None)
os.environ.pop("TM_ENFORCE", None)
OLD_CWD = Path.cwd()
os.chdir(BASE)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import server
import ccboard
import ccstore
import boardteams


class TeamsHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def setUp(self):
        with ccstore.connection() as db:
            epic = ccboard.create(db, "epic", {"title": "Test epic"}, mirror=True)["id"]
            self.epic = epic
            self.key = ccboard.create(db, "task", {"title": "Roster test", "epic": epic},
                                     mirror=True)["id"]
        lead = boardteams.agentdefs.choose_roster({}, {}, {})[0]
        self.selection = [lead, replace(lead, name="reviewer", role="reviewer")]
        self.mock = patch.object(boardteams.agentdefs, "choose_roster", return_value=self.selection)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def call(self, op, body=None, query="", method=None, content_type="application/json"):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.httpd.server_address[1]}/api/board/{op}{query}",
            data=data, method=method)
        if data is not None and content_type:
            request.add_header("Content-Type", content_type)
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.code, json.loads(response.read())

    def write(self, op, **extra):
        return self.call(op, {"id": self.key, "actor": "suite", **extra})

    def read(self):
        return self.call("roster", query="?id=" + self.key)

    def events(self):
        status, payload = self.call("history", query="?id=" + self.key)
        self.assertEqual(status, 200)
        return payload["events"]

    def test_roundtrip_idempotence_and_all_transitions(self):
        self.assertEqual(self.read(), (200, {"id": self.key, "members": [], "count": 0, "gaps": []}))
        status, proposed = self.write("recruit")
        self.assertEqual(status, 200)
        self.assertEqual(proposed["count"], 2)
        self.assertTrue(all(r["status"] == "proposed" and r["proposed_by"] == "suite"
                            for r in proposed["members"]))
        events = self.events()
        self.assertEqual(self.write("recruit"), (200, proposed))
        self.assertEqual(self.events(), events)
        status, approved = self.write("approve", members=["lead"])
        self.assertEqual(status, 200)
        lead, reviewer = approved["members"]
        self.assertEqual((lead["status"], lead["approved_by"]), ("approved", "suite"))
        self.assertTrue(lead["approved_at"])
        self.assertEqual(reviewer["status"], "rejected")
        self.assertEqual(self.read(), (200, approved))
        events = self.events()
        self.assertEqual({e["event"] for e in events} & {"recruit", "approve", "reject"},
                         {"recruit", "approve", "reject"})
        self.assertTrue(all(e["actor"] == "suite" for e in events
                            if e["event"] in ("recruit", "approve", "reject")))
        self.assertEqual(self.write("approve", members=["lead"], actor="retry"), (200, approved))
        self.assertEqual(self.events(), events)
        status, error = self.write("approve", members=[])
        self.assertEqual(status, 409)
        self.assertTrue(error["missing"][0]["hint"])

    def test_recruit_replaces_non_hired_preserves_hired(self):
        self.write("recruit")
        self.write("approve", members=["lead", "reviewer"])
        with ccstore.connection() as db:
            db.execute("UPDATE board_roster SET status='hired',member_name='test-lead',"
                       "worktree='/test',branch='test' WHERE entity_key=? AND agent_name='lead'",
                       (self.key,))
        before = self.read()[1]["members"][0]
        self.selection[:] = [self.selection[0], replace(self.selection[1], name="new-reviewer")]
        status, payload = self.write("recruit")
        self.assertEqual(status, 200)
        self.assertEqual(payload["members"][0], before)
        self.assertEqual(payload["members"][1]["agent_name"], "new-reviewer")
        self.assertEqual(payload["members"][1]["status"], "proposed")
        self.assertIsNone(payload["members"][1]["approved_at"])
        approved = self.write("approve", members=["new-reviewer"])
        self.assertEqual(approved[0], 200)
        self.assertEqual(self.write("approve", members=["new-reviewer"]), approved)

    def test_changing_hired_lead_requires_retirement_before_new_proposal(self):
        self.prepare_hire()
        directory = BASE / ".agentmux/agents"
        path = directory / "new-lead.md"
        path.write_text("---\nname: new-lead\ndescription: New lead\nrole: lead\n---\nNew persona")
        self.addCleanup(path.unlink)
        with ccstore.connection() as db:
            db.execute("UPDATE board_roster SET status='hired',member_name='current-lead' "
                       "WHERE entity_key=? AND role='lead'", (self.key,))
        before = self.read()
        events = self.events()
        status, refusal = self.write("recruit", lead="new-lead")
        self.assertEqual(status, 409)
        self.assertIn("retire the hired lead", refusal["error"])
        self.assertEqual(self.read(), before)
        self.assertEqual(self.events(), events)
        current_path = directory / "lead.md"
        raw = current_path.read_bytes()
        current_path.write_bytes(raw + b"\nChanged hired persona")
        self.assertEqual(self.write("recruit", lead="lead")[0], 409)
        current_path.write_bytes(raw)
        self.assertEqual(self.read(), before)
        self.assertEqual(self.events(), events)
        with ccstore.connection() as db:
            db.execute("DELETE FROM board_roster_definitions WHERE roster_id=?",
                       (before[1]["members"][0]["id"],))
        missing_snapshot = self.read()
        self.assertEqual(self.write("recruit")[0], 409)
        self.assertEqual(self.read(), missing_snapshot)
        self.assertEqual(self.events(), events)
        with patch.object(boardteams.dispatch, "live_agents", return_value=set()):
            self.assertEqual(self.write("retire", members=["lead"])[0], 200)
        status, proposal = self.write("recruit", lead="new-lead")
        self.assertEqual(status, 200)
        self.assertEqual([(r["agent_name"], r["role"]) for r in proposal["members"]], [("new-lead", "lead")])
        approved = self.write("approve", members=["new-lead"])
        self.assertEqual(approved[0], 200)
        self.assertEqual(approved[1]["members"][0]["status"], "approved")

    def test_invalid_approval_is_atomic(self):
        self.write("recruit")
        before, events = self.read(), self.events()
        for members in (["lead", "unknown"], ["lead", "lead"], [None], [1], ["Bad"],
                        "lead", None, ["a"] * 33):
            with self.subTest(members=members):
                self.assertEqual(self.write("approve", members=members)[0], 400)
                self.assertEqual(self.read(), before)
                self.assertEqual(self.events(), events)

    def test_reject_all_is_idempotent(self):
        self.write("recruit")
        result = self.write("approve", members=[])
        self.assertEqual(result[0], 200)
        self.assertTrue(all(r["status"] == "rejected" for r in result[1]["members"]))
        events = self.events()
        self.assertEqual(self.write("approve", members=[]), result)
        self.assertEqual(self.events(), events)

    def test_http_checklist(self):
        for op in ("recruit", "approve"):
            self.assertEqual(self.call(op)[0], 405)
            self.assertEqual(self.call(op, {}, content_type=None)[0], 415)
            for key in (None, "none", "bad", "TM-001\n", "a" * 300):
                self.assertEqual(self.write(op, id=key, members=[])[0], 400)
            self.assertEqual(self.write(op, id="TM-999999999", members=[])[0], 404)
            self.assertEqual(self.write(op, actor=None, members=[])[0], 400)
        self.assertEqual(self.call("roster", {})[0], 405)
        self.assertEqual(self.call("roster", query="?id=TM-999999999")[0], 404)
        for query in ("", "?id=", "?id=none", "?id=Bad", "?id=" + "x" * 300,
                      "?id=TM-001&id=TM-002"):
            self.assertEqual(self.call("roster", query=query)[0], 400)
        self.assertIn(self.call("unknown")[0], (404, 405))
        self.assertEqual(self.write("approve", members=["unknown"])[0], 400)
        status, error = self.write("approve", members=[])
        self.assertEqual(status, 409)
        self.assertTrue(error["missing"][0]["hint"])
        with ccstore.connection() as db:
            db.execute("UPDATE tasks SET status='deleted' WHERE key=?", (self.key,))
        for op in ("recruit", "approve"):
            status, error = self.write(op, members=[])
            self.assertEqual(status, 409)
            self.assertTrue(error["missing"][0]["hint"])

    def test_real_selector_defaults_to_solo_lead(self):
        self.mock.stop()
        with ccstore.connection() as db:
            self.assertTrue(ccboard.config(db)["teamRequireApproval"])
        original = boardteams.definition_team.TeamPlugin.propose_legacy
        with patch.object(boardteams.definition_team.TeamPlugin, "propose_legacy",
                          autospec=True, side_effect=original) as proposal:
            status, payload = self.write("recruit")
        proposal.assert_called_once()
        self.assertIsNone(proposal.call_args.kwargs["lead"])
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["members"][0]["role"], "lead")
        # No approved roster is required to select the dispatcher fallback lead.
        selected = boardteams.agentdefs.choose_roster({}, {}, {"teamRequireApproval": True})
        self.assertEqual([(s.name, s.role) for s in selected], [("lead", "lead")])

    def test_real_recruitment_worker_approval_and_persisted_gaps(self):
        self.mock.stop()
        directory = BASE / ".agentmux/agents"
        directory.mkdir(parents=True, exist_ok=True)
        for name, extra in (("frontend", "capabilities: ui\n"),
                            ("senior-backend", "capabilities: backend\n"),
                            ("reviewer", "role: reviewer\n")):
            path = directory / (name + ".md")
            path.write_text(f"---\nname: {name}\ndescription: Real worker\n{extra}---\n")
            self.addCleanup(path.unlink)
        with ccstore.connection() as db:
            for path in ("dashboard/view.js", "taskmgmt/work.py"):
                ccboard.add_touch(db, self.key, path, actor="suite")
            ccboard.set_label(db, self.key, "missing-capability", True, actor="suite")
        status, proposal = self.write("recruit")
        self.assertEqual(status, 200, proposal)
        self.assertEqual([r["role"] for r in proposal["members"]], ["lead", "worker", "worker"])
        self.assertIn("Capability missing-capability: no definition provides it", proposal["gaps"])
        self.assertEqual(self.read(), (200, proposal))
        self.assertEqual(self.write("recruit"), (200, proposal))
        # A changed diagnostic alone is a new proposal; unchanged retry stays quiet.
        before = len([e for e in self.events() if e["event"] == "recruit"])
        with ccstore.connection() as db:
            ccboard.set_label(db, self.key, "another-missing", True, actor="suite")
        status, proposal = self.write("recruit")
        self.assertEqual(status, 200)
        self.assertIn("Capability another-missing: no definition provides it", proposal["gaps"])
        self.assertEqual(len([e for e in self.events() if e["event"] == "recruit"]), before + 1)
        self.assertEqual(self.write("recruit"), (200, proposal))
        status, approved = self.write("approve", members=[r["agent_name"] for r in proposal["members"]])
        self.assertEqual(status, 200)
        self.assertTrue(all(r["status"] == "approved" for r in approved["members"]))
        self.assertEqual(approved["gaps"], proposal["gaps"])
        with ccstore.connection() as db:
            previous = self.key
            for i in range(3):
                key = ccboard.create(db, "task", {"title": f"Dependency {i}", "epic": self.epic},
                                     mirror=True)["id"]
                ccboard.set_dep(db, previous, key, True, actor="suite")
                previous = key
        status, deep = self.write("recruit")
        self.assertEqual(status, 200, deep)
        self.assertEqual([r["agent_name"] for r in deep["members"]], ["lead", "senior-backend"])
        # Diagnostics describe the saved proposal, even if definitions change.
        (directory / "senior-backend.md").write_text("invalid")
        refreshed = self.read()[1]
        self.assertEqual(refreshed["gaps"], deep["gaps"])
        self.assertEqual(refreshed["members"][1]["definitionState"], "unavailable")

    def test_profile_adoption_is_opt_in_and_preserves_approved_roster_snapshot(self):
        from definition_service import DefinitionScope, DefinitionService
        import profile_packages as packages
        from profile_owner import admit_project
        self.mock.stop()
        status, baseline = self.write("recruit")
        self.assertEqual(status, 200)
        self.assertFalse(packages.NAMES & {row["agent_name"] for row in baseline["members"]})
        project = Path.cwd().resolve()
        service = DefinitionService(DefinitionScope(project, project, project / ".agentmux", "test-project"))
        client = project / "selected-profile-client"
        client.write_bytes(b"executable snapshot only; never executed\n")
        client.chmod(0o700)
        self.addCleanup(client.unlink)
        private = project / ".agentmux/profile-adoptions"
        self.addCleanup(lambda: __import__("shutil").rmtree(private, ignore_errors=True))
        catalog, _ = packages.catalogue()
        selections = [{"packageId": "example.survey", "name": "scan-dev", "relationship": "independent",
                       "parentPackage": None, "sourceChecksum": catalog["scan-dev"].spec.checksum,
                       "overrides": {"paths": {}, "execution": {
                           "posture": "read-only", "worktree": "none", "maxInstances": 1}}}]
        clients = {"codex": str(client)}
        with admit_project(project) as owner:
            preview, _ = packages.preview(project, selections, clients, owner=owner)
            service.adopt_profiles(owner, selections, clients, preview["approvalChecksum"], preview["recordChecksum"])
        with ccstore.connection() as db:
            ccboard.set_label(db, self.key, "inventory", True, actor="suite")
        status, proposal = self.write("recruit")
        self.assertEqual(status, 200)
        self.assertIn("scan-dev", [row["agent_name"] for row in proposal["members"]])
        status, approved = self.write("approve", members=[row["agent_name"] for row in proposal["members"]])
        self.assertEqual(status, 200)
        with ccstore.connection() as db:
            before = [tuple(row) for row in db.execute("SELECT d.* FROM board_roster_definitions d "
                "JOIN board_roster r ON r.id=d.roster_id WHERE r.entity_key=? ORDER BY d.roster_id", (self.key,))]
        events = self.events()
        # Removing future eligibility is not permission to rewrite old approval.
        with admit_project(project) as owner:
            preview, _ = packages.preview(project, [], clients, owner=owner)
            service.adopt_profiles(owner, [], clients, preview["approvalChecksum"], preview["recordChecksum"])
        refreshed = self.read()[1]
        for old, now in zip(approved["members"], refreshed["members"]):
            self.assertTrue(all(old[key] == now[key] for key in
                ("id", "agent_name", "status", "approved_by", "approved_at", "definitionRevision")))
        with ccstore.connection() as db:
            after = [tuple(row) for row in db.execute("SELECT d.* FROM board_roster_definitions d "
                "JOIN board_roster r ON r.id=d.roster_id WHERE r.entity_key=? ORDER BY d.roster_id", (self.key,))]
        self.assertTrue(before == after, "stored persona snapshot changed")
        self.assertEqual(self.events(), events)

    def prepare_hire(self):
        with ccstore.connection() as db:
            ccboard.set_config(db, "dashboardMayHire", True)
            ccboard.set_config(db, "dispatchEnabled", True)
        self.addCleanup(self.reset_hire_config)
        directory = BASE / ".agentmux/agents"
        directory.mkdir(parents=True, exist_ok=True)
        definition = directory / "lead.md"
        definition.write_text("---\nname: lead\ndescription: Hire test\ncli: codex\n"
                              "role: lead\nposture: unrestricted\nmodel: disk-model\n"
                              "---\nDisk persona\n")
        self.addCleanup(definition.unlink)
        self.mock.stop()
        self.write("recruit", lead="lead")
        self.write("approve", members=["lead"])
        repo = patch.object(boardteams.dispatch, "REPO", BASE)
        repo.start()
        self.addCleanup(repo.stop)
        spawn = patch.object(boardteams.dispatch, "agentmux", return_value=(0, "", ""))
        mocked = spawn.start()
        self.addCleanup(spawn.stop)
        return mocked

    def reset_hire_config(self):
        with ccstore.connection() as db:
            ccboard.set_config(db, "dashboardMayHire", False)
            ccboard.set_config(db, "dispatchEnabled", False)

    def test_hire_ignores_injected_launch_fields_and_resolves_disk(self):
        spawn = self.prepare_hire()
        def spawned(*args):
            self.assertEqual(Path(args[args.index("--persona-file") + 1]).read_text(),
                             "Disk persona")
            return 0, "", ""
        spawn.side_effect = spawned
        status, result = self.call("hire", {
            "id": self.key, "name": "lead", "cli": "evil-cli", "cwd": "/evil",
            "argv": ["--evil"], "model": "evil-model", "posture": "read-only",
            "flags": ["--evil"], "actor": "evil-actor"})
        self.assertEqual(status, 200, result)
        args = spawn.call_args.args
        self.assertEqual(args[args.index("--cli") + 1], "codex")
        self.assertEqual(args[args.index("--cwd") + 1], str(BASE))
        self.assertEqual(args[args.index("--model") + 1], "disk-model")
        for injected in ("evil-cli", "/evil", "--evil", "evil-model", "evil-actor"):
            self.assertNotIn(injected, args)
        self.assertEqual(result["members"][0]["status"], "hired")
        self.assertEqual([e["actor"] for e in self.events() if e["event"] == "hire"],
                         ["dashboard"])
        self.assertEqual(self.call("hire", {"id": self.key, "name": "lead"})[0], 409)
        spawn.assert_called_once()

    def test_approved_snapshot_survives_definition_edits_and_is_not_listed(self):
        spawn = self.prepare_hire()
        before = self.read()[1]["members"][0]
        path = BASE / ".agentmux/agents/lead.md"
        path.write_text("---\nname: lead\ndescription: Changed\nrole: lead\ncli: claude\n"
                        "---\nDifferent persona\n")
        current = self.read()[1]["members"][0]
        self.assertEqual(current["definitionState"], "changed")
        for key in ("id", "approved_by", "approved_at", "definitionRevision"):
            self.assertEqual(current[key], before[key])
        self.assertNotIn("persona", json.dumps(current))
        def spawned(*args):
            self.assertEqual(Path(args[args.index("--persona-file") + 1]).read_text(), "Disk persona")
            self.assertEqual(args[args.index("--cli") + 1], "codex")
            return 0, "", ""
        spawn.side_effect = spawned
        self.assertEqual(self.call("hire", {"id": self.key, "name": "lead"})[0], 200)
        spawn.assert_called_once()

    def test_legacy_row_without_snapshot_refuses_hire_without_rewriting_approval(self):
        spawn = self.prepare_hire()
        before = self.read()[1]["members"][0]
        with ccstore.connection() as db:
            db.execute("DELETE FROM board_roster_definitions WHERE roster_id=?", (before["id"],))
        status, refused = self.call("hire", {"id": self.key, "name": "lead"})
        self.assertEqual(status, 409)
        self.assertIn("recruit and approve", refused["missing"][0]["hint"])
        spawn.assert_not_called()
        after = self.read()[1]["members"][0]
        for key in ("id", "approved_by", "approved_at", "status"):
            self.assertEqual(after[key], before[key])

    def test_additive_old_schema_upgrade_does_not_invent_snapshot(self):
        import sqlite3
        with closing(sqlite3.connect(":memory:")) as db, db:
            db.row_factory = sqlite3.Row
            # Copy the actual old base schema, then remove only the new table.
            source = ccstore.connection()
            with source as original:
                schema = original.execute("SELECT sql FROM sqlite_master WHERE name='board_roster'").fetchone()[0]
            db.execute(schema)
            db.execute("INSERT INTO board_roster(id,entity_key,agent_name,role,position,status,"
                       "approved_by,approved_at,at) VALUES(7,'TM-1','lead','lead',0,'approved','original','then','then')")
            statement = next(s for s in ccboard.NEW_TABLES if "CREATE TABLE IF NOT EXISTS board_roster_definitions" in s)
            db.execute(statement)
            db.execute(statement)
            row = db.execute("SELECT * FROM board_roster").fetchone()
            self.assertEqual((row["id"], row["approved_by"], row["approved_at"]), (7, "original", "then"))
            self.assertIsNone(boardteams._saved_spec(db, row))
            self.assertEqual(db.execute("SELECT count(*) FROM board_roster_definitions").fetchone()[0], 0)

    def test_team_require_approval_off_actually_turns_approval_off(self):
        """A setting that was wired to nothing.

        teamRequireApproval is defaulted, validated as a bool, listed in the Teams
        settings panel as "Require roster approval", and documented in
        CONTRACTS_agents.md - and no code path read it. hire() requires
        status='approved' unconditionally, so an operator could turn roster approval
        OFF, recruit, and still be told "hire requires an approved roster row on an
        open card". The switch moved and nothing happened.

        Honoured in recruit() rather than by relaxing hire(): "only an approved row
        may be hired" keeps exactly one meaning, and what the setting really says is
        whether approval is a separate human step or implied by recruiting.
        """
        with ccstore.connection() as db:
            ccboard.set_config(db, "teamRequireApproval", True)
        status, proposed = self.write("recruit")
        self.assertEqual(status, 200)
        self.assertTrue(all(r["status"] == "proposed" for r in proposed["members"]),
                        proposed["members"])

        with ccstore.connection() as db:
            other = ccboard.create(db, "task", {"title": "No-approval card",
                                                "epic": self.epic}, mirror=True)["id"]
        with ccstore.connection() as db:
            ccboard.set_config(db, "teamRequireApproval", False)
        status, payload = self.call("recruit", {"id": other, "actor": "suite"})
        self.assertEqual(status, 200)
        self.assertTrue(payload["members"], "recruit proposed nobody")
        for row in payload["members"]:
            self.assertEqual(row["status"], "approved", row)
            # Approved by SOMEBODY: an implied approval still has an owner, or the
            # audit row goes quiet exactly where it matters.
            self.assertEqual(row["approved_by"], "suite", row)
            self.assertTrue(row["approved_at"], row)
        events = [e for e in self.call("history", query="?id=" + other)[1]["events"]
                  if e["event"] == "approve"]
        self.assertEqual(len(events), 1, events)
        self.assertEqual(events[0]["detail"]["via"], "teamRequireApproval is off")
        with ccstore.connection() as db:
            ccboard.set_config(db, "teamRequireApproval", True)

    def test_retire_takes_members_off_and_is_the_only_write_a_closed_card_allows(self):
        """The transition the model named and nothing ever performed.

        `finished` was already recognised by approve()'s already-decided guard and by
        the Teams panel's `decided` check, and no code path set it: a member could be
        proposed, approved, rejected and hired, and never leave. Worse, every roster
        write refused once the card was done - right for recruiting onto finished work,
        exactly backwards for taking a team off it - so the roster of a completed card
        could not be changed at all. The two agents on TM-083 had been stuck to a card
        that closed on 2026-09-24, and the only way off was editing cc.db by hand.
        """
        self.write("recruit")
        self.write("approve", members=["lead"])

        status, error = self.write("retire", members=["nobody"])
        self.assertEqual(status, 409)
        self.assertIn("not on this roster", error["error"])
        self.assertTrue(error["missing"][0]["hint"])
        for bad in ([], ["lead", "lead"], "lead", ["a" * 65]):
            self.assertEqual(self.write("retire", members=bad)[0], 400, bad)

        status, payload = self.write("retire", members=["lead"])
        self.assertEqual(status, 200)
        by_name = {row["agent_name"]: row for row in payload["members"]}
        self.assertEqual(by_name["lead"]["status"], "finished")
        # A rejected row is already off; retiring does not resurrect or rewrite it.
        self.assertEqual(by_name["reviewer"]["status"], "rejected")
        self.assertEqual(self.read(), (200, payload))
        retired = [e for e in self.events() if e["event"] == "retire"]
        self.assertEqual(len(retired), 1)
        self.assertEqual(retired[0]["actor"], "suite")
        self.assertEqual(retired[0]["detail"]["members"], ["lead"])

        # Already finished: no longer on the roster, so it is refused rather than
        # silently re-stamped with a second history row.
        self.assertEqual(self.write("retire", members=["lead"])[0], 409)
        self.assertEqual(len([e for e in self.events() if e["event"] == "retire"]), 1)

        # AND ON A CLOSED CARD. Every other roster verb refuses here; this one must not.
        self.write("recruit")
        self.write("approve", members=["lead"])
        with ccstore.connection() as db:
            db.execute("UPDATE tasks SET status='done' WHERE key=?", (self.key,))
        self.assertEqual(self.write("recruit")[0], 409, "recruit should still refuse")
        self.assertEqual(self.write("approve", members=["lead"])[0], 409,
                         "approve should still refuse")
        status, payload = self.write("retire", members=["lead"])
        self.assertEqual(status, 200, "a finished card is when a roster most needs clearing")
        self.assertEqual({row["agent_name"]: row["status"]
                          for row in payload["members"]}["lead"], "finished")

    def test_retire_refuses_a_member_whose_pane_is_still_running(self):
        """Off the roster but still running is not retired, it is abandoned."""
        spawn = self.prepare_hire()
        status, hired = self.call("hire", {"id": self.key, "name": "lead"})
        self.assertEqual(status, 200)
        spawn.assert_called_once()
        member = {row["agent_name"]: row for row in hired["members"]}["lead"]["member_name"]
        self.assertTrue(member)

        with patch.object(boardteams.dispatch, "live_agents", return_value={member}):
            status, error = self.write("retire", members=["lead"])
            self.assertEqual(status, 409)
            self.assertIn("still running", error["error"])
            self.assertIn(member, error["missing"][0]["hint"])

        # Liveness that cannot be established is not "it stopped".
        with patch.object(boardteams.dispatch, "live_agents",
                          side_effect=boardteams.dispatch.coordination.TmuxUnavailable("tmux unreachable")):
            self.assertEqual(self.write("retire", members=["lead"])[0], 503)

        with patch.object(boardteams.dispatch, "live_agents", return_value=set()):
            status, payload = self.write("retire", members=["lead"])
        self.assertEqual(status, 200)
        row = {r["agent_name"]: r for r in payload["members"]}["lead"]
        self.assertEqual(row["status"], "finished")
        # The pane it was served by stays on the row: which agent did the work is
        # worth keeping, and the row no longer claims to be live.
        self.assertEqual(row["member_name"], member)

    def test_hire_requires_approval_on_this_card(self):
        spawn = self.prepare_hire()
        for state in ("proposed", "rejected", "hired", "finished"):
            with self.subTest(state=state):
                with ccstore.connection() as db:
                    db.execute("UPDATE board_roster SET status=? WHERE entity_key=?",
                               (state, self.key))
                self.assertEqual(self.call("hire", {"id": self.key, "name": "lead"})[0], 409)
        self.assertEqual(self.call("hire", {"id": self.key, "name": "unknown"})[0], 409)
        with ccstore.connection() as db:
            other = ccboard.create(db, "task", {"title": "Other card", "epic": self.epic},
                                   mirror=True)["id"]
        self.assertEqual(self.call("hire", {"id": other, "name": "lead"})[0], 409)
        spawn.assert_not_called()

    def test_hire_config_and_listener_gates(self):
        spawn = self.prepare_hire()
        for flag in ("dashboardMayHire", "dispatchEnabled"):
            with self.subTest(flag=flag):
                with ccstore.connection() as db:
                    ccboard.set_config(db, flag, False)
                self.assertEqual(self.call("hire", {"id": self.key, "name": "lead"})[0], 403)
                with ccstore.connection() as db:
                    ccboard.set_config(db, flag, True)
        with ccstore.connection() as db:
            for host in (None, "0.0.0.0", "::1", "192.168.1.1"):
                with self.assertRaises(boardteams.HireForbidden):
                    boardteams.hire(db, {"id": self.key, "name": "lead"}, bind_host=host)
        spawn.assert_not_called()

    def test_hire_slots_and_spawn_failure_release(self):
        spawn = self.prepare_hire()
        slots = boardteams.HIRE_SLOTS
        self.assertTrue(slots.acquire(blocking=False))
        self.assertTrue(slots.acquire(blocking=False))
        try:
            self.assertEqual(self.call("hire", {"id": self.key, "name": "lead"})[0], 503)
            spawn.assert_not_called()
        finally:
            slots.release()
            slots.release()
        spawn.return_value = (1, "", "failed")
        self.assertEqual(self.call("hire", {"id": self.key, "name": "lead"})[0], 503)
        self.assertEqual(self.read()[1]["members"][0]["status"], "approved")
        spawn.return_value = (0, "", "")
        self.assertEqual(self.call("hire", {"id": self.key, "name": "lead"})[0], 200)

    def test_hire_posture_ceiling_uses_saved_definition_even_if_import_invalid(self):
        spawn = self.prepare_hire()
        path = BASE / ".agentmux/agents/lead.md"
        original = path.read_text()
        path.write_text("invalid definition")
        self.assertEqual(self.read()[1]["members"][0]["definitionState"], "unavailable")
        with patch.dict(os.environ, {"AGENTMUX_NO_BYPASS": "1"}):
            self.assertEqual(self.call("hire", {"id": self.key, "name": "lead"})[0], 200)
        args = spawn.call_args.args
        self.assertEqual(args[args.index("--posture") + 1], "workspace-write")


if __name__ == "__main__":
    try:
        result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(TeamsHTTP))
    finally:
        os.chdir(OLD_CWD)
        TEMP.cleanup()
    failed = len(result.failures) + len(result.errors)
    print(f"passed {result.testsRun - failed}, failed {failed}")
    sys.exit(bool(failed))
