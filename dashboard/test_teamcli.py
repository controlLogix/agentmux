#!/usr/bin/env python3
"""Team CLI through a private HTTP board; only the actual spawn is mocked."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

# Reuse the isolated board fixtures (private home, database and port).
from test_boardteams import TeamsHTTP, TEMP, OLD_CWD, ccstore, ccboard, boardteams

CLI = Path(__file__).resolve().parents[1] / "taskmgmt/coordination.py"


class TeamCLI(unittest.TestCase):
    setUpClass = classmethod(TeamsHTTP.setUpClass.__func__)
    tearDownClass = classmethod(TeamsHTTP.tearDownClass.__func__)
    setUp = TeamsHTTP.setUp
    prepare_hire = TeamsHTTP.prepare_hire
    reset_hire_config = TeamsHTTP.reset_hire_config
    write = TeamsHTTP.write
    call = TeamsHTTP.call

    def cli(self, *args, code=0):
        env = dict(os.environ, AGENTMUX_DASHBOARD=
                   f"http://127.0.0.1:{self.httpd.server_address[1]}",
                   AGENTMUX_AGENT="teamcli-test", AGENTMUX_TRUST_IDENTITY="1")
        result = subprocess.run([sys.executable, str(CLI), *args], env=env,
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def test_roundtrip_json_and_actor(self):
        # `gaps` joined the payload with roster inference (TM-067): a capability no
        # definition provides is reported rather than silently dropped, and an empty
        # roster has an empty list rather than no field at all.
        self.assertEqual(json.loads(self.cli("roster", self.key, "--json").stdout),
                         {"id": self.key, "members": [], "count": 0, "gaps": []})
        proposed = json.loads(self.cli("recruit", self.key, "--json").stdout)
        self.assertEqual(proposed["count"], 2)
        self.assertTrue(all(r["status"] == "proposed" and r["proposed_by"] == "teamcli-test"
                            for r in proposed["members"]))
        approved = json.loads(self.cli("approve", self.key, "--member", "lead",
                                      "--member", "reviewer", "--json").stdout)
        self.assertTrue(all(r["status"] == "approved" and r["approved_by"] == "teamcli-test"
                            for r in approved["members"]))
        self.assertEqual(json.loads(self.cli("roster", self.key, "--json").stdout), approved)

    def test_explicit_lead_is_a_proposal_until_approved(self):
        self.mock.stop()
        directory = Path.cwd() / ".agentmux/agents"
        directory.mkdir(parents=True, exist_ok=True)
        for name in ("aardvark-bundled", "project-lead"):
            path = directory / (name + ".md")
            path.write_text(f"---\nname: {name}\ndescription: Lead\nrole: lead\n---\n{name} persona")
            self.addCleanup(path.unlink)
        initial = json.loads(self.cli("recruit", self.key, "--json").stdout)
        self.assertEqual(initial["members"][0]["agent_name"], "lead")
        proposal = json.loads(self.cli("recruit", self.key, "--lead", "project-lead", "--json").stdout)
        self.assertEqual(proposal["members"][0]["agent_name"], "project-lead")
        self.assertEqual(proposal["members"][0]["status"], "proposed")
        self.assertIsNone(proposal["members"][0]["approved_by"])
        approved = json.loads(self.cli("approve", self.key, "--member", "project-lead", "--json").stdout)
        self.assertEqual(approved["members"][0]["status"], "approved")
        selected_path = directory / "project-lead.md"
        original = selected_path.read_bytes()
        selected_path.write_bytes(original + b"\nChanged persona")
        self.assertIn("definition changed; saved revision retained",
                      self.cli("roster", self.key).stdout)
        selected_path.write_bytes(original)
        refused = self.cli("recruit", self.key, "--lead", "missing", code=1)
        self.assertIn("available lead definition", refused.stderr)
        self.assertEqual(json.loads(self.cli("roster", self.key, "--json").stdout), approved)

    def test_human_output(self):
        self.assertIn("0 roster member(s)", self.cli("roster", self.key).stdout)
        self.assertIn("lead [lead] proposed", self.cli("recruit", self.key).stdout)
        output = self.cli("approve", self.key, "--member", "lead").stdout
        self.assertIn("lead [lead] approved", output)
        self.assertIn("reviewer [reviewer] rejected", output)

    def test_hire_success_exact_wire_body_and_no_retry(self):
        spawn = self.prepare_hire()
        original = boardteams.hire
        with patch.object(boardteams, "hire", wraps=original) as handler:
            result = json.loads(self.cli("hire", self.key, "--name", "lead", "--json").stdout)
        self.assertEqual(handler.call_count, 1)
        self.assertEqual(handler.call_args.args[1], {"id": self.key, "name": "lead"})
        spawn.assert_called_once()
        lead = result["members"][0]
        self.assertEqual(lead["status"], "hired")
        self.assertTrue(lead["member_name"])
        self.assertIn(" -> " + lead["member_name"], self.cli("roster", self.key).stdout)

    def test_hire_403_preserves_explanation_without_retry(self):
        with ccstore.connection() as db:
            ccboard.set_config(db, "dashboardMayHire", False)
        with patch.object(boardteams, "hire", wraps=boardteams.hire) as handler:
            result = self.cli("hire", self.key, "--name", "lead", "--json", code=1)
        self.assertEqual(handler.call_count, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("dashboardMayHire and dispatchEnabled must both be enabled", result.stderr)
        self.assertNotIn("HTTP Error", result.stderr)

    def test_409_preserves_board_message_and_hint(self):
        self.cli("recruit", self.key)
        self.cli("approve", self.key, "--member", "lead", "--member", "reviewer")
        result = self.cli("approve", self.key, "--member", "lead", code=1)
        self.assertIn("roster already approved", result.stderr)
        self.assertIn("fix: POST /api/board/recruit with id and actor", result.stderr)
        self.prepare_hire()
        result = self.cli("hire", self.key, "--name", "absent", code=1)
        self.assertIn("hire requires an approved roster row", result.stderr)
        self.assertIn("fix: recruit and approve this name for this card", result.stderr)
        self.assertNotIn("HTTP Error", result.stderr)

    def test_hire_rejects_overrides_and_required_arguments(self):
        for flag in ("--cli", "--cwd", "--model", "--argv", "--agent"):
            with self.subTest(flag=flag):
                result = self.cli("hire", self.key, "--name", "lead", flag, "override", code=2)
                self.assertIn("unrecognized arguments", result.stderr)
        self.cli("hire", self.key, code=2)
        self.cli("hire", "--name", "lead", code=2)
        self.cli("approve", self.key, code=2)

    def test_retire_reaches_the_board_and_needs_members(self):
        """The CLI half of the transition nothing could perform.

        `retire` carries --member the way `approve` does, and is identity-bound the
        same way: taking a team off a card is a decision with an owner.
        """
        self.cli("recruit", self.key)
        self.cli("approve", self.key, "--member", "lead")
        self.cli("retire", self.key, code=2)                      # --member required
        retired = json.loads(self.cli("retire", self.key, "--member", "lead",
                                      "--json").stdout)
        by_name = {row["agent_name"]: row for row in retired["members"]}
        self.assertEqual(by_name["lead"]["status"], "finished")
        self.assertIn("lead [lead] finished",
                      self.cli("roster", self.key).stdout)
        result = self.cli("retire", self.key, "--member", "lead", code=1)
        self.assertIn("not on this roster", result.stderr)

    def test_actor_cannot_be_overridden(self):
        for command, extra in (("recruit", []), ("approve", ["--member", "lead"]),
                               ("retire", ["--member", "lead"])):
            result = self.cli(command, self.key, *extra, "--agent", "someone-else", code=2)
            self.assertIn("cannot " + command + " as", result.stderr)
        self.assertEqual(json.loads(self.cli("roster", self.key, "--json").stdout)["count"], 0)

    def test_roster_query_is_encoded(self):
        with patch.object(boardteams, "roster", wraps=boardteams.roster) as handler:
            self.cli("roster", self.key + "&id=TM-999", code=1)
        self.assertEqual(handler.call_args.args[1], {"id": [self.key + "&id=TM-999"]})


if __name__ == "__main__":
    try:
        result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(TeamCLI))
    finally:
        os.chdir(OLD_CWD)
        TEMP.cleanup()
    failures = len(result.failures) + len(result.errors)
    print(f"passed {result.testsRun - failures}, failed {failures}")
    sys.exit(bool(failures))
