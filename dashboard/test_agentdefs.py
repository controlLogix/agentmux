#!/usr/bin/env python3
"""Offline C1/C3 regressions; no live board writes or third-party imports."""
import hashlib
import json
from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "taskmgmt"))
import agentdefs as ad
import definition_team as dt


class AgentDefinitions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="agentdefs-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.home = self.base / "home"
        self.repo = self.base / "repo"
        self.root = self.home / ".agentmux"
        self.root.mkdir(parents=True)
        self.repo.mkdir()
        env = patch.dict(os.environ, {"HOME": str(self.home), "AGENTMUX_HOME": str(self.root)})
        env.start()
        self.addCleanup(env.stop)
        self.dirs = [self.repo / ".agentmux/agents", self.root / "agents",
                     self.repo / ".claude/agents", self.home / ".claude/agents"]

    def write(self, name="worker", scope=0, extra="", body="Persona\nsecond line", raw=None):
        directory = self.dirs[scope]
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / (name + ".md")
        path.write_bytes(raw if raw is not None else
                         f"---\nname: {name}\ndescription: Useful agent\n{extra}---\n{body}".encode())
        return path

    def load(self):
        return ad.load_all(self.repo)

    def test_four_scopes_and_defaults(self):
        for i in range(4):
            self.write("agent" + str(i), i)
        specs, problems = self.load()
        self.assertEqual(problems, [])
        self.assertEqual(len(specs), 4)
        for i, scope in enumerate(("repo", "global", "claude", "claude")):
            s = specs["agent" + str(i)]
            self.assertEqual(s.scope, scope)
            self.assertEqual((s.cli, s.role, s.posture, s.worktree, s.max_instances),
                             ("codex", "worker", "workspace-write", "per-member", 1))
            self.assertEqual((s.model, s.auth, s.tools, s.tools_deny, s.capabilities),
                             (None, None, (), (), ()))
            self.assertTrue(Path(s.path).is_absolute())

    def test_duplicates_every_pair_of_scopes(self):
        for i in range(4):
            for j in range(i + 1, 4):
                with self.subTest(pair=(i, j)):
                    a, b = self.write(scope=i), self.write(scope=j)
                    specs, problems = self.load()
                    self.assertEqual(specs, {})
                    self.assertEqual(len(problems), 1)
                    self.assertIn(str(a), problems[0]["error"])
                    self.assertIn(str(b), problems[0]["error"])
                    a.unlink()
                    b.unlink()

    def test_three_duplicates_and_invalid_duplicate(self):
        for i in range(3):
            self.write(scope=i)
        specs, problems = self.load()
        self.assertEqual(specs, {})
        self.assertEqual(len(problems), 1)
        self.write(scope=1, extra="posture: unsafe\n")
        specs, problems = self.load()
        self.assertEqual(specs, {})
        self.assertEqual(sum("duplicate name" in p["error"] for p in problems), 1)

    def test_flat_quotes_csv_checksum_crlf(self):
        raw = (b'---\r\nname: worker\r\ndescription: "Colon: # text"\r\n'
               b"cli: claude\r\ntools: Read, Bash(git diff:*)\r\ntools-deny: Write, Edit\r\n"
               b"capabilities: review, security\r\nrole: lead\r\nmax_instances: 8\r\n"
               b"model: 'model''s name'\r\n---\r\n\r\nBody\r\nnext\r\n")
        self.write(raw=raw)
        specs, problems = self.load()
        self.assertEqual(problems, [])
        s = specs["worker"]
        self.assertEqual(s.description, "Colon: # text")
        self.assertEqual(s.tools, ("Read", "Bash(git diff:*)"))
        self.assertEqual(s.tools_deny, ("Write", "Edit"))
        self.assertEqual(s.capabilities, ("review", "security"))
        self.assertEqual(s.worktree, "integration")
        self.assertEqual(s.model, "model's name")
        self.assertEqual(s.persona, "Body\nnext")
        self.assertEqual(s.checksum, "sha256:" + hashlib.sha256(raw).hexdigest())

    def test_unknown_keys_warn_and_still_load(self):
        p = self.write(extra="tool: Read\ncolour: green\n")
        specs, problems = self.load()
        self.assertIn("worker", specs)
        self.assertEqual(len(problems), 2)
        self.assertTrue(all(x["path"] == str(p) for x in problems))
        self.assertTrue(any("'tool'" in x["error"] for x in problems))
        self.assertTrue(any("'colour'" in x["error"] for x in problems))

    def test_validation_rejections_are_named(self):
        base = "---\nname: worker\ndescription: Useful\n"
        cases = [
            ("missing", "missing opening"),
            (base, "missing closing"),
            ("---\nname: worker\n---\n", "description"),
            (base.replace("worker", "Wrong") + "---", "name"),
            (base.replace("worker", "other") + "---", "filename"),
            (base + "name: worker\n---", "duplicate frontmatter"),
            (base + "tools:\n  allow: Read\n---", "flat"),
        ]
        for field, value in [("cli", "bad;cli"), ("posture", "unsafe"), ("role", "boss"),
                             ("worktree", "shared"), ("max_instances", "0"),
                             ("max_instances", "9"), ("max_instances", "1.5"),
                             ("capabilities", "Upper"), ("capabilities", ",review"),
                             ("capabilities", ",".join(["tag"] * 17)),
                             ("tools", "Read,,Write"), ("tools", "[Read, Write]"),
                             ("model", '"bad\\nmodel"'), ("auth", "not-a-method")]:
            cases.append((base + f"{field}: {value}\n---", field))
        cases.extend([(base + "---\n" + "x" * 4097, "persona"),
                      (base + "---\nBad\x00", "persona"),
                      (base.replace("Useful", "x" * 2049) + "---", "description"),
                      (base.replace("Useful", "bad\tvalue") + "---", "description")])
        for text, reason in cases:
            with self.subTest(reason=reason, text=text[:100]):
                p = self.write(raw=text.encode())
                specs, problems = self.load()
                self.assertEqual(specs, {})
                self.assertTrue(any(reason in x["error"] and x["path"] == str(p)
                                    for x in problems), problems)

    def test_size_encoding_backups_symlinks_and_directories(self):
        good = self.write("good")
        (good.parent / "backup.md.bak_123").write_bytes(b"invalid")
        self.write("huge", raw=b"x" * (ad.MAX_BYTES + 1))
        self.write("invalid", raw=b"\xff")
        (good.parent / "link.md").symlink_to(good)
        (good.parent / "directory.md").mkdir()
        specs, problems = self.load()
        self.assertEqual(set(specs), {"good"})
        self.assertEqual(len(problems), 4)
        self.assertTrue(any("64 KiB" in x["error"] for x in problems))
        self.assertTrue(any("symlink" in x["error"] for x in problems))

    def test_listing_cap(self):
        for i in range(201):
            self.write("a" + str(i))
        specs, problems = self.load()
        self.assertEqual(specs, {})
        self.assertEqual(len(problems), 1)
        self.assertIn("200", problems[0]["error"])

    def test_board_auth_model_defaults_and_resolve(self):
        with closing(sqlite3.connect(self.root / "cc.db")) as db, db:
            db.execute("CREATE TABLE board_config (name TEXT, value TEXT)")
            db.execute("INSERT INTO board_config VALUES ('dispatchCli', '\"claude\"')")
        methods = json.loads(ad.MANIFEST.read_text())["methods"]
        auth = next(m["id"] for m in methods if m["cli"] == "claude")
        (self.root / "auth.json").write_text(json.dumps({"active": {"claude": auth},
                                                       "methods": {auth: {"model": "chosen"}}}))
        self.write()
        specs, problems = self.load()
        self.assertEqual(problems, [])
        s = specs["worker"]
        self.assertEqual((s.cli, s.auth, s.model), ("claude", auth, "chosen"))
        self.assertEqual(ad.resolve("worker", self.repo), s)
        self.assertIsNone(ad.resolve("missing", self.repo))
        self.write(extra="cli: codex\nauth: " + auth + "\n")
        self.assertEqual(self.load()[0], {})

    def test_io_and_config_failures_do_not_raise(self):
        self.write()
        with patch.object(ad.os, "open", side_effect=PermissionError("denied")):
            specs, problems = self.load()
        self.assertEqual(specs, {})
        self.assertIn("denied", problems[0]["error"])
        (self.root / "auth.json").write_text("{")
        specs, problems = self.load()
        self.assertIn("worker", specs)
        self.assertTrue(any("auth configuration" in p["error"] for p in problems))
        specs, problems = ad.load_all(object())
        self.assertEqual(specs, {})
        self.assertTrue(problems)

    def test_same_directory_not_a_collision(self):
        self.write("homeagent", 3)
        specs, problems = ad.load_all(self.home)
        self.assertEqual(problems, [])
        self.assertEqual(set(specs), {"homeagent"})

    def test_roster_fallback_and_override(self):
        for cfg, override, cli in [({}, None, "codex"), ({"dispatchCli": "claude"}, None, "claude"),
                                   ({"dispatchCli": "claude"}, "grok", "grok"),
                                   ({"dispatchCli": ""}, "", "codex")]:
            roster = ad.choose_roster({}, {}, cfg, override)
            self.assertEqual(len(roster), 1)
            self.assertEqual((roster[0].cli, roster[0].role), (cli, "lead"))
        self.write(extra="role: lead\ntools: Read\n")
        specs, problems = self.load()
        self.assertEqual(problems, [])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            roster = ad.choose_roster({}, specs, {}, approved_lead=specs["worker"])
        self.assertEqual(roster[0], specs["worker"])
        self.assertIn("degrade", str(caught[0].message))

    def roster_specs(self):
        for name, extra in (
            ("alpha", "capabilities: frontend\n"),
            ("backend", "capabilities: backend\n"),
            ("senior-dev", "capabilities: senior, backend\nmax_instances: 8\n"),
            ("review", "role: reviewer\ncapabilities: security\n"),
            ("research", "role: researcher\n"),
        ):
            self.write(name, extra=extra)
        return self.load()[0]

    def test_worker_sizing_caps_and_determinism(self):
        specs = self.roster_specs()
        task = {"touches": ["ui/a", "ui/b", "api/c"]}
        roster = ad.choose_roster(task, specs, {"teamMaxWorkers": 8})
        self.assertEqual(len(roster), 3)
        self.assertEqual(roster, ad.choose_roster(task, dict(reversed(list(specs.items()))),
                                                 {"teamMaxWorkers": 8}))
        task["acceptance"] = [{"text": str(i)} for i in range(5)]
        self.assertEqual(len(ad.choose_roster(task, specs, {"teamMaxWorkers": 8})), 4)
        for cap in (0, 1, 2):
            self.assertEqual(len(ad.choose_roster(task, specs, {"teamMaxWorkers": cap})), cap + 1)
        roster = ad.choose_roster({"touches": [f"d{i}/a" for i in range(8)]},
                                  {"senior-dev": specs["senior-dev"]}, {"teamMaxWorkers": 8})
        self.assertEqual([s.name for s in roster], ["lead", "senior-dev"])
        self.assertTrue(roster.gaps)

    def test_a_well_matched_lead_does_not_hand_the_card_to_the_alphabet(self):
        """Workers were ranked only by what the LEAD lacks, so a lead that already
        covered the card left every candidate tied and `spec.name` decided.

        Found on a real card: TM-100, labelled inventory/catalog/filesystem, whose
        lead covered all three. It recruited hr-recruiter, plc-dev and
        plc-test-engineer - the first three worker definitions in the alphabet - to
        scan a filesystem, while the three scanners written for that exact card sat
        unproposed because "scan-" sorts after "plc-".
        """
        for name, extra in (
            ("aardvark", "capabilities: unrelated\n"),
            ("beetle", "capabilities: unrelated\n"),
            ("zebra-scanner", "capabilities: inventory, filesystem\n"),
        ):
            self.write(name, extra=extra)
        self.write("catalog-lead", extra="role: lead\ncapabilities: inventory, filesystem\n")
        specs = self.load()[0]
        task = {"labels": ["inventory", "filesystem"]}

        roster = ad.choose_roster(task, specs, {"teamMaxWorkers": 1},
                                  approved_lead=specs["catalog-lead"])
        self.assertEqual(roster[0].name, "catalog-lead")
        self.assertEqual([s.name for s in roster[1:]], ["zebra-scanner"],
                         "the worker matching the card lost to the alphabet")
        # Still deterministic, and still independent of how the specs are ordered.
        self.assertEqual(roster, ad.choose_roster(
            task, dict(reversed(list(specs.items()))), {"teamMaxWorkers": 1},
            approved_lead=specs["catalog-lead"]))
        # With nothing to match on, alphabetical order is still the answer.
        plain = ad.choose_roster({}, specs, {"teamMaxWorkers": 1})
        self.assertEqual([s.name for s in plain[1:]], ["aardvark"])

    def test_labels_gaps_types_and_depth(self):
        specs = self.roster_specs()
        roster = ad.choose_roster({"labels": ["backend", "missing"]}, specs, {})
        self.assertIn("backend", [s.name for s in roster])
        self.assertIn("Capability missing: no definition provides it", roster.gaps)
        bug = ad.choose_roster({"type": "bug"}, specs, {"teamMaxWorkers": 8})
        self.assertEqual([s.role for s in bug], ["lead", "worker", "reviewer"])
        for kind in ("story", "spike"):
            self.assertEqual(len(ad.choose_roster({"type": kind}, specs, {})), 3)
        dependencies = {"A": ["B"], "B": ["C"], "C": ["A"]}
        task = {"type": "story", "blockedBy": ["A"], "labels": ["frontend"]}
        deep = ad.choose_roster(task, specs, {"teamMaxWorkers": 8}, dependencies=dependencies)
        self.assertEqual([s.name for s in deep], ["lead", "senior-dev"])
        self.assertIn("Capability frontend: not covered by selected roster", deep.gaps)
        self.assertFalse(ad._deep_chain({"blockedBy": ["A"]}, {"A": ["A"]}))
        self.assertFalse(ad._deep_chain({"key": "ROOT", "blockedBy": ["A"]},
                                        {"A": ["B"], "B": ["ROOT"]}))
        fallback = ad.choose_roster(task, {}, {"dispatchCli": "claude"}, dependencies=dependencies)
        self.assertEqual([(s.name, s.cli) for s in fallback], [("lead", "claude")])
        self.assertTrue(fallback.gaps)

    def test_import_manifest_preserves_exact_bytes_roots_and_package_provenance(self):
        raw = b"---\r\nname: worker\r\ndescription: Exact\r\nunknown: retained\r\n---\r\nBody\r\n"
        path = self.write(raw=raw)
        plugin = dt.DefinitionPlugin(self.repo, home=self.home, global_root=self.root)
        with patch.dict(os.environ, {"HOME": "/unused", "AGENTMUX_HOME": "/unused"}):
            manifests, problems = plugin.import_all(package_name="project-definitions",
                                                   parent_package="project")
        self.assertEqual(len(manifests), 1)
        manifest = manifests[0]
        self.assertEqual(manifest.source, raw)
        self.assertEqual(manifest.spec.path, str(path))
        self.assertEqual(manifest.spec.checksum, "sha256:" + hashlib.sha256(raw).hexdigest())
        self.assertEqual((manifest.schema_version, manifest.parent_package), ("1.0.0", "project"))
        self.assertIn("unknown", problems[0]["error"])
        self.write(scope=1, raw=b"invalid")
        self.assertEqual(plugin.import_all(package_name="project")[0], ())

    def test_fifo_replacement_after_regular_file_check_is_refused(self):
        path = self.write()
        original_open = ad.os.open
        def replace_with_fifo(value, flags, *args, **kwargs):
            if Path(value) == path:
                path.unlink()
                os.mkfifo(path)
            return original_open(value, flags, *args, **kwargs)
        with patch.object(ad.os, "open", side_effect=replace_with_fifo):
            specs, problems = self.load()
        self.assertEqual(specs, {})
        self.assertIn("regular file", problems[0]["error"])

    def test_legacy_team_adapter_keeps_result_gaps_and_selection_arguments(self):
        specs = self.roster_specs()
        task = {"type": "bug", "labels": ["backend", "missing"], "blockedBy": ["A"]}
        dependencies = {"A": ["B"], "B": ["C"]}
        expected = ad.choose_roster(task, specs, {"teamMaxWorkers": 2}, "claude",
                                    dependencies=dependencies)
        with patch.object(ad, "choose_roster", return_value=expected) as select:
            actual = dt.TeamPlugin().propose_legacy(task, specs, {"teamMaxWorkers": 2},
                                                    "claude", dependencies=dependencies)
        self.assertIs(actual, expected)
        self.assertEqual(actual.gaps, expected.gaps)
        select.assert_called_once_with(task, specs, {"teamMaxWorkers": 2}, cli_override="claude",
                                       dependencies=dependencies, approved_lead=None)
        self.assertFalse(dt.TeamPlugin().propose(task, specs, {}, lead=None, members=()).approved_lead)

    def test_project_lead_eligibility_and_immutable_revision(self):
        self.write("aardvark", 3, extra="role: lead\n")
        self.write("project-lead", extra="role: lead\n")
        specs = self.roster_specs()
        fallback = ad.choose_roster({}, specs, {})
        self.assertEqual(fallback[0].name, "lead")
        self.assertIn("Lead: no project-approved definition; using compatibility fallback", fallback.gaps)
        plugin = dt.TeamPlugin()
        self.assertFalse(plugin.propose({}, specs, {}, lead=None, members=()).approved_lead)
        lead = dt.DefinitionRevision.of(specs["project-lead"])
        worker = dt.DefinitionRevision.of(specs["backend"])
        proposal = plugin.propose({"labels": ["backend", "frontend"]}, specs, {},
                                  lead=lead, members=(worker,))
        self.assertEqual([s.name for s in proposal.members], ["project-lead", "backend"])
        self.assertIn("Capability frontend: no definition provides it", proposal.gaps)
        changed_defaults = dict(specs, **{"project-lead": ad.replace(specs["project-lead"],
                                                                   model="new-default")})
        self.assertEqual(proposal.revision_changes(changed_defaults), (("project-lead", "changed"),))
        self.assertEqual(changed_defaults["project-lead"].checksum, specs["project-lead"].checksum)
        with self.assertRaisesRegex(ValueError, "changed"):
            plugin.propose({}, changed_defaults, {}, lead=lead, members=(worker,))
        saved = dt.dump_spec(proposal.members[0])
        self.assertEqual(dt.load_spec(saved), proposal.members[0])
        self.write("project-lead", extra="role: lead\n", body="New persona")
        current = self.load()[0]
        self.assertEqual(proposal.revision_changes(current), (("project-lead", "changed"),))
        self.assertNotEqual(proposal.members[0].persona, current["project-lead"].persona)
        with self.assertRaisesRegex(ValueError, "changed"):
            plugin.propose({}, current, {}, lead=lead, members=(worker,))
        intent = dt.tool_intent(ad.replace(specs["backend"], tools=("Read", "Bash")),
                                host_tools=("Read",))
        self.assertEqual(intent["hostEnforceable"], ("Read",))
        self.assertEqual(intent["advisory"], ("Bash",))
        self.assertEqual(dt.tool_intent(ad.replace(specs["backend"], tools=("Read",)))["hostEnforceable"], ())

    def test_existing_claude_definitions_unchanged(self):
        # Portable CI uses representative names; on the dispatched machine, copy
        # the actual five bytes-for-byte into the isolated fixture and test them.
        source = Path("/home/nick/.claude/agents")
        names = ("hr-recruiter", "plc-dev", "plc-test-engineer", "scheduler", "senior-reviewer")
        for name in names:
            p = source / (name + ".md")
            if p.is_file():
                self.write(name, 3, raw=p.read_bytes())
            else:
                self.write(name, 3)
        specs, problems = self.load()
        self.assertEqual(problems, [])
        self.assertEqual(set(specs), set(names))
        self.assertTrue(all(s.role == "worker" and s.posture == "workspace-write"
                            and s.max_instances == 1 for s in specs.values()))


if __name__ == "__main__":
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(AgentDefinitions))
    failures = len(result.failures) + len(result.errors)
    print(f"passed {result.testsRun - failures}, failed {failures}")
    sys.exit(bool(failures))
