"""Exercise source ownership guards in disposable Git repositories only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "docs/planning/2026-10-09/verify-component-coverage.py"
spec = importlib.util.spec_from_file_location("component_coverage", CHECKER)
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class SourceSurfaceContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agentmux-go-surface-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.here = self.root / "docs/planning/2026-10-09"
        self.here.mkdir(parents=True)
        self.paths = ["app/main" + suffix for suffix in
                      (".py", ".sh", ".js", ".mjs", ".ts", ".cmd", ".go")]
        self.paths += ["app/main_test.go", "app/main.test.mjs", "app/tests/sample.go",
                       "analysis/sample.go", "orchtest/sample.go", "app/vendor/sample.go"]
        for path in self.paths:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("// fixture\n", encoding="utf-8", newline="\n")
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")
        self.git("add", "app", "analysis", "orchtest")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture baseline")
        commit = self.git("rev-parse", "HEAD").strip()
        blobs = {}
        for row in self.git("ls-tree", "-rz", "HEAD").split("\0"):
            if row:
                meta, path = row.split("\t", 1)
                blobs[path] = meta.split()[2]
        self.inventory = {"baselineCommit": commit, "manifests": ["components.json"],
                          "files": [{"path": path, "componentIds": ["FIX-01"],
                                     "baselineBlob": blobs[path]} for path in self.paths]}
        self.component = {"id": "FIX-01", "name": "Disposable sources", "files": self.paths.copy(),
                          "currentBehavior": "Fixture only", "reusePlan": "Retain fixture",
                          "enhancements": ["Check source registration"], "migrationChecks": ["Retain files"],
                          "ownerPhase": "P02", "disposition": "retain",
                          "baselineGroups": [f"BASE-{i:02}" for i in range(1, 38)],
                          "behaviorChecks": [{"id": "FIX-C01", "description": "Check fixture ownership",
                                              "requiredEnvironment": "Disposable Git repository", "existingTests": [],
                                              "baselineStatus": "not-run", "targetStatus": "not-run"}]}
        self.surface = {"files": [{"path": path, "componentIds": ["FIX-01"],
                                   "workingFileSha256": hashlib.sha256((self.root / path).read_bytes()).hexdigest()}
                                  for path in self.paths[:7]]}
        self.write("phases.json", {"phases": [{"id": "P02", "work": ["ADD-01 preservation"],
                                             "criteria": [{"id": "AC01", "text": "Preserve existing components"}]}]})
        (self.here / "implementation-plan.md").write_text("**AC01:** Preserve existing components\n", encoding="utf-8")
        self.write("verification-matrix.json", {"cases": []})
        (self.here / "verification-matrix.md").write_text("Fixture\n", encoding="utf-8")
        self.write("gate-record.template.json", {"componentPreservation": {"required": True}})
        self.save()
        self.assertEqual(self.check()["errors"], [])

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root).decode("utf-8")

    def write(self, name, value):
        (self.here / name).write_text(json.dumps(value) + "\n", encoding="utf-8", newline="\n")

    def save(self):
        self.write("component-inventory.json", self.inventory)
        self.write("components.json", {"components": [self.component]})
        self.write("source-surface-index.json", self.surface)

    def check(self):
        return coverage.check(root=self.root, here=self.here)

    def rejects(self, expected):
        result = self.check()
        self.assertFalse(result["ok"], result)
        self.assertIn(expected, result["errors"])

    def test_all_existing_languages_and_go_require_surface_records(self):
        for path in self.paths[:7]:
            with self.subTest(path=path):
                original = self.surface["files"].copy()
                self.surface["files"] = [row for row in original if row["path"] != path]
                self.save()
                self.rejects("Surface inventory is incomplete or contains duplicate paths")
                self.surface["files"] = original
                self.save()
                self.assertTrue(self.check()["ok"])

    def test_unregistered_go_runtime_file_is_rejected(self):
        (self.root / "app/new.go").write_text("package app\n", encoding="utf-8")
        self.rejects("New/unmapped source or missing inventory file: ['app/new.go']")

    def test_go_hash_drift_is_rejected(self):
        (self.root / "app/main.go").write_text("package changed\n", encoding="utf-8")
        self.rejects("Surface inventory stale; review source changes: app/main.go")

    def test_duplicate_go_surface_record_is_rejected(self):
        self.surface["files"].append(dict(self.surface["files"][-1]))
        self.save()
        self.rejects("Surface inventory is incomplete or contains duplicate paths")

    def test_go_test_file_is_excluded_only_from_surface(self):
        self.assertNotIn("app/main_test.go", [row["path"] for row in self.surface["files"]])
        self.assertTrue(self.check()["ok"])
        self.inventory["files"] = [row for row in self.inventory["files"] if row["path"] != "app/main_test.go"]
        self.component["files"].remove("app/main_test.go")
        self.save()
        self.rejects("New/unmapped source or missing inventory file: ['app/main_test.go']")
        self.rejects("Baseline blob inventory differs from the pinned commit")

    def test_go_test_file_requires_matching_component_owner(self):
        row = next(row for row in self.inventory["files"] if row["path"] == "app/main_test.go")
        row["componentIds"] = ["WRONG"]
        self.save()
        self.rejects("Incorrect component owners: app/main_test.go")

    def test_go_test_file_cannot_be_listed_as_runtime_surface(self):
        self.surface["files"].append({"path": "app/main_test.go", "componentIds": ["FIX-01"],
                                     "workingFileSha256": hashlib.sha256((self.root / "app/main_test.go").read_bytes()).hexdigest()})
        self.save()
        self.rejects("Surface inventory is incomplete or contains duplicate paths")


if __name__ == "__main__":
    unittest.main()
