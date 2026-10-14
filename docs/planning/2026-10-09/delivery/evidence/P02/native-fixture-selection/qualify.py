"""Run only the native fixture's selection, copy and inventory controls.

This collector does not contact an engine, install a release or qualify a host.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone


OWNED = [
    "platform/launcher/bootstrap_docker_integration_test.go",
    "platform/launcher/bootstrap_docker_selection_test.go",
    "platform/launcher/bootstrap_docker_selection_controls_test.go",
    "platform/launcher/bootstrap_docker_native_linux_test.go",
    "platform/launcher/bootstrap_docker_native_darwin_test.go",
]
EXPECTED_TESTS = (
    "TestBootstrapSelectionNativeMatrixAndLegacyWSL",
    "TestBootstrapSelectionRejectsUnpinnedOrAmbiguousInput",
    "TestBootstrapSelectionRejectsWrongHostAndAmbientTargets",
    "TestBootstrapSelectionBuildCommandsStayNative",
    "TestBootstrapSelectionCopiesAndSignsExactRoles",
    "TestBootstrapSelectionProtectedCopyPlanAndLeases",
    "TestBootstrapSelectionDescriptorRejectsActualSubstitutions",
    "TestBootstrapVolumeTemplateProducesCompleteJSON",
    "TestBootstrapInventoryBatchRequiresCompleteExactRoster",
    "TestBootstrapInventoryRequiresCompleteStateAndPortFields",
)
SELECTION = "^(" + "|".join(EXPECTED_TESTS) + ")$"
PACKAGE = "github.com/controlLogix/agentmux/platform/launcher"


def admit_go_events(raw):
    problems, runs, passes, top = [], {}, {}, set()
    starts = package_passes = 0
    terminal_package = False
    for line in raw.decode("utf-8", errors="strict").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            problems.append("malformed_event")
            continue
        if not isinstance(event, dict) or event.get("Package") != PACKAGE:
            problems.append("unexpected_package_or_event")
            continue
        action, test = event.get("Action"), event.get("Test")
        if action not in {"start", "run", "pause", "cont", "output", "pass", "fail", "skip"}:
            problems.append("unexpected_action")
            continue
        if action in {"fail", "skip"}:
            problems.append("failed_or_skipped_event")
        if action != "start" and starts != 1:
            problems.append("event_before_package_start")
        if terminal_package:
            problems.append("event_after_package_completion")
        if test is not None:
            if not isinstance(test, str) or test.split("/", 1)[0] not in EXPECTED_TESTS:
                problems.append("unselected_test_event")
                continue
            if action == "run":
                if test in passes:
                    problems.append("test_run_after_terminal_event")
                runs[test] = runs.get(test, 0) + 1
            if action == "pass":
                if runs.get(test) != 1 or test in passes:
                    problems.append("test_terminal_without_one_prior_run")
                passes[test] = passes.get(test, 0) + 1
                if "/" not in test:
                    top.add(test)
        elif action == "start":
            starts += 1
        elif action == "pass":
            package_passes += 1
            terminal_package = True
        elif action != "output":
            problems.append("package_event_missing_test")
    if starts != 1 or package_passes != 1:
        problems.append("missing_or_duplicate_package_lifecycle")
    if top != set(EXPECTED_TESTS):
        problems.append("missing_selected_top_level_pass")
    if not runs or runs.keys() != passes.keys() or any(count != 1 for count in runs.values()) or any(count != 1 for count in passes.values()):
        problems.append("incomplete_or_duplicate_test_lifecycle")
    return {"admitted": not problems, "problems": sorted(set(problems)), "namedPasses": sum(passes.values()),
            "packagePasses": package_passes, "topLevelPasses": sorted(top)}


class EventAdmissionControls(unittest.TestCase):
    def events(self):
        result = [{"Package": PACKAGE, "Action": "start"}]
        for name in EXPECTED_TESTS:
            result += [{"Package": PACKAGE, "Action": "run", "Test": name}, {"Package": PACKAGE, "Action": "pass", "Test": name}]
        result.append({"Package": PACKAGE, "Action": "pass"})
        return result

    def admit(self, events):
        return admit_go_events("\n".join(json.dumps(item) for item in events).encode())

    def test_complete_selection(self):
        self.assertTrue(self.admit(self.events())["admitted"])

    def test_empty_and_malformed(self):
        self.assertFalse(admit_go_events(b"")["admitted"])
        self.assertFalse(admit_go_events(b"not-json")["admitted"])

    def test_incomplete_skipped_failed_or_duplicate(self):
        for kind in ("missing-test", "missing-run", "skip", "fail", "duplicate-pass", "missing-package", "foreign-package", "unknown-action", "event-after-package", "reversed-test", "late-start", "missing-test-name"):
            with self.subTest(kind=kind):
                events = self.events()
                if kind == "missing-test": del events[1:3]
                elif kind == "missing-run": del events[1]
                elif kind in ("skip", "fail"): events[2]["Action"] = kind
                elif kind == "duplicate-pass": events.insert(3, events[2].copy())
                elif kind == "missing-package": events.pop()
                elif kind == "foreign-package": events[1]["Package"] = "other"
                elif kind == "unknown-action": events[1]["Action"] = "unknown"
                elif kind == "event-after-package": events.append(events[2].copy())
                elif kind == "reversed-test": events[1], events[2] = events[2], events[1]
                elif kind == "late-start": events.insert(3, events.pop(0))
                elif kind == "missing-test-name": events.insert(3, {"Package": PACKAGE, "Action": "run"})
                self.assertFalse(self.admit(events)["admitted"])

    def test_subtest_requires_complete_lifecycle(self):
        events = self.events()
        child = {"Package": PACKAGE, "Test": EXPECTED_TESTS[0]+"/child"}
        events[-1:-1] = [dict(child, Action="run"), dict(child, Action="pass")]
        self.assertTrue(self.admit(events)["admitted"])
        del events[-3]
        self.assertFalse(self.admit(events)["admitted"])


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--go", type=Path)
    parser.add_argument("--cache", type=Path)
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EventAdmissionControls))
        return 0 if result.wasSuccessful() else 1
    if not args.root or not args.go or not args.cache:
        parser.error("--root, --go and --cache are required for qualification")
    root = args.root.resolve(strict=True)
    args.cache.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="p02-native-fixture-selection-", dir=args.cache))
    producer = Path(__file__).resolve(strict=True)
    producer_hash = digest(producer)
    shutil.copyfile(producer, output / "qualify.py")
    if digest(output / "qualify.py") != producer_hash:
        raise RuntimeError("Collector source changed while copying")
    before = {name: digest(root / name) for name in OWNED}
    frozen = output / "source"
    frozen.mkdir()
    # Copy the authoritative schemas with the platform, never just the module.
    shutil.copytree(root / "platform", frozen / "platform")
    shutil.copytree(root / "contracts" / "v1", frozen / "contracts" / "v1")
    copied = {name: digest(frozen / name) for name in OWNED}
    if copied != before:
        raise RuntimeError("Owned source changed during fixture copy")
    sources = {
        path.relative_to(frozen).as_posix(): digest(path)
        for path in sorted(frozen.rglob("*")) if path.is_file()
    }
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off", "GORACE": "atexit_sleep_ms=0"})
    # Do not inherit authorization for real fixture paths, even if mistakenly
    # included in a later selection. No selected control needs those grants.
    removed = []
    for key in list(env):
        if key.startswith("AMX_BOOTSTRAP_") or key == "AMX_DARWIN_INSTALL_AUTHORIZED":
            removed.append(key)
            del env[key]
    commands = [
        [str(args.go), "test", "-race", "-count=1", "-json", "-tags=agentmux_bootstrap_docker", "-run", SELECTION, "./launcher"],
        [str(args.go), "vet", "-tags=agentmux_bootstrap_docker", "./launcher"],
    ]
    results = []
    for index, argv in enumerate(commands):
        started = utc()
        run = subprocess.run(argv, cwd=frozen / "platform", env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        ended = utc()
        log = output / f"command-{index}.log"
        log.write_bytes(run.stdout)
        results.append({"argv": argv, "cwd": str(frozen / "platform"), "startedAt": started, "endedAt": ended,
                        "exitCode": run.returncode, "log": str(log), "logSHA256": digest(log)})
        if run.returncode:
            break
    after = {name: digest(root / name) for name in OWNED}
    frozen_after = {path.relative_to(frozen).as_posix(): digest(path) for path in sorted(frozen.rglob("*")) if path.is_file()}
    admission = admit_go_events((output / "command-0.log").read_bytes())
    result = {
        "schemaVersion": "1.0.0", "taskId": "P02-T07", "scope": "Pure fixture selection, signed copies, literal build plans and existing inventory controls",
        "sourceCommit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "producerCopy": str(output / "qualify.py"), "producerSHA256": producer_hash,
        "producerUnchanged": digest(producer) == producer_hash,
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip(),
        "ownedBefore": before, "ownedFrozen": copied, "ownedAfter": after, "ownedSourceUnchanged": before == after,
        "frozenSources": sources, "frozenSourceUnchanged": sources == frozen_after,
        "goExecutable": str(args.go), "goExecutableSHA256": digest(args.go),
        "explicitEnvironment": {key: env[key] for key in ("GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "GOWORK", "GORACE")},
        "removedAuthorizationNames": sorted(removed), "commands": results,
        "eventAdmission": admission, "namedPasses": admission["namedPasses"], "packagePasses": admission["packagePasses"],
        "nativeQualification": False, "phaseAcceptance": False,
        "limitations": ["No Docker engine, broker, installation, protected process or CI job was started.",
                        "Darwin compiler, SDK, privileged copy and image admission remain unexecuted.",
                        "Linux and Darwin architecture controls are input/build-plan checks, not runs on all four host targets.",
                        "Inherited environment is not fully captured. Recorded times bracket subprocess.run, not exact OS process start and exit."],
    }
    report = output / "selection-review.json"
    report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"report": str(report), "reportSHA256": digest(report), "namedPasses": result["namedPasses"], "packagePasses": result["packagePasses"],
                      "exits": [item["exitCode"] for item in results], "ownedSourceUnchanged": result["ownedSourceUnchanged"], "frozenSourceUnchanged": result["frozenSourceUnchanged"]}))
    return 0 if len(results) == 2 and all(item["exitCode"] == 0 for item in results) and admission["admitted"] and before == after and sources == frozen_after and result["producerUnchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
