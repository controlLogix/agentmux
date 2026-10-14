"""Check planning coverage. This does not run or qualify Agentmux behavior."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def check(root=ROOT, here=HERE):
    def load(name):
        return json.loads((here / name).read_text(encoding="utf-8"))

    errors = []
    inventory = load("component-inventory.json")
    phases = load("phases.json")
    phase_ids = {p["id"] for p in phases["phases"]}
    components = []
    for manifest in inventory["manifests"]:
        components.extend(load(manifest)["components"])
    ids = [c["id"] for c in components]
    if len(ids) != len(set(ids)):
        errors.append("Duplicate component ID")
    owners = {}
    checks = set()
    groups = set()
    allowed = {"retain", "wrap", "extract", "extend", "replace", "retain-evidence"}
    for c in components:
        cid = c["id"]
        for field in ["name", "files", "currentBehavior", "reusePlan", "enhancements", "behaviorChecks", "migrationChecks"]:
            if not c.get(field):
                errors.append(f"{cid}: missing {field}")
        if c["ownerPhase"] not in phase_ids or c["disposition"] not in allowed:
            errors.append(f"{cid}: invalid phase or reuse disposition")
        if c["disposition"] == "replace" and not c.get("replacementReason"):
            errors.append(f"{cid}: replacement requires a reason")
        for g in c["baselineGroups"]:
            groups.add(g)
        for f in c["files"]:
            owners.setdefault(f, set()).add(cid)
            if not (root / f).is_file():
                errors.append(f"{cid}: missing file {f}")
        for b in c["behaviorChecks"]:
            if b["id"] in checks:
                errors.append(f"Duplicate behavior check {b['id']}")
            checks.add(b["id"])
            if not b.get("description") or not b.get("requiredEnvironment"):
                errors.append(f"{b['id']}: missing behavior or environment")
            for f in b["existingTests"]:
                if not (root / f).is_file():
                    errors.append(f"{b['id']}: missing test reference {f}")
            # These manifests define future comparisons, never pass attestations.
            if b["baselineStatus"] != "not-run" or b["targetStatus"] != "not-run":
                errors.append(f"{b['id']}: store executed results in a gate record, not this proposal")
    expected_groups = {f"BASE-{i:02}" for i in range(1, 38)}
    if groups != expected_groups:
        errors.append(f"Baseline group mismatch: missing {sorted(expected_groups-groups)}, extra {sorted(groups-expected_groups)}")
    files = {f["path"]: f for f in inventory["files"]}
    listed = set(files)
    if len(listed) != len(inventory["files"]):
        errors.append("Duplicate file inventory path")
    if listed != set(owners):
        errors.append(f"Inventory/manifest mismatch: {sorted(listed ^ set(owners))}")
    for path, row in files.items():
        if set(row["componentIds"]) != owners.get(path, set()):
            errors.append(f"Incorrect component owners: {path}")
    tracked = set(subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root).decode().strip("\0").split("\0"))
    excluded_prefix = str(HERE.relative_to(ROOT)).replace("\\", "/") + "/"
    current = {p for p in tracked if not p.startswith(excluded_prefix)}
    if current != listed:
        errors.append(f"New/unmapped source or missing inventory file: {sorted(current ^ listed)}")
    baseline = subprocess.check_output(["git", "ls-tree", "-rz", inventory["baselineCommit"]], cwd=root).split(b"\0")
    baseline_map = {}
    for row in filter(None, baseline):
        meta, path = row.split(b"\t", 1)
        baseline_map[path.decode()] = meta.decode().split()[2]
    actual_baseline = {p: r["baselineBlob"] for p, r in files.items() if r["baselineBlob"] is not None}
    if actual_baseline != baseline_map:
        errors.append("Baseline blob inventory differs from the pinned commit")
    for p in phases["phases"]:
        if not any("ADD-01" in x for x in p["work"]):
            errors.append(f"{p['id']}: missing preservation work")
        if not any("component" in c["text"].lower() or "existing" in c["text"].lower() for c in p["criteria"]):
            errors.append(f"{p['id']}: missing preservation criterion")
    plan = (here / "implementation-plan.md").read_text(encoding="utf-8")
    for p in phases["phases"]:
        for a in p["criteria"]:
            if f"**{a['id']}:** {a['text']}" not in plan:
                errors.append(f"Plan/phase mismatch: {a['id']}")
    cases = load("verification-matrix.json")["cases"]
    failure_md = (here / "verification-matrix.md").read_text(encoding="utf-8")
    for c in cases:
        if c["id"] not in failure_md or c["status"] != "not-run":
            errors.append(f"Failure scenario mismatch or claimed result: {c['id']}")
    if not load("gate-record.template.json").get("componentPreservation"):
        errors.append("Gate record lacks component preservation evidence fields")
    surface = load("source-surface-index.json")
    expected_surface = {f for f in listed if Path(f).suffix in (".py", ".sh", ".js", ".mjs", ".ts", ".cmd", ".go") and not f.endswith((".test.mjs", "_test.go")) and "/vendor/" not in f and "/test" not in f and not f.startswith(("analysis/", "orchtest/"))}
    surface_paths = [r["path"] for r in surface["files"]]
    if set(surface_paths) != expected_surface or len(surface_paths) != len(set(surface_paths)):
        errors.append("Surface inventory is incomplete or contains duplicate paths")
    for record in surface["files"]:
        if record["path"] not in files or set(record["componentIds"]) != owners[record["path"]]:
            errors.append(f"Surface ownership mismatch: {record['path']}")
        if hashlib.sha256((root / record["path"]).read_bytes()).hexdigest() != record["workingFileSha256"]:
            errors.append(f"Surface inventory stale; review source changes: {record['path']}")
    return dict(ok=not errors, baselineFiles=len(baseline_map), additionalFiles=len(files)-len(baseline_map), components=len(components), behaviorChecks=len(checks), baselineGroups=len(groups), phaseCriteria=sum(len(p["criteria"]) for p in phases["phases"]), failureScenarios=len(cases), errors=errors, assurance="Checks planning coverage and references only; does not prove semantic completeness or execute runtime tests.")


if __name__ == "__main__":
    try:
        result = check()
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        result = dict(ok=False, errors=[str(exc)])
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["ok"] else 1)
