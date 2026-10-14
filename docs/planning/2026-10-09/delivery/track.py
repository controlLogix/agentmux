"""Repository-owned delivery tracking. This is not Agentmux runtime task storage."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
PLAN = HERE.parent
ROOT = PLAN.parents[2]
STATE = HERE / "tasks.json"
STATES = ("planned", "ready", "in_progress", "blocked", "verification", "done")
ACTIVE_STATES = ("ready", "in_progress", "verification")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, data):
    write_text_atomic(path, json.dumps(data, indent=2, ensure_ascii=False) + '\n')


def write_text_atomic(path, text):
    """Replace generated text without truncating a file held by a reader."""
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def now():
    return datetime.now(timezone.utc).isoformat()


def source_hashes():
    return {name: hashlib.sha256((PLAN / name).read_bytes()).hexdigest() for name in (
        "phases.json", "verification-matrix.json", "jev-coverage.json", "component-inventory.json",
        "component-audit-hub.json", "component-audit-harness.json", "component-audit-dashboard.json",
        "component-audit-repository.json")}


def make_task(key, phase, kind, title, scope, steps, acceptance, dependencies, **extra):
    return {"id": key, "phase": phase, "kind": kind, "title": title, "scope": scope,
            "status": "planned", "owner": "Codex", "dependsOn": dependencies,
            "implementationPlan": steps,
            "acceptanceCriteria": [{"id": f"{key}-AC{i:02}", "text": text} for i, text in enumerate(acceptance, 1)],
            "evidence": [], "commits": [], "blocker": None, "history": [], **extra}


def final_acceptance_task():
    contract = read(PLAN / 'phases.json')['mergeGate']
    return make_task('MERGE-01', 'P14', 'final-acceptance', 'Autonomous final feature-branch acceptance and verified push',
        [contract],
        ['Verify every approved phase against the exact candidate and supported environments; collect the phase-by-phase evidence index and resolve every required gap.',
         'Use agent-operated, independently enrolled running hubs with distinct administration identities. Demonstrate automatic Compose start and reuse, instance identity, readiness and scoped hub status.',
         'Connect those hubs with explicit scoped grants. Run the plan\'s read-only fixture orchestration in both directions, with origin-owned acceptance in each direction.',
         'Preserve fixture checksums, artifact digests, task/delegation/attempt/result identities and terminal/dashboard observations. Verify bounded outputs and unchanged inputs; rerun affected checks after material changes.',
         'Codex reviews the actual evidence and subagent findings, records its dated final acceptance of this exact candidate and verifies the pushed feature-branch commit. Record mergeAuthorized=false; this acceptance never permits a merge.'],
        ['Every required P00–P14 criterion and environment has reviewed, current evidence with no unresolved required gap.',
         'Two agent-operated, independently enrolled real hubs complete the non-destructive orchestration in both directions, including explicit origin acceptance.',
         'The complete finalMergeGate evidence bundle identifies the exact candidate, scopes, operations, artifacts, checksums and before/after observations.',
         'Codex reviews that evidence and accepts the exact candidate after verifying the remote feature-branch commit. No human review is required and no merge is authorized.'],
        [p + '-GATE' for p in contract['requiredPhases']], phaseCriteria=[], catalogRecordIds=[], behaviorCheckIds=[],
        verification=['Execute every step of implementation-plan.md, MERGE-01, on the final candidate.'],
        deliverables=['Completed final acceptance record and linked real-instance evidence', 'Dated Codex review, verified remote commit and mergeAuthorized=false'])


def initialize():
    assert not STATE.exists(), "tasks.json already exists; do not reset delivery history"
    phases = read(PLAN / "phases.json")["phases"]
    failures = read(PLAN / "verification-matrix.json")["cases"]
    catalog = read(PLAN / "jev-coverage.json")
    records = sum((catalog[k] for k in ("useCases", "videoApplications", "videoEnablers", "skills")), [])
    inventory = read(PLAN / "component-inventory.json")
    components = sum((read(PLAN / name)["components"] for name in inventory["manifests"]), [])
    tasks, epics = [], []
    for phase in phases:
        pid = phase["id"]
        previous = [p + "-GATE" for p in phase["dependsOn"]]
        preservation = next(i for i, w in enumerate(phase["work"], 1) if "ADD-01" in w)
        preservation_id = f"{pid}-T{preservation:02}"
        owned = [c for c in components if c["ownerPhase"] == pid]
        for i, work in enumerate(phase["work"], 1):
            key = f"{pid}-T{i:02}"
            scope = [{"id": f"{pid}-W{i:02}", "text": work}]
            dependencies = previous + ([preservation_id] if i != preservation else [])
            steps = [
                "Inspect the existing source and callers for this exact work item: " + work,
                "Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.",
                "Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.",
                "Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.",
                "Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted."]
            acceptance = [
                "The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: " + work,
                "Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.",
                "Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.",
                "Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented."]
            task = make_task(key, pid, "implementation", work.split(". ")[0], scope, steps, acceptance, dependencies,
                             phaseCriteria=[c["id"] for c in phase["criteria"]],
                             verification=phase["verify"], deliverables=[work, "Focused regression evidence and affected compatibility/migration records"],
                             componentIds=[c["id"] for c in owned],
                             behaviorCheckIds=[b["id"] for c in components for b in c["behaviorChecks"]
                                               if b.get("qualificationPhase", c["ownerPhase"]) == pid] if i == preservation else [],
                             catalogRecordIds=[])
            if i == preservation:
                task["implementationPlan"] = [
                    "Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.",
                    "Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.",
                    "Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.",
                    "Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction."]
                task["acceptanceCriteria"] = [{"id": f"{key}-AC{n:02}", "text": text} for n, text in enumerate([
                    "Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.",
                    "Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.",
                    "Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.",
                    "Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed."], 1)]
            tasks.append(task)
        for record in (r for r in records if r["ownerPhase"] == pid):
            key = pid + "-" + record["id"]
            proposal = record["sourceProposal"]
            skill = record["recordType"] == "skill"
            steps = [
                "Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.",
                ("Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: " if skill else "Implement or extend a versioned definition/capability for: ") + record["title"],
                "Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.",
                "Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.",
                "Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.",
                "Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies."]
            tasks.append(make_task(key, pid, "skill" if skill else "catalog-qualification", record["title"],
                [record["id"]], steps, record["acceptanceCriteria"] + [
                    "All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.",
                    "Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice."],
                previous + [preservation_id], sourceRecord=record, catalogRecordIds=[record["id"]],
                behaviorCheckIds=[], verification=["Run the item's required evaluation gates: " + ", ".join(record["evaluationGateIds"])],
                deliverables=["Versioned implementation or explicit evaluated disposition", "Item-specific fixtures, holdout results and host/cost evidence"]))
        members = [t["id"] for t in tasks if t["phase"] == pid]
        gate = make_task(pid + "-GATE", pid, "phase-verification", "Verify and accept " + pid,
            [{"id": c["id"], "text": c["text"]} for c in phase["criteria"]],
            ["Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.",
             "Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.",
             "Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.",
             "Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate."],
            [c["text"] for c in phase["criteria"]] + [
                "All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.",
                "The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed."],
            members, phaseCriteria=[c["id"] for c in phase["criteria"]],
            failureScenarioIds=[f["id"] for f in failures if pid in f["phases"]],
            verification=phase["verify"], deliverables=phase["evidence"],
            behaviorCheckIds=[], catalogRecordIds=[])
        tasks.append(gate)
        epics.append({"id": pid, "title": phase["name"], "outcome": phase["outcome"], "ownerFunction": phase["owner"],
                      "dependsOn": phase["dependsOn"], "acceptanceCriteria": phase["criteria"],
                      "rollback": phase["rollback"], "gateTask": gate["id"]})
    tasks.append(final_acceptance_task())
    save(STATE, {"schemaVersion": "1.0.0", "branch": "feat/agentmux-platform-rearchitecture",
        "createdAt": now(), "sourceHashes": source_hashes(), "trackingDecision": "Repository tracking replaces Jira at Ryan's request; no Atlassian connection is required.",
        "epics": epics, "tasks": tasks,
        "history": [{"at": now(), "actor": "Codex", "action": "initialized", "note": "Created the full phase/work/catalog backlog. No implementation or phase pass is implied."}]})


def validate(data):
    assert data["sourceHashes"] == source_hashes(), "Planning sources changed; reconcile task scope and update sourceHashes explicitly, preserving history"
    tasks = {t["id"]: t for t in data["tasks"]}
    assert len(tasks) == len(data["tasks"]), "duplicate task ID"
    phases = read(PLAN / "phases.json")["phases"]
    expected_work = {f"{p['id']}-W{i:02}" for p in phases for i in range(1, len(p["work"]) + 1)}
    owned_work = [s["id"] for t in tasks.values() if t["kind"] == "implementation" for s in t["scope"]]
    assert len(owned_work) == len(set(owned_work)) and set(owned_work) == expected_work, "phase work coverage mismatch"
    work_text = {f"{p['id']}-W{i:02}": w for p in phases for i, w in enumerate(p['work'], 1)}
    for t in tasks.values():
        if t['kind'] == 'implementation':
            assert all(s['text'] == work_text[s['id']] for s in t['scope']), 'task scope differs from the phase work'
    catalog = read(PLAN / "jev-coverage.json")
    expected_catalog = {r["id"] for name in ("useCases", "videoApplications", "videoEnablers", "skills") for r in catalog[name]}
    owned_catalog = [r for t in tasks.values() for r in t.get("catalogRecordIds", [])]
    assert len(owned_catalog) == len(set(owned_catalog)) and set(owned_catalog) == expected_catalog, "catalog coverage mismatch"
    assert {e['id'] for e in data['epics']} == {p['id'] for p in phases}, "phase coverage mismatch"
    failures = read(PLAN / "verification-matrix.json")["cases"]
    inventory = read(PLAN / "component-inventory.json")
    components = sum((read(PLAN / name)["components"] for name in inventory["manifests"]), [])
    expected_checks = {b['id']: b.get('qualificationPhase', c['ownerPhase'])
                       for c in components for b in c['behaviorChecks']}
    assigned_checks = [(b, t['phase']) for t in tasks.values() for b in t.get('behaviorCheckIds', [])]
    assert len(assigned_checks) == len(set(b for b, _ in assigned_checks)), "duplicate component behavior owner"
    assert set(expected_checks) == {b for b, _ in assigned_checks}, "component behavior coverage mismatch"
    assert all(expected_checks[b] == phase for b, phase in assigned_checks), "component behavior qualification phase mismatch"
    for phase in phases:
        epic = next(e for e in data['epics'] if e['id'] == phase['id'])
        assert epic['acceptanceCriteria'] == phase['criteria'], "phase criteria changed in tracker"
        gate = tasks[phase['id'] + '-GATE']
        assert gate['phaseCriteria'] == [c['id'] for c in phase['criteria']], "gate criteria missing"
        assert set(gate['failureScenarioIds']) == {f['id'] for f in failures if phase['id'] in f['phases']}, "failure scenarios missing"
        assert set(gate['dependsOn']) == {t['id'] for t in tasks.values() if t['phase'] == phase['id'] and t['kind'] not in ('phase-verification', 'final-acceptance')}, "gate has unmapped phase work"
    assert tasks['MERGE-01']['kind'] == 'final-acceptance' and set(tasks['MERGE-01']['dependsOn']) == {p['id'] + '-GATE' for p in phases}, 'final acceptance cannot omit phases'
    active_phases = {t['phase'] for t in tasks.values() if t['status'] in ACTIVE_STATES}
    assert len(active_phases) <= 1, 'only one phase may have active work'
    for t in tasks.values():
        assert t["status"] in STATES, t["id"]
        assert len(t["implementationPlan"]) >= 3 and len(t["acceptanceCriteria"]) >= 3, t["id"]
        assert set(t["dependsOn"]) <= tasks.keys(), t["id"]
        if t["status"] in ("ready", "in_progress", "verification", "done"):
            earlier = [p['id'] for p in phases[:next(i for i, p in enumerate(phases) if p['id'] == t['phase'])]]
            assert all(tasks[p + '-GATE']['status'] == 'done' for p in earlier), f"{t['id']}: prior phase gate incomplete"
            assert all(tasks[d]["status"] == "done" for d in t["dependsOn"]), f"{t['id']}: predecessor incomplete"
        if t["status"] == "blocked":
            assert t.get("blocker"), f"{t['id']}: blocker reason required"
        if t["status"] == "done":
            assert t["evidence"] and t["commits"], f"{t['id']}: completion evidence and commit required"
    visited = set()
    def visit(key, active):
        assert key not in active, "task dependency cycle: " + key
        if key in visited:
            return
        for d in tasks[key]["dependsOn"]:
            visit(d, active | {key})
        visited.add(key)
    for key in tasks:
        visit(key, set())
    return tasks


def render(data):
    tasks = validate(data)
    lines = ["# Implementation status", "", "Generated from delivery/tasks.json. Edit status through delivery/track.py; this page is a view, not another source of truth.",
             "", "Branch: `" + data["branch"] + "`. No phase or merge approval is implied by a task count.", "",
             "| Phase | Planned | Ready | In progress | Blocked | Verification | Done | Gate |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |"]
    for epic in data["epics"]:
        rows = [t for t in tasks.values() if t["phase"] == epic["id"]]
        counts = [sum(t["status"] == status for t in rows) for status in STATES]
        lines.append("| " + epic["id"] + " | " + " | ".join(map(str, counts)) + " | " + tasks[epic["gateTask"]]["status"] + " |")
    lines += ["", "## Current work and blockers", ""]
    for t in tasks.values():
        if t["status"] in ("in_progress", "blocked", "verification"):
            lines += [f"- **{t['id']} — {t['status']}:** {t['title']}"]
            if t.get("blocker"):
                lines.append("  Reason: " + t["blocker"])
    for epic in data["epics"]:
        lines += ["", "## " + epic["id"] + ". " + epic["title"], "", epic["outcome"], "",
                  "| Task | Status | Owner | Scope |", "| --- | --- | --- | --- |"]
        for t in tasks.values():
            if t["phase"] == epic["id"]:
                lines.append(f"| [{t['id']}](delivery/task-details.md#{t['id']}) | {t['status']} | {t['owner']} | {t['title'].replace('|', '/')} |")
    write_text_atomic(PLAN / "implementation-status.md", "\n".join(lines) + "\n")
    detail = ["# Implementation tasks", "", "Generated from tasks.json. Status and evidence remain owned by that file.", ""]
    for epic in data['epics']:
        detail += ['## ' + epic['id'] + '. ' + epic['title'], '', epic['outcome'], '', '**Epic acceptance criteria**', '']
        detail += ['- **' + c['id'] + ':** ' + c['text'] for c in epic['acceptanceCriteria']]
        for t in tasks.values():
            if t['phase'] != epic['id']:
                continue
            detail += ['', '<a id="' + t['id'] + '"></a>', '', '### ' + t['id'] + ': ' + t['title'], '',
                       '**Status:** ' + t['status'] + '. **Owner:** ' + t['owner'] + '.', '',
                       '**Dependencies:** ' + (', '.join(t['dependsOn']) or 'none') + '.', '']
            for title, values in [('Implementation plan', t['implementationPlan']), ('Deliverables', t['deliverables']),
                                  ('Acceptance criteria', [a['id'] + ': ' + a['text'] for a in t['acceptanceCriteria']]),
                                  ('Verification', t['verification'])]:
                detail += ['**' + title + '**', ''] + [f'{i}. {v}' for i, v in enumerate(values, 1)] + ['']
            if t.get('sourceRecord'):
                detail += ['**Original proposal and item-specific boundaries**', '', '```json',
                           json.dumps(t['sourceRecord']['sourceProposal'], indent=2, ensure_ascii=False), '```', '']
            detail += ['**Evidence:** ' + (', '.join(t['evidence']) or 'not yet recorded'), '',
                       '**Commits:** ' + (', '.join(t['commits']) or 'not yet recorded'), '']
            if t.get('blocker'):
                detail += ['**Blocker:** ' + t['blocker'], '']
    write_text_atomic(HERE / 'task-details.md', '\n'.join(detail).rstrip() + '\n')


def codex_review(record, decision_key, decision):
    reviewer = record.get('independentReviewer', record.get('reviewer'))
    if isinstance(reviewer, dict):
        reviewer = reviewer.get('actor')
    assert reviewer == 'Codex', 'Codex must review the actual evidence'
    approval = record.get(decision_key, {})
    assert approval.get('actor') == 'Codex' and approval.get('date') and approval.get('decision') == decision, 'dated Codex decision required'


def final_evidence(record, tasks, commit):
    """Check final record structure. Codex must also inspect the linked evidence."""
    assert record.get('sourceCommit') == commit, 'wrong final candidate'
    assert record.get('mergeAuthorized') is False, 'final acceptance must not authorize merging'
    codex_review(record, 'decision', 'accepted')
    expected = {t['id'] for t in tasks.values() if t['kind'] == 'phase-verification'}
    rows = record.get('phaseGateEvidence', [])
    assert len(rows) == len(expected) and {r.get('taskId') for r in rows} == expected, 'every phase gate needs final evidence'
    assert all(tasks[r['taskId']]['status'] == 'done' and r.get('evidence') for r in rows), 'final acceptance requires completed reviewed phase gates'
    hubs = record.get('hubs', [])
    assert len(hubs) == 2 and len({h.get('hubId') for h in hubs}) == 2, 'two distinct running hubs required'
    assert len({h.get('adminIdentity') for h in hubs}) == 2, 'independent hub administration identities required'
    assert all(h.get('hubId') and h.get('adminIdentity') and h.get('enrollmentEvidence') and h.get('startupEvidence') for h in hubs), 'hub enrollment and startup evidence required'
    a, b = [h['hubId'] for h in hubs]
    runs = record.get('bilateralRuns', [])
    assert len(runs) == 2 and {(r.get('originHubId'), r.get('executorHubId')) for r in runs} == {(a, b), (b, a)}, 'successful orchestration in both directions required'
    for run in runs:
        assert run.get('nonDestructive') is True and run.get('inputDigestBefore') and run['inputDigestBefore'] == run.get('inputDigestAfter'), 'non-destructive fixture proof required'
        assert all(run.get(k) for k in ('taskId', 'delegationId', 'attemptId', 'resultId', 'artifactDigest', 'evidence')), 'correlated execution and artifact evidence required'
        acceptance = run.get('originAcceptance', {})
        assert acceptance.get('hubId') == run['originHubId'] and acceptance.get('decision') == 'accepted' and acceptance.get('evidence'), 'origin-owned acceptance evidence required'


def update(args):
    data = read(STATE)
    tasks = validate(data)
    branch = subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip()
    assert branch == data['branch'], "tracking updates belong on the implementation feature branch"
    assert args.task in tasks, "unknown task"
    task = tasks[args.task]
    old = task["status"]
    assert old != args.status, "status is unchanged"
    if args.status == "done":
        assert args.record, "done requires --record with criterion-level evidence"
        record_path = (ROOT / args.record).resolve()
        assert record_path.is_relative_to(ROOT), "evidence must be in the repository"
        record = read(record_path)
        assert record["taskId"] == task["id"], "evidence belongs to another task"
        required = {a["id"] for a in task["acceptanceCriteria"]}
        results = {a["criterionId"]: a for a in record["acceptanceResults"]}
        assert len(record['acceptanceResults']) == len(required) and set(results) == required, "evidence must cover every task criterion exactly"
        assert all(a["status"] == "passed" and a.get("evidence") for a in results.values()), "required evidence incomplete"
        commit = record["sourceCommit"]
        subprocess.run(["git", "rev-parse", "--verify", commit + "^{commit}"], cwd=ROOT, check=True, capture_output=True)
        if task["kind"] == "phase-verification":
            assert record.get("gateRecord") and record.get("advancementApproval") and record.get("remoteCommit") == commit, "phase gate needs reviewed gate record, explicit advancement approval and verified pushed commit"
            gate_path = (ROOT / record['gateRecord']).resolve()
            assert gate_path.is_relative_to(ROOT), "gate evidence must be in the repository"
            gate = read(gate_path)
            assert gate['phaseId'] == task['phase'] and gate['sourceCommit'] == commit, "wrong phase/candidate gate record"
            expected = set(task['phaseCriteria'])
            actual = {a['criterionId']: a for a in gate['acceptanceResults']}
            assert set(actual) == expected and all(a['status'] == 'passed' and a.get('evidence') for a in actual.values()), "phase criteria evidence incomplete"
            assert len(gate['acceptanceResults']) == len(expected), 'duplicate phase criterion evidence'
            codex_review(gate, 'advancementApproval', 'approved')
        if task['kind'] == 'final-acceptance':
            assert record.get('finalAcceptanceRecord') and record.get('remoteCommit') == commit, 'final acceptance needs a reviewed final record and pushed commit'
            final_path = (ROOT / record['finalAcceptanceRecord']).resolve()
            assert final_path.is_relative_to(ROOT), 'final evidence must be in the repository'
            final_evidence(read(final_path), tasks, commit)
        if task['kind'] in ('phase-verification', 'final-acceptance'):
            remote = subprocess.check_output(['git', 'ls-remote', '--heads', 'origin', data['branch']], cwd=ROOT, text=True).split()
            assert remote and remote[0] == commit, "phase candidate is not the current pushed feature-branch commit"
        task["evidence"].append(args.record)
        task["commits"].append(commit)
    task["status"] = args.status
    task["blocker"] = args.note if args.status == "blocked" else None
    event = {"at": now(), "actor": args.actor, "from": old, "to": args.status, "note": args.note}
    task["history"].append(event)
    data["history"].append({**event, "taskId": task["id"]})
    validate(data)
    save(STATE, data)
    render(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "check", "render"):
        sub.add_parser(name)
    edit = sub.add_parser("update")
    edit.add_argument("task")
    edit.add_argument("status", choices=STATES)
    edit.add_argument("--note", required=True)
    edit.add_argument("--actor", default="Codex")
    edit.add_argument("--record")
    args = parser.parse_args()
    if args.command == "init":
        initialize()
    if args.command == "update":
        update(args)
    else:
        data = read(STATE)
        tasks = validate(data)
        if args.command in ("init", "render"):
            render(data)
        print(json.dumps({"ok": True, "phases": len(data['epics']), "tasks": len(tasks),
                          "statuses": {s: sum(t['status'] == s for t in tasks.values()) for s in STATES}}, indent=2))


if __name__ == "__main__":
    main()
