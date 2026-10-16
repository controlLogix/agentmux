# Local testing

Use [Jira project AMUX](https://adag-csai.atlassian.net/jira/software/c/projects/AMUX) as the sole authority for development tasks, acceptance criteria, status, blockers and review outcomes. Do not maintain a local task ledger, generated status board, source-hash evidence gate or autonomous phase-advancement workflow. Migrate and reconcile all existing tasks and acceptance criteria before removing the local tracker.

The current beta targets native macOS ARM64 only. Linux, macOS AMD64 and Windows/WSL work does not qualify that target. Run builds and tests locally. Do not run CI builds or verification; the existing CI prohibition remains in effect. This workflow does not authorize a merge or release.

## Focused iteration

1. Work on the assigned Jira issue and identify the behavior it changes.
2. Run the smallest relevant test, inspect failures and rerun it after the fix. Add an ordinary regression test when the issue needs one.
3. Run relevant integration tests for changed boundaries. Use race detection for concurrency changes. Do not replace required live behavior checks with mocks or weaken correctness deadlines.
4. Review the diff and affected callers. Report the tests run, results, remaining limitations and review findings in the Jira issue. Do not claim unrun checks passed.

Reuse existing prepared dependencies and test tools. Do not download tools, create new fixture frameworks, rerun unrelated suites or rebuild presentations as routine bookkeeping. Missing prerequisites are blockers, not passing results.

## Existing test commands

From the repository root, using the prepared Python environment:

```sh
python -m hub.tests.run_local --list
python -m hub.tests.run_local hub.tests.test_governance.WorkProtocol
python -m hub.tests.run_local --failed
python -m hub.tests.run_local --profile offline
python -m hub.tests.run_local --profile live
```

The `test_governance` module tests product work-protocol behavior; it is not the development tracker. Select only the commands relevant to the issue. A hub test profile does not cover dashboard or platform changes.

For platform changes, select an existing test from `platform/`, for example:

```sh
go test ./launcher -run '^TestName$' -count=1
```

Use the prepared native Go toolchain. For dashboard changes, use the relevant existing tests; use `dashboard/run_tests.sh` only when that broader suite is needed, preserving its shared-resource locks.

## Safe integration work

Serialize tests that share a Docker engine or other mutable fixture. Do not compete with timing-sensitive integration tests. Use disposable, explicitly owned resources; do not reuse production services, prune the engine, change account configuration or delete unrelated data to obtain a pass.

Keep ownership of any child process through its original wait and output-reader completion. Do not start duplicate jobs or abandon a live owner. Bound output, protect private logs and do not publish credentials, private engine projections or arbitrary error text. Keep failed or uncertain resources when cleanup ownership is unresolved; report their status and required next action.

Product authentication, authorization, security, data-retention, task-management and recovery requirements remain unchanged. Removing development verification scaffolding does not authorize removing product tests or bypassing product safeguards.

When debugging startup failures, use the existing closed diagnostic categories to distinguish engine selection, network inspection, broker creation, host startup and cleanup. Keep private engine details and raw errors out of shared output. A later successful diagnostic does not prove the cause of an earlier failure whose output was lost.

Retained fixtures require current ownership and lock checks before reuse or cleanup. Recheck the exact resource at each mutation boundary. Historical results do not qualify a changed executable.
