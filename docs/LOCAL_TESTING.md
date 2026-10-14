# Faster local testing during implementation

Use a small test selection while editing. Run the wider affected suites once the fix works, then collect the required phase evidence on a stable candidate. Do not regenerate presentations, re-run unrelated suites or reinstall dependencies during each debug cycle.

## Commands

From PowerShell at the repository root:

```powershell
# Default: fast unit and governance regressions, stopping at the first failure.
./hub/tests/local.ps1

# One class or one method while fixing a specific behavior.
./hub/tests/local.ps1 hub.tests.test_governance.WorkProtocol
./hub/tests/local.ps1 hub.tests.test_governance.WorkProtocol.test_origin_reservation_and_grant_rollback_together

# Repeat the last failing selection after a fix.
./hub/tests/local.ps1 --failed

# Broader checks after relevant changes; full collects all hub failures.
./hub/tests/local.ps1 --profile offline
./hub/tests/local.ps1 --profile live
./hub/tests/local.ps1 --profile full
```

On macOS/Linux or inside WSL, use the same arguments with `python -m hub.tests.run_local`, using the prepared virtual environment. `--list` prints the selection without starting fixtures; `--keep-going` disables fail-fast for a focused run.

| Selection | When to use it | Coverage |
| --- | --- | --- |
| One method/class | Each edit while fixing a known problem | Explicitly selected behavior |
| `fast` (default) | Quick confidence after related edits | Runner checks, governance regressions and federation unit tests |
| `offline` | Store, local API, leases, migration or local transport changes | Fast selection plus the full existing hub offline suite, including real local processes |
| `live` | Broker, subjects, identity, delivery, reconnection or work protocol changes | Existing Core NATS and JWT federation suites using disposable brokers and hubs |
| `full` | Stable hub candidate before its verification handoff | Every existing hub suite plus runner checks; all tests run even after failures |

These profiles select tests; they do not weaken assertions, shorten correctness timeouts or replace live checks with mocks. A full hub run is only one part of a phase gate. Dashboard, harness, platform and autonomous final hub acceptance requirements remain separate. Codex reviews delivery evidence; Ryan and Nick are not required for phase advancement. Use existing targeted dashboard tests for dashboard edits, and `dashboard/run_tests.sh` when that component's full environment is needed. Preserve its lock and isolated server behavior; do not parallelize its shared tmux fixtures.

## Environment and evidence

The PowerShell launcher uses the default WSL distribution. It chooses the repository `.venv`, then the persistent environment already prepared at `~/.cache/agentmux-governance/venv`, then `python3`. It also adds the existing cache's NATS tools to PATH. Set `AGENTMUX_TEST_PYTHON` inside WSL to select another interpreter. There is no implicit installation, upgrade, Docker restart or production service reuse. Maintain dependencies with `hub/requirements.lock`; prepare missing broker tools once, not on each run.

Keep the virtual environment and downloaded tools in the Linux home directory. Test stores and broker state remain disposable. The local runner refuses the cluster-reset mode `AGENTMUX_FED_KIND=1`; use the separate qualified procedure for a disposable cluster.

Each run writes a log and JSON result under `~/.cache/agentmux-tests/<checkout-id>/<run-id>/` (or `XDG_CACHE_HOME`). Reports include selection, Python version, source hashes, failures, skips, total duration and the ten slowest tests. The total includes loading and fixture setup; individual timings include each test's setup/teardown but not shared class setup. Missing dependencies that cause skips, expected failures or an empty selection return a nonzero status. Logs stay local until deliberately reviewed and attached as evidence.

`--failed` uses the last unsuccessful selection. A successful unrelated run does not erase it. After that selection passes, it is cleared. This shortcut never substitutes for the wider affected suite. Use one runner at a time per checkout when relying on this shared failure list; concurrent runs have separate evidence folders but the last failure-list writer wins.

## Agent workflow

1. Reproduce the problem with the smallest meaningful existing test, or add a regression at the affected boundary.
2. Edit, run that test with fail-fast, and use `--failed` during repair. Read the failure before broadening the run.
3. Once fixed, run the relevant profile. A broker change needs live tests; a store change needs offline tests. Run independent checks together only when their fixtures do not share mutable state.
4. At the verification handoff, run the required wider suites once on unchanged source, update component and pattern evidence, then run the governance gate. Expand or repeat only for new changes, failures or unresolved concerns.
5. Update the plan and presentation when behavior or scope changes, not for each internal edit. Keep all phase acceptance and MERGE-01 requirements intact.

## Platform and Docker debug cycles

Use three stages for platform changes. Keep the existing startup, frontend and cleanup deadlines; faster iteration comes from selecting less work, not relaxing the product contract.

1. **Diagnose the failing boundary.** Record the operation, safe error code, elapsed time and whether its context expired. If network baseline inspection fails, exercise that read against the admitted engine directly. Do not start a broker or host merely to diagnose a listing or decoding error. Reuse captured private output for parser regressions when useful, keeping private engine details outside the repository. Captured output does not replace a later real-engine check.
2. **Repair and check the affected behavior.** Use an anchored Go test selection from `platform/`, for example `go test ./launcher -run '^TestName$' -count=1`. Use the prepared Go runtime and module cache. Run the affected race checks when the fix is stable, or earlier for a concurrency defect. Start one real Docker test only after the relevant local controls pass.
3. **Verify the stable candidate.** Freeze the source and run the required actual lifecycle cohort, SDK validation, affected suites and supported-environment checks. Collect their results once. Repeat only the checks invalidated by a subsequent change, and record why unaffected evidence remains applicable. A failed phase check still blocks advancement.

Serialize all tests that share a Docker engine. Parallelize pure controls, source review and independent SDK checks only when they do not compete with timing-sensitive runs. Reuse downloaded tools, compiled dependency caches and approved cached images. Preserve fixture data and release only resources whose exact ownership and cleanup have been verified; do not prune the engine to make tests faster.

Each failure should produce enough safe detail to choose the next action without another complete startup run. Distinguish engine selection, network listing, network inspection, decoding, broker creation, host startup and cleanup. Do not publish credentials, private network projections or arbitrary Docker error text.

For CLI tests, preserve both stdout and stderr privately after the sole process wait and output-copy operations have joined, before checking the exit code, elapsed time or response schema. Bound each capture, use private file permissions, and publish only hashes, byte counts and closed diagnostic fields. An unjoined process does not permit reading its output buffers. If an earlier run lost output, record that limit; a successful later diagnostic cannot establish the earlier failure's cause.

When a fixture is retained after failure, first qualify its exact ownership and cleanup requirements. Prefer a read-only check against that same enrolled fixture when it can isolate the failing boundary. Reuse does not replace the final cold-start check, and an old installed executable does not qualify a changed candidate.

For recovery sequences, recheck admission and the identity of actually held locks at each mutation boundary. Earlier acquisition alone does not prove that a lock descriptor still identifies the file used by the current profile. Repeat the exact resource check next to the action, using the original bounded context; a later network removal needs its own checks even when the earlier broker stop passed.

Hash source snapshots and verify artifact manifests in a batch inside the environment that owns the files. Return one structured result for the parent to compare; do not launch WSL or another subprocess once per file. Keep the frozen snapshot and before/copy/after checks intact. This reduces process-launch overhead without reducing the source or artifact checks.

Review evidence in batches at the stable-candidate handoff. Keep raw logs and source pins during debugging, but avoid regenerating the presentation or creating a new full-source evidence copy for every edit. Retain failed runs and bind final claims to the exact tested source. Maintain one tracker writer and update it at meaningful state changes.

## Iteration schedule and parallel work

Use one active phase and three independent work lanes: implementation with focused controls, source and evidence review, and preparation of the next required test within that phase. Keep one owner for shared source promotion and task tracking. Reviewers can inspect a frozen source slice while another worker prepares a separate slice. Do not make every internal edit wait for a full review or a new evidence package; resolve review findings before promotion and acceptance. A new privileged observer or execution boundary still needs its required source review before live execution.

For each failure, choose one of three next actions: repair source, repair the disposable fixture, or resolve an environment admission failure. Record the exact failing assertion and the smallest rerun that can prove the repair. Compilation failures return directly to compilation. Parser failures use captured-input controls. A refused engine identity returns to admission checks. None of these requires a complete stack startup to diagnose.

Use this order for each stable source slice:

Inspect the package's test entry point and initialization before creating a separate test runner. If an anchored selection runs without starting shared services, use the actual package tests. For example, the launcher `TestMain` runs the selected tests directly when `AMX_DOCKER_FIXTURE` is not `1`; its synthetic Docker handler is a separate, explicit mode. Clear inherited fixture overrides and keep actual Docker authorization disabled for pure checks. This avoids copying functions or compiling twice just to bypass an entry point that does no setup. Use compile-only checks when execution is not yet approved or the selected package cannot run without unwanted work.

1. Compile and run the smallest meaningful regression. Use a normal focused run for a non-concurrency edit; use race detection immediately for a concurrency defect.
2. Run the affected regression group, with race detection and static checks where required. Batch independent pure checks in the same prepared environment.
3. Run the required real integration selection against a frozen candidate. Give a timing-sensitive test exclusive use of its shared Docker engine and avoid competing builds or bulk reads during its timing window.
4. Have the reviewer check source pins, named test results, failures, skips, timing and cleanup in one evidence batch. Run the broader phase matrix when the candidate is stable.

Before pushing a stable checkpoint, run the inexpensive delivery and retention checks: `python docs/planning/2026-10-09/delivery/track.py check` and `python docs/planning/2026-10-09/delivery/check_regressions.py --self-test`. When an accepted regression changes, record its exact reviewed replacement in `regression-baseline.json`; keep the accepted inventory and negative controls. Run the pattern gate after the final source and evidence changes. These checks prevent avoidable CI failures, but do not replace affected integration suites or phase acceptance. A shared platform constant correction should also inspect every use before the candidate is frozen.

Prepare scripts, read source and plan unrelated fixture work while an integration test waits for readiness. Keep new compiler work outside its timing window. Do not repeatedly poll an unchanged run; retain its original process handle and collect its terminal result. Check a specific unresolved stage when progress or the original deadline requires it.

Record total wall time separately from compile, fixture setup, assertion, cleanup and evidence review time when those measurements are available. Optimize the largest measured stage first. Set a target for quick feedback, not a shorter correctness deadline; report a slow stage rather than changing the product contract to make it pass. The current actual WSL pending test took 104.73 seconds overall while its frontend responded in 6.569 seconds. Those measure different responsibilities, so the frontend number cannot justify skipping lifecycle or cleanup checks.

After a source change, identify which assertions and executable dependencies changed. Rerun those checks and explain why retained evidence still applies to unchanged behavior. A changed binary requires fresh execution evidence for claims about that binary. Historical results remain useful for diagnosis but never become an exact-candidate phase pass through a hash refresh.

Measured on this WSL environment: the final fast profile passed 44 tests in 5.37 seconds; a focused reservation regression passed in 0.50 seconds. The full hub profile passed 124 tests in 63.96 seconds before the final retry-metadata correction; focused checks then covered that correction. These smaller selections do not provide identical coverage. Cold WSL startup and tool-call overhead are outside these timings. See [the measurement record](planning/2026-10-09/local-test-runner-evidence.json) for exact selections and source hashes.

For WSL checks that repeatedly load schemas or modules, run from a byte-verified snapshot in the Linux cache rather than directly from `/mnt/c`. Copy the affected source and contract resources once, verify before/copy/after hashes, and use the prepared toolchains. Keep the original assertions and timeouts. The current two-SDK HOST shape selection exceeded its 60-second runner limit from the Windows mount, then passed in 1.15 seconds from a 55-file Linux-local snapshot. The first run lost raw output, so its exact cause is unproven; this comparison does not establish a general speed guarantee. See `delivery/evidence/P02/checkpoint-host-contract-controls/root-review.json` under the planning directory.
