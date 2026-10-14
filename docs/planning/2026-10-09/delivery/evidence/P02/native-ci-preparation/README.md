# P02 native foundation CI preparation

This is a qualification harness awaiting native execution on a stable candidate. It is not a P02 pass or supported-platform acceptance.

The implementation coordinator owns the candidate commit, source registration, push, evidence review and phase gate. This slice changes only `.github/workflows/platform-foundation.yml` and `tests/platform/native_go.py`; it does not change runtime code or the delivery tracker.

## Foundation checks

The workflow runs on native Ubuntu 24.04 and macOS 15. Each run prepares checksum-pinned Go 1.27.2 from the [official release metadata](https://go.dev/dl/?mode=json&include=all). The broker downloader reuses the reviewed NATS 2.15.0 checksums in `tests/contracts/ci.py`. The module must retain the Go 1.27.2 and nats.go 1.54.0 pins. Dependencies use the public Go checksum database and readonly module resolution; automatic toolchain switching is disabled.

The runner copies platform and contract files to an isolated workspace and requires their bytes to match the recorded source hashes. It isolates home, cache and temporary state, without inheriting provider credentials, Go configuration, broker selection or Git configuration. Each package runs with fresh Go JSON output. Empty results, skipped tests, failures, malformed output and missing package completion cannot pass. Evidence contains raw test events, stderr, their hashes, the source commit, source hashes and before/after source checks. Private broker configuration and broker logs are not copied into artifacts.

Assembly, account permission and launcher scopes are separate. Linux runtime checks execute the native subprocess fixtures. The normal macOS runtime scope checks only `TestDarwinProductRemainsFailClosed`; this is a refusal check, not successful runtime boot. The report keeps macOS runtime qualification unqualified even when that check passes.

## Separate Darwin research

The coordinator separately authorized the macOS research job. It runs exact `TestDarwinUnlinkedDescriptorResearch` through `--darwin-research`, using an independent workspace, result and artifact. A separate exact `TestDarwinProductRemainsFailClosed` control binds the report's `productBackendFailClosed` flag to an actual test result; the flag starts unknown before that control runs. Actual failure produces a failed result and job. No skip, cross-build or ordinary foundation success replaces this evidence. The result also declares `researchOnly` and `phaseAccepted: false`. Successful descriptor execution still cannot establish same-UID immutability or product support. The unchanged native probe records its actual observations in the raw Go events.

The current research report names that control `unprotectedImageRefusalObserved`. Earlier records retain their original `productBackendFailClosed` field. The control proves refusal of an unprotected image, not that every protected-install backend is disabled.

## Separate protected-install fixture

The coordinator also authorized `--darwin-install` and its separate macOS 15 job. It refuses non-Darwin hosts, missing `AMX_DARWIN_INSTALL_AUTHORIZED=1`, and root execution before preparation. It observes actual Apple clang and SDK versions, fixes the compiler/SDK selection, enables cgo, and runs the four approved runtime tests with the `agentmux_darwin_install` tag, race detection and a 180-second test timeout. Tagged Go inventory must contain their actual declarations; all four top-level tests must pass. Research and install flags and preparation markers are mutually exclusive.

The fixture owns its bounded `sudo -n` setup under the fixed protected release base. Unique installed versions are retained; the harness performs no privileged setup or recursive cleanup itself. The runtime/adversary execute without elevation. A sudo-capable runner is not described as a qualified non-admin account.

`protectedInstallEvidence` becomes true only after all admitted checks pass on unchanged source. `fourRoleBootQualified`, `composeQualified`, `phaseAccepted` and native runtime qualification remain false or unqualified. This is installed-image, adversary and marker-process evidence—not native NATS, four-role startup, EOF, Compose or a production signed installer pass. Actual execution remains the coordinator's responsibility.

## Local preparation checks

On native Windows, seven embedded evidence-admission and checkout-preservation tests, 23 existing inventory tests and seven source-surface regression tests passed during preparation. Python syntax and workflow YAML checks passed. These are runner/regression checks, not native foundation execution. A Windows invocation refused the unsupported host before downloads or child tests, returned exit code 1 and wrote a failed result. No native CI run, workflow dispatch, implementation commit or push was performed by this worker.

The design-pattern check reports a stale review digest while the shared P02 candidate is changing. The coordinator must review the final candidate and its registrations; the preparation worker does not refresh global evidence to hide concurrent changes.

The separate `runner-refinement.json` preserves the original preparation record while identifying a later runner source revision. Five added synthetic orchestration tests bring the embedded suite to 12. They check report failure behavior, environment isolation, unsupported-host refusal, executed-source drift and the research/control split. Their tool and subprocess observations are mocked; they supply no native platform acceptance.

`package-matrix-expansion.json` records the later coordinator-approved extension to all seven current P02 packages with tests: assembly, communication accounts, deployment, protocol, boot, launcher and runtime. The harness checks the actual Go package inventory and refuses missing, new unreviewed, repeated or incomplete test-bearing packages. Actual OS-selected test-file lists are retained. Packages with no tests are listed but not claimed as test passes. The control suite now contains 14 tests; this is still synthetic runner verification, not a native CI run.

Linux boot includes sealed-process fixtures. Darwin boot currently runs real NATS actors, while runtime checks only fail-closed behavior; neither establishes native macOS protected-process boot. Complete Compose startup, supported-host and phase evidence remain separate requirements.

`collector-hardening.json` records a further source revision. Go workspace discovery is disabled, results are checkpointed, and the shared collection budget leaves unfinished scopes explicitly unexecuted. Fifteen synthetic controls pass, including timeout and budget-exhaustion cases. These controls do not replace actual native execution.

`atomic-preparation-controls.json` identifies the next refinement with 16 passing synthetic controls. Checkpoint publication is atomic, a timed-out process cannot pass by returning zero, and tool preparation is bounded in an owned subprocess using the same shared deadline. No background download thread or shared downloader replacement is used. Earlier source-bound reports remain historical; native execution and final independent review are still separate requirements.

Full Compose, protected-role integration, actual boot, WSL, recovery, security and supported-environment acceptance remain mandatory. This harness does not replace them or authorize phase advancement, a merge or a release.

`interruption-workspace-controls.json` records 19 passing synthetic controls and 30 affected inventory/source-surface regressions. Preparation and tests stop and reap their owned child on interrupted waits. The hidden preparation command refuses unrelated existing files before downloads or writes; only an empty regular research marker is allowed. Final independent closure for this revision is recorded separately from earlier findings and native execution.

`reaped-child-controls.json` records the next revision with 20 passing synthetic controls. Cleanup skips signaling when Python has already reaped the child before reporting an interruption. It retains the focused timeout regression failure and successful repair before the complete control-suite pass. Native platform execution remains separate.
