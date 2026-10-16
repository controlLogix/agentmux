# PLATFORM-SCOPE-02: Native Linux/macOS delivery

Approved by Ryan Helms on October 14, 2026.

## Current scope

Implement and qualify native Linux and macOS only, on AMD64 and ARM64. Windows and WSL are not supported delivery targets and do not block implementation task or phase acceptance.

This supersedes Windows/WSL qualification in WSL-CLIENT-01 and the earlier platform matrix. It does not remove existing Windows code, tests, data, or historical evidence. Keep that history intact and label it as outside current platform qualification. WSL execution is not evidence of native Linux qualification.

The current structured decision is `platformScopeDecision` in `phases.json`. Every delivery task references this decision, and `deliveryGovernance.platformScope` in `tasks.json` defines the same matrix. Changed requirements retain their previous values in append-only history. Original catalog proposals, task and criterion IDs, dependencies, statuses, evidence and commit references are preserved. Windows-only behavior checks HAR-05-C02 and HAR-05-C03 retain their assertions but require preservation review rather than Windows execution; this is a scoped retirement, not a passing runtime result.

## Requirements that do not change

- Security and credential boundaries, protected-process identity, permission isolation and honest status reporting.
- Startup, concurrency, crash recovery, bounded cleanup and persistence checks on the supported native platforms.
- Existing Linux/macOS behavior, migration, rollback, user configuration and data preservation.
- Actual-host evidence for supported clients and toolchains; mocks, cross-builds and historical WSL results do not qualify native execution.
- One active phase, independent Codex evidence review, feature-branch commit/push and verified remote candidate before advancement.
- All 15 phase gates and the final two-real-hub bilateral demonstration. No merge or release.

Completed P00/P01 evidence remains recorded under its original broader scope. This decision does not manufacture a new pass, reopen unrelated accepted work, or accept P02. P03 implementation remains blocked by P02-GATE.

Windows-only industrial applications are unsupported in this delivery. Keep explicit capability limits and read/simulation alternatives; do not imply remote Windows execution or equipment authority.
