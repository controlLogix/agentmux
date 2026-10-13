# P02 deployment and bootstrap preflight

This is a read-only P02-T06 audit. It identifies the retained deployment paths and the proposed isolated Compose addition. It does not start implementation or accept P02. Exact source hashes, observations and limits are in audit.json.

## Current environment

Windows Docker Desktop responds: Desktop 4.92.0, Engine 29.8.0 and Compose 5.5.1, using the local desktop-linux named-pipe context. Ubuntu-26.04 currently resolves a Docker Desktop stub that reports WSL integration unavailable. No setting, daemon, service, container, image or volume was changed. Windows engine success does not qualify the WSL runtime. Missing WSL integration blocks real WSL Compose tests; it does not prevent safe isolated source work after preflight acceptance. Pin and qualify the selected Compose version deliberately: the approved decision lists 5.6.0 as a candidate, not a mandatory verified installation.

## Preserved entry points and callers

| Current surface | Callers and behavior to preserve | P02 decision |
| --- | --- | --- |
| agentmux.sh, agentmux.cmd, agentmux_windows.py, install.sh | Harness commands, Python CLI delegation, interpreter selection, Windows callback validation, WSL environment/path selection, Bash/macOS portability and managed installer entries | Retain. Add an explicit opt-in platform launcher; do not change ordinary legacy commands or Windows client profiles. |
| hub/cli.py start and hub/server.py | Existing hub ping/start/status/stop and local socket/TCP identity; server optionally constructs Core NATS bridge and federation | Keep the existing runtime available. New and old writers use separate disposable homes/accounts, never one live task. |
| deploy/nats/up.sh plus values/kind/nodeport files | Existing explicit kind/Helm cluster, TLS secret, operator circle, PVCs and stream provisioning; --no-kind uses ambient kubectl context | Retain this administration path; do not invoke it from automatic local startup. Add deploy/compose independently. |
| deploy/nats/circle.sh and hub/fed/admin.py | Explicit circle administration, generated signing state, account push and stream/KV provisioning; called by deployment, demo and fedharness | Preserve original credentials, subjects and provisioning semantics. Never silently apply new retention to old resources. |
| hub/fed/conn.py and runtime.py | Lazy dependencies, credential references, CA/endpoint checks, five-second initial connection and explicit runtime reconnect; bounded push requests | Retain/wrap supported contracts. Add versioned independent account/domain profiles without migrating business authority in P02. |
| hub/tests/fedharness.py, test_fed_live.py, test_windows_callbacks.py and tests/platform | Existing isolated broker/hub fixtures, direct callback argument/auth boundary, honest Windows-client placement inventory | Reuse source-equivalent baseline evidence and preserve assertions. Extend with separate real Compose and kernel permission fixtures. |
| orchestration hook scripts and dashboard/server.py | Guarded tool callbacks and configured AGENTMUX_HOME, existing operational controls | Preserve. Actual installed startup hooks and dashboard status agreement remain P06/P07, not a P02 acceptance shortcut. |

Twenty-five relevant source files match the accepted P01 candidate and current gate-record commit byte for byte. Eighteen of the original 24 are additionally pinned in the reviewed native P01 CI report. This proves source equivalence for retained behavior, not new Compose tests or complete HUB-15 qualification.

The current storage layout uses AM_MSG age 14 days, AM_WORK workqueue age 30 days, AM_SHARE age 365 days, discard-old, board history 16 and presence TTL 90 seconds. Existing provision updates streams but does not reconcile existing KV policies. The approved owner-ledger design has a different authority/retention boundary. Keep it separate; P04 owns migration. Preserve existing old resource names, IDs, outstanding deliveries and rollback paths.

## Required candidate checks

| Check | Required execution and evidence |
| --- | --- |
| HUB-15-C01 | Real isolated provision twice, exact subjects/retention/replicas/duplicate windows/KV history/TTL, then compare the independently versioned target profile. Never use customer stores. |
| HUB-15-C02 | Absent dependency, wrong CA/endpoint, missing credential, revoked account and interrupted provisioning with bounded diagnostic and safe cleanup. |
| FAIL-55 | Real cold and warm launches from different directories; same authenticated instance/project/volume identity and unchanged durable probe, same versioned status schema. |
| FAIL-56 | Concurrent processes/WSL sessions, kill startup owner at controlled boundaries, recover process-held advisory lock; reject PID reuse and unrelated resources, no duplicate stack. |
| FAIL-57 | Missing Docker/Compose, daemon/permission/pull failures; deadlines and exact diagnostic, no installation, secret output or retry storm; later recovery preserves data. |
| FAIL-58 | Explicit wrong/remote/changed context, owner/release mismatch and occupied endpoint; refuse attachment or shadow startup before any mutation. |
| FAIL-59 | Partial services/readiness timeout and restart after durable data; preserve owned instance/volume/data and report actual service health. Container running alone cannot pass. |

Also prove protected-account permissions against a real broker: external clients may receive authorized exports but cannot write to kernel subjects. Kill a protected plugin and broker, verify bounded recovery and late-subscriber snapshot/update consistency. Do not label unavailable future services or hub inventory healthy. macOS/Linux/WSL boot remains required, without an LLM or hosted Jev. Single-node persistence and graceful restarts do not prove R3, power-loss or production enrollment.

## Bounded implementation slices after preflight

1. P02-T01/T02/T03: fixed protected assembly and NATS account/subject permissions, exported readiness/status contract and unauthorized-client tests. Do not replace Python domain code.
2. P02-T05: digest-pinned Compose/NATS configurations, R1 persistent paths/limits/domain and declared team connection profile. No live storage conversion or automatic kind/Helm upgrade.
3. P02-T04/T07: enrolled context-bound profile, OS-held startup lock, bounded doctor/start/reuse/readiness and controlled owned recovery. Integrate after the assembly/config/status contracts are agreed. Use private real Compose fixtures for phase acceptance.

The simpler alternative is to extend the old hub start command or invoke up.sh automatically. Both lack the approved context/resource identity, protected assembly and reliable application readiness. Keep them available while adding the narrow new path. Extra Go processes and Compose coordination cost startup time, packaging and test effort; measure before optimizing. Rollback disables the opt-in new entry point and preserves its data and the old launcher, with no business cutover in P02.

## Privacy and outstanding limits

No credentials, signing keys, Docker auth configuration, container environments or live task data were read. No model/browser/provider session was launched. Native Docker tests and all FAIL-55–59 executions remain unrun. Current WSL integration is unavailable. The required pattern checker reports a stale review digest; the root reviewer must resolve that gate after examining the complete candidate. This preflight does not refresh an attestation or make a passing claim.
