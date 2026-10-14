# P02 acceptance coverage audit

Read-only audit, October 14, 2026. Component checks do not replace installed-candidate acceptance. No engine calls or duplicate tests were performed for this audit.

| Criterion | Existing coverage | Remaining acceptance |
| --- | --- | --- |
| T01-AC05: authenticated L04 | Actual TLS/NATS bridge correlation, freshness, forgery and enrollment tests; owner-bridge-tls evidence. Some session frames are explicitly synthetic. | Actual installed ensure/status against enrolled Compose; complete unchanged L04 output. |
| T01-AC06: concurrency and frontend exit | Actual process/lease controls; Linux and Darwin installed-host frontend-exit fixture tests. | Actual concurrent installed CLI launches converge on one owner and assembly. Real frontend exits while real host, NATS and roles survive. Reused clients cannot stop another owner. |
| T01-AC07: failure and recovery | Safe command exit codes, killed lock-owner recovery, independently closed concrete cleanup ownership tests. | Bounded recovery from abrupt actual installed host/startup-owner crash. Current Compose recovery cancels its lifetime normally. |
| T01-AC08; gate AC01/AC06: platforms | native_go.py and platform-foundation.yml cover ten foundation packages on Ubuntu/macOS and separate native Darwin installation fixtures. | Exact-candidate installed boot on native Linux, native macOS and approved WSL. Crossbuilds and declared CI jobs are not executed-environment proof. |
| T03-AC05: optional HOST isolation | Factory admission and real HOST publish denials; ordinary-account isolation tests. | Actual HOST publish/subscribe denial matrix: exact kernel contract subjects, SYS/JS/health, existing business routes, other hubs and inverted HOST roles; cross-account credential rejection. Newly assigned test-only matrix work is separate from this original audit. |
| T03-AC06: authenticate server before credentials | Pinned TLS, malicious peers, actor reconnect, private enrollment and owned Docker inspection component checks. | All actual installed credential-bearing paths on final candidate; no fake broker credential disclosure, downgrade, alternate endpoint or system-root fallback. |
| T07; gate AC06: cold/warm persistence | TestBootstrapRealComposeConcurrentColdWarmAndOwnerRecovery has actual cold/concurrent/warm/persistence assertions. | Complete passing final TLS Compose run. Inspected retained attempts failed; warm timing repair is active. |
| Gate AC07: conflicts and crash convergence | Driver/configuration/lease/process denial controls. | Actual installed/Compose occupied ports, wrong context, incompatible/partial stack and crashed startup owner; unrelated containers/volumes remain intact. |
| L02: ten-second starting | Read-only narrow bootstrap receipt and early-NATS proposals. | Implement and qualify actual pending receipt, ten-second bound, cancellation/reaping/frontend survival and subsequent refresh. Current CLI waits budget+10 seconds and rejects starting as success; bridge serves after bootstrap. Broker-absent later refresh remains unresolved. |
| Gate AC05/AC09/AC10: preservation and advancement | Historical component/preservation evidence and independent source reviews. | Required baseline/candidate comparisons, final supported-environment runs including native ACL/mount controls, findings closed, reviewed phase commit pushed to feature branch and remote SHA verified. No merge. |

The real Compose fixture is Linux-tagged and hardcodes WindowsInterop Docker Desktop selection. It cannot prove native Linux or macOS Compose acceptance without supported-environment fixtures.

The native collector/workflow do not select agentmux_bootstrap_docker tests. Their explicit source comments exclude complete Compose boot and whole-phase acceptance.

Original HOST matrix audit found a negative subject ending .internal.boot.command; communication.Subjects actually places it under .kernel.internal.boot.command. Ordinary-account tests do not establish optional HOST permissions. Business transport examples should come from existing hub/names.py and PROTOCOL.md, not an invented new SDK route.

Inspection inputs: delivery/tasks.json; startup-contract.md L02/L04; tests/platform/native_go.py; .github/workflows/platform-foundation.yml; platform/launcher/bootstrap_integration_test.go and bootstrap_docker_integration_test.go; launcher/owner_bridge_test.go; runtime/installed_host_linux_test.go and installed_host_darwin_install_test.go; cmd/agentmux-runtime/main.go/test.go; component evidence under delivery/evidence/P02.