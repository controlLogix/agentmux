# P00 decisions for review

Current delivery target: [PLATFORM-SCOPE-03](PLATFORM-SCOPE-03-macos-arm64-beta.md) sets a macOS ARM64-only initial beta. Other platform qualification is deferred, not passed. [DELIVERY-LOCAL-01](DELIVERY-LOCAL-01-local-verification.md) still prohibits CI builds and verification until all phase gates are complete. The original P00 recommendations and review history below remain preserved.

These are concrete engineering recommendations prepared on October 9, 2026. Ryan's existing requirements remain binding. Proposed implementation choices below are awaiting Codex P00 review; no phase advancement is recorded. Ryan and Nick are not required for delivery review.

| Record | Scope | Task |
| --- | --- | --- |
| [Runtime and deployment](runtime-and-deployment.md) | Language comparison, protected assembly, SDKs, identity, execution, UI, capacity and data policy | P00-T02 |
| [Storage contract](storage-contract.md) | NATS authority, records, retention, access, recovery and qualification profiles | P00-T05 |
| [Automatic startup](startup-contract.md) | Instance ownership, Compose, host hooks, readiness, status and time limits | P00-T07 |

P00-T04 now has draft versioned manifest/context schemas, state machines, migration ownership and a requirement-to-phase matrix in [the contract package](../contracts/README.md) and [coverage record](../requirements-coverage.json). Seventy draft fixtures pass; final Codex contract approval remains pending. These decision documents constrain that review. P00-T01 still needs Codex review of the public entry points and behavioral inventory. The tracker keeps all of these tasks and the P00 gate open until the required work and review are complete.

The bounded [runtime comparison](../spikes/runtime/README.md) is executed evidence. Design proposals, performance targets and platform targets are not test results. No Jev token, provider inference, industrial device action, live user hub or Docker setting was used or changed by this preparation.

## Accepted design revision

Codex accepted the engineering decisions after the final review of `b067e98e8a051c33d7df2e7facfe26d9f747239a`. [Acceptance and remaining implementation proof](acceptance.md) supersedes the pending-review status above. Historical recommendations remain intact. P00 phase advancement still requires its separate gate.
