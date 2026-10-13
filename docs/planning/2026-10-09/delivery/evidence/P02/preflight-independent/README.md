# Independent P02 preflight review

Preflight is not approved. Root has parked P02 and reopened affected P01 work after identifying omitted accepted obligations. Preserve the prior gate record and all passing evidence as history. This review changed no source or tracker files.

`audit.json` contains the exact eight P02 criteria, seven assigned failures, current task decomposition and source hashes. It records reviewed safe deployment observations and the required pattern check failure. This review ran no runtime tests, models or providers and changed no Docker configuration.

## Missing predecessor proof

1. Accepted P00 `acceptance.md:3` accepts L01–L05. `startup-contract.md:50` explicitly promises a P01 status response schema and success/failure fixtures. The current `status-query` is request-only. The closed `operation-outcome` cannot carry L04 observations. This is missing P01 contract qualification, not an obligation that may silently move to P02. Qualify authenticated scope, errors, freshness, unknown versus observed zero, forbidden versus empty inventory, and privacy. P02 still owns actual start/reuse status and readiness.
2. Accepted S03 `storage-contract.md:54` explicitly requires P01/P04 proof of application completion reserve enforcement. `tests/storage/run.py` and its two clients have no capacity admission or completion reserve policy. The 20 cases enumerated by `P01-T07-acceptance.json` prove other storage guarantees, not this reserve. The task decomposition omitted this obligation. Preserve those 20 passes and reopen only the missing qualification. P01 needs a bounded real JetStream fixture with an explicit application admission/reserve policy. P04 needs production enforcement and recovery; a fixture does not prove those services.

The minimum reserve fixture must exercise warning and bulk admission boundaries, concurrent admissions that cannot overspend the budget, denied new bulk work while final results and reconciliation can still commit, explicit failure when the reserve itself is exhausted, retained history, restart and duplicate reconciliation. A meaningful negative control must bypass reserve protection and fail the admission/completion assertion. Small declared byte quotas can qualify semantics; they cannot establish the proposed 10/100 GiB capacity or production performance. A storage work reservation is not a byte completion reserve. Discard-new alone does not reserve room for final results. Cross-stream storage does not become atomic because the application budgets it.

## P02 scope and boundary findings

- All P02 tasks currently map only HUB-15. Register new launcher, protected assembly, status and Compose entry points before implementation. Record exact tests and owners; mapping every task to all eight criteria does not identify responsibility for each behavior.
- Retain exactly four trusted protected roles: boot, kernel-lifecycle, internal-communication and exported-status. Validate release membership and executable digests before launch. SDK manifest validation alone does not enforce real account permissions. Ordinary plugins cannot replace protected members or publish lifecycle, kernel status, command or management traffic.
- Keep system, protected, application and confidential accounts separate. NATS domains locate storage and do not authorize access. Export only bounded permitted kernel information. Test exact and wildcard denials with actual ordinary credentials and broker audit evidence. Raw system credentials or broad runtime/store handles cannot be injected into ordinary services.
- Keep language-neutral JSON/NATS and supervised executables. Retain existing Python/TypeScript domain behavior. Ordinary communication uses NATS after bootstrap. Process supervision before broker readiness is bounded infrastructure, not a second application bus. Full scoped dependency and child lifetimes remain P03, but P02 must preserve these seams.
- Legacy `hub/fed/admin.py` automatically updates existing stream policies; existing KV policy is not reconciled. Its discard-old and age limits differ from the approved owner ledger profile. Do not call it unchanged for automatic warm reuse or change live policies as an implicit migration. Dedicated HUB-15 twice-provisioned policy checks and dependency/CA/endpoint/credential/revocation/interruption negatives remain needed before related changes. Never use the kind cluster-reset fixture against live resources.
- Reviewed deployment evidence shows Windows Docker 29.8.0 and Compose 5.5.1, while selected Ubuntu-26.04 has no usable Docker/Compose. Windows connectivity does not qualify WSL. P00 Compose 5.6.0 was a candidate; select actual version and image digests deliberately. Real Compose and native macOS/Linux qualification remain absent.
- Required pattern check exits 1 because the review is stale. Resolve it through actual changed-source review, not a digest-only refresh.

## Affected callers and preservation ownership

| Current owner | Callers and assertions to retain |
| --- | --- |
| HUB-15 / P02 | `hub/fed/conn.py`, `hub/fed/admin.py`: exact stream/KV policy, idempotent provisioning, bounded failures and recovery. |
| HUB-02 / P05 | `hub/server.py`: existing task/SQLite ownership and domain behavior; do not construct a legacy Hub for a read-only kernel probe because construction creates state. |
| HUB-04 / P06 | `hub/cli.py`, `agentmux_windows.py`: existing startup diagnostics, callback guards, environment selection, arguments, stdin and exit codes. |
| HUB-08, HUB-10, HUB-23 / P10 | `hub/bridge.py`, `hub/fed/runtime.py`, `deploy/nats`: legacy federation subjects, account identity, grants, reconnect behavior and explicit kind/Helm administration. |
| HAR-01 / P06; HAR-05 / P12 | `agentmux.sh`, installer and Windows wrappers: command compatibility, private session cleanup, unrelated settings and commands, Windows-owned clients and explicit selected WSL distribution. |
| Contract and CI owners / P01; future consumers P03/P06/P07/P10 | Independent SDK validation, compatibility and source admission. New status consumers need explicit ownership. Later host hooks, UI and live federation proof stay separate. |

Existing P01 source-equivalent results can support unchanged assertions only. They do not prove new Go process supervision, kernel account enforcement, Compose behavior or the two missing contract obligations. Old and new paths must never own the same live task or write the same fixture records.

## Candidate acceptance evidence expected

| Owner | Required evidence |
| --- | --- |
| P02-T01 | No model/Jev dependency; release-bound fixed membership; startup and process overhead observations. |
| P02-T02 | Bounded lifecycle/shutdown; failed protected member fails closed; surrounding failure leaves boot intact; late subscribers receive consistent snapshot and updates. |
| P02-T03 | Actual scoped credentials and exact/wildcard publish, subscribe, reply and management denial tests. |
| P02-T04 | Bad configuration, occupied ports, broker outage/recovery and protected process failure; bounded actionable diagnostics; required application readiness distinct from kernel readiness and optional unavailability. |
| P02-T05 | Explicit paths, domains, limits and file-backed persistence health; durable restart data; team connection profile without claiming independent-host R3 from local replicas. |
| P02-T07 | Real isolated Compose cold/warm, concurrency, crashed owner, wrong context, other user, incompatible version and partial startup. OS-held lock and authenticated instance/profile/context identity. Same response on start/reuse, retained volumes and data, no warm pull/recreate/upgrade or shadow stack. |
| P02-GATE | All eight criteria and FAIL-01/02/55–59; source-bound Linux/macOS/WSL evidence, affected legacy/candidate integrations, component and pattern checks, independent review, committed/pushed feature candidate and verified remote. |

Use the approved budgets: 5-second daemon calls, 30-second ownership wait, 60-second cached cold start, separately visible 180-second authorized image download, 5-second hard warm probe and 10-second client wait. A background operation must demonstrably retain ownership and survive hook exit; PID or stale file age alone cannot authorize lock takeover. Missing later services must remain unavailable in actual status, never fixture-derived healthy.

## Rollback evidence expected

Disable the new opt-in entry point and retain the old launcher. P02 performs no legacy data conversion. Preserve instance identity, volumes and unrelated configuration. Do not use volume deletion, pruning, forced recreation or implicit upgrades. Use separate disposable legacy/candidate stores. Source rollback and persistent format recovery are different operations; incompatible data or release stops for an explicit supported recovery action.

P06 qualifies real installed client hooks, P07 actual UI status, P10 authorized live hub observations, and P12 production topology, backup and recovery. None of those later ownership assignments cancels the explicit P01 L04 or S03 promise.
