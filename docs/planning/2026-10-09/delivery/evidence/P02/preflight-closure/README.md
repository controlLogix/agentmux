# P02 preflight closure proposal

Root may use this bounded proposal to close the planning preflight after reviewing its ownership and safety boundaries. It is not preflight approval or implementation evidence. The prior three audits remain unchanged.

The accepted P01 gate record was pushed as 2740e31. It binds the corrected d3f8d9d candidate, including the L04 response schema and 52-test SDK qualification, and the S03 27-case capacity/reserve fixture. Those two former predecessor omissions are resolved; actual status production and production capacity policy remain P02/P04 work. All 25 legacy deployment audit source files still match the record commit and prior audited bytes. source-refresh.json records 151 prior-audit binding rows, including changed planning context and the root's uncommitted tracker edits.

## Planned ownership before implementation

| Proposed component | Planned path family | Primary task | Additional gain-check owners |
| --- | --- | --- | --- |
| PLAT-01 | platform/launcher, platform/cmd/agentmux-platform, platform/go.mod/go.sum | P02-T01 | T04 diagnostics/status; T07 bootstrap/lock/context |
| KERN-01 | platform/kernel/assembly, boot, manifests; platform/cmd/agentmux-kernel | P02-T02 | T01 release/member/entrypoint checks |
| KERN-02 | platform/kernel/lifecycle | P02-T02 | T04 bounded recovery |
| KERN-03 | platform/kernel/communication | P02-T03 | T02 wiring; T05 account/config fixtures |
| KERN-04 | platform/kernel/status | P02-T04 | T02 wiring; T03 exported permissions |
| PLAT-02 | platform/runtime | P02-T02 | T01 launcher; T04 exact process supervision |
| PLAT-03 | deploy/compose | P02-T05 | T03 account bounds; T07 resource identity/readiness |
| PLAT-04 | platform/tools/source-surface; tests/platform/go-surface | P02-T01 | T06 ownership review and additive Go coverage |

proposal.json defines 13 new planned behavior checks, each with exactly one P02 task owner. These paths are proposed, not files claimed to exist. Root records the approved mapping before source implementation; actual files enter inventory and surface records when created. Preserve all current metadata/history. Do not insert fictional files to satisfy the current validator.

The source-surface guard currently omits .go. Its new P02 extension must check real missing, stale and duplicate Go records, preserve existing Python/JS/TS/.mjs assertions and distinguish *_test.go fixture ownership from non-test declarations. P01 did not have a Go runtime to qualify; do not relabel this new language proof as historical P01 coverage.

## Existing boundaries remain owned

HAR-01 and HUB-04 remain P06; HAR-05 P12; HUB-02 P05; HUB-08/HUB-10/HUB-23 P10. REPO-03/HUB-26 retain their P01 checks, and HUB-15 its P02 policy/provision checks. This proposal moves none of their qualification phases. Retain the old CLI, Windows callback argument/environment boundaries, installer, local Python hub, SQLite/token/PID/tmux homes, outboxes and work reservations. Preserve explicit kind/Helm/circle administration; never invoke its ambient-context mutation path from automatic Compose startup.

HUB-15's dedicated twice-provisioned policy and dependency/TLS/credential/revocation/interruption baseline remains incomplete. Collect it before changing legacy connection/provision behavior. New separate profile checks execute under T05 and the gate. It is not a requirement that every future candidate test pass before a safe isolated new source path can start.

## Accepted foundation and recovery

The fixed four roles are boot, kernel-lifecycle, internal-communication and exported-status. Use the thin Go foundation without rewriting Python/TypeScript domains or creating a Go-only plugin ABI. All post-bootstrap inter-plugin communication uses NATS. Bounded configuration, selected Compose invocation and exact-owned OS process supervision are infrastructure, not a second application bus. Release membership, authority/digests, contained entrypoints and real system/protected/application account permissions are separate checks.

The new path stays opt-in with distinct owned profile, resources and persistence. Actual cold/warm/concurrent starts, killed-owner locks, context/identity/ports/version/partial readiness and durable restart tests remain mandatory under P02-T01/T02/T03/T04/T05/T07 and FAIL-55–59. Later services are unavailable until built; fixtures cannot report them healthy. Hosted Jev, an LLM or hosted sign-in cannot be boot prerequisites.

Rollback disables only the new entrypoint, stops only exact-owned new children/resources and retains old data/configuration and new volumes/profile identity. No prune, down-v, force-recreate, silent upgrade/context change or SQLite import. Original and candidate writers never share one live task/store.

## Docker and governance limits

The earlier native Desktop WSL integration failure is preserved. Root observed Windows docker.exe from WSL reaching the same local Linux engine and Compose; the receipts worker is checking isolated real Compose/NATS connectivity. This proposal does not approve a production backend amendment. T07 must qualify explicit backend/context/daemon selection, literal path/argument handling, deadlines and owned readiness before mutations. Failed GUI tools do not authorize a bypass or settings changes.

The current pattern checker reports a stale sourceDigest. Root must review the complete candidate and resolve its normal attestation. This proposal changes no registry or attestation and invents no pattern. PLAN-03/05/07/08/14 supply the relevant recorded relationships; actual applied locations and diagrams are recorded during implementation.

No runtime tests, Docker mutations, models/providers, browser sessions, credentials or live business records were used by this closure draft. Root alone reviews and accepts the preflight and updates its tracker.
