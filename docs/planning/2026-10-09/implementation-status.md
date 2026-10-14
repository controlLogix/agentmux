# Implementation status

Generated from delivery/tasks.json. Edit status through delivery/track.py; this page is a view, not another source of truth.

Branch: `feat/agentmux-platform-rearchitecture`. No phase or merge approval is implied by a task count.

| Phase | Planned | Ready | In progress | Blocked | Verification | Done | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| P00 | 0 | 0 | 0 | 0 | 0 | 8 | done |
| P01 | 0 | 0 | 0 | 0 | 0 | 9 | done |
| P02 | 1 | 0 | 6 | 0 | 0 | 1 | planned |
| P03 | 8 | 0 | 0 | 0 | 0 | 0 | planned |
| P04 | 8 | 0 | 0 | 0 | 0 | 0 | planned |
| P05 | 10 | 0 | 0 | 0 | 0 | 0 | planned |
| P06 | 10 | 0 | 0 | 0 | 0 | 0 | planned |
| P07 | 9 | 0 | 0 | 0 | 0 | 0 | planned |
| P08 | 9 | 0 | 0 | 0 | 0 | 0 | planned |
| P09 | 43 | 0 | 0 | 0 | 0 | 0 | planned |
| P10 | 19 | 0 | 0 | 0 | 0 | 0 | planned |
| P11 | 20 | 0 | 0 | 0 | 0 | 0 | planned |
| P12 | 11 | 0 | 0 | 0 | 0 | 0 | planned |
| P13 | 79 | 0 | 0 | 0 | 0 | 0 | planned |
| P14 | 7 | 0 | 0 | 0 | 0 | 0 | planned |

## Current work and blockers

- **P02-T01 — in_progress:** Implement a minimal launcher that establishes the configured NATS substrate and loads the fixed protected boot assembly.
- **P02-T02 — in_progress:** Implement boot, protected-plugin lifecycle, protected internal communication, and deliberate publication of kernel status.
- **P02-T03 — in_progress:** Separate protected internal subjects/accounts from exported information and surrounding application services.
- **P02-T04 — in_progress:** Provide readiness snapshots, bounded startup/shutdown, broker recovery, basic installer/doctor skeleton, and local bootstrap diagnostics.
- **P02-T05 — in_progress:** Provision the approved local file-backed JetStream profile and team connection profile with explicit storage paths, limits, health and domain settings
- **P02-T07 — in_progress:** Implement LOCAL-01 bootstrap with pinned Docker Compose configuration, persistent NATS volumes, explicit project identity, bounded health/readiness checks and one startup owner across concurrent terminals

## P00. Scope, baseline, and architecture decisions

An approved implementation contract with no unresolved decision hidden in code.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P00-T01](delivery/task-details.md#P00-T01) | done | Codex | Freeze df46e94570fadf78ef67a75a692dd48b968a10f7 as the behavioral comparison baseline and inventory every CLI verb, dashboard view, protocol, state store, integration, and evaluation. |
| [P00-T02](delivery/task-details.md#P00-T02) | done | Codex | Resolve launch workflow, dashboard controls, language/runtime and initial SDKs, storage topology, NATS account/domain layout, supported OS/tool versions, initial scale, identity enrollment, and provider/data policy. |
| [P00-T03](delivery/task-details.md#P00-T03) | done | Codex | Reproduce or explicitly scope the previously reported federation correctness defects |
| [P00-T04](delivery/task-details.md#P00-T04) | done | Codex | Approve versioned state machines, authority boundaries, plugin manifest/context schemas, migration ownership, and the requirement-to-phase matrix. |
| [P00-T05](delivery/task-details.md#P00-T05) | done | Codex | Record approved storage direction STATE-01 |
| [P00-T06](delivery/task-details.md#P00-T06) | done | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P00-T07](delivery/task-details.md#P00-T07) | done | Codex | Record LOCAL-01: automatic Docker Compose startup or verified reuse on supported agent-client launch |
| [P00-GATE](delivery/task-details.md#P00-GATE) | done | Codex | Verify and accept P00 |

## P01. Executable contracts, baseline repairs, and verification

Contracts and failure scenarios can be tested before business plugins grow.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P01-T01](delivery/task-details.md#P01-T01) | done | Codex | Publish language-neutral command/event schemas and compatibility rules with organization, project, task, delegation, attempt, operation, schema version, and trace identifiers. |
| [P01-T02](delivery/task-details.md#P01-T02) | done | Codex | Create reusable contract fixtures and controllable fake workers/providers plus real NATS integration environments for CI. |
| [P01-T03](delivery/task-details.md#P01-T03) | done | Codex | Specify lifecycle, delivery acknowledgment, idempotency, deadline, cancellation, approval, and unavailable/unknown result semantics. |
| [P01-T04](delivery/task-details.md#P01-T04) | done | Codex | Establish per-phase evidence records, dependency gates, migration fixtures, and security/quality regression jobs. |
| [P01-T05](delivery/task-details.md#P01-T05) | done | Codex | Build an early two-hub contract spike with separate broker accounts and a leaf link |
| [P01-T06](delivery/task-details.md#P01-T06) | done | Codex | Preserve and extend the verified repairs for the six baseline findings |
| [P01-T07](delivery/task-details.md#P01-T07) | done | Codex | Build a bounded NATS persistence spike before production storage code: one owning task record, persistent operation identity, conditional competing writes, complete provenance/effect intent, lost acknowledgments and replay |
| [P01-T08](delivery/task-details.md#P01-T08) | done | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P01-GATE](delivery/task-details.md#P01-GATE) | done | Codex | Verify and accept P01 |

## P02. Protected boot and the NATS foundation

A local installation boots deterministically with protected kernel plugins.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P02-T01](delivery/task-details.md#P02-T01) | in_progress | Codex | Implement a minimal launcher that establishes the configured NATS substrate and loads the fixed protected boot assembly. |
| [P02-T02](delivery/task-details.md#P02-T02) | in_progress | Codex | Implement boot, protected-plugin lifecycle, protected internal communication, and deliberate publication of kernel status. |
| [P02-T03](delivery/task-details.md#P02-T03) | in_progress | Codex | Separate protected internal subjects/accounts from exported information and surrounding application services. |
| [P02-T04](delivery/task-details.md#P02-T04) | in_progress | Codex | Provide readiness snapshots, bounded startup/shutdown, broker recovery, basic installer/doctor skeleton, and local bootstrap diagnostics. |
| [P02-T05](delivery/task-details.md#P02-T05) | in_progress | Codex | Provision the approved local file-backed JetStream profile and team connection profile with explicit storage paths, limits, health and domain settings |
| [P02-T06](delivery/task-details.md#P02-T06) | done | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P02-T07](delivery/task-details.md#P02-T07) | in_progress | Codex | Implement LOCAL-01 bootstrap with pinned Docker Compose configuration, persistent NATS volumes, explicit project identity, bounded health/readiness checks and one startup owner across concurrent terminals |
| [P02-GATE](delivery/task-details.md#P02-GATE) | planned | Codex | Verify and accept P02 |

## P03. Plugin framework, nested packages, and inherited context

A third-party author can build a compatible trusted plugin without changing the kernel.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P03-T01](delivery/task-details.md#P03-T01) | planned | Codex | Start with hub/fed/plugin.py, runtime context, command registry and the five installed plugins |
| [P03-T02](delivery/task-details.md#P03-T02) | planned | Codex | Implement manifest validation, dependency/version resolution, lifecycle supervision, package provenance, configuration schemas, and contribution registration. |
| [P03-T03](delivery/task-details.md#P03-T03) | planned | Codex | Support independently reusable and parent-owned child packages, separately declaring runtime instance ownership and placement. |
| [P03-T04](delivery/task-details.md#P03-T04) | planned | Codex | Inject PluginContext and per-call OperationContext |
| [P03-T05](delivery/task-details.md#P03-T05) | planned | Codex | Add declared storage, artifacts, secrets, workspace, process, policy, and decision handles without sharing raw service implementations or an unrestricted container. |
| [P03-T06](delivery/task-details.md#P03-T06) | planned | Codex | Build starter SDKs and conformance tooling in at least two selected languages |
| [P03-T07](delivery/task-details.md#P03-T07) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P03-GATE](delivery/task-details.md#P03-GATE) | planned | Codex | Verify and accept P03 |

## P04. Identity, projects, durable state, and workspaces

Multiple users and projects share a hub with explicit authority and durable ownership.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P04-T01](delivery/task-details.md#P04-T01) | planned | Codex | Implement human, device, service, and plugin identities, enrollment/revocation, organization/project membership, permissions, approvals, and audit outside the kernel |
| [P04-T02](delivery/task-details.md#P04-T02) | planned | Codex | Implement NATS-backed persistence through ordinary domain-owner plugins |
| [P04-T03](delivery/task-details.md#P04-T03) | planned | Codex | Provide scoped workspace/Git/worktree management, configuration, connection/secret references, quotas, and resource reservations. |
| [P04-T04](delivery/task-details.md#P04-T04) | planned | Codex | Provide local single-user defaults and self-hosted identity configuration using the same contracts. |
| [P04-T05](delivery/task-details.md#P04-T05) | planned | Codex | Implement the approved worker execution profile so mutually untrusted task code cannot share unrestricted access to another user's files or credentials |
| [P04-T06](delivery/task-details.md#P04-T06) | planned | Codex | Build optional SQLite/SQL query indexes and caches from committed records and versioned checkpoints |
| [P04-T07](delivery/task-details.md#P04-T07) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P04-GATE](delivery/task-details.md#P04-GATE) | planned | Codex | Verify and accept P04 |

## P05. Local orchestration and evidence-based completion

A developer can finish a reviewable software task through durable coordinated work.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P05-T01](delivery/task-details.md#P05-T01) | planned | Codex | Reuse the existing task, dispatch, run, coordination and courier behavior behind the new contracts |
| [P05-T02](delivery/task-details.md#P05-T02) | planned | Codex | Implement project plans, tasks, dependencies, boards, role/agent/team definitions, assignment, run/attempt state, claims, resource scheduling, and explicit acceptance. |
| [P05-T03](delivery/task-details.md#P05-T03) | planned | Codex | Implement supervised workers, session resume capability, isolated worktrees, tool calls, messages, handoffs, progress, conversation records, artifacts, validation, and review workflows. |
| [P05-T04](delivery/task-details.md#P05-T04) | planned | Codex | Separate provider/process exit, reported completion, verified evidence, and owner acceptance |
| [P05-T05](delivery/task-details.md#P05-T05) | planned | Codex | Port existing journal/notice/dead-letter, search/knowledge, code sharing, cost/resource, and orchestration evaluation behavior behind plugins. |
| [P05-T06](delivery/task-details.md#P05-T06) | planned | Codex | Produce a software-change workflow from request through test evidence and a reviewable diff/PR proposal |
| [P05-T07](delivery/task-details.md#P05-T07) | planned | Codex | Preserve epics, sprints, ADR/capability proposal records, WIP/readiness gates, notifications, objections, and independent reviewer policy |
| [P05-T08](delivery/task-details.md#P05-T08) | planned | Codex | Persist orchestration transitions through the NATS-owning domain contracts |
| [P05-T09](delivery/task-details.md#P05-T09) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P05-GATE](delivery/task-details.md#P05-GATE) | planned | Codex | Verify and accept P05 |

## P06. Agent-client entry points and portable tooling

Developers use Agentmux from their preferred supported client.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P06-T01](delivery/task-details.md#P06-T01) | planned | Codex | Extend current CLI, MCP, provider and workspace tooling |
| [P06-T02](delivery/task-details.md#P06-T02) | planned | Codex | Provide stable CLI and MCP interfaces generated from declared command contracts, with discoverable resources and error semantics. |
| [P06-T03](delivery/task-details.md#P06-T03) | planned | Codex | Package and test integrations for Claude Code, Codex CLI, Pi, and Claude Desktop using each host's documented capabilities. |
| [P06-T04](delivery/task-details.md#P06-T04) | planned | Codex | Distinguish external client sessions submitting work from Agentmux-managed worker sessions |
| [P06-T05](delivery/task-details.md#P06-T05) | planned | Codex | Add setup, credential references, diagnostics, install checks, and client-specific documentation without silently replacing user configuration. |
| [P06-T06](delivery/task-details.md#P06-T06) | planned | Codex | Inventory and qualify existing Grok/provider authentication methods and any Bedrock compatibility path |
| [P06-T07](delivery/task-details.md#P06-T07) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P06-T08](delivery/task-details.md#P06-T08) | planned | Codex | Wire LOCAL-01 ensure-running into each supported terminal/client startup integration |
| [P06-VIDEO-E1](delivery/task-details.md#P06-VIDEO-E1) | planned | Codex | Declarative agent-lifecycle hook contributions |
| [P06-GATE](delivery/task-details.md#P06-GATE) | planned | Codex | Verify and accept P06 |

## P07. Existing dashboard: AG-UI and Atomic Design migration

Authorized users can understand work across agents, projects, and hubs.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P07-T01](delivery/task-details.md#P07-T01) | planned | Codex | Extend the existing dashboard incrementally with a NATS-facing interface plugin that maps authorized state/events to a pinned AG-UI contract for CopilotKit. |
| [P07-T02](delivery/task-details.md#P07-T02) | planned | Codex | Retain the ten existing views and their useful actions |
| [P07-T03](delivery/task-details.md#P07-T03) | planned | Codex | Use snapshots, ordered deltas, stable IDs/cursors, resynchronization, redaction, and explicit unknown/stale state. |
| [P07-T04](delivery/task-details.md#P07-T04) | planned | Codex | Use atoms, molecules, organisms, templates, and feature/page composition |
| [P07-T05](delivery/task-details.md#P07-T05) | planned | Codex | Include approvals and run controls only to the approved scope |
| [P07-T06](delivery/task-details.md#P07-T06) | planned | Codex | Read authorized NATS-backed views with source revisions/checkpoint cursors |
| [P07-T07](delivery/task-details.md#P07-T07) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P07-T08](delivery/task-details.md#P07-T08) | planned | Codex | Display the LOCAL-01 instance, readiness and authorized hub status in the existing dashboard through its NATS-to-AG-UI interface, using the same versioned status contract as terminal clients. |
| [P07-GATE](delivery/task-details.md#P07-GATE) | planned | Codex | Verify and accept P07 |

## P08. Jev decision services and measured efficiency

Plugins request bounded semantic advice with traceable evidence and safe fallback.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P08-T01](delivery/task-details.md#P08-T01) | planned | Codex | Implement a language-neutral decision service with optional Jev provider, versioned definitions/rubrics/schemas, scoped NATS requests, cache, budgets, cancellation, and evidence ledger. |
| [P08-T02](delivery/task-details.md#P08-T02) | planned | Codex | Check exact rules and data-export authority before hosted inference |
| [P08-T03](delivery/task-details.md#P08-T03) | planned | Codex | Support the eight reusable decision families and contributed definitions |
| [P08-T04](delivery/task-details.md#P08-T04) | planned | Codex | Preserve exact source IDs/spans, required facts, contrary evidence, and context-expansion routes |
| [P08-T05](delivery/task-details.md#P08-T05) | planned | Codex | Measure downstream tokens, provider costs, prompt-cache effects, latency, retries, rework, and accepted outcomes against a baseline. |
| [P08-T06](delivery/task-details.md#P08-T06) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P08-VIDEO-E2](delivery/task-details.md#P08-VIDEO-E2) | planned | Codex | Portable, nested decision-definition packages |
| [P08-VIDEO-E4](delivery/task-details.md#P08-VIDEO-E4) | planned | Codex | Scoped decision records and replay views |
| [P08-GATE](delivery/task-details.md#P08-GATE) | planned | Codex | Verify and accept P08 |

## P09. Portable Jev plugin and first skill wave

The same Jev capabilities improve supported clients with host-specific packaging.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P09-T01](delivery/task-details.md#P09-T01) | planned | Codex | Build one shared Jev CLI/MCP runtime and portable skill content with separate Claude, Codex, Pi, and Desktop packaging. |
| [P09-T02](delivery/task-details.md#P09-T02) | planned | Codex | Keep standalone Jev usable without Agentmux or NATS |
| [P09-T03](delivery/task-details.md#P09-T03) | planned | Codex | Create the proposed first general skill wave: setup, classify, scout, context, triage, review, author, and eval. |
| [P09-T04](delivery/task-details.md#P09-T04) | planned | Codex | Create the first Agentmux wave: prepare-worker, delegate, inspect-hub, and review-results |
| [P09-T05](delivery/task-details.md#P09-T05) | planned | Codex | Use skill-creator to draft, run paired behavioral and trigger tests, review results, revise, and qualify untouched holdout cases. |
| [P09-T06](delivery/task-details.md#P09-T06) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P09-JEV-001](delivery/task-details.md#P09-JEV-001) | planned | Codex | Intent-to-handler selection |
| [P09-JEV-002](delivery/task-details.md#P09-JEV-002) | planned | Codex | Missing-information detection |
| [P09-JEV-004](delivery/task-details.md#P09-JEV-004) | planned | Codex | Domain guidance selection |
| [P09-JEV-008](delivery/task-details.md#P09-JEV-008) | planned | Codex | Approved workflow selection |
| [P09-JEV-015](delivery/task-details.md#P09-JEV-015) | planned | Codex | Plugin capability shortlist |
| [P09-JEV-016](delivery/task-details.md#P09-JEV-016) | planned | Codex | Skill and instruction loading |
| [P09-JEV-017](delivery/task-details.md#P09-JEV-017) | planned | Codex | Tool operation selection |
| [P09-JEV-019](delivery/task-details.md#P09-JEV-019) | planned | Codex | Tool-output evidence selection |
| [P09-JEV-021](delivery/task-details.md#P09-JEV-021) | planned | Codex | Pre-extracted value selection |
| [P09-JEV-023](delivery/task-details.md#P09-JEV-023) | planned | Codex | Passage relevance ranking |
| [P09-JEV-024](delivery/task-details.md#P09-JEV-024) | planned | Codex | Answer-presence screening |
| [P09-JEV-025](delivery/task-details.md#P09-JEV-025) | planned | Codex | Exact source-span selection |
| [P09-JEV-026](delivery/task-details.md#P09-JEV-026) | planned | Codex | Contradictory-evidence preservation |
| [P09-JEV-027](delivery/task-details.md#P09-JEV-027) | planned | Codex | Recipient-specific context packs |
| [P09-JEV-031](delivery/task-details.md#P09-JEV-031) | planned | Codex | Worker specialization fit |
| [P09-JEV-034](delivery/task-details.md#P09-JEV-034) | planned | Codex | Bounded decision without generation |
| [P09-JEV-044](delivery/task-details.md#P09-JEV-044) | planned | Codex | Failure category triage |
| [P09-JEV-049](delivery/task-details.md#P09-JEV-049) | planned | Codex | Evidence relationship assessment |
| [P09-JEV-056](delivery/task-details.md#P09-JEV-056) | planned | Codex | Citation and source-span checks |
| [P09-JEV-065](delivery/task-details.md#P09-JEV-065) | planned | Codex | Bounded status-question routing |
| [P09-JEV-084](delivery/task-details.md#P09-JEV-084) | planned | Codex | Extractive activity cards |
| [P09-VIDEO-01](delivery/task-details.md#P09-VIDEO-01) | planned | Codex | Agent-authored bounded questions |
| [P09-VIDEO-02](delivery/task-details.md#P09-VIDEO-02) | planned | Codex | Questions about files without loading their contents |
| [P09-VIDEO-03](delivery/task-details.md#P09-VIDEO-03) | planned | Codex | Budgeted semantic repository scouting |
| [P09-VIDEO-08](delivery/task-details.md#P09-VIDEO-08) | planned | Codex | Observe a command, then return a narrow judgment |
| [P09-VIDEO-11](delivery/task-details.md#P09-VIDEO-11) | planned | Codex | Change-description fidelity checks |
| [P09-VIDEO-E3](delivery/task-details.md#P09-VIDEO-E3) | planned | Codex | Reviewed promotion of useful ad hoc questions |
| [P09-jev-setup](delivery/task-details.md#P09-jev-setup) | planned | Codex | jev-setup |
| [P09-jev-classify](delivery/task-details.md#P09-jev-classify) | planned | Codex | jev-classify |
| [P09-jev-scout](delivery/task-details.md#P09-jev-scout) | planned | Codex | jev-scout |
| [P09-jev-context](delivery/task-details.md#P09-jev-context) | planned | Codex | jev-context |
| [P09-jev-triage](delivery/task-details.md#P09-jev-triage) | planned | Codex | jev-triage |
| [P09-jev-review](delivery/task-details.md#P09-jev-review) | planned | Codex | jev-review |
| [P09-jev-author](delivery/task-details.md#P09-jev-author) | planned | Codex | jev-author |
| [P09-jev-eval](delivery/task-details.md#P09-jev-eval) | planned | Codex | jev-eval |
| [P09-agentmux-jev-prepare-worker](delivery/task-details.md#P09-agentmux-jev-prepare-worker) | planned | Codex | agentmux-jev-prepare-worker |
| [P09-GATE](delivery/task-details.md#P09-GATE) | planned | Codex | Verify and accept P09 |

## P10. Connected hubs, leaf nodes, and cross-organization work

Independent teams share authorized work while retaining their own authority.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P10-T01](delivery/task-details.md#P10-T01) | planned | Codex | Extend current federation capability |
| [P10-T02](delivery/task-details.md#P10-T02) | planned | Codex | Implement scoped trust agreements, node/peer enrollment, NATS leaf topology, independent JetStream domains where needed, and selective sharing/replication. |
| [P10-T03](delivery/task-details.md#P10-T03) | planned | Codex | Publish authorized capabilities and capacity |
| [P10-T04](delivery/task-details.md#P10-T04) | planned | Codex | Implement durable offer, acceptance, reservation, execution reporting, result submission, origin acceptance, reconciliation, revocation, and explicit reassignment. |
| [P10-T05](delivery/task-details.md#P10-T05) | planned | Codex | Support work/context/artifacts/code/findings/messages/board projections with authenticated provenance, digests, visibility, and retention. |
| [P10-T06](delivery/task-details.md#P10-T06) | planned | Codex | Add automatic receiving-hub acceptance inside approved rules, pending human approval for review-required work, and rejection for hard-denied work |
| [P10-T07](delivery/task-details.md#P10-T07) | planned | Codex | Qualify and enable the remote-hub modes of P09 delegate, inspect-hub, and review-results skills on real connected hubs and supported clients |
| [P10-T08](delivery/task-details.md#P10-T08) | planned | Codex | Use separate persistent JetStream domains for hubs that must operate autonomously |
| [P10-T09](delivery/task-details.md#P10-T09) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P10-T10](delivery/task-details.md#P10-T10) | planned | Codex | Populate LOCAL-01 status with authorized configured/connected hubs, trust scope, last observation and known delegated/reserved work |
| [P10-JEV-010](delivery/task-details.md#P10-JEV-010) | planned | Codex | Acceptance-criterion ambiguity |
| [P10-JEV-032](delivery/task-details.md#P10-JEV-032) | planned | Codex | Partner-hub suitability |
| [P10-JEV-043](delivery/task-details.md#P10-JEV-043) | planned | Codex | Stage handoff readiness advice |
| [P10-VIDEO-05](delivery/task-details.md#P10-VIDEO-05) | planned | Codex | Federated questions before artifact transfer |
| [P10-VIDEO-12](delivery/task-details.md#P10-VIDEO-12) | planned | Codex | Cross-hub deliverable-meaning checks |
| [P10-agentmux-jev-delegate](delivery/task-details.md#P10-agentmux-jev-delegate) | planned | Codex | agentmux-jev-delegate |
| [P10-agentmux-jev-inspect-hub](delivery/task-details.md#P10-agentmux-jev-inspect-hub) | planned | Codex | agentmux-jev-inspect-hub |
| [P10-agentmux-jev-review-results](delivery/task-details.md#P10-agentmux-jev-review-results) | planned | Codex | agentmux-jev-review-results |
| [P10-GATE](delivery/task-details.md#P10-GATE) | planned | Codex | Verify and accept P10 |

## P11. Industrial and vendor extension packages

Industrial workflows extend Agentmux through the same contracts as other domains.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P11-T01](delivery/task-details.md#P11-T01) | planned | Codex | Package industrial orchestration guidance, tools, schemas, UI renderers, and skills with explicitly independent or parent-owned children. |
| [P11-T02](delivery/task-details.md#P11-T02) | planned | Codex | Migrate current Modbus, MQTT, network discovery, PROFINET snapshot/DCP, passive BOOTP, EtherNet/IP/Logix, ADS, EtherCAT diagnostics, CODESYS runtime tooling, PCAP analysis, and existing engineering wrappers to declared capability plugins. |
| [P11-T03](delivery/task-details.md#P11-T03) | planned | Codex | Define CODESYS, Siemens, Rockwell, and related vendor integration slices with actual licensed tool/OS/hardware prerequisites and test environments. |
| [P11-T04](delivery/task-details.md#P11-T04) | planned | Codex | Add engineering build/migration/evidence skills and Jev definitions for diagnostics and source-preserving comparisons. |
| [P11-T05](delivery/task-details.md#P11-T05) | planned | Codex | Implement read/simulation-first reference workflows and per-action permissions for equipment changes |
| [P11-T06](delivery/task-details.md#P11-T06) | planned | Codex | Inventory existing PCM600/ABB-related privilege hooks as integration requirements, preserving target/action confirmation and audit |
| [P11-T07](delivery/task-details.md#P11-T07) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P11-JEV-068](delivery/task-details.md#P11-JEV-068) | planned | Codex | Engineering vendor/workflow selection |
| [P11-JEV-069](delivery/task-details.md#P11-JEV-069) | planned | Codex | Offline compiler/build triage |
| [P11-JEV-070](delivery/task-details.md#P11-JEV-070) | planned | Codex | Tag and entity alignment |
| [P11-JEV-071](delivery/task-details.md#P11-JEV-071) | planned | Codex | Requirement-to-engineering-artifact mapping |
| [P11-JEV-072](delivery/task-details.md#P11-JEV-072) | planned | Codex | Vendor manual passage selection |
| [P11-JEV-073](delivery/task-details.md#P11-JEV-073) | planned | Codex | Migration concern classification |
| [P11-JEV-074](delivery/task-details.md#P11-JEV-074) | planned | Codex | Commissioning evidence coverage |
| [P11-JEV-086](delivery/task-details.md#P11-JEV-086) | planned | Codex | Engineering requirement semantic diff |
| [P11-JEV-088](delivery/task-details.md#P11-JEV-088) | planned | Codex | Erratum and release-note applicability |
| [P11-industrial-jev-build](delivery/task-details.md#P11-industrial-jev-build) | planned | Codex | industrial-jev-build |
| [P11-industrial-jev-migration](delivery/task-details.md#P11-industrial-jev-migration) | planned | Codex | industrial-jev-migration |
| [P11-industrial-jev-evidence](delivery/task-details.md#P11-industrial-jev-evidence) | planned | Codex | industrial-jev-evidence |
| [P11-GATE](delivery/task-details.md#P11-GATE) | planned | Codex | Verify and accept P11 |

## P12. Production hardening and first sellable release

Customers can install, operate, recover, and support the complete launch product.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P12-T01](delivery/task-details.md#P12-T01) | planned | Codex | Finish signed/reproducible distributions, dependency locks/SBOM, versioned configuration, upgrade/rollback, package verification, and support diagnostics. |
| [P12-T02](delivery/task-details.md#P12-T02) | planned | Codex | Complete self-hosted topology guides, backup/restore drills, durable retention/pruning, quotas/fairness, monitoring, alerts, incident procedures, and consented telemetry. |
| [P12-T03](delivery/task-details.md#P12-T03) | planned | Codex | Validate launch performance/capacity profiles, broker/storage failure recovery, long-running work, and cross-organization safety. |
| [P12-T04](delivery/task-details.md#P12-T04) | planned | Codex | Finish onboarding, documentation, reference plugins, accessibility, support ownership, commercial licensing/provider eligibility, and pilot feedback. |
| [P12-T05](delivery/task-details.md#P12-T05) | planned | Codex | Rehearse migration from v0.32.0 across board/run/hub/federation state, credentials, worktrees, and integrations |
| [P12-T06](delivery/task-details.md#P12-T06) | planned | Codex | Restore an origin hub while a receiver continues accepted work and reconcile outstanding reservations before admitting replacements |
| [P12-T07](delivery/task-details.md#P12-T07) | planned | Codex | Qualify NATS storage capacity, retention, immutable artifact lifecycle, snapshot/archive integrity, sync policy and recovery time for solo and team profiles |
| [P12-T08](delivery/task-details.md#P12-T08) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P12-T09](delivery/task-details.md#P12-T09) | planned | Codex | Qualify LOCAL-01 installation, automatic launch, upgrade compatibility, data retention and recovery using the pinned Docker/Compose/OS/client matrix |
| [P12-T10](delivery/task-details.md#P12-T10) | planned | Codex | Prepare the MERGE-01 two-instance, agent-operated rehearsal and evidence package |
| [P12-GATE](delivery/task-details.md#P12-GATE) | planned | Codex | Verify and accept P12 |

## P13. Remaining Jev catalog and skill expansion

Every remaining research proposal receives a measured implementation decision.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P13-T01](delivery/task-details.md#P13-T01) | planned | Codex | Implement the complete remaining catalog in bounded batches using the coverage appendix, without duplicating overlapping video and original use cases. |
| [P13-T02](delivery/task-details.md#P13-T02) | planned | Codex | Complete general extract, compare, checkpoint, integrate, and optimize skills plus remaining Agentmux planning, coordination, diagnosis, knowledge, plugin review, and policy-tuning skills. |
| [P13-T03](delivery/task-details.md#P13-T03) | planned | Codex | Expand temporary bounded questions, semantic inventories, federated source inspection, compaction/retention controls, what-if replay, fidelity review, bilateral contract interpretation, and opportunity scorecards. |
| [P13-T04](delivery/task-details.md#P13-T04) | planned | Codex | Promote only qualified definitions |
| [P13-T05](delivery/task-details.md#P13-T05) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P13-JEV-003](delivery/task-details.md#P13-JEV-003) | planned | Codex | Project and repository disambiguation |
| [P13-JEV-005](delivery/task-details.md#P13-JEV-005) | planned | Codex | Potential duplicate task discovery |
| [P13-JEV-006](delivery/task-details.md#P13-JEV-006) | planned | Codex | Request-change interpretation |
| [P13-JEV-007](delivery/task-details.md#P13-JEV-007) | planned | Codex | Attention and urgency triage |
| [P13-JEV-009](delivery/task-details.md#P13-JEV-009) | planned | Codex | Plan completeness check |
| [P13-JEV-011](delivery/task-details.md#P13-JEV-011) | planned | Codex | Dependency suggestions |
| [P13-JEV-012](delivery/task-details.md#P13-JEV-012) | planned | Codex | Parallel-work conflict screening |
| [P13-JEV-013](delivery/task-details.md#P13-JEV-013) | planned | Codex | Delegation granularity advice |
| [P13-JEV-014](delivery/task-details.md#P13-JEV-014) | planned | Codex | Additional specialist review selection |
| [P13-JEV-018](delivery/task-details.md#P13-JEV-018) | planned | Codex | Closed argument interpretation |
| [P13-JEV-020](delivery/task-details.md#P13-JEV-020) | planned | Codex | Approved tool-recipe selection |
| [P13-JEV-022](delivery/task-details.md#P13-JEV-022) | planned | Codex | Next evidence source selection |
| [P13-JEV-028](delivery/task-details.md#P13-JEV-028) | planned | Codex | Relevant prior memory selection |
| [P13-JEV-029](delivery/task-details.md#P13-JEV-029) | planned | Codex | Material context-change detection |
| [P13-JEV-030](delivery/task-details.md#P13-JEV-030) | planned | Codex | Compaction coverage checking |
| [P13-JEV-033](delivery/task-details.md#P13-JEV-033) | planned | Codex | Model or agent tier selection |
| [P13-JEV-035](delivery/task-details.md#P13-JEV-035) | planned | Codex | Small-model result escalation |
| [P13-JEV-036](delivery/task-details.md#P13-JEV-036) | planned | Codex | Previous work applicability |
| [P13-JEV-037](delivery/task-details.md#P13-JEV-037) | planned | Codex | Optional message recipient selection |
| [P13-JEV-038](delivery/task-details.md#P13-JEV-038) | planned | Codex | Planner wake-up screening |
| [P13-JEV-039](delivery/task-details.md#P13-JEV-039) | planned | Codex | Related update grouping |
| [P13-JEV-040](delivery/task-details.md#P13-JEV-040) | planned | Codex | Clarification consolidation |
| [P13-JEV-041](delivery/task-details.md#P13-JEV-041) | planned | Codex | Cross-agent claim conflict detection |
| [P13-JEV-042](delivery/task-details.md#P13-JEV-042) | planned | Codex | Ineffective-loop detection |
| [P13-JEV-045](delivery/task-details.md#P13-JEV-045) | planned | Codex | Failure-log episode grouping |
| [P13-JEV-046](delivery/task-details.md#P13-JEV-046) | planned | Codex | Additional test-family suggestions |
| [P13-JEV-047](delivery/task-details.md#P13-JEV-047) | planned | Codex | Requirement-to-change coverage |
| [P13-JEV-048](delivery/task-details.md#P13-JEV-048) | planned | Codex | Review focus selection |
| [P13-JEV-050](delivery/task-details.md#P13-JEV-050) | planned | Codex | Narrow rework selection |
| [P13-JEV-051](delivery/task-details.md#P13-JEV-051) | planned | Codex | Knowledge tagging and indexing |
| [P13-JEV-052](delivery/task-details.md#P13-JEV-052) | planned | Codex | Knowledge duplication suggestions |
| [P13-JEV-053](delivery/task-details.md#P13-JEV-053) | planned | Codex | Stale or conflicting guidance flags |
| [P13-JEV-054](delivery/task-details.md#P13-JEV-054) | planned | Codex | Document structure recovery |
| [P13-JEV-055](delivery/task-details.md#P13-JEV-055) | planned | Codex | Knowledge ingestion triage |
| [P13-JEV-057](delivery/task-details.md#P13-JEV-057) | planned | Codex | Protected-kernel status interpretation |
| [P13-JEV-058](delivery/task-details.md#P13-JEV-058) | planned | Codex | Setup-help selection |
| [P13-JEV-059](delivery/task-details.md#P13-JEV-059) | planned | Codex | Support incident grouping |
| [P13-JEV-060](delivery/task-details.md#P13-JEV-060) | planned | Codex | Operational symptom interpretation |
| [P13-JEV-061](delivery/task-details.md#P13-JEV-061) | planned | Codex | Provider degradation classification |
| [P13-JEV-062](delivery/task-details.md#P13-JEV-062) | planned | Codex | Plugin-update impact triage |
| [P13-JEV-063](delivery/task-details.md#P13-JEV-063) | planned | Codex | Registered presentation selection |
| [P13-JEV-064](delivery/task-details.md#P13-JEV-064) | planned | Codex | Dashboard attention annotation |
| [P13-JEV-066](delivery/task-details.md#P13-JEV-066) | planned | Codex | Optional notification grouping |
| [P13-JEV-067](delivery/task-details.md#P13-JEV-067) | planned | Codex | Conversation navigation labels |
| [P13-JEV-075](delivery/task-details.md#P13-JEV-075) | planned | Codex | Suspicious-instruction annotation |
| [P13-JEV-076](delivery/task-details.md#P13-JEV-076) | planned | Codex | Data-handling review assistance |
| [P13-JEV-077](delivery/task-details.md#P13-JEV-077) | planned | Codex | Proposed-effect ambiguity detection |
| [P13-JEV-078](delivery/task-details.md#P13-JEV-078) | planned | Codex | Evaluation-case prioritization |
| [P13-JEV-079](delivery/task-details.md#P13-JEV-079) | planned | Codex | Decision-definition candidate evaluation |
| [P13-JEV-080](delivery/task-details.md#P13-JEV-080) | planned | Codex | Outcome-model feature extraction |
| [P13-JEV-081](delivery/task-details.md#P13-JEV-081) | planned | Codex | Conflicting plugin guidance |
| [P13-JEV-082](delivery/task-details.md#P13-JEV-082) | planned | Codex | Capability-description consistency |
| [P13-JEV-083](delivery/task-details.md#P13-JEV-083) | planned | Codex | Plugin example/fixture gap detection |
| [P13-JEV-085](delivery/task-details.md#P13-JEV-085) | planned | Codex | Minimal support-packet assembly |
| [P13-JEV-087](delivery/task-details.md#P13-JEV-087) | planned | Codex | Part and variant relationship suggestions |
| [P13-VIDEO-04](delivery/task-details.md#P13-VIDEO-04) | planned | Codex | Incremental semantic inventories |
| [P13-VIDEO-06](delivery/task-details.md#P13-VIDEO-06) | planned | Codex | Adaptive compaction timing |
| [P13-VIDEO-07](delivery/task-details.md#P13-VIDEO-07) | planned | Codex | Active-work retention boundaries |
| [P13-VIDEO-09](delivery/task-details.md#P13-VIDEO-09) | planned | Codex | Narrow hypothesis challenges during implementation |
| [P13-VIDEO-10](delivery/task-details.md#P13-VIDEO-10) | planned | Codex | Policy what-if analysis using saved factor judgments |
| [P13-VIDEO-13](delivery/task-details.md#P13-VIDEO-13) | planned | Codex | Implementation-alternative scorecards |
| [P13-VIDEO-14](delivery/task-details.md#P13-VIDEO-14) | planned | Codex | Qualify proposed plugin investments |
| [P13-jev-extract](delivery/task-details.md#P13-jev-extract) | planned | Codex | jev-extract |
| [P13-jev-compare](delivery/task-details.md#P13-jev-compare) | planned | Codex | jev-compare |
| [P13-jev-checkpoint](delivery/task-details.md#P13-jev-checkpoint) | planned | Codex | jev-checkpoint |
| [P13-jev-integrate](delivery/task-details.md#P13-jev-integrate) | planned | Codex | jev-integrate |
| [P13-jev-optimize](delivery/task-details.md#P13-jev-optimize) | planned | Codex | jev-optimize |
| [P13-agentmux-jev-plan](delivery/task-details.md#P13-agentmux-jev-plan) | planned | Codex | agentmux-jev-plan |
| [P13-agentmux-jev-coordinate](delivery/task-details.md#P13-agentmux-jev-coordinate) | planned | Codex | agentmux-jev-coordinate |
| [P13-agentmux-jev-diagnose-run](delivery/task-details.md#P13-agentmux-jev-diagnose-run) | planned | Codex | agentmux-jev-diagnose-run |
| [P13-agentmux-jev-curate-knowledge](delivery/task-details.md#P13-agentmux-jev-curate-knowledge) | planned | Codex | agentmux-jev-curate-knowledge |
| [P13-agentmux-jev-review-plugin](delivery/task-details.md#P13-agentmux-jev-review-plugin) | planned | Codex | agentmux-jev-review-plugin |
| [P13-agentmux-jev-tune-policies](delivery/task-details.md#P13-agentmux-jev-tune-policies) | planned | Codex | agentmux-jev-tune-policies |
| [P13-GATE](delivery/task-details.md#P13-GATE) | planned | Codex | Verify and accept P13 |

## P14. Sandboxed plugins and ecosystem expansion

Untrusted third-party plugins gain a tested containment option.

| Task | Status | Owner | Scope |
| --- | --- | --- | --- |
| [P14-T01](delivery/task-details.md#P14-T01) | planned | Codex | Choose and threat-model isolated execution profiles, process/container/WASM options, host brokers, and platform limitations against actual plugin needs. |
| [P14-T02](delivery/task-details.md#P14-T02) | planned | Codex | Enforce declared filesystem/network/process/device access, secret isolation, quotas, termination, and package provenance at runtime. |
| [P14-T03](delivery/task-details.md#P14-T03) | planned | Codex | Qualify UI contribution isolation and publisher/distribution controls before enabling a public plugin ecosystem. |
| [P14-T04](delivery/task-details.md#P14-T04) | planned | Codex | Retain trusted native profiles only with clear administrator choice |
| [P14-T05](delivery/task-details.md#P14-T05) | planned | Codex | Apply ADD-01 and the component preservation matrix to every changed source file and affected caller |
| [P14-GATE](delivery/task-details.md#P14-GATE) | planned | Codex | Verify and accept P14 |
| [MERGE-01](delivery/task-details.md#MERGE-01) | planned | Codex | Autonomous final feature-branch acceptance and verified push |
