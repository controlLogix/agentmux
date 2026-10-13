# Implementation tasks

Generated from tasks.json. Status and evidence remain owned by that file.

## P00. Scope, baseline, and architecture decisions

An approved implementation contract with no unresolved decision hidden in code.

**Epic acceptance criteria**

- **P00-AC01:** Every accepted user decision and all existing functional groups have a named owner phase and verification scenario.
- **P00-AC02:** Codex reviews the complete plan, decision log, contracts and criterion-level evidence, records its review and advancement decision, and verifies the committed and pushed P00 candidate before P01 starts. Ryan and Nick are not required for delivery approval.
- **P00-AC03:** All P01–P04 blocking choices have recorded alternatives, rationale, and consequences. Later choices have a deadline before their owning phase.
- **P00-AC04:** Baseline checks identify passes, failures, missing environments, and historic-only claims separately.
- **P00-AC05:** The complete source inventory, component reuse decisions and behavior checks are reviewed. Every baseline file and additional governed source file has an owner; unmapped entry points or uncertain behavior are recorded as blocking gaps. No retirement is implied by a launch-scope choice.
- **P00-AC06:** LOCAL-01 has a reviewed host/platform support matrix, stable instance identity, safe Docker context and credential rules, readiness/status contract, and assigned verification owners. Automatic launch is required for every integration advertised as supporting it.

<a id="P00-T01"></a>

### P00-T01: Freeze df46e94570fadf78ef67a75a692dd48b968a10f7 as the behavioral comparison baseline and inventory every CLI verb, dashboard view, protocol, state store, integration, and evaluation.

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-T06.

**Implementation plan**

1. Pin df46e94570fadf78ef67a75a692dd48b968a10f7 and verify all 338 baseline Git blobs against component-inventory.json; retain later files as additional governed scope.
2. Check each of the four component manifests, the 37 baseline groups, source-surface-index fingerprints, commands, dashboard views/routes, protocols, stores, integrations and evaluation owners. Record uncertain dynamic behavior for maintainer review.
3. Reconcile historical dashboard specifications and instruction changes against current code without replacing historical evidence. Preserve all behavior-check IDs and distinguish static inventory coverage from runtime qualification.
4. Attach inventory results and source-bound checks. Submit the public-entry-point and behavior review to P00-GATE; keep any unresolved completeness gap visible before refactoring.

**Deliverables**

1. Freeze df46e94570fadf78ef67a75a692dd48b968a10f7 as the behavioral comparison baseline and inventory every CLI verb, dashboard view, protocol, state store, integration, and evaluation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P00-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Freeze df46e94570fadf78ef67a75a692dd48b968a10f7 as the behavioral comparison baseline and inventory every CLI verb, dashboard view, protocol, state store, integration, and evaluation.
2. P00-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P00-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P00-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Review the traceability matrix and inspect contracts together.
2. Run existing relevant suites on supported environments and reproduce the four reported crash/dispatch defects with isolated fixtures.
3. Record the exact commit, tools, fixtures, and results. Review missing environments as gaps, not passes.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Review the LOCAL-01 flow and FAIL-55–FAIL-62 against actual host startup capabilities; distinguish approved behavior from unresolved host/version choices.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P00/inventory-review.md, docs/planning/2026-10-09/delivery/evidence/P00/P00-T01.json

**Commits:** c513ffa0565936916b342ae8ad7a8dc837b4d6e8, 7a9acadf68439abeed5a0768edc5d3f4d08c6a3b


<a id="P00-T02"></a>

### P00-T02: Resolve launch workflow, dashboard controls, language/runtime and initial SDKs, storage topology, NATS account/domain layout, supported OS/tool versions, initial scale, identity enrollment, and provider/data policy.

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-T06.

**Implementation plan**

1. Compare Go, Python and TypeScript over the same disposable NATS request/reply fixture, verify absent-service failure, and cross-compile the candidate foundation without treating build success as native-platform evidence.
2. Recommend runtime/SDK pins, protected process placement, repository layout and reuse boundaries. Record alternatives and costs in decisions/runtime-and-deployment.md.
3. Define identity/enrollment, worker isolation, provider/data policy, audience/workflow, retained dashboard controls and capacity test targets. Preserve existing functionality and distinguish proposed support from actual host evidence.
4. Attach exact source/dependency/result hashes and submit D01-D06 for P00 review. Resolve or explicitly assign later-provider/version decisions before their owning implementation begins.

**Deliverables**

1. Resolve launch workflow, dashboard controls, language/runtime and initial SDKs, storage topology, NATS account/domain layout, supported OS/tool versions, initial scale, identity enrollment, and provider/data policy.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P00-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Resolve launch workflow, dashboard controls, language/runtime and initial SDKs, storage topology, NATS account/domain layout, supported OS/tool versions, initial scale, identity enrollment, and provider/data policy.
2. P00-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P00-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P00-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Review the traceability matrix and inspect contracts together.
2. Run existing relevant suites on supported environments and reproduce the four reported crash/dispatch defects with isolated fixtures.
3. Record the exact commit, tools, fixtures, and results. Review missing environments as gaps, not passes.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Review the LOCAL-01 flow and FAIL-55–FAIL-62 against actual host startup capabilities; distinguish approved behavior from unresolved host/version choices.

**Evidence:** docs/planning/2026-10-09/delivery/decisions/runtime-and-deployment.md, docs/planning/2026-10-09/delivery/spikes/runtime/comparison-result.json, docs/planning/2026-10-09/delivery/evidence/P00/P00-T02.json

**Commits:** b067e98e8a051c33d7df2e7facfe26d9f747239a


<a id="P00-T03"></a>

### P00-T03: Reproduce or explicitly scope the previously reported federation correctness defects

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-T06.

**Implementation plan**

1. Read AMX-BASE-001 through AMX-BASE-006, their original acceptance text, repair report and upgrade limitations. Verify the old reproduction source is attributable to the frozen baseline.
2. Check SHA-256 identity for all eight repaired runtime/test files and three historical logs. Retain old-source failures and the 119-test broker run as historical evidence rather than rerunning unchanged broad suites.
3. Run ./hub/tests/local.ps1 hub.tests.test_governance in the prepared WSL environment. Retain the result, log, source fingerprints, exit code and any missing coverage.
4. Assign each assertion to P01-T06 and its replacing state, authorization, orchestration or federation task. Keep repository-version, external-artifact and delegated-actor acceptance gaps explicitly open in P05/P10.
5. Record every task criterion with current evidence. Do not change runtime behavior, failure-matrix status or phase acceptance through this scoping task.

**Deliverables**

1. Reproduce or explicitly scope the previously reported federation correctness defects. Turn each into a regression case owned by the replacing phase.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P00-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Reproduce or explicitly scope the previously reported federation correctness defects. Turn each into a regression case owned by the replacing phase.
2. P00-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P00-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P00-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Review the traceability matrix and inspect contracts together.
2. Run existing relevant suites on supported environments and reproduce the four reported crash/dispatch defects with isolated fixtures.
3. Record the exact commit, tools, fixtures, and results. Review missing environments as gaps, not passes.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Review the LOCAL-01 flow and FAIL-55–FAIL-62 against actual host startup capabilities; distinguish approved behavior from unresolved host/version choices.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P00/P00-T03.json

**Commits:** c513ffa0565936916b342ae8ad7a8dc837b4d6e8


<a id="P00-T04"></a>

### P00-T04: Approve versioned state machines, authority boundaries, plugin manifest/context schemas, migration ownership, and the requirement-to-phase matrix.

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Approve versioned state machines, authority boundaries, plugin manifest/context schemas, migration ownership, and the requirement-to-phase matrix.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Approve versioned state machines, authority boundaries, plugin manifest/context schemas, migration ownership, and the requirement-to-phase matrix.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P00-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Approve versioned state machines, authority boundaries, plugin manifest/context schemas, migration ownership, and the requirement-to-phase matrix.
2. P00-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P00-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P00-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Review the traceability matrix and inspect contracts together.
2. Run existing relevant suites on supported environments and reproduce the four reported crash/dispatch defects with isolated fixtures.
3. Record the exact commit, tools, fixtures, and results. Review missing environments as gaps, not passes.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Review the LOCAL-01 flow and FAIL-55–FAIL-62 against actual host startup capabilities; distinguish approved behavior from unresolved host/version choices.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P00/P00-T04.json

**Commits:** b067e98e8a051c33d7df2e7facfe26d9f747239a


<a id="P00-T05"></a>

### P00-T05: Record approved storage direction STATE-01

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-T06.

**Implementation plan**

1. Define independent hub domains and kernel/system/project/agreement account boundaries, with broker-enforced credentials and domain-owner validation.
2. Specify one conditional complete transition record, durable operation identity, recoverable effect intent, lost-reply reconciliation and immutable artifacts; distinguish same-stream atomicity from cross-boundary recovery.
3. Set initial retention, quota/headroom, checkpoint, replica/sync and backup/restore targets for solo/team/offline profiles. Record what source research and configuration validation do and do not prove.
4. Assign concurrency, migration, authorization, replay and fault-model checks to P01/P04/P10/P12; carry every baseline invariant forward. Submit S01-S05 for review without introducing authoritative SQL.

**Deliverables**

1. Record approved storage direction STATE-01. Select JetStream authority boundaries, retention/checkpoint policy, replication/sync profiles, broker/API access scopes and supported SDK versions. Keep any proposed authoritative SQL exception visible for review.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P00-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Record approved storage direction STATE-01. Select JetStream authority boundaries, retention/checkpoint policy, replication/sync profiles, broker/API access scopes and supported SDK versions. Keep any proposed authoritative SQL exception visible for review.
2. P00-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P00-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P00-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Review the traceability matrix and inspect contracts together.
2. Run existing relevant suites on supported environments and reproduce the four reported crash/dispatch defects with isolated fixtures.
3. Record the exact commit, tools, fixtures, and results. Review missing environments as gaps, not passes.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Review the LOCAL-01 flow and FAIL-55–FAIL-62 against actual host startup capabilities; distinguish approved behavior from unresolved host/version choices.

**Evidence:** docs/planning/2026-10-09/delivery/decisions/storage-contract.md, docs/planning/2026-10-09/delivery/evidence/P00/P00-T05.json

**Commits:** b067e98e8a051c33d7df2e7facfe26d9f747239a


<a id="P00-T06"></a>

### P00-T06: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** done. **Owner:** Codex.

**Dependencies:** none.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P00-T06-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P00-T06-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P00-T06-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P00-T06-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Review the traceability matrix and inspect contracts together.
2. Run existing relevant suites on supported environments and reproduce the four reported crash/dispatch defects with isolated fixtures.
3. Record the exact commit, tools, fixtures, and results. Review missing environments as gaps, not passes.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Review the LOCAL-01 flow and FAIL-55–FAIL-62 against actual host startup capabilities; distinguish approved behavior from unresolved host/version choices.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P00/P00-T06.json

**Commits:** c513ffa0565936916b342ae8ad7a8dc837b4d6e8


<a id="P00-T07"></a>

### P00-T07: Record LOCAL-01: automatic Docker Compose startup or verified reuse on supported agent-client launch

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-T06.

**Implementation plan**

1. Specify stable enrolled profile identity, release/context ownership and an OS-held startup lock that works before NATS exists; prohibit accidental second stacks and implicit upgrades.
2. Define inspect/reuse/start/readiness/failure states, separate warm/cold/download budgets, helper lifecycle and honest partial status.
3. Research actual host startup events and record the required integration path for Claude Code, Codex, Pi and Desktop; distinguish documented capabilities, observed installed versions and untested Agentmux hooks.
4. Define the shared caller-scoped instance/persistence/work/hub status fields and assign FAIL-55 through FAIL-62 to actual host and Compose qualification. Record Docker availability gaps and submit L01-L05 for review.

**Deliverables**

1. Record LOCAL-01: automatic Docker Compose startup or verified reuse on supported agent-client launch. Approve instance/profile ownership, Docker context selection, enrollment prerequisites, host startup hooks, status schema and timeout targets.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P00-T07-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Record LOCAL-01: automatic Docker Compose startup or verified reuse on supported agent-client launch. Approve instance/profile ownership, Docker context selection, enrollment prerequisites, host startup hooks, status schema and timeout targets.
2. P00-T07-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P00-T07-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P00-T07-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Review the traceability matrix and inspect contracts together.
2. Run existing relevant suites on supported environments and reproduce the four reported crash/dispatch defects with isolated fixtures.
3. Record the exact commit, tools, fixtures, and results. Review missing environments as gaps, not passes.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Review the LOCAL-01 flow and FAIL-55–FAIL-62 against actual host startup capabilities; distinguish approved behavior from unresolved host/version choices.

**Evidence:** docs/planning/2026-10-09/delivery/decisions/startup-contract.md, docs/planning/2026-10-09/delivery/evidence/P00/P00-T07.json

**Commits:** b067e98e8a051c33d7df2e7facfe26d9f747239a


<a id="P00-GATE"></a>

### P00-GATE: Verify and accept P00

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-T01, P00-T02, P00-T03, P00-T04, P00-T05, P00-T06, P00-T07.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Approved plan revision and decision log
2. Baseline behavior inventory and defect fixtures
3. Compatibility and capacity profiles
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P00-GATE-AC01: Every accepted user decision and all existing functional groups have a named owner phase and verification scenario.
2. P00-GATE-AC02: Codex reviews the complete plan, decision log, contracts and criterion-level evidence, records its review and advancement decision, and verifies the committed and pushed P00 candidate before P01 starts. Ryan and Nick are not required for delivery approval.
3. P00-GATE-AC03: All P01–P04 blocking choices have recorded alternatives, rationale, and consequences. Later choices have a deadline before their owning phase.
4. P00-GATE-AC04: Baseline checks identify passes, failures, missing environments, and historic-only claims separately.
5. P00-GATE-AC05: The complete source inventory, component reuse decisions and behavior checks are reviewed. Every baseline file and additional governed source file has an owner; unmapped entry points or uncertain behavior are recorded as blocking gaps. No retirement is implied by a launch-scope choice.
6. P00-GATE-AC06: LOCAL-01 has a reviewed host/platform support matrix, stable instance identity, safe Docker context and credential rules, readiness/status contract, and assigned verification owners. Automatic launch is required for every integration advertised as supporting it.
7. P00-GATE-AC07: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
8. P00-GATE-AC08: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Review the traceability matrix and inspect contracts together.
2. Run existing relevant suites on supported environments and reproduce the four reported crash/dispatch defects with isolated fixtures.
3. Record the exact commit, tools, fixtures, and results. Review missing environments as gaps, not passes.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Review the LOCAL-01 flow and FAIL-55–FAIL-62 against actual host startup capabilities; distinguish approved behavior from unresolved host/version choices.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P00/P00-GATE.json

**Commits:** 605e96d495b4763997a13f3935245efb77e6ba84

## P01. Executable contracts, baseline repairs, and verification

Contracts and failure scenarios can be tested before business plugins grow.

**Epic acceptance criteria**

- **P01-AC01:** Two independently implemented test clients exchange valid requests and reject incompatible or malformed envelopes.
- **P01-AC02:** Fixtures cover duplicate, delayed, out-of-order, unauthorized, canceled, timed-out, and replayed messages without conflating execution with delivery.
- **P01-AC03:** A failing predecessor gate prevents promotion. Waivers cannot bypass accepted ownership or security invariants.
- **P01-AC04:** CI captures exact versions and logs without recording credentials or private model reasoning. Known baseline blockers are repaired or disproved with evidence, and the required repository governance gate passes before P02 progression. WSL-CLIENT-01 has a recorded placement contract, Windows/WSL client/version inventory and honest current interop observations; P06-specific integration claims remain unaccepted until actual-host qualification.
- **P01-AC05:** Two language clients pass the NATS storage fixtures on pinned server/client versions: competing revisions admit one transition, partial atomic batches leave no partial record set, and lost acknowledgments reconcile the same operation. Unsupported cross-stream or external-effect transactions are rejected or handled by an explicit recovery contract.
- **P01-AC06:** The existing regression assertions are retained or mapped to equivalent assertions. Characterization fixtures capture each affected behavior before refactoring; a deliberately removed assertion, missing component, or unapproved retirement prevents progression.

<a id="P01-T01"></a>

### P01-T01: Publish language-neutral command/event schemas and compatibility rules with organization, project, task, delegation, attempt, operation, schema version, and trace identifiers.

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-GATE, P01-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Publish language-neutral command/event schemas and compatibility rules with organization, project, task, delegation, attempt, operation, schema version, and trace identifiers.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Publish language-neutral command/event schemas and compatibility rules with organization, project, task, delegation, attempt, operation, schema version, and trace identifiers.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P01-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Publish language-neutral command/event schemas and compatibility rules with organization, project, task, delegation, attempt, operation, schema version, and trace identifiers.
2. P01-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P01-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P01-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run schema/contract suites in macOS, Linux, and WSL test jobs.
2. Break one contract fixture and one phase gate deliberately and confirm the pipeline refuses promotion.
3. Exercise a real broker restart and reconnect in the harness.
4. Run FAIL-42, FAIL-43 and FAIL-47 with real JetStream. Record which server/API/SDK capabilities provide each guarantee, including batch behavior and authoritative read freshness.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P01/payload-storage-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/model-leaf-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/recovery-ci-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/P01-T01.json

**Commits:** 7ef00dcb299c100d6dda45bfffa2b4e127345a50, f19c6473d56335b8eeb28704b02895b9d9ab7fcc, a2e9ee6d84a44a0b2f5783c3c0a3a613d50d0e41


<a id="P01-T02"></a>

### P01-T02: Create reusable contract fixtures and controllable fake workers/providers plus real NATS integration environments for CI.

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-GATE, P01-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Create reusable contract fixtures and controllable fake workers/providers plus real NATS integration environments for CI.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Record WSL-CLIENT-01 actual client installation/version ownership and environmental contract fixtures. Separate Windows-client interop observations from native Linux/WSL runtime conformance and leave P06-specific client integration open.

**Deliverables**

1. Create reusable contract fixtures and controllable fake workers/providers plus real NATS integration environments for CI.
2. Focused regression evidence and affected compatibility/migration records
3. WSL-CLIENT-01 client ownership contract, current environment inventory and explicit interop gap record

**Acceptance criteria**

1. P01-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Create reusable contract fixtures and controllable fake workers/providers plus real NATS integration environments for CI. WSL-CLIENT-01: Record WSL-CLIENT-01 actual client installation/version ownership and environmental contract fixtures. Separate Windows-client interop observations from native Linux/WSL runtime conformance and leave P06-specific client integration open.
2. P01-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope. Each applicable WSL-CLIENT-01 claim requires actual evidence; failed interop, omitted host coverage or Linux-client substitution cannot count as success. P01 environmental evidence does not accept P06 integration.
3. P01-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P01-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run schema/contract suites in macOS, Linux, and WSL test jobs.
2. Break one contract fixture and one phase gate deliberately and confirm the pipeline refuses promotion.
3. Exercise a real broker restart and reconnect in the harness.
4. Run FAIL-42, FAIL-43 and FAIL-47 with real JetStream. Record which server/API/SDK capabilities provide each guarantee, including batch behavior and authoritative read freshness.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. For WSL-CLIENT-01, record direct Windows and WSL-resolved client identity/version, configuration ownership and observed interop failures without copying credentials. Keep platform-runtime tests distinct from Windows-client transport tests; identify P06-owned qualification gaps.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P01/payload-storage-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/model-leaf-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/recovery-ci-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/controlled-storage-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/platform-contract/result.json, docs/planning/2026-10-09/delivery/evidence/P01/wsl-inventory/inventory.json, docs/planning/2026-10-09/delivery/evidence/P01/wsl-inventory/validation.json, docs/planning/2026-10-09/delivery/evidence/P01/P01-T02-acceptance.json

**Commits:** 7ef00dcb299c100d6dda45bfffa2b4e127345a50, f19c6473d56335b8eeb28704b02895b9d9ab7fcc, a2e9ee6d84a44a0b2f5783c3c0a3a613d50d0e41, 00353fd0ccb0b4ce34cb4eb45549703430af30d1, 80f43e02f3344696a3985c48ef12578319f3bd0f


<a id="P01-T03"></a>

### P01-T03: Specify lifecycle, delivery acknowledgment, idempotency, deadline, cancellation, approval, and unavailable/unknown result semantics.

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-GATE, P01-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Specify lifecycle, delivery acknowledgment, idempotency, deadline, cancellation, approval, and unavailable/unknown result semantics.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Specify lifecycle, delivery acknowledgment, idempotency, deadline, cancellation, approval, and unavailable/unknown result semantics.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P01-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Specify lifecycle, delivery acknowledgment, idempotency, deadline, cancellation, approval, and unavailable/unknown result semantics.
2. P01-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P01-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P01-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run schema/contract suites in macOS, Linux, and WSL test jobs.
2. Break one contract fixture and one phase gate deliberately and confirm the pipeline refuses promotion.
3. Exercise a real broker restart and reconnect in the harness.
4. Run FAIL-42, FAIL-43 and FAIL-47 with real JetStream. Record which server/API/SDK capabilities provide each guarantee, including batch behavior and authoritative read freshness.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P01/payload-storage-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/model-leaf-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/recovery-ci-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/P01-T03.json

**Commits:** 7ef00dcb299c100d6dda45bfffa2b4e127345a50, f19c6473d56335b8eeb28704b02895b9d9ab7fcc, a2e9ee6d84a44a0b2f5783c3c0a3a613d50d0e41


<a id="P01-T04"></a>

### P01-T04: Establish per-phase evidence records, dependency gates, migration fixtures, and security/quality regression jobs.

**Status:** in_progress. **Owner:** Codex.

**Dependencies:** P00-GATE, P01-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Establish per-phase evidence records, dependency gates, migration fixtures, and security/quality regression jobs.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Bind Windows/WSL evidence to client installation/version, Windows auth/config ownership and actual interop observations; keep unsupported environments and P06 qualification gaps explicit rather than treating native Linux results as equivalent.

**Deliverables**

1. Establish per-phase evidence records, dependency gates, migration fixtures, and security/quality regression jobs.
2. Focused regression evidence and affected compatibility/migration records
3. WSL-CLIENT-01 client ownership contract, current environment inventory and explicit interop gap record

**Acceptance criteria**

1. P01-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Establish per-phase evidence records, dependency gates, migration fixtures, and security/quality regression jobs. WSL-CLIENT-01: Bind Windows/WSL evidence to client installation/version, Windows auth/config ownership and actual interop observations; keep unsupported environments and P06 qualification gaps explicit rather than treating native Linux results as equivalent.
2. P01-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope. Each applicable WSL-CLIENT-01 claim requires actual evidence; failed interop, omitted host coverage or Linux-client substitution cannot count as success. P01 environmental evidence does not accept P06 integration.
3. P01-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P01-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run schema/contract suites in macOS, Linux, and WSL test jobs.
2. Break one contract fixture and one phase gate deliberately and confirm the pipeline refuses promotion.
3. Exercise a real broker restart and reconnect in the harness.
4. Run FAIL-42, FAIL-43 and FAIL-47 with real JetStream. Record which server/API/SDK capabilities provide each guarantee, including batch behavior and authoritative read freshness.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. For WSL-CLIENT-01, record direct Windows and WSL-resolved client identity/version, configuration ownership and observed interop failures without copying credentials. Keep platform-runtime tests distinct from Windows-client transport tests; identify P06-owned qualification gaps.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P01/recovery-ci-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/controlled-storage-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/preservation/repair-review.md, docs/planning/2026-10-09/delivery/evidence/P01/native/37e0d8c/review.json, docs/planning/2026-10-09/delivery/evidence/P01/preservation/acceptance-map.json, docs/planning/2026-10-09/delivery/evidence/P01/native/7a7d47a/review.json, docs/planning/2026-10-09/delivery/evidence/P01/windows-clients/README.md, docs/planning/2026-10-09/delivery/evidence/P01/dashboard-windows/archive-manifest.json, docs/planning/2026-10-09/delivery/evidence/P01/hub-current-pre-followup/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/conformance-reviewed/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/native/09fe9c7/review.json, docs/planning/2026-10-09/delivery/evidence/P01/windows-callback-review.json, docs/planning/2026-10-09/delivery/evidence/P01/windows-callback-final/README.md, docs/planning/2026-10-09/delivery/evidence/P01/hub-callback-incomplete-setup/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/hub-callback-final-failed/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/server-api-diagnostics/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/native/9647b42/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/bash-portability/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/wsl-native-9647b42/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/plugin-restoration-spec.md, docs/planning/2026-10-09/delivery/evidence/P01/recovery-evidence.json, docs/planning/2026-10-09/delivery/evidence/P01/native/80f43e0/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/plugin-restoration/parent-review.json, docs/planning/2026-10-09/delivery/evidence/P01/preservation/har20-fresh/result.json, docs/planning/2026-10-09/delivery/evidence/P01/wsl-native-80f43e0/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/plugin-restoration/metadata-fastpath-parent-review.json, docs/planning/2026-10-09/delivery/evidence/P01/native/a21f03a/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/preservation/fault-sensitivity/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/preservation/legacy-step-negative/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/preservation/assertion-mapping/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/preservation/identity-shell/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/windows-link-failure/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/windows-prerequisites/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/calibration-interop/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/calibration-interop/original-calibration-task-pass/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/actual-checked-observer/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/checked-observer/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/calibration-comparison/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/historical-scenario-inputs/manifest.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/crossrepo-path/manifest.json, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/team-startup-failure/README.md, docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/team-startup-failure/archive-allowlist.json

**Commits:** f19c6473d56335b8eeb28704b02895b9d9ab7fcc, a2e9ee6d84a44a0b2f5783c3c0a3a613d50d0e41, 00353fd0ccb0b4ce34cb4eb45549703430af30d1, 7a7d47ae6830f86b8fed318ee64da6a5aac52701

**Blocker:** Windows Grok login is available in its canonical profile. One original TEAM attempt on c370290 stopped during provider setup before task posting or E1-E6 scoring: launch-time Grok preflight rejected a changed native hook source set. Review exact cleanup and source drift before retry. Original team, crossrepo and swarm evidence remains required; no phase acceptance.


<a id="P01-T05"></a>

### P01-T05: Build an early two-hub contract spike with separate broker accounts and a leaf link

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-GATE, P01-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Build an early two-hub contract spike with separate broker accounts and a leaf link. Exercise lost acceptance acknowledgment and reservation reconciliation before the later production federation phase.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Build an early two-hub contract spike with separate broker accounts and a leaf link. Exercise lost acceptance acknowledgment and reservation reconciliation before the later production federation phase.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P01-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Build an early two-hub contract spike with separate broker accounts and a leaf link. Exercise lost acceptance acknowledgment and reservation reconciliation before the later production federation phase.
2. P01-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P01-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P01-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run schema/contract suites in macOS, Linux, and WSL test jobs.
2. Break one contract fixture and one phase gate deliberately and confirm the pipeline refuses promotion.
3. Exercise a real broker restart and reconnect in the harness.
4. Run FAIL-42, FAIL-43 and FAIL-47 with real JetStream. Record which server/API/SDK capabilities provide each guarantee, including batch behavior and authoritative read freshness.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P01/model-leaf-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/recovery-ci-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/P01-T05.json

**Commits:** f19c6473d56335b8eeb28704b02895b9d9ab7fcc, a2e9ee6d84a44a0b2f5783c3c0a3a613d50d0e41


<a id="P01-T06"></a>

### P01-T06: Preserve and extend the verified repairs for the six baseline findings

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-GATE, P01-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Preserve and extend the verified repairs for the six baseline findings. Ryan authorized this bounded repair pass; its source hashes and executed regressions are in governance-repair-evidence.json. Complete every other P01 criterion before advancing to P02.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-001, AMX-BASE-002, AMX-BASE-003, AMX-BASE-004, AMX-BASE-005, AMX-BASE-006 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Preserve and extend the verified repairs for the six baseline findings. Ryan authorized this bounded repair pass; its source hashes and executed regressions are in governance-repair-evidence.json. Complete every other P01 criterion before advancing to P02.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P01-T06-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Preserve and extend the verified repairs for the six baseline findings. Ryan authorized this bounded repair pass; its source hashes and executed regressions are in governance-repair-evidence.json. Complete every other P01 criterion before advancing to P02.
2. P01-T06-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P01-T06-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P01-T06-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run schema/contract suites in macOS, Linux, and WSL test jobs.
2. Break one contract fixture and one phase gate deliberately and confirm the pipeline refuses promotion.
3. Exercise a real broker restart and reconnect in the harness.
4. Run FAIL-42, FAIL-43 and FAIL-47 with real JetStream. Record which server/API/SDK capabilities provide each guarantee, including batch behavior and authoritative read freshness.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P01/recovery-ci-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/P01-T06.json

**Commits:** f19c6473d56335b8eeb28704b02895b9d9ab7fcc, a2e9ee6d84a44a0b2f5783c3c0a3a613d50d0e41


<a id="P01-T07"></a>

### P01-T07: Build a bounded NATS persistence spike before production storage code: one owning task record, persistent operation identity, conditional competing writes, complete provenance/effect intent, lost acknowledgments and replay

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-GATE, P01-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Build a bounded NATS persistence spike before production storage code: one owning task record, persistent operation identity, conditional competing writes, complete provenance/effect intent, lost acknowledgments and replay. Exercise single-record commits and any required atomic batch inside one stream.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-002 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Build a bounded NATS persistence spike before production storage code: one owning task record, persistent operation identity, conditional competing writes, complete provenance/effect intent, lost acknowledgments and replay. Exercise single-record commits and any required atomic batch inside one stream.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P01-T07-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Build a bounded NATS persistence spike before production storage code: one owning task record, persistent operation identity, conditional competing writes, complete provenance/effect intent, lost acknowledgments and replay. Exercise single-record commits and any required atomic batch inside one stream.
2. P01-T07-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P01-T07-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P01-T07-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run schema/contract suites in macOS, Linux, and WSL test jobs.
2. Break one contract fixture and one phase gate deliberately and confirm the pipeline refuses promotion.
3. Exercise a real broker restart and reconnect in the harness.
4. Run FAIL-42, FAIL-43 and FAIL-47 with real JetStream. Record which server/API/SDK capabilities provide each guarantee, including batch behavior and authoritative read freshness.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P01/payload-storage-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/recovery-ci-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/controlled-storage-checkpoint.md, docs/planning/2026-10-09/delivery/evidence/P01/parent-change-review.json, docs/planning/2026-10-09/delivery/evidence/P01/incoming-storage/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/incoming-storage-negative/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/backup-boundary/archive.json, docs/planning/2026-10-09/delivery/evidence/P01/P01-T07-acceptance.json

**Commits:** 7ef00dcb299c100d6dda45bfffa2b4e127345a50, f19c6473d56335b8eeb28704b02895b9d9ab7fcc, a2e9ee6d84a44a0b2f5783c3c0a3a613d50d0e41, 00353fd0ccb0b4ce34cb4eb45549703430af30d1, 9647b4240a43c60c246512efa1553e8f4cb58530


<a id="P01-T08"></a>

### P01-T08: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** done. **Owner:** Codex.

**Dependencies:** P00-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P01-T08-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P01-T08-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P01-T08-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P01-T08-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run schema/contract suites in macOS, Linux, and WSL test jobs.
2. Break one contract fixture and one phase gate deliberately and confirm the pipeline refuses promotion.
3. Exercise a real broker restart and reconnect in the harness.
4. Run FAIL-42, FAIL-43 and FAIL-47 with real JetStream. Record which server/API/SDK capabilities provide each guarantee, including batch behavior and authoritative read freshness.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** docs/planning/2026-10-09/delivery/evidence/P01/P01-T08.json

**Commits:** d337bd509c2e1757c816de2d1dd79afeb31bdc51


<a id="P01-GATE"></a>

### P01-GATE: Verify and accept P01

**Status:** planned. **Owner:** Codex.

**Dependencies:** P01-T01, P01-T02, P01-T03, P01-T04, P01-T05, P01-T06, P01-T07, P01-T08.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.
5. Review WSL-CLIENT-01 evidence at this phase boundary: environment contract, inventory and honest observations; do not accept P06 integration early.

**Deliverables**

1. Contract version 1 fixtures
2. Failure injection harness
3. CI gate and compatibility reports
4. NATS storage capability report and transaction-boundary fixtures for STATE-01
5. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P01-GATE-AC01: Two independently implemented test clients exchange valid requests and reject incompatible or malformed envelopes. WSL-CLIENT-01 is included in this phase's evidence review, with no skipped-environment substitution.
2. P01-GATE-AC02: Fixtures cover duplicate, delayed, out-of-order, unauthorized, canceled, timed-out, and replayed messages without conflating execution with delivery.
3. P01-GATE-AC03: A failing predecessor gate prevents promotion. Waivers cannot bypass accepted ownership or security invariants.
4. P01-GATE-AC04: CI captures exact versions and logs without recording credentials or private model reasoning. Known baseline blockers are repaired or disproved with evidence, and the required repository governance gate passes before P02 progression.
5. P01-GATE-AC05: Two language clients pass the NATS storage fixtures on pinned server/client versions: competing revisions admit one transition, partial atomic batches leave no partial record set, and lost acknowledgments reconcile the same operation. Unsupported cross-stream or external-effect transactions are rejected or handled by an explicit recovery contract.
6. P01-GATE-AC06: The existing regression assertions are retained or mapped to equivalent assertions. Characterization fixtures capture each affected behavior before refactoring; a deliberately removed assertion, missing component, or unapproved retirement prevents progression.
7. P01-GATE-AC07: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
8. P01-GATE-AC08: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run schema/contract suites in macOS, Linux, and WSL test jobs.
2. Break one contract fixture and one phase gate deliberately and confirm the pipeline refuses promotion.
3. Exercise a real broker restart and reconnect in the harness.
4. Run FAIL-42, FAIL-43 and FAIL-47 with real JetStream. Record which server/API/SDK capabilities provide each guarantee, including batch behavior and authoritative read freshness.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. For WSL-CLIENT-01, record direct Windows and WSL-resolved client identity/version, configuration ownership and observed interop failures without copying credentials. Keep platform-runtime tests distinct from Windows-client transport tests; identify P06-owned qualification gaps.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P02. Protected boot and the NATS foundation

A local installation boots deterministically with protected kernel plugins.

**Epic acceptance criteria**

- **P02-AC01:** macOS, Linux, and WSL installations boot without an LLM or hosted Jev connection.
- **P02-AC02:** An outside plugin can subscribe only to permitted kernel information and cannot publish commands or writes into the kernel.
- **P02-AC03:** Bad configuration, occupied ports, unavailable broker, and failed protected plugin produce actionable bounded failures.
- **P02-AC04:** Surrounding plugin failure does not corrupt boot state. Ordinary runtime communication uses NATS after bootstrap.
- **P02-AC05:** The existing launcher, environment selection and failure diagnostics remain available while the new boot path is opt-in. Both paths pass their defined startup and shutdown comparisons without sharing ownership of a live task.
- **P02-AC06:** LOCAL-01 cold launch starts the selected local Compose stack and waits for broker persistence and application readiness. Warm launch reuses the same instance without recreation or lost state. macOS, Linux and WSL fixtures pass without an LLM or Jev.
- **P02-AC07:** Simultaneous launches and a crashed startup owner converge on one owned instance. Wrong Docker context, conflicting ports, incompatible versions and partial startup produce bounded, specific diagnostics without deleting volumes, starting a shadow stack or attaching to another user.
- **P02-AC08:** The same versioned status response follows successful start and reuse. It includes instance identity/version, selected profile and endpoint, readiness, persistence health and authorized hub information with freshness. Missing or unimplemented services are labeled unavailable, never healthy.

<a id="P02-T01"></a>

### P02-T01: Implement a minimal launcher that establishes the configured NATS substrate and loads the fixed protected boot assembly.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P01-GATE, P02-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement a minimal launcher that establishes the configured NATS substrate and loads the fixed protected boot assembly.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement a minimal launcher that establishes the configured NATS substrate and loads the fixed protected boot assembly.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P02-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement a minimal launcher that establishes the configured NATS substrate and loads the fixed protected boot assembly.
2. P02-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P02-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P02-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Capture broker traffic and audit permissions while running normal and unauthorized clients.
2. Cold-start and restart each platform. Kill NATS and one protected plugin at controlled points.
3. Verify late subscribers receive a consistent readiness snapshot and updates.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Exercise FAIL-55–FAIL-59 with real Compose processes and persistent volumes. In P02 use declared status fixtures for later services; repeat against real client and federation implementations in P06/P10/P12.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P02-T02"></a>

### P02-T02: Implement boot, protected-plugin lifecycle, protected internal communication, and deliberate publication of kernel status.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P01-GATE, P02-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement boot, protected-plugin lifecycle, protected internal communication, and deliberate publication of kernel status.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement boot, protected-plugin lifecycle, protected internal communication, and deliberate publication of kernel status.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P02-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement boot, protected-plugin lifecycle, protected internal communication, and deliberate publication of kernel status.
2. P02-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P02-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P02-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Capture broker traffic and audit permissions while running normal and unauthorized clients.
2. Cold-start and restart each platform. Kill NATS and one protected plugin at controlled points.
3. Verify late subscribers receive a consistent readiness snapshot and updates.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Exercise FAIL-55–FAIL-59 with real Compose processes and persistent volumes. In P02 use declared status fixtures for later services; repeat against real client and federation implementations in P06/P10/P12.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P02-T03"></a>

### P02-T03: Separate protected internal subjects/accounts from exported information and surrounding application services.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P01-GATE, P02-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Separate protected internal subjects/accounts from exported information and surrounding application services.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Separate protected internal subjects/accounts from exported information and surrounding application services.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P02-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Separate protected internal subjects/accounts from exported information and surrounding application services.
2. P02-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P02-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P02-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Capture broker traffic and audit permissions while running normal and unauthorized clients.
2. Cold-start and restart each platform. Kill NATS and one protected plugin at controlled points.
3. Verify late subscribers receive a consistent readiness snapshot and updates.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Exercise FAIL-55–FAIL-59 with real Compose processes and persistent volumes. In P02 use declared status fixtures for later services; repeat against real client and federation implementations in P06/P10/P12.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P02-T04"></a>

### P02-T04: Provide readiness snapshots, bounded startup/shutdown, broker recovery, basic installer/doctor skeleton, and local bootstrap diagnostics.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P01-GATE, P02-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Provide readiness snapshots, bounded startup/shutdown, broker recovery, basic installer/doctor skeleton, and local bootstrap diagnostics.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Provide readiness snapshots, bounded startup/shutdown, broker recovery, basic installer/doctor skeleton, and local bootstrap diagnostics.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P02-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Provide readiness snapshots, bounded startup/shutdown, broker recovery, basic installer/doctor skeleton, and local bootstrap diagnostics.
2. P02-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P02-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P02-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Capture broker traffic and audit permissions while running normal and unauthorized clients.
2. Cold-start and restart each platform. Kill NATS and one protected plugin at controlled points.
3. Verify late subscribers receive a consistent readiness snapshot and updates.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Exercise FAIL-55–FAIL-59 with real Compose processes and persistent volumes. In P02 use declared status fixtures for later services; repeat against real client and federation implementations in P06/P10/P12.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P02-T05"></a>

### P02-T05: Provision the approved local file-backed JetStream profile and team connection profile with explicit storage paths, limits, health and domain settings

**Status:** planned. **Owner:** Codex.

**Dependencies:** P01-GATE, P02-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Provision the approved local file-backed JetStream profile and team connection profile with explicit storage paths, limits, health and domain settings. Business state ownership stays in surrounding plugins.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Provision the approved local file-backed JetStream profile and team connection profile with explicit storage paths, limits, health and domain settings. Business state ownership stays in surrounding plugins.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P02-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Provision the approved local file-backed JetStream profile and team connection profile with explicit storage paths, limits, health and domain settings. Business state ownership stays in surrounding plugins.
2. P02-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P02-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P02-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Capture broker traffic and audit permissions while running normal and unauthorized clients.
2. Cold-start and restart each platform. Kill NATS and one protected plugin at controlled points.
3. Verify late subscribers receive a consistent readiness snapshot and updates.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Exercise FAIL-55–FAIL-59 with real Compose processes and persistent volumes. In P02 use declared status fixtures for later services; repeat against real client and federation implementations in P06/P10/P12.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P02-T06"></a>

### P02-T06: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P01-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P02-T06-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P02-T06-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P02-T06-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P02-T06-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Capture broker traffic and audit permissions while running normal and unauthorized clients.
2. Cold-start and restart each platform. Kill NATS and one protected plugin at controlled points.
3. Verify late subscribers receive a consistent readiness snapshot and updates.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Exercise FAIL-55–FAIL-59 with real Compose processes and persistent volumes. In P02 use declared status fixtures for later services; repeat against real client and federation implementations in P06/P10/P12.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P02-T07"></a>

### P02-T07: Implement LOCAL-01 bootstrap with pinned Docker Compose configuration, persistent NATS volumes, explicit project identity, bounded health/readiness checks and one startup owner across concurrent terminals

**Status:** planned. **Owner:** Codex.

**Dependencies:** P01-GATE, P02-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement LOCAL-01 bootstrap with pinned Docker Compose configuration, persistent NATS volumes, explicit project identity, bounded health/readiness checks and one startup owner across concurrent terminals. Reuse an authorized compatible healthy instance without recreating it.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement LOCAL-01 bootstrap with pinned Docker Compose configuration, persistent NATS volumes, explicit project identity, bounded health/readiness checks and one startup owner across concurrent terminals. Reuse an authorized compatible healthy instance without recreating it.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P02-T07-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement LOCAL-01 bootstrap with pinned Docker Compose configuration, persistent NATS volumes, explicit project identity, bounded health/readiness checks and one startup owner across concurrent terminals. Reuse an authorized compatible healthy instance without recreating it.
2. P02-T07-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P02-T07-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P02-T07-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Capture broker traffic and audit permissions while running normal and unauthorized clients.
2. Cold-start and restart each platform. Kill NATS and one protected plugin at controlled points.
3. Verify late subscribers receive a consistent readiness snapshot and updates.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Exercise FAIL-55–FAIL-59 with real Compose processes and persistent volumes. In P02 use declared status fixtures for later services; repeat against real client and federation implementations in P06/P10/P12.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P02-GATE"></a>

### P02-GATE: Verify and accept P02

**Status:** planned. **Owner:** Codex.

**Dependencies:** P02-T01, P02-T02, P02-T03, P02-T04, P02-T05, P02-T06, P02-T07.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Boot and shutdown matrix
2. Kernel publication contract and permission tests
3. Bootstrap recovery guide
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P02-GATE-AC01: macOS, Linux, and WSL installations boot without an LLM or hosted Jev connection.
2. P02-GATE-AC02: An outside plugin can subscribe only to permitted kernel information and cannot publish commands or writes into the kernel.
3. P02-GATE-AC03: Bad configuration, occupied ports, unavailable broker, and failed protected plugin produce actionable bounded failures.
4. P02-GATE-AC04: Surrounding plugin failure does not corrupt boot state. Ordinary runtime communication uses NATS after bootstrap.
5. P02-GATE-AC05: The existing launcher, environment selection and failure diagnostics remain available while the new boot path is opt-in. Both paths pass their defined startup and shutdown comparisons without sharing ownership of a live task.
6. P02-GATE-AC06: LOCAL-01 cold launch starts the selected local Compose stack and waits for broker persistence and application readiness. Warm launch reuses the same instance without recreation or lost state. macOS, Linux and WSL fixtures pass without an LLM or Jev.
7. P02-GATE-AC07: Simultaneous launches and a crashed startup owner converge on one owned instance. Wrong Docker context, conflicting ports, incompatible versions and partial startup produce bounded, specific diagnostics without deleting volumes, starting a shadow stack or attaching to another user.
8. P02-GATE-AC08: The same versioned status response follows successful start and reuse. It includes instance identity/version, selected profile and endpoint, readiness, persistence health and authorized hub information with freshness. Missing or unimplemented services are labeled unavailable, never healthy.
9. P02-GATE-AC09: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
10. P02-GATE-AC10: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Capture broker traffic and audit permissions while running normal and unauthorized clients.
2. Cold-start and restart each platform. Kill NATS and one protected plugin at controlled points.
3. Verify late subscribers receive a consistent readiness snapshot and updates.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Exercise FAIL-55–FAIL-59 with real Compose processes and persistent volumes. In P02 use declared status fixtures for later services; repeat against real client and federation implementations in P06/P10/P12.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P03. Plugin framework, nested packages, and inherited context

A third-party author can build a compatible trusted plugin without changing the kernel.

**Epic acceptance criteria**

- **P03-AC01:** Both child package modes install and activate correctly. Removing one parent retains independent children used elsewhere.
- **P03-AC02:** Two concurrent users cannot overwrite an ambient current-user/current-project value. A child cannot widen its grant or forge logger identity.
- **P03-AC03:** Dependency cycles, missing versions, partial initialization, and stale handles fail deterministically and clean up resources.
- **P03-AC04:** A plugin in each selected language passes the same contract fixtures and interacts with another plugin over NATS.
- **P03-AC05:** The protected kernel has no replacement option in package management. Trusted native code is accurately documented as unsandboxed.
- **P03-AC06:** Existing federation plugin lifecycle, command registry, contributions and context each have a documented reuse or justified replacement decision. Existing bundled plugins pass compatibility fixtures before their old runtime path is disabled.

<a id="P03-T01"></a>

### P03-T01: Start with hub/fed/plugin.py, runtime context, command registry and the five installed plugins

**Status:** planned. **Owner:** Codex.

**Dependencies:** P02-GATE, P03-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Start with hub/fed/plugin.py, runtime context, command registry and the five installed plugins. Extract or wrap proven behavior before writing replacement framework code; document language/security boundaries that require a different implementation.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Start with hub/fed/plugin.py, runtime context, command registry and the five installed plugins. Extract or wrap proven behavior before writing replacement framework code; document language/security boundaries that require a different implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P03-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Start with hub/fed/plugin.py, runtime context, command registry and the five installed plugins. Extract or wrap proven behavior before writing replacement framework code; document language/security boundaries that require a different implementation.
2. P03-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P03-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P03-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run an independent author exercise using only published SDK/docs.
2. Test lifecycle/resource leaks, dependency failure, configuration precedence, version skew, and upgrades with active operations.
3. Inspect NATS traces and execute negative tests at remote resource owners.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P03-T02"></a>

### P03-T02: Implement manifest validation, dependency/version resolution, lifecycle supervision, package provenance, configuration schemas, and contribution registration.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P02-GATE, P03-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement manifest validation, dependency/version resolution, lifecycle supervision, package provenance, configuration schemas, and contribution registration.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement manifest validation, dependency/version resolution, lifecycle supervision, package provenance, configuration schemas, and contribution registration.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P03-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement manifest validation, dependency/version resolution, lifecycle supervision, package provenance, configuration schemas, and contribution registration.
2. P03-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P03-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P03-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run an independent author exercise using only published SDK/docs.
2. Test lifecycle/resource leaks, dependency failure, configuration precedence, version skew, and upgrades with active operations.
3. Inspect NATS traces and execute negative tests at remote resource owners.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P03-T03"></a>

### P03-T03: Support independently reusable and parent-owned child packages, separately declaring runtime instance ownership and placement.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P02-GATE, P03-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Support independently reusable and parent-owned child packages, separately declaring runtime instance ownership and placement.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Support independently reusable and parent-owned child packages, separately declaring runtime instance ownership and placement.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P03-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Support independently reusable and parent-owned child packages, separately declaring runtime instance ownership and placement.
2. P03-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P03-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P03-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run an independent author exercise using only published SDK/docs.
2. Test lifecycle/resource leaks, dependency failure, configuration precedence, version skew, and upgrades with active operations.
3. Inspect NATS traces and execute negative tests at remote resource owners.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P03-T04"></a>

### P03-T04: Inject PluginContext and per-call OperationContext

**Status:** planned. **Owner:** Codex.

**Dependencies:** P02-GATE, P03-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Inject PluginContext and per-call OperationContext. Supply identity, scoped logger, tracing/metrics, config, lifecycle, clock, and approved NATS service clients.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Inject PluginContext and per-call OperationContext. Supply identity, scoped logger, tracing/metrics, config, lifecycle, clock, and approved NATS service clients.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P03-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Inject PluginContext and per-call OperationContext. Supply identity, scoped logger, tracing/metrics, config, lifecycle, clock, and approved NATS service clients.
2. P03-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P03-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P03-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run an independent author exercise using only published SDK/docs.
2. Test lifecycle/resource leaks, dependency failure, configuration precedence, version skew, and upgrades with active operations.
3. Inspect NATS traces and execute negative tests at remote resource owners.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P03-T05"></a>

### P03-T05: Add declared storage, artifacts, secrets, workspace, process, policy, and decision handles without sharing raw service implementations or an unrestricted container.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P02-GATE, P03-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Add declared storage, artifacts, secrets, workspace, process, policy, and decision handles without sharing raw service implementations or an unrestricted container.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Add declared storage, artifacts, secrets, workspace, process, policy, and decision handles without sharing raw service implementations or an unrestricted container.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P03-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Add declared storage, artifacts, secrets, workspace, process, policy, and decision handles without sharing raw service implementations or an unrestricted container.
2. P03-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P03-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P03-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run an independent author exercise using only published SDK/docs.
2. Test lifecycle/resource leaks, dependency failure, configuration precedence, version skew, and upgrades with active operations.
3. Inspect NATS traces and execute negative tests at remote resource owners.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P03-T06"></a>

### P03-T06: Build starter SDKs and conformance tooling in at least two selected languages

**Status:** planned. **Owner:** Codex.

**Dependencies:** P02-GATE, P03-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Build starter SDKs and conformance tooling in at least two selected languages. Provide install/upgrade/disable/uninstall and drain behavior.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Build starter SDKs and conformance tooling in at least two selected languages. Provide install/upgrade/disable/uninstall and drain behavior.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P03-T06-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Build starter SDKs and conformance tooling in at least two selected languages. Provide install/upgrade/disable/uninstall and drain behavior.
2. P03-T06-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P03-T06-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P03-T06-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run an independent author exercise using only published SDK/docs.
2. Test lifecycle/resource leaks, dependency failure, configuration precedence, version skew, and upgrades with active operations.
3. Inspect NATS traces and execute negative tests at remote resource owners.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P03-T07"></a>

### P03-T07: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P02-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P03-T07-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P03-T07-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P03-T07-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P03-T07-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run an independent author exercise using only published SDK/docs.
2. Test lifecycle/resource leaks, dependency failure, configuration precedence, version skew, and upgrades with active operations.
3. Inspect NATS traces and execute negative tests at remote resource owners.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P03-GATE"></a>

### P03-GATE: Verify and accept P03

**Status:** planned. **Owner:** Codex.

**Dependencies:** P03-T01, P03-T02, P03-T03, P03-T04, P03-T05, P03-T06, P03-T07.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Plugin manifest and SDK reference
2. Conformance matrix and author tutorial
3. Nested-package/lifecycle test report
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P03-GATE-AC01: Both child package modes install and activate correctly. Removing one parent retains independent children used elsewhere.
2. P03-GATE-AC02: Two concurrent users cannot overwrite an ambient current-user/current-project value. A child cannot widen its grant or forge logger identity.
3. P03-GATE-AC03: Dependency cycles, missing versions, partial initialization, and stale handles fail deterministically and clean up resources.
4. P03-GATE-AC04: A plugin in each selected language passes the same contract fixtures and interacts with another plugin over NATS.
5. P03-GATE-AC05: The protected kernel has no replacement option in package management. Trusted native code is accurately documented as unsandboxed.
6. P03-GATE-AC06: Existing federation plugin lifecycle, command registry, contributions and context each have a documented reuse or justified replacement decision. Existing bundled plugins pass compatibility fixtures before their old runtime path is disabled.
7. P03-GATE-AC07: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
8. P03-GATE-AC08: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run an independent author exercise using only published SDK/docs.
2. Test lifecycle/resource leaks, dependency failure, configuration precedence, version skew, and upgrades with active operations.
3. Inspect NATS traces and execute negative tests at remote resource owners.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P04. Identity, projects, durable state, and workspaces

Multiple users and projects share a hub with explicit authority and durable ownership.

**Epic acceptance criteria**

- **P04-AC01:** Cross-user/project/organization negative tests deny unauthorized commands, subscriptions, files, artifacts, and secret resolution.
- **P04-AC02:** A committed NATS record or qualified same-stream batch preserves the state change, provenance and recoverable outgoing intent. Crashes before or after commit, publication or acknowledgment converge to the recorded operation without a second business effect.
- **P04-AC03:** Duplicate delivery with the same operation ID and payload hash returns the existing outcome without allocating a second workspace or task. Reusing an operation ID with a different payload is rejected as a conflict.
- **P04-AC04:** Backup/restore preserves ownership and result provenance. Migration fences the former writer, preserves stable IDs, dirty worktrees and unmerged branches, and verifies imported records before admitting new writes.
- **P04-AC05:** Node revocation and secret rotation have tested online behavior and explicit offline limits.
- **P04-AC06:** Deleting or corrupting an optional SQL index or derived KV view is recoverable from retained authoritative records and validated checkpoints. Rebuild preserves authorized results and cursors, detects missing history, and cannot launch work or replay external effects.
- **P04-AC07:** Task history and reservations survive work-queue acknowledgment and presence expiry. Storage/API permissions prevent unauthorized reads and raw writes. Stale views expose their revision and cannot authorize a claim, approval or reassignment.
- **P04-AC08:** Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.

<a id="P04-T01"></a>

### P04-T01: Implement human, device, service, and plugin identities, enrollment/revocation, organization/project membership, permissions, approvals, and audit outside the kernel

**Status:** planned. **Owner:** Codex.

**Dependencies:** P03-GATE, P04-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement human, device, service, and plugin identities, enrollment/revocation, organization/project membership, permissions, approvals, and audit outside the kernel. Distinguish allowed, denied, and review-required actions; ordinary approval cannot override a hard denial.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-001 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.
7. Reuse P01 HUB-01-C02 assertion mappings and immutable baseline artifacts when comparing the actual production adapter; retain refused inputs, original identity fields and every failed/skipped outcome.

**Deliverables**

1. Implement human, device, service, and plugin identities, enrollment/revocation, organization/project membership, permissions, approvals, and audit outside the kernel. Distinguish allowed, denied, and review-required actions; ordinary approval cannot override a hard denial.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P04-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement human, device, service, and plugin identities, enrollment/revocation, organization/project membership, permissions, approvals, and audit outside the kernel. Distinguish allowed, denied, and review-required actions; ordinary approval cannot override a hard denial.
2. P04-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P04-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P04-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.
5. P04-T01-AC05: Execute the retained identity/generation/local/remote selection fixtures against the actual production legacy-to-v1 identity adapter. Preserve original aliases with source hub and generation, reject collisions across organizations/projects/instances, and verify same short names do not change scoped recipients. P01 characterization is not migration acceptance.

**Verification**

1. Run the permission matrix against application owners and real broker accounts. Run an adversarial worker that attempts cross-project file, process, network, and credential access under the supported execution profile.
2. Inject failures before/after commit and publish acknowledgment, exhaust disk/quota, and restore from backup.
3. Run concurrency tests against every supported storage provider. Reject a provider that lacks required guarantees.
4. Run FAIL-42 through FAIL-48, delete projections, corrupt a checkpoint, simulate lagging views and test direct broker APIs. Verify snapshots and retained history form a complete recovery chain.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P04-T02"></a>

### P04-T02: Implement NATS-backed persistence through ordinary domain-owner plugins

**Status:** planned. **Owner:** Codex.

**Dependencies:** P03-GATE, P04-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement NATS-backed persistence through ordinary domain-owner plugins. Commit validated state changes, provenance, operation outcomes and recoverable outgoing intent together in the owning JetStream record or qualified same-stream batch. Provide KV configuration/current views, Object Store evidence references, scoped access, retention and backup/restore.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-002, AMX-BASE-003, AMX-BASE-006 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Implement NATS-backed persistence through ordinary domain-owner plugins. Commit validated state changes, provenance, operation outcomes and recoverable outgoing intent together in the owning JetStream record or qualified same-stream batch. Provide KV configuration/current views, Object Store evidence references, scoped access, retention and backup/restore.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P04-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement NATS-backed persistence through ordinary domain-owner plugins. Commit validated state changes, provenance, operation outcomes and recoverable outgoing intent together in the owning JetStream record or qualified same-stream batch. Provide KV configuration/current views, Object Store evidence references, scoped access, retention and backup/restore.
2. P04-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P04-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P04-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the permission matrix against application owners and real broker accounts. Run an adversarial worker that attempts cross-project file, process, network, and credential access under the supported execution profile.
2. Inject failures before/after commit and publish acknowledgment, exhaust disk/quota, and restore from backup.
3. Run concurrency tests against every supported storage provider. Reject a provider that lacks required guarantees.
4. Run FAIL-42 through FAIL-48, delete projections, corrupt a checkpoint, simulate lagging views and test direct broker APIs. Verify snapshots and retained history form a complete recovery chain.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P04-T03"></a>

### P04-T03: Provide scoped workspace/Git/worktree management, configuration, connection/secret references, quotas, and resource reservations.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P03-GATE, P04-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Provide scoped workspace/Git/worktree management, configuration, connection/secret references, quotas, and resource reservations.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Provide scoped workspace/Git/worktree management, configuration, connection/secret references, quotas, and resource reservations.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P04-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Provide scoped workspace/Git/worktree management, configuration, connection/secret references, quotas, and resource reservations.
2. P04-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P04-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P04-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the permission matrix against application owners and real broker accounts. Run an adversarial worker that attempts cross-project file, process, network, and credential access under the supported execution profile.
2. Inject failures before/after commit and publish acknowledgment, exhaust disk/quota, and restore from backup.
3. Run concurrency tests against every supported storage provider. Reject a provider that lacks required guarantees.
4. Run FAIL-42 through FAIL-48, delete projections, corrupt a checkpoint, simulate lagging views and test direct broker APIs. Verify snapshots and retained history form a complete recovery chain.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P04-T04"></a>

### P04-T04: Provide local single-user defaults and self-hosted identity configuration using the same contracts.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P03-GATE, P04-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Provide local single-user defaults and self-hosted identity configuration using the same contracts.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Provide local single-user defaults and self-hosted identity configuration using the same contracts.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P04-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Provide local single-user defaults and self-hosted identity configuration using the same contracts.
2. P04-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P04-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P04-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the permission matrix against application owners and real broker accounts. Run an adversarial worker that attempts cross-project file, process, network, and credential access under the supported execution profile.
2. Inject failures before/after commit and publish acknowledgment, exhaust disk/quota, and restore from backup.
3. Run concurrency tests against every supported storage provider. Reject a provider that lacks required guarantees.
4. Run FAIL-42 through FAIL-48, delete projections, corrupt a checkpoint, simulate lagging views and test direct broker APIs. Verify snapshots and retained history form a complete recovery chain.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P04-T05"></a>

### P04-T05: Implement the approved worker execution profile so mutually untrusted task code cannot share unrestricted access to another user's files or credentials

**Status:** planned. **Owner:** Codex.

**Dependencies:** P03-GATE, P04-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement the approved worker execution profile so mutually untrusted task code cannot share unrestricted access to another user's files or credentials. Qualify OS/container/host separation independently of the later third-party-plugin sandbox.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement the approved worker execution profile so mutually untrusted task code cannot share unrestricted access to another user's files or credentials. Qualify OS/container/host separation independently of the later third-party-plugin sandbox.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P04-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement the approved worker execution profile so mutually untrusted task code cannot share unrestricted access to another user's files or credentials. Qualify OS/container/host separation independently of the later third-party-plugin sandbox.
2. P04-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P04-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P04-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the permission matrix against application owners and real broker accounts. Run an adversarial worker that attempts cross-project file, process, network, and credential access under the supported execution profile.
2. Inject failures before/after commit and publish acknowledgment, exhaust disk/quota, and restore from backup.
3. Run concurrency tests against every supported storage provider. Reject a provider that lacks required guarantees.
4. Run FAIL-42 through FAIL-48, delete projections, corrupt a checkpoint, simulate lagging views and test direct broker APIs. Verify snapshots and retained history form a complete recovery chain.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P04-T06"></a>

### P04-T06: Build optional SQLite/SQL query indexes and caches from committed records and versioned checkpoints

**Status:** planned. **Owner:** Codex.

**Dependencies:** P03-GATE, P04-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Build optional SQLite/SQL query indexes and caches from committed records and versioned checkpoints. Record consumed sequence and schema version, expose freshness, rebuild without commands or side effects, and prevent projections from granting execution or approval.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-006 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Build optional SQLite/SQL query indexes and caches from committed records and versioned checkpoints. Record consumed sequence and schema version, expose freshness, rebuild without commands or side effects, and prevent projections from granting execution or approval.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P04-T06-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Build optional SQLite/SQL query indexes and caches from committed records and versioned checkpoints. Record consumed sequence and schema version, expose freshness, rebuild without commands or side effects, and prevent projections from granting execution or approval.
2. P04-T06-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P04-T06-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P04-T06-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the permission matrix against application owners and real broker accounts. Run an adversarial worker that attempts cross-project file, process, network, and credential access under the supported execution profile.
2. Inject failures before/after commit and publish acknowledgment, exhaust disk/quota, and restore from backup.
3. Run concurrency tests against every supported storage provider. Reject a provider that lacks required guarantees.
4. Run FAIL-42 through FAIL-48, delete projections, corrupt a checkpoint, simulate lagging views and test direct broker APIs. Verify snapshots and retained history form a complete recovery chain.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P04-T07"></a>

### P04-T07: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P03-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P04-T07-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P04-T07-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P04-T07-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P04-T07-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run the permission matrix against application owners and real broker accounts. Run an adversarial worker that attempts cross-project file, process, network, and credential access under the supported execution profile.
2. Inject failures before/after commit and publish acknowledgment, exhaust disk/quota, and restore from backup.
3. Run concurrency tests against every supported storage provider. Reject a provider that lacks required guarantees.
4. Run FAIL-42 through FAIL-48, delete projections, corrupt a checkpoint, simulate lagging views and test direct broker APIs. Verify snapshots and retained history form a complete recovery chain.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P04-GATE"></a>

### P04-GATE: Verify and accept P04

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-T01, P04-T02, P04-T03, P04-T04, P04-T05, P04-T06, P04-T07.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Threat model and permission matrix
2. Storage capability and migration contracts
3. Recovery and isolation reports
4. Authoritative record, KV and object inventory with retention, checkpoint and projection rebuild evidence
5. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P04-GATE-AC01: Cross-user/project/organization negative tests deny unauthorized commands, subscriptions, files, artifacts, and secret resolution.
2. P04-GATE-AC02: A committed NATS record or qualified same-stream batch preserves the state change, provenance and recoverable outgoing intent. Crashes before or after commit, publication or acknowledgment converge to the recorded operation without a second business effect.
3. P04-GATE-AC03: Duplicate delivery with the same operation ID and payload hash returns the existing outcome without allocating a second workspace or task. Reusing an operation ID with a different payload is rejected as a conflict.
4. P04-GATE-AC04: Backup/restore preserves ownership and result provenance. Migration fences the former writer, preserves stable IDs, dirty worktrees and unmerged branches, and verifies imported records before admitting new writes.
5. P04-GATE-AC05: Node revocation and secret rotation have tested online behavior and explicit offline limits.
6. P04-GATE-AC06: Deleting or corrupting an optional SQL index or derived KV view is recoverable from retained authoritative records and validated checkpoints. Rebuild preserves authorized results and cursors, detects missing history, and cannot launch work or replay external effects.
7. P04-GATE-AC07: Task history and reservations survive work-queue acknowledgment and presence expiry. Storage/API permissions prevent unauthorized reads and raw writes. Stale views expose their revision and cannot authorize a claim, approval or reassignment.
8. P04-GATE-AC08: Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.
9. P04-GATE-AC09: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
10. P04-GATE-AC10: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run the permission matrix against application owners and real broker accounts. Run an adversarial worker that attempts cross-project file, process, network, and credential access under the supported execution profile.
2. Inject failures before/after commit and publish acknowledgment, exhaust disk/quota, and restore from backup.
3. Run concurrency tests against every supported storage provider. Reject a provider that lacks required guarantees.
4. Run FAIL-42 through FAIL-48, delete projections, corrupt a checkpoint, simulate lagging views and test direct broker APIs. Verify snapshots and retained history form a complete recovery chain.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P05. Local orchestration and evidence-based completion

A developer can finish a reviewable software task through durable coordinated work.

**Epic acceptance criteria**

- **P05-AC01:** A complete fixture workflow creates a plan, delegates tasks, executes in isolated workspaces, validates the result, and returns reviewable evidence.
- **P05-AC02:** Two developers working on different or shared projects do not steal each other's claims, sessions, workspaces, or tool credentials.
- **P05-AC03:** No task becomes accepted from terminal text, process exit, or a worker's self-reported done event alone.
- **P05-AC04:** A crashed or disconnected worker leaves a recoverable known or explicitly unknown attempt. Retry preserves the prior attempt and its effects.
- **P05-AC05:** Every P05-owned legacy functional group has parity evidence or an explicit replacement and data migration decision. Later client, dashboard, federation, and domain groups have an owned inventory and migration plan, with parity gated in their own phases. Changed artifacts invalidate bound approvals, and migration preserves distinct board, run, hub-work, and shared-board identities.
- **P05-AC06:** Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.

<a id="P05-T01"></a>

### P05-T01: Reuse the existing task, dispatch, run, coordination and courier behavior behind the new contracts

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-GATE, P05-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Reuse the existing task, dispatch, run, coordination and courier behavior behind the new contracts. Replace persistence and coupling only at recorded boundaries, retaining existing test assertions and data relationships.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Reuse the existing task, dispatch, run, coordination and courier behavior behind the new contracts. Replace persistence and coupling only at recorded boundaries, retaining existing test assertions and data relationships.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P05-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Reuse the existing task, dispatch, run, coordination and courier behavior behind the new contracts. Replace persistence and coupling only at recorded boundaries, retaining existing test assertions and data relationships.
2. P05-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P05-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P05-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P05-T02"></a>

### P05-T02: Implement project plans, tasks, dependencies, boards, role/agent/team definitions, assignment, run/attempt state, claims, resource scheduling, and explicit acceptance.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-GATE, P05-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement project plans, tasks, dependencies, boards, role/agent/team definitions, assignment, run/attempt state, claims, resource scheduling, and explicit acceptance.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement project plans, tasks, dependencies, boards, role/agent/team definitions, assignment, run/attempt state, claims, resource scheduling, and explicit acceptance.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P05-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement project plans, tasks, dependencies, boards, role/agent/team definitions, assignment, run/attempt state, claims, resource scheduling, and explicit acceptance.
2. P05-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P05-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P05-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P05-T03"></a>

### P05-T03: Implement supervised workers, session resume capability, isolated worktrees, tool calls, messages, handoffs, progress, conversation records, artifacts, validation, and review workflows.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-GATE, P05-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement supervised workers, session resume capability, isolated worktrees, tool calls, messages, handoffs, progress, conversation records, artifacts, validation, and review workflows.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement supervised workers, session resume capability, isolated worktrees, tool calls, messages, handoffs, progress, conversation records, artifacts, validation, and review workflows.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P05-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement supervised workers, session resume capability, isolated worktrees, tool calls, messages, handoffs, progress, conversation records, artifacts, validation, and review workflows.
2. P05-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P05-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P05-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P05-T04"></a>

### P05-T04: Separate provider/process exit, reported completion, verified evidence, and owner acceptance

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-GATE, P05-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Separate provider/process exit, reported completion, verified evidence, and owner acceptance. Model cancellation-requested, canceled, failed, and unknown states.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-005 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Separate provider/process exit, reported completion, verified evidence, and owner acceptance. Model cancellation-requested, canceled, failed, and unknown states.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P05-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Separate provider/process exit, reported completion, verified evidence, and owner acceptance. Model cancellation-requested, canceled, failed, and unknown states.
2. P05-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P05-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P05-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P05-T05"></a>

### P05-T05: Port existing journal/notice/dead-letter, search/knowledge, code sharing, cost/resource, and orchestration evaluation behavior behind plugins.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-GATE, P05-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Port existing journal/notice/dead-letter, search/knowledge, code sharing, cost/resource, and orchestration evaluation behavior behind plugins.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Port existing journal/notice/dead-letter, search/knowledge, code sharing, cost/resource, and orchestration evaluation behavior behind plugins.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P05-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Port existing journal/notice/dead-letter, search/knowledge, code sharing, cost/resource, and orchestration evaluation behavior behind plugins.
2. P05-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P05-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P05-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P05-T06"></a>

### P05-T06: Produce a software-change workflow from request through test evidence and a reviewable diff/PR proposal

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-GATE, P05-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Produce a software-change workflow from request through test evidence and a reviewable diff/PR proposal. Publishing and merging follow explicit permissions.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Produce a software-change workflow from request through test evidence and a reviewable diff/PR proposal. Publishing and merging follow explicit permissions.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P05-T06-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Produce a software-change workflow from request through test evidence and a reviewable diff/PR proposal. Publishing and merging follow explicit permissions.
2. P05-T06-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P05-T06-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P05-T06-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P05-T07"></a>

### P05-T07: Preserve epics, sprints, ADR/capability proposal records, WIP/readiness gates, notifications, objections, and independent reviewer policy

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-GATE, P05-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Preserve epics, sprints, ADR/capability proposal records, WIP/readiness gates, notifications, objections, and independent reviewer policy. Bind reviews to immutable repository/commit/artifact identities across multiple repositories.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Preserve epics, sprints, ADR/capability proposal records, WIP/readiness gates, notifications, objections, and independent reviewer policy. Bind reviews to immutable repository/commit/artifact identities across multiple repositories.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P05-T07-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Preserve epics, sprints, ADR/capability proposal records, WIP/readiness gates, notifications, objections, and independent reviewer policy. Bind reviews to immutable repository/commit/artifact identities across multiple repositories.
2. P05-T07-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P05-T07-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P05-T07-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P05-T08"></a>

### P05-T08: Persist orchestration transitions through the NATS-owning domain contracts

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-GATE, P05-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Persist orchestration transitions through the NATS-owning domain contracts. Drive dispatch and result publication from recoverable committed intent, and keep queue acknowledgment separate from task completion and origin acceptance.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-002, AMX-BASE-003 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Persist orchestration transitions through the NATS-owning domain contracts. Drive dispatch and result publication from recoverable committed intent, and keep queue acknowledgment separate from task completion and origin acceptance.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P05-T08-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Persist orchestration transitions through the NATS-owning domain contracts. Drive dispatch and result publication from recoverable committed intent, and keep queue acknowledgment separate from task completion and origin acceptance.
2. P05-T08-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P05-T08-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P05-T08-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P05-T09"></a>

### P05-T09: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P04-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P05-T09-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P05-T09-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P05-T09-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P05-T09-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P05-GATE"></a>

### P05-GATE: Verify and accept P05

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-T01, P05-T02, P05-T03, P05-T04, P05-T05, P05-T06, P05-T07, P05-T08, P05-T09.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. End-to-end workflow recording
2. Completion/ownership invariant report
3. Legacy parity and migration checklist
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P05-GATE-AC01: A complete fixture workflow creates a plan, delegates tasks, executes in isolated workspaces, validates the result, and returns reviewable evidence.
2. P05-GATE-AC02: Two developers working on different or shared projects do not steal each other's claims, sessions, workspaces, or tool credentials.
3. P05-GATE-AC03: No task becomes accepted from terminal text, process exit, or a worker's self-reported done event alone.
4. P05-GATE-AC04: A crashed or disconnected worker leaves a recoverable known or explicitly unknown attempt. Retry preserves the prior attempt and its effects.
5. P05-GATE-AC05: Every P05-owned legacy functional group has parity evidence or an explicit replacement and data migration decision. Later client, dashboard, federation, and domain groups have an owned inventory and migration plan, with parity gated in their own phases. Changed artifacts invalidate bound approvals, and migration preserves distinct board, run, hub-work, and shared-board identities.
6. P05-GATE-AC06: Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.
7. P05-GATE-AC07: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
8. P05-GATE-AC08: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run normal, failure, retry, cancellation, resume, parallel-team, cross-repo, and swarm-style scenario suites.
2. Inject crash windows around work attribution and result publication identified in the repository analysis.
3. Use real CLI worker smoke tests plus deterministic fake workers for exhaustive state transitions.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P06. Agent-client entry points and portable tooling

Developers use Agentmux from their preferred supported client.

**Epic acceptance criteria**

- **P06-AC01:** Each supported client can submit a task, inspect progress/evidence, participate in required approvals, and retrieve the result.
- **P06-AC02:** Unsupported event capture, cancellation, or compaction reports an explicit capability limit instead of simulating success. Windows/WSL interop failures and unsupported client/path combinations remain explicit; a Linux fallback or version-only check cannot simulate a supported workflow.
- **P06-AC03:** Closing the originating client or observer does not duplicate or implicitly terminate durable work.
- **P06-AC04:** Fresh-user install and uninstall preserve unrelated client settings and secrets. Under WSL-CLIENT-01, Windows retains sole ownership of each Windows-installed AI client and its updates, authentication and configuration; no duplicate Linux installation or credential copying is introduced.
- **P06-AC05:** All existing supported harness commands, session safeguards, agent definitions, provider setup methods and integration workflows have passing comparisons or an explicitly approved capability change. Retained and added tests cover modal decisions, idle cleanup, credential refresh, WSL paths and external-write uncertainty. Direct Windows and WSL/tmux launches resolve the same installed version before and after a Windows-only update. Stable launchers survive updates without version-specific binary paths; arguments and working directories preserve spaces, quoting, mounted Windows paths and WSL UNC paths.
- **P06-AC06:** Installing and configuring the Agentmux plugin makes each supported terminal/client launch automatically start or reuse the selected stack and show its instance and authorized hub summary. Actual-host tests qualify startup hooks or a clearly named installed launcher; manual commands cannot stand in for promised automatic launch. Windows-owned client callbacks reach the selected WSL hub, and concurrent tmux workers/external clients preserve distinct project, hub, session and host identities without cross-session configuration or callbacks.
- **P06-AC07:** Client startup preserves MCP/JSON-RPC framing, never prints secrets and avoids recursive starts by managed workers. Closing a terminal leaves shared work running; an explicit authorized stop follows the drain policy. Failed prerequisites report recovery steps without silently installing privileged software or changing client settings.

<a id="P06-T01"></a>

### P06-T01: Extend current CLI, MCP, provider and workspace tooling

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-GATE, P06-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Extend current CLI, MCP, provider and workspace tooling. Preserve command semantics, safe prompt handling, session cleanup boundaries and credential setup; expose new scopes through the existing entry points where compatible.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Qualify REPO-01-C01 in actual supported agent hosts: confirm shared instructions and the branch/merge restriction are delivered, preserve user settings, and retain per-host/version evidence. P00 static review is not a substitute.
7. Implement durable WSL symlinks or wrappers resolving each Windows-owned AI client. Preserve exact arguments and working directories, including spaces, quoting, mounted Windows paths and WSL UNC paths; do not install a duplicate Linux client.

**Deliverables**

1. Extend current CLI, MCP, provider and workspace tooling. Preserve command semantics, safe prompt handling, session cleanup boundaries and credential setup; expose new scopes through the existing entry points where compatible.
2. Focused regression evidence and affected compatibility/migration records
3. WSL-CLIENT-01 direct-Windows/WSL identity and update parity, configuration ownership, argument/path, callback and concurrent-session evidence

**Acceptance criteria**

1. P06-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Extend current CLI, MCP, provider and workspace tooling. Preserve command semantics, safe prompt handling, session cleanup boundaries and credential setup; expose new scopes through the existing entry points where compatible. WSL-CLIENT-01: Implement durable WSL symlinks or wrappers resolving each Windows-owned AI client. Preserve exact arguments and working directories, including spaces, quoting, mounted Windows paths and WSL UNC paths; do not install a duplicate Linux client.
2. P06-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope. WSL-CLIENT-01 requires actual Windows/WSL workflow evidence; a version-only check, Linux-client substitution or skipped interop case cannot count as success.
3. P06-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P06-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Execute the same reference workflow on every pinned client version in the support matrix.
2. Test reconnect, authentication expiry, missing tool, malformed MCP request, and client shutdown.
3. Review provider commercial integration terms before promising a supported paid distribution.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Run cold, warm and concurrent launches on each advertised client/OS version, including separate WSL sessions and paths with spaces. Capture client-visible status and protocol streams; exercise FAIL-60–FAIL-61.
6. Execute WSL-CLIENT-01 on each supported Windows-installed client: compare direct/WSL version and installation identity, perform a Windows-only update and repeat, verify Windows auth/config ownership without secret copying, test exact arguments and working directories with spaces and WSL UNC paths, verify selected-hub callbacks, and run concurrent tmux/host sessions. Capture actual failures and recovery; retain native macOS/Linux runtime tests separately.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P06-T02"></a>

### P06-T02: Provide stable CLI and MCP interfaces generated from declared command contracts, with discoverable resources and error semantics.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-GATE, P06-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Provide stable CLI and MCP interfaces generated from declared command contracts, with discoverable resources and error semantics.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Provide stable CLI and MCP interfaces generated from declared command contracts, with discoverable resources and error semantics.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P06-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Provide stable CLI and MCP interfaces generated from declared command contracts, with discoverable resources and error semantics.
2. P06-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P06-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P06-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Execute the same reference workflow on every pinned client version in the support matrix.
2. Test reconnect, authentication expiry, missing tool, malformed MCP request, and client shutdown.
3. Review provider commercial integration terms before promising a supported paid distribution.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Run cold, warm and concurrent launches on each advertised client/OS version, including separate WSL sessions and paths with spaces. Capture client-visible status and protocol streams; exercise FAIL-60–FAIL-61.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P06-T03"></a>

### P06-T03: Package and test integrations for Claude Code, Codex CLI, Pi, and Claude Desktop using each host's documented capabilities.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-GATE, P06-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Package and test integrations for Claude Code, Codex CLI, Pi, and Claude Desktop using each host's documented capabilities.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Execute supported-client workflows from Windows and WSL/tmux against the same installation, compare version identity, perform a Windows-only update and repeat without editing version-specific paths. Record actual interop limitations and recovery steps.
7. Create and inspect stable WSL command symlinks for every supported Windows-installed client. Link to a supported Windows entry point or a forwarding launcher; resolve Windows-managed installation paths after updates and detect conflicting existing commands.

**Deliverables**

1. Package and test integrations for Claude Code, Codex CLI, Pi, and Claude Desktop using each host's documented capabilities.
2. Focused regression evidence and affected compatibility/migration records
3. WSL-CLIENT-01 direct-Windows/WSL identity and update parity, configuration ownership, argument/path, callback and concurrent-session evidence

**Acceptance criteria**

1. P06-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Package and test integrations for Claude Code, Codex CLI, Pi, and Claude Desktop using each host's documented capabilities. WSL-CLIENT-01: Execute supported-client workflows from Windows and WSL/tmux against the same installation, compare version identity, perform a Windows-only update and repeat without editing version-specific paths. Record actual interop limitations and recovery steps.
2. P06-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope. WSL-CLIENT-01 requires actual Windows/WSL workflow evidence; a version-only check, Linux-client substitution or skipped interop case cannot count as success.
3. P06-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P06-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.
5. P06-T03-AC05: Actual-host evidence identifies each WSL symlink and resolved Windows installation. A Windows-only update is visible through the unchanged link/launcher; no duplicate Linux client or version-pinned replacement is installed. Conflicting user commands are detected and preserved.

**Verification**

1. Execute the same reference workflow on every pinned client version in the support matrix.
2. Test reconnect, authentication expiry, missing tool, malformed MCP request, and client shutdown.
3. Review provider commercial integration terms before promising a supported paid distribution.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Run cold, warm and concurrent launches on each advertised client/OS version, including separate WSL sessions and paths with spaces. Capture client-visible status and protocol streams; exercise FAIL-60–FAIL-61.
6. Execute WSL-CLIENT-01 on each supported Windows-installed client: compare direct/WSL version and installation identity, perform a Windows-only update and repeat, verify Windows auth/config ownership without secret copying, test exact arguments and working directories with spaces and WSL UNC paths, verify selected-hub callbacks, and run concurrent tmux/host sessions. Capture actual failures and recovery; retain native macOS/Linux runtime tests separately.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P06-T04"></a>

### P06-T04: Distinguish external client sessions submitting work from Agentmux-managed worker sessions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-GATE, P06-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Distinguish external client sessions submitting work from Agentmux-managed worker sessions. Publish coverage for events, controls, resume, hooks, and compaction.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Run concurrent tmux workers and external Windows clients on separate projects/hubs. Verify session and host identity, correct callbacks and no cross-session configuration changes or result attribution.

**Deliverables**

1. Distinguish external client sessions submitting work from Agentmux-managed worker sessions. Publish coverage for events, controls, resume, hooks, and compaction.
2. Focused regression evidence and affected compatibility/migration records
3. WSL-CLIENT-01 direct-Windows/WSL identity and update parity, configuration ownership, argument/path, callback and concurrent-session evidence

**Acceptance criteria**

1. P06-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Distinguish external client sessions submitting work from Agentmux-managed worker sessions. Publish coverage for events, controls, resume, hooks, and compaction. WSL-CLIENT-01: Run concurrent tmux workers and external Windows clients on separate projects/hubs. Verify session and host identity, correct callbacks and no cross-session configuration changes or result attribution.
2. P06-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope. WSL-CLIENT-01 requires actual Windows/WSL workflow evidence; a version-only check, Linux-client substitution or skipped interop case cannot count as success.
3. P06-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P06-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Execute the same reference workflow on every pinned client version in the support matrix.
2. Test reconnect, authentication expiry, missing tool, malformed MCP request, and client shutdown.
3. Review provider commercial integration terms before promising a supported paid distribution.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Run cold, warm and concurrent launches on each advertised client/OS version, including separate WSL sessions and paths with spaces. Capture client-visible status and protocol streams; exercise FAIL-60–FAIL-61.
6. Execute WSL-CLIENT-01 on each supported Windows-installed client: compare direct/WSL version and installation identity, perform a Windows-only update and repeat, verify Windows auth/config ownership without secret copying, test exact arguments and working directories with spaces and WSL UNC paths, verify selected-hub callbacks, and run concurrent tmux/host sessions. Capture actual failures and recovery; retain native macOS/Linux runtime tests separately.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P06-T05"></a>

### P06-T05: Add setup, credential references, diagnostics, install checks, and client-specific documentation without silently replacing user configuration.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-GATE, P06-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Add setup, credential references, diagnostics, install checks, and client-specific documentation without silently replacing user configuration.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Keep authentication and configuration in their Windows-owned locations. Reference them through the Windows client without copying credentials or printing secrets; preserve unrelated settings during install, update and uninstall.
7. Record per-client Windows-owned auth/config locations and their native lookup or supported link mechanism. Verify Windows-side changes are visible from WSL without copying secrets or manual synchronization; record link permission failures and preserve unrelated files on removal.

**Deliverables**

1. Add setup, credential references, diagnostics, install checks, and client-specific documentation without silently replacing user configuration.
2. Focused regression evidence and affected compatibility/migration records
3. WSL-CLIENT-01 direct-Windows/WSL identity and update parity, configuration ownership, argument/path, callback and concurrent-session evidence

**Acceptance criteria**

1. P06-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Add setup, credential references, diagnostics, install checks, and client-specific documentation without silently replacing user configuration. WSL-CLIENT-01: Keep authentication and configuration in their Windows-owned locations. Reference them through the Windows client without copying credentials or printing secrets; preserve unrelated settings during install, update and uninstall.
2. P06-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope. WSL-CLIENT-01 requires actual Windows/WSL workflow evidence; a version-only check, Linux-client substitution or skipped interop case cannot count as success.
3. P06-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P06-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.
5. P06-T05-AC05: Windows and WSL use the same Windows-owned authentication/configuration files through native Windows lookup or supported links. Actual-host tests demonstrate change visibility without copying credentials or manual synchronization, preserve unrelated files, and record unsupported link mechanisms as unresolved rather than passing.

**Verification**

1. Execute the same reference workflow on every pinned client version in the support matrix.
2. Test reconnect, authentication expiry, missing tool, malformed MCP request, and client shutdown.
3. Review provider commercial integration terms before promising a supported paid distribution.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Run cold, warm and concurrent launches on each advertised client/OS version, including separate WSL sessions and paths with spaces. Capture client-visible status and protocol streams; exercise FAIL-60–FAIL-61.
6. Execute WSL-CLIENT-01 on each supported Windows-installed client: compare direct/WSL version and installation identity, perform a Windows-only update and repeat, verify Windows auth/config ownership without secret copying, test exact arguments and working directories with spaces and WSL UNC paths, verify selected-hub callbacks, and run concurrent tmux/host sessions. Capture actual failures and recovery; retain native macOS/Linux runtime tests separately.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P06-T06"></a>

### P06-T06: Inventory and qualify existing Grok/provider authentication methods and any Bedrock compatibility path

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-GATE, P06-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Inventory and qualify existing Grok/provider authentication methods and any Bedrock compatibility path. Migrate GitHub and Jira/Confluence workflows as tool plugins with explicit writes and credentials.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Inventory and qualify existing Grok/provider authentication methods and any Bedrock compatibility path. Migrate GitHub and Jira/Confluence workflows as tool plugins with explicit writes and credentials.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P06-T06-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Inventory and qualify existing Grok/provider authentication methods and any Bedrock compatibility path. Migrate GitHub and Jira/Confluence workflows as tool plugins with explicit writes and credentials.
2. P06-T06-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P06-T06-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P06-T06-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Execute the same reference workflow on every pinned client version in the support matrix.
2. Test reconnect, authentication expiry, missing tool, malformed MCP request, and client shutdown.
3. Review provider commercial integration terms before promising a supported paid distribution.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Run cold, warm and concurrent launches on each advertised client/OS version, including separate WSL sessions and paths with spaces. Capture client-visible status and protocol streams; exercise FAIL-60–FAIL-61.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P06-T07"></a>

### P06-T07: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P06-T07-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P06-T07-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P06-T07-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P06-T07-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Execute the same reference workflow on every pinned client version in the support matrix.
2. Test reconnect, authentication expiry, missing tool, malformed MCP request, and client shutdown.
3. Review provider commercial integration terms before promising a supported paid distribution.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Run cold, warm and concurrent launches on each advertised client/OS version, including separate WSL sessions and paths with spaces. Capture client-visible status and protocol streams; exercise FAIL-60–FAIL-61.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P06-T08"></a>

### P06-T08: Wire LOCAL-01 ensure-running into each supported terminal/client startup integration

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-GATE, P06-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Wire LOCAL-01 ensure-running into each supported terminal/client startup integration. Show one concise status summary with dashboard access; provide structured status for clients, suppress recursive bootstrap in managed workers, and keep protocol stdout free of banners.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Verify Windows client startup and callbacks reach the selected WSL hub across cold, warm and concurrent launches, preserving CLI/MCP framing and authorized instance/hub status.

**Deliverables**

1. Wire LOCAL-01 ensure-running into each supported terminal/client startup integration. Show one concise status summary with dashboard access; provide structured status for clients, suppress recursive bootstrap in managed workers, and keep protocol stdout free of banners.
2. Focused regression evidence and affected compatibility/migration records
3. WSL-CLIENT-01 direct-Windows/WSL identity and update parity, configuration ownership, argument/path, callback and concurrent-session evidence

**Acceptance criteria**

1. P06-T08-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Wire LOCAL-01 ensure-running into each supported terminal/client startup integration. Show one concise status summary with dashboard access; provide structured status for clients, suppress recursive bootstrap in managed workers, and keep protocol stdout free of banners. WSL-CLIENT-01: Verify Windows client startup and callbacks reach the selected WSL hub across cold, warm and concurrent launches, preserving CLI/MCP framing and authorized instance/hub status.
2. P06-T08-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope. WSL-CLIENT-01 requires actual Windows/WSL workflow evidence; a version-only check, Linux-client substitution or skipped interop case cannot count as success.
3. P06-T08-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P06-T08-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Execute the same reference workflow on every pinned client version in the support matrix.
2. Test reconnect, authentication expiry, missing tool, malformed MCP request, and client shutdown.
3. Review provider commercial integration terms before promising a supported paid distribution.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Run cold, warm and concurrent launches on each advertised client/OS version, including separate WSL sessions and paths with spaces. Capture client-visible status and protocol streams; exercise FAIL-60–FAIL-61.
6. Execute WSL-CLIENT-01 on each supported Windows-installed client: compare direct/WSL version and installation identity, perform a Windows-only update and repeat, verify Windows auth/config ownership without secret copying, test exact arguments and working directories with spaces and WSL UNC paths, verify selected-hub callbacks, and run concurrent tmux/host sessions. Capture actual failures and recovery; retain native macOS/Linux runtime tests separately.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P06-VIDEO-E1"></a>

### P06-VIDEO-E1: Declarative agent-lifecycle hook contributions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P05-GATE, P06-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Declarative agent-lifecycle hook contributions
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P06-VIDEO-E1-AC01: Unsupported hooks neither load nor pretend to execute; callable tools still work where supported.
2. P06-VIDEO-E1-AC02: Outage/failure of a semantic check never bypasses deterministic denial or silently changes host security policy.
3. P06-VIDEO-E1-AC03: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
4. P06-VIDEO-E1-AC04: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-E1",
  "title": "Declarative agent-lifecycle hook contributions",
  "description": "A plugin can contribute reviewed checks to supported pre-tool, post-tool, end-of-turn and pre-compaction hooks. The runtime records exact capability coverage per client. Deterministic denials execute independently; a model outage produces the configured review/fallback outcome. For clients without hooks, expose only the supported tools and observations."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P06-GATE"></a>

### P06-GATE: Verify and accept P06

**Status:** planned. **Owner:** Codex.

**Dependencies:** P06-T01, P06-T02, P06-T03, P06-T04, P06-T05, P06-T06, P06-T07, P06-T08, P06-VIDEO-E1.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.
5. Review WSL-CLIENT-01 evidence at this phase boundary: all required direct Windows/WSL installation, update, config/auth, path, callback and concurrent-session proofs.

**Deliverables**

1. Actual-host compatibility matrix
2. CLI/MCP reference and setup guides
3. Per-client workflow results
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P06-GATE-AC01: Each supported client can submit a task, inspect progress/evidence, participate in required approvals, and retrieve the result. WSL-CLIENT-01 is included in this phase's evidence review, with no skipped-environment substitution.
2. P06-GATE-AC02: Unsupported event capture, cancellation, or compaction reports an explicit capability limit instead of simulating success.
3. P06-GATE-AC03: Closing the originating client or observer does not duplicate or implicitly terminate durable work.
4. P06-GATE-AC04: Fresh-user install and uninstall preserve unrelated client settings and secrets.
5. P06-GATE-AC05: All existing supported harness commands, session safeguards, agent definitions, provider setup methods and integration workflows have passing comparisons or an explicitly approved capability change. Retained and added tests cover modal decisions, idle cleanup, credential refresh, WSL paths and external-write uncertainty.
6. P06-GATE-AC06: Installing and configuring the Agentmux plugin makes each supported terminal/client launch automatically start or reuse the selected stack and show its instance and authorized hub summary. Actual-host tests qualify startup hooks or a clearly named installed launcher; manual commands cannot stand in for promised automatic launch.
7. P06-GATE-AC07: Client startup preserves MCP/JSON-RPC framing, never prints secrets and avoids recursive starts by managed workers. Closing a terminal leaves shared work running; an explicit authorized stop follows the drain policy. Failed prerequisites report recovery steps without silently installing privileged software or changing client settings.
8. P06-GATE-AC08: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
9. P06-GATE-AC09: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Execute the same reference workflow on every pinned client version in the support matrix.
2. Test reconnect, authentication expiry, missing tool, malformed MCP request, and client shutdown.
3. Review provider commercial integration terms before promising a supported paid distribution.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Run cold, warm and concurrent launches on each advertised client/OS version, including separate WSL sessions and paths with spaces. Capture client-visible status and protocol streams; exercise FAIL-60–FAIL-61.
6. Execute WSL-CLIENT-01 on each supported Windows-installed client: compare direct/WSL version and installation identity, perform a Windows-only update and repeat, verify Windows auth/config ownership without secret copying, test exact arguments and working directories with spaces and WSL UNC paths, verify selected-hub callbacks, and run concurrent tmux/host sessions. Capture actual failures and recovery; retain native macOS/Linux runtime tests separately.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P07. Existing dashboard: AG-UI and Atomic Design migration

Authorized users can understand work across agents, projects, and hubs.

**Epic acceptance criteria**

- **P07-AC01:** Refresh, reconnect, duplicate events, delayed events, and history gaps converge to the same authorized view without starting work.
- **P07-AC02:** An unauthorized user cannot access another project's snapshots, streams, conversation, or artifact by guessing an ID.
- **P07-AC03:** Every displayed completion or cancellation state distinguishes worker output from accepted/confirmed state.
- **P07-AC04:** Domain UI contributions use versioned registered components. Core views remain usable when an optional plugin fails.
- **P07-AC05:** Reusable component boundaries and accessibility checks pass for all launch views.
- **P07-AC06:** All ten existing dashboard views and their actions, terminal streams, saved preferences, editor conflicts, themes and integration panels have reviewed before/after evidence. Existing capabilities remain reachable until their replacements pass; AG-UI and component restructuring do not authorize dropping controls.
- **P07-AC07:** Terminal and dashboard status agree at the same source revision. Refresh and reconnect preserve explicit stale/unknown states, hide inaccessible hubs and do not start a second stack or grant additional control.

<a id="P07-T01"></a>

### P07-T01: Extend the existing dashboard incrementally with a NATS-facing interface plugin that maps authorized state/events to a pinned AG-UI contract for CopilotKit.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P06-GATE, P07-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Extend the existing dashboard incrementally with a NATS-facing interface plugin that maps authorized state/events to a pinned AG-UI contract for CopilotKit.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Extend the existing dashboard incrementally with a NATS-facing interface plugin that maps authorized state/events to a pinned AG-UI contract for CopilotKit.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P07-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Extend the existing dashboard incrementally with a NATS-facing interface plugin that maps authorized state/events to a pinned AG-UI contract for CopilotKit.
2. P07-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P07-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P07-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run multi-viewer browser tests, revoked-session tests, stream replay, and network interruptions.
2. Compare UI snapshots to authoritative records after each failure scenario.
3. Run component dependency checks, keyboard/screen-reader review, and visual regression tests.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Compare terminal and dashboard status snapshots, versions and timestamps, including absent federation support, no configured hubs, denied scope and stale observations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P07-T02"></a>

### P07-T02: Retain the ten existing views and their useful actions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P06-GATE, P07-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Retain the ten existing views and their useful actions. Extract reusable behavior and migrate components in slices; add plans, cross-hub activity, evidence, decision/cost views and domain slots without losing terminal or operator workflows.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Retain the ten existing views and their useful actions. Extract reusable behavior and migrate components in slices; add plans, cross-hub activity, evidence, decision/cost views and domain slots without losing terminal or operator workflows.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P07-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Retain the ten existing views and their useful actions. Extract reusable behavior and migrate components in slices; add plans, cross-hub activity, evidence, decision/cost views and domain slots without losing terminal or operator workflows.
2. P07-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P07-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P07-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run multi-viewer browser tests, revoked-session tests, stream replay, and network interruptions.
2. Compare UI snapshots to authoritative records after each failure scenario.
3. Run component dependency checks, keyboard/screen-reader review, and visual regression tests.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Compare terminal and dashboard status snapshots, versions and timestamps, including absent federation support, no configured hubs, denied scope and stale observations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P07-T03"></a>

### P07-T03: Use snapshots, ordered deltas, stable IDs/cursors, resynchronization, redaction, and explicit unknown/stale state.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P06-GATE, P07-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Use snapshots, ordered deltas, stable IDs/cursors, resynchronization, redaction, and explicit unknown/stale state.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Use snapshots, ordered deltas, stable IDs/cursors, resynchronization, redaction, and explicit unknown/stale state.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P07-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Use snapshots, ordered deltas, stable IDs/cursors, resynchronization, redaction, and explicit unknown/stale state.
2. P07-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P07-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P07-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run multi-viewer browser tests, revoked-session tests, stream replay, and network interruptions.
2. Compare UI snapshots to authoritative records after each failure scenario.
3. Run component dependency checks, keyboard/screen-reader review, and visual regression tests.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Compare terminal and dashboard status snapshots, versions and timestamps, including absent federation support, no configured hubs, denied scope and stale observations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P07-T04"></a>

### P07-T04: Use atoms, molecules, organisms, templates, and feature/page composition

**Status:** planned. **Owner:** Codex.

**Dependencies:** P06-GATE, P07-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Use atoms, molecules, organisms, templates, and feature/page composition. Implement keyboard, contrast, accessible names, empty/error/offline states.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Use atoms, molecules, organisms, templates, and feature/page composition. Implement keyboard, contrast, accessible names, empty/error/offline states.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P07-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Use atoms, molecules, organisms, templates, and feature/page composition. Implement keyboard, contrast, accessible names, empty/error/offline states.
2. P07-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P07-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P07-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run multi-viewer browser tests, revoked-session tests, stream replay, and network interruptions.
2. Compare UI snapshots to authoritative records after each failure scenario.
3. Run component dependency checks, keyboard/screen-reader review, and visual regression tests.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Compare terminal and dashboard status snapshots, versions and timestamps, including absent federation support, no configured hubs, denied scope and stale observations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P07-T05"></a>

### P07-T05: Include approvals and run controls only to the approved scope

**Status:** planned. **Owner:** Codex.

**Dependencies:** P06-GATE, P07-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Include approvals and run controls only to the approved scope. Commands always return to their authoritative owner over NATS.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Include approvals and run controls only to the approved scope. Commands always return to their authoritative owner over NATS.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P07-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Include approvals and run controls only to the approved scope. Commands always return to their authoritative owner over NATS.
2. P07-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P07-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P07-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run multi-viewer browser tests, revoked-session tests, stream replay, and network interruptions.
2. Compare UI snapshots to authoritative records after each failure scenario.
3. Run component dependency checks, keyboard/screen-reader review, and visual regression tests.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Compare terminal and dashboard status snapshots, versions and timestamps, including absent federation support, no configured hubs, denied scope and stale observations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P07-T06"></a>

### P07-T06: Read authorized NATS-backed views with source revisions/checkpoint cursors

**Status:** planned. **Owner:** Codex.

**Dependencies:** P06-GATE, P07-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Read authorized NATS-backed views with source revisions/checkpoint cursors. Show lag or rebuild status explicitly; destructive controls revalidate at the record owner instead of trusting cached display state.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Read authorized NATS-backed views with source revisions/checkpoint cursors. Show lag or rebuild status explicitly; destructive controls revalidate at the record owner instead of trusting cached display state.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P07-T06-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Read authorized NATS-backed views with source revisions/checkpoint cursors. Show lag or rebuild status explicitly; destructive controls revalidate at the record owner instead of trusting cached display state.
2. P07-T06-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P07-T06-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P07-T06-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run multi-viewer browser tests, revoked-session tests, stream replay, and network interruptions.
2. Compare UI snapshots to authoritative records after each failure scenario.
3. Run component dependency checks, keyboard/screen-reader review, and visual regression tests.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Compare terminal and dashboard status snapshots, versions and timestamps, including absent federation support, no configured hubs, denied scope and stale observations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P07-T07"></a>

### P07-T07: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P06-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P07-T07-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P07-T07-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P07-T07-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P07-T07-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run multi-viewer browser tests, revoked-session tests, stream replay, and network interruptions.
2. Compare UI snapshots to authoritative records after each failure scenario.
3. Run component dependency checks, keyboard/screen-reader review, and visual regression tests.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Compare terminal and dashboard status snapshots, versions and timestamps, including absent federation support, no configured hubs, denied scope and stale observations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P07-T08"></a>

### P07-T08: Display the LOCAL-01 instance, readiness and authorized hub status in the existing dashboard through its NATS-to-AG-UI interface, using the same versioned status contract as terminal clients.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P06-GATE, P07-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Display the LOCAL-01 instance, readiness and authorized hub status in the existing dashboard through its NATS-to-AG-UI interface, using the same versioned status contract as terminal clients.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Display the LOCAL-01 instance, readiness and authorized hub status in the existing dashboard through its NATS-to-AG-UI interface, using the same versioned status contract as terminal clients.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P07-T08-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Display the LOCAL-01 instance, readiness and authorized hub status in the existing dashboard through its NATS-to-AG-UI interface, using the same versioned status contract as terminal clients.
2. P07-T08-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P07-T08-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P07-T08-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run multi-viewer browser tests, revoked-session tests, stream replay, and network interruptions.
2. Compare UI snapshots to authoritative records after each failure scenario.
3. Run component dependency checks, keyboard/screen-reader review, and visual regression tests.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Compare terminal and dashboard status snapshots, versions and timestamps, including absent federation support, no configured hubs, denied scope and stale observations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P07-GATE"></a>

### P07-GATE: Verify and accept P07

**Status:** planned. **Owner:** Codex.

**Dependencies:** P07-T01, P07-T02, P07-T03, P07-T04, P07-T05, P07-T06, P07-T07, P07-T08.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. AG-UI event mapping
2. UI extension and accessibility reports
3. Dashboard before/after demonstration
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P07-GATE-AC01: Refresh, reconnect, duplicate events, delayed events, and history gaps converge to the same authorized view without starting work.
2. P07-GATE-AC02: An unauthorized user cannot access another project's snapshots, streams, conversation, or artifact by guessing an ID.
3. P07-GATE-AC03: Every displayed completion or cancellation state distinguishes worker output from accepted/confirmed state.
4. P07-GATE-AC04: Domain UI contributions use versioned registered components. Core views remain usable when an optional plugin fails.
5. P07-GATE-AC05: Reusable component boundaries and accessibility checks pass for all launch views.
6. P07-GATE-AC06: All ten existing dashboard views and their actions, terminal streams, saved preferences, editor conflicts, themes and integration panels have reviewed before/after evidence. Existing capabilities remain reachable until their replacements pass; AG-UI and component restructuring do not authorize dropping controls.
7. P07-GATE-AC07: Terminal and dashboard status agree at the same source revision. Refresh and reconnect preserve explicit stale/unknown states, hide inaccessible hubs and do not start a second stack or grant additional control.
8. P07-GATE-AC08: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
9. P07-GATE-AC09: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run multi-viewer browser tests, revoked-session tests, stream replay, and network interruptions.
2. Compare UI snapshots to authoritative records after each failure scenario.
3. Run component dependency checks, keyboard/screen-reader review, and visual regression tests.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
5. Compare terminal and dashboard status snapshots, versions and timestamps, including absent federation support, no configured hubs, denied scope and stale observations.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P08. Jev decision services and measured efficiency

Plugins request bounded semantic advice with traceable evidence and safe fallback.

**Epic acceptance criteria**

- **P08-AC01:** Boot and core orchestration still work when Jev is disabled or unreachable, using documented fallbacks.
- **P08-AC02:** Jev cannot grant authority, mutate kernel state, invent tool success, transfer task ownership, or accept a result.
- **P08-AC03:** Cache keys bind tenant, scope, source/version, definition/model, and policy. Revoked sharing cannot return a cached restricted result.
- **P08-AC04:** All calls obey size/time/budget limits and account for failed/uncertain attempts. Replay of stored annotations makes no new paid call.
- **P08-AC05:** Each enabled definition passes its own labeled holdout criteria and workflow non-regression threshold before promotion.
- **P08-AC06:** Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.

<a id="P08-T01"></a>

### P08-T01: Implement a language-neutral decision service with optional Jev provider, versioned definitions/rubrics/schemas, scoped NATS requests, cache, budgets, cancellation, and evidence ledger.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P07-GATE, P08-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement a language-neutral decision service with optional Jev provider, versioned definitions/rubrics/schemas, scoped NATS requests, cache, budgets, cancellation, and evidence ledger.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement a language-neutral decision service with optional Jev provider, versioned definitions/rubrics/schemas, scoped NATS requests, cache, budgets, cancellation, and evidence ledger.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P08-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement a language-neutral decision service with optional Jev provider, versioned definitions/rubrics/schemas, scoped NATS requests, cache, budgets, cancellation, and evidence ledger.
2. P08-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P08-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P08-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the existing synthetic examples and 44-case policy illustration as historical inputs, then extend with real service and NATS tests.
2. Evaluate with provider mocks for mechanics, separately with capped live calls for semantic quality after local token configuration and budget approval.
3. Compare deterministic baseline, Jev tools only, and tools plus skills on equivalent fresh tasks.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P08-T02"></a>

### P08-T02: Check exact rules and data-export authority before hosted inference

**Status:** planned. **Owner:** Codex.

**Dependencies:** P07-GATE, P08-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Check exact rules and data-export authority before hosted inference. Distinguish known answer, abstention, partial evidence, unavailable provider, and ambiguous billing.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Check exact rules and data-export authority before hosted inference. Distinguish known answer, abstention, partial evidence, unavailable provider, and ambiguous billing.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P08-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Check exact rules and data-export authority before hosted inference. Distinguish known answer, abstention, partial evidence, unavailable provider, and ambiguous billing.
2. P08-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P08-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P08-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the existing synthetic examples and 44-case policy illustration as historical inputs, then extend with real service and NATS tests.
2. Evaluate with provider mocks for mechanics, separately with capped live calls for semantic quality after local token configuration and budget approval.
3. Compare deterministic baseline, Jev tools only, and tools plus skills on equivalent fresh tasks.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P08-T03"></a>

### P08-T03: Support the eight reusable decision families and contributed definitions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P07-GATE, P08-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Support the eight reusable decision families and contributed definitions. Start in shadow/advisory mode for capability discovery, evidence selection, failure triage, and review.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Support the eight reusable decision families and contributed definitions. Start in shadow/advisory mode for capability discovery, evidence selection, failure triage, and review.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P08-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Support the eight reusable decision families and contributed definitions. Start in shadow/advisory mode for capability discovery, evidence selection, failure triage, and review.
2. P08-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P08-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P08-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the existing synthetic examples and 44-case policy illustration as historical inputs, then extend with real service and NATS tests.
2. Evaluate with provider mocks for mechanics, separately with capped live calls for semantic quality after local token configuration and budget approval.
3. Compare deterministic baseline, Jev tools only, and tools plus skills on equivalent fresh tasks.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P08-T04"></a>

### P08-T04: Preserve exact source IDs/spans, required facts, contrary evidence, and context-expansion routes

**Status:** planned. **Owner:** Codex.

**Dependencies:** P07-GATE, P08-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Preserve exact source IDs/spans, required facts, contrary evidence, and context-expansion routes. Mandatory events bypass relevance filters.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Preserve exact source IDs/spans, required facts, contrary evidence, and context-expansion routes. Mandatory events bypass relevance filters.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P08-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Preserve exact source IDs/spans, required facts, contrary evidence, and context-expansion routes. Mandatory events bypass relevance filters.
2. P08-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P08-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P08-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the existing synthetic examples and 44-case policy illustration as historical inputs, then extend with real service and NATS tests.
2. Evaluate with provider mocks for mechanics, separately with capped live calls for semantic quality after local token configuration and budget approval.
3. Compare deterministic baseline, Jev tools only, and tools plus skills on equivalent fresh tasks.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P08-T05"></a>

### P08-T05: Measure downstream tokens, provider costs, prompt-cache effects, latency, retries, rework, and accepted outcomes against a baseline.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P07-GATE, P08-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Measure downstream tokens, provider costs, prompt-cache effects, latency, retries, rework, and accepted outcomes against a baseline.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Measure downstream tokens, provider costs, prompt-cache effects, latency, retries, rework, and accepted outcomes against a baseline.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P08-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Measure downstream tokens, provider costs, prompt-cache effects, latency, retries, rework, and accepted outcomes against a baseline.
2. P08-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P08-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P08-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the existing synthetic examples and 44-case policy illustration as historical inputs, then extend with real service and NATS tests.
2. Evaluate with provider mocks for mechanics, separately with capped live calls for semantic quality after local token configuration and budget approval.
3. Compare deterministic baseline, Jev tools only, and tools plus skills on equivalent fresh tasks.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P08-T06"></a>

### P08-T06: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P07-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P08-T06-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P08-T06-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P08-T06-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P08-T06-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run the existing synthetic examples and 44-case policy illustration as historical inputs, then extend with real service and NATS tests.
2. Evaluate with provider mocks for mechanics, separately with capped live calls for semantic quality after local token configuration and budget approval.
3. Compare deterministic baseline, Jev tools only, and tools plus skills on equivalent fresh tasks.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P08-VIDEO-E2"></a>

### P08-VIDEO-E2: Portable, nested decision-definition packages

**Status:** planned. **Owner:** Codex.

**Dependencies:** P07-GATE, P08-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Portable, nested decision-definition packages
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P08-VIDEO-E2-AC01: Parent defaults produce separately scoped children; a rubric override produces a new revision without widening grants.
2. P08-VIDEO-E2-AC02: Both independent and private children obey declared lifecycle/dependency rules; source credentials are absent from packages.
3. P08-VIDEO-E2-AC03: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
4. P08-VIDEO-E2-AC04: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-E2",
  "title": "Portable, nested decision-definition packages",
  "description": "Package question schemas, domain rubrics, fixtures, model compatibility, budgets and fallbacks with plugins. Children inherit scoped logging, tracing and decision access; they receive only granted data/provider rights. Explicit rubric overrides produce a new definition revision. An industrial toolkit could include vendor-specific compiler and migration questions, independently usable where its manifest permits."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P08-VIDEO-E4"></a>

### P08-VIDEO-E4: Scoped decision records and replay views

**Status:** planned. **Owner:** Codex.

**Dependencies:** P07-GATE, P08-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Scoped decision records and replay views
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P08-VIDEO-E4-AC01: Decision metadata crosses components through NATS and authorized UI projections through AG-UI.
2. P08-VIDEO-E4-AC02: A new viewer or replay issues no new inference; evidence bodies are not mirrored into unrestricted traces.
3. P08-VIDEO-E4-AC03: Authoritative state, model annotations and unknown billing remain distinguishable.
4. P08-VIDEO-E4-AC04: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
5. P08-VIDEO-E4-AC05: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-PRESENTATION, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-E4",
  "title": "Scoped decision records and replay views",
  "description": "Publish redacted, authorized decision metadata through NATS and the AG-UI interface plugin. CopilotKit components can show source coverage, selected outcome, definition/model versions, uncertainty, fallback and actual usage. Keep original evidence in separately controlled storage; do not mirror full source content into every trace. Replays and additional viewers reuse existing results."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P08-GATE"></a>

### P08-GATE: Verify and accept P08

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-T01, P08-T02, P08-T03, P08-T04, P08-T05, P08-T06, P08-VIDEO-E2, P08-VIDEO-E4.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Decision contracts and policy ledger
2. Definition-specific scorecards
3. Cost per accepted outcome and fallback report
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P08-GATE-AC01: Boot and core orchestration still work when Jev is disabled or unreachable, using documented fallbacks.
2. P08-GATE-AC02: Jev cannot grant authority, mutate kernel state, invent tool success, transfer task ownership, or accept a result.
3. P08-GATE-AC03: Cache keys bind tenant, scope, source/version, definition/model, and policy. Revoked sharing cannot return a cached restricted result.
4. P08-GATE-AC04: All calls obey size/time/budget limits and account for failed/uncertain attempts. Replay of stored annotations makes no new paid call.
5. P08-GATE-AC05: Each enabled definition passes its own labeled holdout criteria and workflow non-regression threshold before promotion.
6. P08-GATE-AC06: Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.
7. P08-GATE-AC07: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
8. P08-GATE-AC08: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run the existing synthetic examples and 44-case policy illustration as historical inputs, then extend with real service and NATS tests.
2. Evaluate with provider mocks for mechanics, separately with capped live calls for semantic quality after local token configuration and budget approval.
3. Compare deterministic baseline, Jev tools only, and tools plus skills on equivalent fresh tasks.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P09. Portable Jev plugin and first skill wave

The same Jev capabilities improve supported clients with host-specific packaging.

**Epic acceptance criteria**

- **P09-AC01:** All first-wave skills have a clear trigger, declared input/output, real use case, error/fallback behavior, and evaluation fixtures.
- **P09-AC02:** Whole-suite near-miss tests show skills do not compete unnecessarily or trigger a broad ask-everything path.
- **P09-AC03:** Every claimed host capability passes on that actual host. Unsupported hooks/compaction are declared.
- **P09-AC04:** Skills preserve counterevidence and required obligations and cannot override system permissions or invent authority.
- **P09-AC05:** Live semantic and end-to-end cost gates pass before the corresponding skill is enabled by default.
- **P09-AC06:** Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.

<a id="P09-T01"></a>

### P09-T01: Build one shared Jev CLI/MCP runtime and portable skill content with separate Claude, Codex, Pi, and Desktop packaging.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Build one shared Jev CLI/MCP runtime and portable skill content with separate Claude, Codex, Pi, and Desktop packaging.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Build one shared Jev CLI/MCP runtime and portable skill content with separate Claude, Codex, Pi, and Desktop packaging.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P09-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Build one shared Jev CLI/MCP runtime and portable skill content with separate Claude, Codex, Pi, and Desktop packaging.
2. P09-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P09-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P09-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run approximately 20 positive/near-miss trigger prompts per skill and representative task pairs plus shared boundary cases.
2. Use independent review and separate tuning/validation/release sets.
3. Measure skill discovery metadata overhead, context cost, accuracy, and accepted outcomes across hosts.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-T02"></a>

### P09-T02: Keep standalone Jev usable without Agentmux or NATS

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Keep standalone Jev usable without Agentmux or NATS. In Agentmux mode route decision requests through scoped hub services.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Keep standalone Jev usable without Agentmux or NATS. In Agentmux mode route decision requests through scoped hub services.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P09-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Keep standalone Jev usable without Agentmux or NATS. In Agentmux mode route decision requests through scoped hub services.
2. P09-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P09-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P09-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run approximately 20 positive/near-miss trigger prompts per skill and representative task pairs plus shared boundary cases.
2. Use independent review and separate tuning/validation/release sets.
3. Measure skill discovery metadata overhead, context cost, accuracy, and accepted outcomes across hosts.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-T03"></a>

### P09-T03: Create the proposed first general skill wave: setup, classify, scout, context, triage, review, author, and eval.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Create the proposed first general skill wave: setup, classify, scout, context, triage, review, author, and eval.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Create the proposed first general skill wave: setup, classify, scout, context, triage, review, author, and eval.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P09-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Create the proposed first general skill wave: setup, classify, scout, context, triage, review, author, and eval.
2. P09-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P09-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P09-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run approximately 20 positive/near-miss trigger prompts per skill and representative task pairs plus shared boundary cases.
2. Use independent review and separate tuning/validation/release sets.
3. Measure skill discovery metadata overhead, context cost, accuracy, and accepted outcomes across hosts.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-T04"></a>

### P09-T04: Create the first Agentmux wave: prepare-worker, delegate, inspect-hub, and review-results

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Create the first Agentmux wave: prepare-worker, delegate, inspect-hub, and review-results. Qualify local-hub behavior in P09 and keep remote-hub modes disabled until P10 actual-hub acceptance. Keep final delegation authorization with platform owners.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Create the first Agentmux wave: prepare-worker, delegate, inspect-hub, and review-results. Qualify local-hub behavior in P09 and keep remote-hub modes disabled until P10 actual-hub acceptance. Keep final delegation authorization with platform owners.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P09-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Create the first Agentmux wave: prepare-worker, delegate, inspect-hub, and review-results. Qualify local-hub behavior in P09 and keep remote-hub modes disabled until P10 actual-hub acceptance. Keep final delegation authorization with platform owners.
2. P09-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P09-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P09-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run approximately 20 positive/near-miss trigger prompts per skill and representative task pairs plus shared boundary cases.
2. Use independent review and separate tuning/validation/release sets.
3. Measure skill discovery metadata overhead, context cost, accuracy, and accepted outcomes across hosts.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-T05"></a>

### P09-T05: Use skill-creator to draft, run paired behavioral and trigger tests, review results, revise, and qualify untouched holdout cases.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Use skill-creator to draft, run paired behavioral and trigger tests, review results, revise, and qualify untouched holdout cases.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Use skill-creator to draft, run paired behavioral and trigger tests, review results, revise, and qualify untouched holdout cases.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P09-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Use skill-creator to draft, run paired behavioral and trigger tests, review results, revise, and qualify untouched holdout cases.
2. P09-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P09-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P09-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run approximately 20 positive/near-miss trigger prompts per skill and representative task pairs plus shared boundary cases.
2. Use independent review and separate tuning/validation/release sets.
3. Measure skill discovery metadata overhead, context cost, accuracy, and accepted outcomes across hosts.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-T06"></a>

### P09-T06: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P09-T06-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P09-T06-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P09-T06-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P09-T06-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run approximately 20 positive/near-miss trigger prompts per skill and representative task pairs plus shared boundary cases.
2. Use independent review and separate tuning/validation/release sets.
3. Measure skill discovery metadata overhead, context cost, accuracy, and accepted outcomes across hosts.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-001"></a>

### P09-JEV-001: Intent-to-handler selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Intent-to-handler selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-001-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-001-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-001-AC03: Preserve this item-specific boundary: Typed commands route directly without Jev; mutation authorization remains separate.
4. P09-JEV-001-AC04: Report Correct route and costly misroutes on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-001-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-001-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-001",
  "group": "intake",
  "title": "Intent-to-handler selection",
  "primitives": [
    "C"
  ],
  "stage": "First",
  "owner": "Client integration and task-intake plugins",
  "decision": "Task wording and eligible handlers → read-only query, investigation, implementation, or clarification.",
  "saving": "Avoid a general planner call for a recognized bounded request.",
  "boundary": "Typed commands route directly without Jev; mutation authorization remains separate.",
  "metric": "Correct route and costly misroutes",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-002"></a>

### P09-JEV-002: Missing-information detection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Missing-information detection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-002-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-002-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-002-AC03: Preserve this item-specific boundary: Validate exact required fields in code first; question selection does not invent missing values.
4. P09-JEV-002-AC04: Report Prevented abandoned runs; unnecessary questions on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-002-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-002-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-002",
  "group": "intake",
  "title": "Missing-information detection",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "First",
  "owner": "Client integration and task-intake plugins",
  "decision": "Task and required input schema → identify which known prerequisite needs clarification.",
  "saving": "Avoid exploratory agent runs that cannot succeed with the available inputs.",
  "boundary": "Validate exact required fields in code first; question selection does not invent missing values.",
  "metric": "Prevented abandoned runs; unnecessary questions",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-004"></a>

### P09-JEV-004: Domain guidance selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Domain guidance selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-004-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-004-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-004-AC03: Preserve this item-specific boundary: Mandatory platform/user instructions stay loaded; include an unknown-domain path.
4. P09-JEV-004-AC04: Report Relevant instruction recall; prompt size on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-004-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-004-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-004",
  "group": "intake",
  "title": "Domain guidance selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Client integration and task-intake plugins",
  "decision": "Task semantics and installed domain capabilities → select relevant domain guidance.",
  "saving": "Keep unrelated industrial, web, data, or other guidance out of the worker context.",
  "boundary": "Mandatory platform/user instructions stay loaded; include an unknown-domain path.",
  "metric": "Relevant instruction recall; prompt size",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-008"></a>

### P09-JEV-008: Approved workflow selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Approved workflow selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-008-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-008-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-008-AC03: Preserve this item-specific boundary: Workflow selection never grants permissions or removes required stages.
4. P09-JEV-008-AC04: Report Plan-generation calls avoided; workflow fit on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-008-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-008-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-008",
  "group": "planning",
  "title": "Approved workflow selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Planning and orchestration plugins",
  "decision": "Task and compatible workflow catalog → choose an existing workflow or none.",
  "saving": "Reuse known steps instead of generating a new plan every time.",
  "boundary": "Workflow selection never grants permissions or removes required stages.",
  "metric": "Plan-generation calls avoided; workflow fit",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-015"></a>

### P09-JEV-015: Plugin capability shortlist

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Plugin capability shortlist
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-015-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-015-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-015-AC03: Preserve this item-specific boundary: Publisher descriptions are untrusted evidence; enforce compatibility and grants first.
4. P09-JEV-015-AC04: Report Correct capability recall; full schemas loaded on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-015-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-015-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-015",
  "group": "tools",
  "title": "Plugin capability shortlist",
  "primitives": [
    "C",
    "S",
    "N"
  ],
  "stage": "First",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Authorized installed capabilities and task → shortlist with an explicit no-fit result.",
  "saving": "Reduce expensive agent inspection of irrelevant plugin catalogs.",
  "boundary": "Publisher descriptions are untrusted evidence; enforce compatibility and grants first.",
  "metric": "Correct capability recall; full schemas loaded",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-016"></a>

### P09-JEV-016: Skill and instruction loading

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Skill and instruction loading
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-016-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-016-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-016-AC03: Preserve this item-specific boundary: The client must actually support selective loading; unchanged mandatory guidance stays.
4. P09-JEV-016-AC04: Report Instruction tokens and wrong skill loads on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-016-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-016-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-016",
  "group": "tools",
  "title": "Skill and instruction loading",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Permitted skill catalog and current task → suggest which detailed instructions to retrieve.",
  "saving": "Avoid loading every skill body into each worker prompt.",
  "boundary": "The client must actually support selective loading; unchanged mandatory guidance stays.",
  "metric": "Instruction tokens and wrong skill loads",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-017"></a>

### P09-JEV-017: Tool operation selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Tool operation selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-017-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-017-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-017-AC03: Preserve this item-specific boundary: Tool owner independently validates permissions, effects, and target.
4. P09-JEV-017-AC04: Report Selection errors; selection-only LLM calls avoided on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-017-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-017-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-017",
  "group": "tools",
  "title": "Tool operation selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Task and eligible operations → choose a specific tool or none.",
  "saving": "Replace an otherwise generative tool-selection step where the output is bounded.",
  "boundary": "Tool owner independently validates permissions, effects, and target.",
  "metric": "Selection errors; selection-only LLM calls avoided",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-019"></a>

### P09-JEV-019: Tool-output evidence selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Tool-output evidence selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-019-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P09-JEV-019-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P09-JEV-019-AC03: Preserve this item-specific boundary: Preserve critical errors, provenance, and retrieval access; exact filtering comes first.
4. P09-JEV-019-AC04: Report Critical evidence recall and delivered tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-019-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-019-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-019",
  "group": "tools",
  "title": "Tool-output evidence selection",
  "primitives": [
    "S",
    "C"
  ],
  "stage": "First",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Parsed result sections and the current question → choose relevant section IDs.",
  "saving": "Keep large logs, tables, and intermediate results out of agent context.",
  "boundary": "Preserve critical errors, provenance, and retrieval access; exact filtering comes first.",
  "metric": "Critical evidence recall and delivered tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-021"></a>

### P09-JEV-021: Pre-extracted value selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Pre-extracted value selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-021-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-021-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-021-AC03: Preserve this item-specific boundary: Code copies the original span and validates it; none if the parser missed the right value.
4. P09-JEV-021-AC04: Report Exact-value accuracy and fallback rate on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-021-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-021-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-021",
  "group": "tools",
  "title": "Pre-extracted value selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Parser-found identifiers/paths/versions plus nearby text → select the value with the requested semantic role.",
  "saving": "Avoid generative extraction and copying of exact values.",
  "boundary": "Code copies the original span and validates it; none if the parser missed the right value.",
  "metric": "Exact-value accuracy and fallback rate",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-023"></a>

### P09-JEV-023: Passage relevance ranking

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Passage relevance ranking
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-023-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P09-JEV-023-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P09-JEV-023-AC03: Preserve this item-specific boundary: Measure missing-essential-evidence rate; broad retrieval remains available.
4. P09-JEV-023-AC04: Report Critical recall and downstream input tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-023-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-023-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-023",
  "group": "context",
  "title": "Passage relevance ranking",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "First",
  "owner": "Context and knowledge plugins",
  "decision": "Retrieved permitted passages and a task → rank contextual usefulness.",
  "saving": "Send fewer irrelevant passages to expensive agents.",
  "boundary": "Measure missing-essential-evidence rate; broad retrieval remains available.",
  "metric": "Critical recall and downstream input tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-024"></a>

### P09-JEV-024: Answer-presence screening

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Answer-presence screening
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-024-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P09-JEV-024-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P09-JEV-024-AC03: Preserve this item-specific boundary: A negative answer is not proof of absence; uncertain cases retain broader search.
4. P09-JEV-024-AC04: Report False absence and downstream reads avoided on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-024-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-024-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-024",
  "group": "context",
  "title": "Answer-presence screening",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "First",
  "owner": "Context and knowledge plugins",
  "decision": "Candidate document and question → likely present, absent, or uncertain.",
  "saving": "Avoid handing every retrieved document to a reasoning agent.",
  "boundary": "A negative answer is not proof of absence; uncertain cases retain broader search.",
  "metric": "False absence and downstream reads avoided",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-025"></a>

### P09-JEV-025: Exact source-span selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Exact source-span selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-025-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P09-JEV-025-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P09-JEV-025-AC03: Preserve this item-specific boundary: Maintain exact source/version references and enough surrounding qualifications.
4. P09-JEV-025-AC04: Report Span coverage and token reduction on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-025-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-025-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-025",
  "group": "context",
  "title": "Exact source-span selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Context and knowledge plugins",
  "decision": "Numbered source spans and a question → select evidence IDs and neighboring context.",
  "saving": "Use extractive bundles instead of generating summaries of entire documents.",
  "boundary": "Maintain exact source/version references and enough surrounding qualifications.",
  "metric": "Span coverage and token reduction",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-026"></a>

### P09-JEV-026: Contradictory-evidence preservation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Contradictory-evidence preservation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-026-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P09-JEV-026-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P09-JEV-026-AC03: Preserve this item-specific boundary: Relevance must not mean agreement; do not let a majority hide a critical exception.
4. P09-JEV-026-AC04: Report Contradiction recall on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-026-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-026-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-026",
  "group": "context",
  "title": "Contradictory-evidence preservation",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Context and knowledge plugins",
  "decision": "Task claim and candidate passage → supporting, contradictory, contextual, or irrelevant.",
  "saving": "Retain important counterevidence while dropping unrelated material.",
  "boundary": "Relevance must not mean agreement; do not let a majority hide a critical exception.",
  "metric": "Contradiction recall",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-027"></a>

### P09-JEV-027: Recipient-specific context packs

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Recipient-specific context packs
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-027-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P09-JEV-027-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P09-JEV-027-AC03: Preserve this item-specific boundary: Shared decisions and obligations are pinned; scoped access still enforced.
4. P09-JEV-027-AC04: Report Per-worker tokens and missing-context rework on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-027-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-027-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-027",
  "group": "context",
  "title": "Recipient-specific context packs",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "First",
  "owner": "Context and knowledge plugins",
  "decision": "Current task plus worker role and permitted evidence → select each worker's relevant sources.",
  "saving": "Avoid copying a complete multi-agent conversation into every worker.",
  "boundary": "Shared decisions and obligations are pinned; scoped access still enforced.",
  "metric": "Per-worker tokens and missing-context rework",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-031"></a>

### P09-JEV-031: Worker specialization fit

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Worker specialization fit
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-031-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-031-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-031-AC03: Preserve this item-specific boundary: Tool support, user grants, capacity, and freshness are deterministic prerequisites.
4. P09-JEV-031-AC04: Report Accepted work per assignment on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-031-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-031-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-031",
  "group": "placement",
  "title": "Worker specialization fit",
  "primitives": [
    "S",
    "C"
  ],
  "stage": "Next",
  "owner": "Orchestration and resource owners",
  "decision": "Eligible workers and task → assess semantic expertise fit.",
  "saving": "Reduce failed assignments and repeated context transfer.",
  "boundary": "Tool support, user grants, capacity, and freshness are deterministic prerequisites.",
  "metric": "Accepted work per assignment",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-034"></a>

### P09-JEV-034: Bounded decision without generation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Bounded decision without generation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-034-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-034-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-034-AC03: Preserve this item-specific boundary: Known structured queries use ordinary code without Jev; uncertainty escalates.
4. P09-JEV-034-AC04: Report Calls avoided at bounded error rate on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-034-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-034-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-034",
  "group": "placement",
  "title": "Bounded decision without generation",
  "primitives": [
    "C",
    "N",
    "S"
  ],
  "stage": "First",
  "owner": "Orchestration and resource owners",
  "decision": "Classification or scoring request with complete permitted inputs → return structured result/template.",
  "saving": "Eliminate a generative-model call when no novel text or code is needed.",
  "boundary": "Known structured queries use ordinary code without Jev; uncertainty escalates.",
  "metric": "Calls avoided at bounded error rate",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-044"></a>

### P09-JEV-044: Failure category triage

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Failure category triage
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-044-AC01: Keep exact exit/status/protocol facts unchanged; classify only the residual unstructured evidence.
2. P09-JEV-044-AC02: Incomplete logs and uncertain external actions remain explicit; diagnosis does not replay a command or declare it stopped.
3. P09-JEV-044-AC03: Preserve this item-specific boundary: Known codes use direct rules; diagnosis does not authorize replay.
4. P09-JEV-044-AC04: Report Diagnosis accuracy and repeated failed attempts on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-044-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-044-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-044",
  "group": "verification",
  "title": "Failure category triage",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Execution, validation, and review plugins",
  "decision": "Parsed error code plus bounded unstructured diagnostic → likely category or unknown.",
  "saving": "Select a focused recovery investigation rather than restarting broad reasoning.",
  "boundary": "Known codes use direct rules; diagnosis does not authorize replay.",
  "metric": "Diagnosis accuracy and repeated failed attempts",
  "status": "proposed; not benchmarked",
  "decisionFamily": "diagnostic-classification"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-049"></a>

### P09-JEV-049: Evidence relationship assessment

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Evidence relationship assessment
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-049-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P09-JEV-049-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P09-JEV-049-AC03: Preserve this item-specific boundary: Do not convert supplied claims into verified facts or task acceptance.
4. P09-JEV-049-AC04: Report Unsupported-claim misses and review tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-049-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-049-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-049",
  "group": "verification",
  "title": "Evidence relationship assessment",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Execution, validation, and review plugins",
  "decision": "Claim and bounded source/test evidence → supports, contradicts, or insufficient.",
  "saving": "Replace repetitive generative yes/no evidence judgments where qualified.",
  "boundary": "Do not convert supplied claims into verified facts or task acceptance.",
  "metric": "Unsupported-claim misses and review tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-056"></a>

### P09-JEV-056: Citation and source-span checks

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Citation and source-span checks
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-056-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P09-JEV-056-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P09-JEV-056-AC03: Preserve this item-specific boundary: Exact quote/digest checks run first; uncertain support requires review.
4. P09-JEV-056-AC04: Report Unsupported citations and checking cost on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-056-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-056-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-056",
  "group": "knowledge",
  "title": "Citation and source-span checks",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Knowledge and artifact plugins",
  "decision": "Located quote/context and associated claim → support relation.",
  "saving": "Avoid repeatedly asking a large model to inspect every citation.",
  "boundary": "Exact quote/digest checks run first; uncertain support requires review.",
  "metric": "Unsupported citations and checking cost",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship",
  "reusesMechanismOf": [
    "JEV-049"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-065"></a>

### P09-JEV-065: Bounded status-question routing

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Bounded status-question routing
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-065-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P09-JEV-065-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P09-JEV-065-AC03: Preserve this item-specific boundary: No arbitrary SQL or fabricated state; native agent client may still spend its own turn.
4. P09-JEV-065-AC04: Report Worker calls avoided; query correctness on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-065-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-065-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-PRESENTATION, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-065",
  "group": "interface",
  "title": "Bounded status-question routing",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Interface and presentation plugins",
  "decision": "User wording and permitted read-only query templates → query plus known filters or clarify.",
  "saving": "Answer many operational questions with real data and templates, avoiding a worker run.",
  "boundary": "No arbitrary SQL or fabricated state; native agent client may still spend its own turn.",
  "metric": "Worker calls avoided; query correctness",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection",
  "reusesMechanismOf": [
    "JEV-001",
    "JEV-034"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-JEV-084"></a>

### P09-JEV-084: Extractive activity cards

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Extractive activity cards
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-JEV-084-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P09-JEV-084-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P09-JEV-084-AC03: Preserve this item-specific boundary: Preserve factual state and context; reuse only within the same evidence visibility scope.
4. P09-JEV-084-AC04: Report Summary calls avoided and important-fact recall on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P09-JEV-084-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-JEV-084-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-PRESENTATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-084",
  "group": "interface",
  "title": "Extractive activity cards",
  "primitives": [
    "C",
    "S"
  ],
  "stage": "First",
  "owner": "Interface and presentation plugins",
  "decision": "Authorized event and evidence IDs plus fixed card slots → select short supporting excerpts.",
  "saving": "Render useful status cards without a generative summary per event or viewer.",
  "boundary": "Preserve factual state and context; reuse only within the same evidence visibility scope.",
  "metric": "Summary calls avoided and important-fact recall",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection",
  "reusesMechanismOf": [
    "JEV-025",
    "JEV-063"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-VIDEO-01"></a>

### P09-VIDEO-01: Agent-authored bounded questions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Agent-authored bounded questions
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-VIDEO-01-AC01: Reject disallowed evidence, malformed or oversized questions and exhausted budget before a provider call.
2. P09-VIDEO-01-AC02: Equivalent repeated self-confirmation questions stop or reuse a scoped record; the agent cannot author its own acceptance authority.
3. P09-VIDEO-01-AC03: Preserve source boundary: Validate question shape, permitted evidence references, option counts, budgets, deadlines and output size in code. Ad hoc answers remain advisory and cannot mint permissions or redefine task acceptance. Include an unknown outcome.
4. P09-VIDEO-01-AC04: Measure Accepted-task cost and completion time; useful-question rate; avoidable follow-up calls; repeated self-confirmation loops.
5. P09-VIDEO-01-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-VIDEO-01-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-01",
  "title": "Agent-authored bounded questions",
  "kind": "New integration surface",
  "level": 10,
  "time": "29:28",
  "seconds": 1768,
  "prior": [
    "JEV-034",
    "JEV-079"
  ],
  "owner": "Agent integration and decision-service plugins",
  "proposal": "Expose a scoped decision.ask tool so an agent can construct a small Noul, Choice, or Score question when no registered decision covers its immediate information need. A debugging agent could ask whether a captured failure is an assertion mismatch, missing dependency, environment error, or insufficient evidence.",
  "delta": "Our catalog concentrated on predefined decisions. This adds runtime question authoring with an explicit lifecycle and budget.",
  "benefit": "May replace a reasoning detour or investigation-only subagent; measure the agent turn required to author and consume the question too.",
  "boundary": "Validate question shape, permitted evidence references, option counts, budgets, deadlines and output size in code. Ad hoc answers remain advisory and cannot mint permissions or redefine task acceptance. Include an unknown outcome.",
  "metric": "Accepted-task cost and completion time; useful-question rate; avoidable follow-up calls; repeated self-confirmation loops.",
  "priority": "First",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=1768s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/extensions/ask-jev.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-VIDEO-02"></a>

### P09-VIDEO-02: Questions about files without loading their contents

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Questions about files without loading their contents
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-VIDEO-02-AC01: Test allowed, denied, symlink-escaping, unreadable, truncated and stale files; every answer reports evidence revision and completeness.
2. P09-VIDEO-02-AC02: A needed full-source read remains possible without rerunning inference.
3. P09-VIDEO-02-AC03: Preserve source boundary: The evidence plugin still reads the file and may send it to a hosted provider. Apply source access and provider/export rules first, resolve paths safely, and distinguish absent evidence from unreadable, omitted or truncated input.
4. P09-VIDEO-02-AC04: Measure Main-model input avoided; answer error rate; later source-expansion rate; cache-adjusted total cost.
5. P09-VIDEO-02-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-VIDEO-02-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-02",
  "title": "Questions about files without loading their contents",
  "kind": "Deeper implementation of existing use cases",
  "level": 8,
  "time": "20:02",
  "seconds": 1202,
  "prior": [
    "JEV-019",
    "JEV-023",
    "JEV-024",
    "JEV-027"
  ],
  "owner": "Workspace evidence plugin",
  "proposal": "Add decision.ask_file over an authorized, versioned file reference. Ask whether it validates JWT signatures, contains retry behavior, or belongs to a specified architectural layer. Return a typed finding plus source revision and completeness status; fetch code only when an agent needs to inspect, quote or edit it.",
  "delta": "This changes the tool boundary from returning relevant excerpts to returning only the answer to a narrow question.",
  "benefit": "Reduces investigation-only file reads and subsequent repeated consumption of those files by the main model.",
  "boundary": "The evidence plugin still reads the file and may send it to a hosted provider. Apply source access and provider/export rules first, resolve paths safely, and distinguish absent evidence from unreadable, omitted or truncated input.",
  "metric": "Main-model input avoided; answer error rate; later source-expansion rate; cache-adjusted total cost.",
  "priority": "First",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=1202s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/extensions/ask-jev-file.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-VIDEO-03"></a>

### P09-VIDEO-03: Budgeted semantic repository scouting

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Budgeted semantic repository scouting
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-VIDEO-03-AC01: Compare the shortlist with files actually needed for reviewed fixes, including a cross-file dependency missed by isolated classification.
2. P09-VIDEO-03-AC02: Budget/concurrency/cancellation limits hold and the coverage manifest accounts for every candidate, successful or not.
3. P09-VIDEO-03-AC03: Preserve source boundary: Enforce request and input-token budgets, bounded concurrency and cancellation. Report excluded files and failures. A per-file view can miss cross-file interactions; retain dependency expansion and broader-search fallback. Do not copy a demo file cap as a platform limit.
4. P09-VIDEO-03-AC04: Measure Recall of files needed for accepted fixes; discovery latency; total calls and charged usage including retries.
5. P09-VIDEO-03-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-VIDEO-03-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-03",
  "title": "Budgeted semantic repository scouting",
  "kind": "Deeper implementation of existing use cases",
  "level": 9,
  "time": "23:39",
  "seconds": 1419,
  "prior": [
    "JEV-022",
    "JEV-023",
    "JEV-048"
  ],
  "owner": "Repository discovery plugin",
  "proposal": "Use ordinary search, changed-file lists and symbol/dependency metadata to shortlist candidates, then apply the same task-specific question to each eligible file. Return a compact shortlist and coverage manifest. For example, find files likely involved in duplicate NATS work execution before launching an implementation agent.",
  "delta": "Turns relevance judgments into an explicit discovery stage spanning many files, followed by deliberate evidence expansion.",
  "benefit": "Avoids using an expensive agent as a file-by-file crawler.",
  "boundary": "Enforce request and input-token budgets, bounded concurrency and cancellation. Report excluded files and failures. A per-file view can miss cross-file interactions; retain dependency expansion and broader-search fallback. Do not copy a demo file cap as a platform limit.",
  "metric": "Recall of files needed for accepted fixes; discovery latency; total calls and charged usage including retries.",
  "priority": "First",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=1419s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level09/ask-files.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-VIDEO-08"></a>

### P09-VIDEO-08: Observe a command, then return a narrow judgment

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Observe a command, then return a narrow judgment
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-VIDEO-08-AC01: Classify an immutable invocation artifact; provider timeout/retry creates zero additional executions.
2. P09-VIDEO-08-AC02: Exact exit/test statuses and original evidence remain retrievable; model label never converts failure into success.
3. P09-VIDEO-08-AC03: Preserve source boundary: Prefer an existing invocation/artifact reference to an unrestricted command string. Tests can execute arbitrary project code; a read-only label is insufficient. Authorization, execution and judgment are separate. Retries classify the existing result without rerunning the command.
4. P09-VIDEO-08-AC04: Measure Log tokens avoided; diagnosis accuracy; expansion frequency; zero duplicate executions.
5. P09-VIDEO-08-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-VIDEO-08-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-08",
  "title": "Observe a command, then return a narrow judgment",
  "kind": "Deeper implementation of existing use cases",
  "level": 10,
  "time": "29:28",
  "seconds": 1768,
  "prior": [
    "JEV-019",
    "JEV-020",
    "JEV-044",
    "JEV-069"
  ],
  "owner": "Execution plugin and evidence plugin",
  "proposal": "Run a permitted operation through the existing execution service, retain its structured result and logs, then classify the captured output. A build can return exact exit status plus a likely failure family and relevant evidence references instead of flooding the agent with all output.",
  "delta": "Combines execution, evidence capture and bounded semantic observation behind a compact tool response.",
  "benefit": "Avoids main-agent ingestion of large routine logs while preserving their availability.",
  "boundary": "Prefer an existing invocation/artifact reference to an unrestricted command string. Tests can execute arbitrary project code; a read-only label is insufficient. Authorization, execution and judgment are separate. Retries classify the existing result without rerunning the command.",
  "metric": "Log tokens avoided; diagnosis accuracy; expansion frequency; zero duplicate executions.",
  "priority": "First",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=1768s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level10/assemble.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-VIDEO-11"></a>

### P09-VIDEO-11: Change-description fidelity checks

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Change-description fidelity checks
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-VIDEO-11-AC01: Detect seeded behavior changes concealed by docs-only descriptions, with generated/executable-document context.
2. P09-VIDEO-11-AC02: A clean result neither skips mandatory review nor proves whole-program correctness.
3. P09-VIDEO-11-AC03: Preserve source boundary: Generated files, executable documentation and effects outside the diff require context. A clean finding neither proves safety nor removes mandatory review.
4. P09-VIDEO-11-AC04: Measure Scope mismatches found; false flags; review effort; defects discovered after acceptance.
5. P09-VIDEO-11-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-VIDEO-11-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-11",
  "title": "Change-description fidelity checks",
  "kind": "Domain refinement of existing use cases",
  "level": 3,
  "time": "6:20",
  "seconds": 380,
  "prior": [
    "JEV-047",
    "JEV-048",
    "JEV-049",
    "JEV-062",
    "JEV-082",
    "JEV-086"
  ],
  "owner": "Review plugin",
  "proposal": "Compare a proposed change description with the actual diff and relevant context. Flag a change described as documentation-only that also touches retry behavior, authentication or task ownership. Use the discrepancy to select additional review.",
  "delta": "Checks the alignment of declared change scope and observed implementation rather than generic risk or requirement coverage alone.",
  "benefit": "Can catch under-described scope early and target reviewer attention.",
  "boundary": "Generated files, executable documentation and effects outside the diff require context. A clean finding neither proves safety nor removes mandatory review.",
  "metric": "Scope mismatches found; false flags; review effort; defects discovered after acceptance.",
  "priority": "Next",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=380s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level03/code-review-risk.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-VIDEO-E3"></a>

### P09-VIDEO-E3: Reviewed promotion of useful ad hoc questions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Reviewed promotion of useful ad hoc questions
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-VIDEO-E3-AC01: A temporary successful question becomes a proposed definition, never automatically an authoritative production policy.
2. P09-VIDEO-E3-AC02: Promotion requires independent holdout results and explicit owner review; runtime question content cannot redefine its acceptance criteria.
3. P09-VIDEO-E3-AC03: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
4. P09-VIDEO-E3-AC04: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-E3",
  "title": "Reviewed promotion of useful ad hoc questions",
  "description": "Collect successful temporary questions as candidates, not automatically trusted policies. A developer or agent proposes a reusable definition, tests schema/offline fallback behavior, and evaluates held-out real cases before enabling it. Provide a concise agent-facing skill/tool description explaining when to ask Jev, when to read evidence and when ordinary code is sufficient."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-jev-setup"></a>

### P09-jev-setup: jev-setup

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-setup
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-jev-setup-AC01: Missing credentials produce a useful setup result; diagnostics never expose secrets; unsupported hooks are clearly marked.
2. P09-jev-setup-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P09-jev-setup-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P09-jev-setup-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P09-jev-setup-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-jev-setup-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-setup",
  "description": "Configure and diagnose the Jev runtime, provider connection, credential reference, budgets and supported host capabilities.",
  "useCase": "Make Jev tools available in a new Pi installation and report which integrations are ready, without displaying the API key.",
  "eval": "Missing credentials produce a useful setup result; diagnostics never expose secrets; unsupported hooks are clearly marked.",
  "first": true
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-jev-classify"></a>

### P09-jev-classify: jev-classify

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-classify
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-jev-classify-AC01: Uses code for exact arithmetic; distinguishes uncertainty from negative evidence; returns categories without executing handlers or granting permissions.
2. P09-jev-classify-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P09-jev-classify-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P09-jev-classify-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P09-jev-classify-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-jev-classify-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-classify",
  "description": "Apply declared semantic categories or checks to supplied records, preserving unknown outcomes and evidence boundaries.",
  "useCase": "Classify incoming requests as defect, feature, support or unclear, and flag missing information before routing.",
  "eval": "Uses code for exact arithmetic; distinguishes uncertainty from negative evidence; returns categories without executing handlers or granting permissions.",
  "first": true
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-jev-scout"></a>

### P09-jev-scout: jev-scout

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-scout
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-jev-scout-AC01: Finds required sources; reports skipped and unreadable files; respects path/data scope; exposes a source-expansion path.
2. P09-jev-scout-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P09-jev-scout-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P09-jev-scout-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P09-jev-scout-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-jev-scout-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-scout",
  "description": "Answer narrow questions about known files or find likely sources across a bounded file set, returning findings and coverage before full reads.",
  "useCase": "Locate files involved in retry and acknowledgement behavior before the coding agent opens their contents.",
  "eval": "Finds required sources; reports skipped and unreadable files; respects path/data scope; exposes a source-expansion path.",
  "first": true
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-jev-context"></a>

### P09-jev-context: jev-context

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-context
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-jev-context-AC01: Preserves required instructions, exceptions and contradictory evidence; keeps source IDs and versions; measures downstream rereads.
2. P09-jev-context-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P09-jev-context-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P09-jev-context-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P09-jev-context-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-jev-context-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-context",
  "description": "Assemble a compact evidence pack for a task from an already identified source set, retaining binding facts and counterevidence.",
  "useCase": "Turn a large set of logs and documents into a source-linked packet for the next implementation step.",
  "eval": "Preserves required instructions, exceptions and contradictory evidence; keeps source IDs and versions; measures downstream rereads.",
  "first": true
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-jev-triage"></a>

### P09-jev-triage: jev-triage

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-triage
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-jev-triage-AC01: Retains real exit/test status; handles incomplete logs; never reruns a consequential command merely to classify it.
2. P09-jev-triage-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P09-jev-triage-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P09-jev-triage-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P09-jev-triage-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-jev-triage-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-triage",
  "description": "Classify captured failures and identify a useful next diagnostic observation while preserving exact execution facts.",
  "useCase": "Separate an assertion failure from a missing dependency or environment issue using an existing CI result.",
  "eval": "Retains real exit/test status; handles incomplete logs; never reruns a consequential command merely to classify it.",
  "first": true
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-jev-review"></a>

### P09-jev-review: jev-review

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-review
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-jev-review-AC01: Finds seeded mismatches; cites real evidence; avoids claiming a correctness proof or replacing mandatory tests.
2. P09-jev-review-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P09-jev-review-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P09-jev-review-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P09-jev-review-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-jev-review-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-review",
  "description": "Assess a bounded change or claim against supplied evidence; surface unsupported assertions, scope mismatches and focused review concerns.",
  "useCase": "Flag a PR described as documentation-only when its diff changes retry behavior.",
  "eval": "Finds seeded mismatches; cites real evidence; avoids claiming a correctness proof or replacing mandatory tests.",
  "first": true
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-jev-author"></a>

### P09-jev-author: jev-author

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-author
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-jev-author-AC01: Separates semantic judgments from arithmetic and authorization; includes boundary/negative cases; validates against the actual provider contract.
2. P09-jev-author-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P09-jev-author-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P09-jev-author-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P09-jev-author-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-jev-author-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-author",
  "description": "Turn a recurring decision into a versioned question definition with schemas, rubrics, fallbacks and representative labeled examples.",
  "useCase": "Design a reusable build-failure classifier with a specific insufficient-evidence outcome.",
  "eval": "Separates semantic judgments from arithmetic and authorization; includes boundary/negative cases; validates against the actual provider contract.",
  "first": true
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-jev-eval"></a>

### P09-jev-eval: jev-eval

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-eval
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-jev-eval-AC01: Keeps final holdout untouched; reports failures and variance; separates offline contract checks from live semantic quality.
2. P09-jev-eval-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P09-jev-eval-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P09-jev-eval-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P09-jev-eval-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-jev-eval-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-eval",
  "description": "Evaluate decision definitions and skill workflows with labeled fixtures, independent grading, baseline comparisons and reviewable results.",
  "useCase": "Compare two source-selection rubrics and two skill revisions without exposing held-out answers to the tested agents.",
  "eval": "Keeps final holdout untouched; reports failures and variance; separates offline contract checks from live semantic quality.",
  "first": true
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-agentmux-jev-prepare-worker"></a>

### P09-agentmux-jev-prepare-worker: agentmux-jev-prepare-worker

**Status:** planned. **Owner:** Codex.

**Dependencies:** P08-GATE, P09-T06.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-prepare-worker
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P09-agentmux-jev-prepare-worker-AC01: Forbidden workers cannot win; mandatory guidance and counterevidence survive selection; supports no suitable worker.
2. P09-agentmux-jev-prepare-worker-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P09-agentmux-jev-prepare-worker-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P09-agentmux-jev-prepare-worker-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P09-agentmux-jev-prepare-worker-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P09-agentmux-jev-prepare-worker-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-prepare-worker",
  "description": "Filter capabilities and permissions in code, then assess worker fit and prepare scoped tools, instructions and evidence.",
  "useCase": "Prepare an eligible worker to investigate a reconnect failure without loading every installed tool.",
  "eval": "Forbidden workers cannot win; mandatory guidance and counterevidence survive selection; supports no suitable worker."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P09-GATE"></a>

### P09-GATE: Verify and accept P09

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-T01, P09-T02, P09-T03, P09-T04, P09-T05, P09-T06, P09-JEV-001, P09-JEV-002, P09-JEV-004, P09-JEV-008, P09-JEV-015, P09-JEV-016, P09-JEV-017, P09-JEV-019, P09-JEV-021, P09-JEV-023, P09-JEV-024, P09-JEV-025, P09-JEV-026, P09-JEV-027, P09-JEV-031, P09-JEV-034, P09-JEV-044, P09-JEV-049, P09-JEV-056, P09-JEV-065, P09-JEV-084, P09-VIDEO-01, P09-VIDEO-02, P09-VIDEO-03, P09-VIDEO-08, P09-VIDEO-11, P09-VIDEO-E3, P09-jev-setup, P09-jev-classify, P09-jev-scout, P09-jev-context, P09-jev-triage, P09-jev-review, P09-jev-author, P09-jev-eval, P09-agentmux-jev-prepare-worker.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Host packages and skill catalog
2. Paired skill-creator evaluation reports
3. Cross-host conformance and release holdout
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P09-GATE-AC01: All first-wave skills have a clear trigger, declared input/output, real use case, error/fallback behavior, and evaluation fixtures.
2. P09-GATE-AC02: Whole-suite near-miss tests show skills do not compete unnecessarily or trigger a broad ask-everything path.
3. P09-GATE-AC03: Every claimed host capability passes on that actual host. Unsupported hooks/compaction are declared.
4. P09-GATE-AC04: Skills preserve counterevidence and required obligations and cannot override system permissions or invent authority.
5. P09-GATE-AC05: Live semantic and end-to-end cost gates pass before the corresponding skill is enabled by default.
6. P09-GATE-AC06: Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.
7. P09-GATE-AC07: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
8. P09-GATE-AC08: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run approximately 20 positive/near-miss trigger prompts per skill and representative task pairs plus shared boundary cases.
2. Use independent review and separate tuning/validation/release sets.
3. Measure skill discovery metadata overhead, context cost, accuracy, and accepted outcomes across hosts.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P10. Connected hubs, leaf nodes, and cross-organization work

Independent teams share authorized work while retaining their own authority.

**Epic acceptance criteria**

- **P10-AC01:** Same-organization and cross-organization reference workflows both finish with origin-owned result acceptance.
- **P10-AC02:** Accepted work stays reserved while disconnected. Missing acceptance acknowledgment remains ambiguous until reconciled, never automatically redispatched.
- **P10-AC03:** Duplicate offer/result delivery creates one delegation/attempt outcome. Wrong executor, project, repository, or task version is rejected. Stale grants cannot authorize new effects. Authenticated historical results from previously authorized reserved work are retained for reconciliation or quarantine when current policy requires it; grant expiry cannot erase the obligation or its evidence.
- **P10-AC04:** Unauthorized accounts cannot subscribe to private project subjects or fetch protected artifacts. Transitive hub connectivity grants no access.
- **P10-AC05:** Reconnect recovers progress/results and durable revocations. A stop request is not reported as execution stopped until confirmed or clearly unknown.
- **P10-AC06:** A leaf outage and independent local persistence produce the agreed offline behavior without treating broker connectivity as shared ownership.
- **P10-AC07:** After a partition, mirror lag, retention gap or restoration of an older origin snapshot, hubs reconcile authoritative task and execution records before admitting overlapping work. Replication never grants write authority, and accepted or acceptance-unknown work remains reserved.
- **P10-AC08:** Migration fixtures retain current hub verbs, five federation plugins, pending outbox/quarantine records, seen IDs, durable consumer positions, shared-board revisions, knowledge search/capture and code pointers. Existing account, credential and ACL installations have an approved migration path.
- **P10-AC09:** Startup and refreshed summaries distinguish connected, disconnected, stale, unknown and not-configured hubs at the caller scope. A partition cannot appear as healthy federation, expose another tenant or release reserved work; broker reachability alone does not establish usable partner capacity.

<a id="P10-T01"></a>

### P10-T01: Extend current federation capability

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Extend current federation capability. Move one recorded protocol and persistence boundary at a time, preserving existing messages, work, board, knowledge, code and deployment administration workflows.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Reuse P01 HUB-11-C02 assertion mappings and immutable baseline artifacts when comparing the actual production adapter; retain refused inputs, original identity fields and every failed/skipped outcome.

**Deliverables**

1. Extend current federation capability. Move one recorded protocol and persistence boundary at a time, preserving existing messages, work, board, knowledge, code and deployment administration workflows.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Extend current federation capability. Move one recorded protocol and persistence boundary at a time, preserving existing messages, work, board, knowledge, code and deployment administration workflows.
2. P10-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P10-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P10-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.
5. P10-T01-AC05: Execute actual legacy-v2/v3 to new-v1 envelope translation through the production federation adapter. Compare sender, source node, repository, original message/work IDs, peer/account, plane/type/recipient and version refusals against the retained native129 baseline and P01 per-field mapping; retain all refusal/recovery cases. P01 characterization is not adapter acceptance.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-T02"></a>

### P10-T02: Implement scoped trust agreements, node/peer enrollment, NATS leaf topology, independent JetStream domains where needed, and selective sharing/replication.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement scoped trust agreements, node/peer enrollment, NATS leaf topology, independent JetStream domains where needed, and selective sharing/replication.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-001 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Implement scoped trust agreements, node/peer enrollment, NATS leaf topology, independent JetStream domains where needed, and selective sharing/replication.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement scoped trust agreements, node/peer enrollment, NATS leaf topology, independent JetStream domains where needed, and selective sharing/replication.
2. P10-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P10-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P10-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-T03"></a>

### P10-T03: Publish authorized capabilities and capacity

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Publish authorized capabilities and capacity. Filter deterministic eligibility before optional Jev suitability scoring and revalidate at offer time.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-004 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Publish authorized capabilities and capacity. Filter deterministic eligibility before optional Jev suitability scoring and revalidate at offer time.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Publish authorized capabilities and capacity. Filter deterministic eligibility before optional Jev suitability scoring and revalidate at offer time.
2. P10-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P10-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P10-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-T04"></a>

### P10-T04: Implement durable offer, acceptance, reservation, execution reporting, result submission, origin acceptance, reconciliation, revocation, and explicit reassignment.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement durable offer, acceptance, reservation, execution reporting, result submission, origin acceptance, reconciliation, revocation, and explicit reassignment.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-002, AMX-BASE-003, AMX-BASE-004, AMX-BASE-005 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Implement durable offer, acceptance, reservation, execution reporting, result submission, origin acceptance, reconciliation, revocation, and explicit reassignment.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement durable offer, acceptance, reservation, execution reporting, result submission, origin acceptance, reconciliation, revocation, and explicit reassignment.
2. P10-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P10-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P10-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-T05"></a>

### P10-T05: Support work/context/artifacts/code/findings/messages/board projections with authenticated provenance, digests, visibility, and retention.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Support work/context/artifacts/code/findings/messages/board projections with authenticated provenance, digests, visibility, and retention.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.
6. Preserve the assertions assigned to this task for AMX-BASE-005 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Support work/context/artifacts/code/findings/messages/board projections with authenticated provenance, digests, visibility, and retention.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Support work/context/artifacts/code/findings/messages/board projections with authenticated provenance, digests, visibility, and retention.
2. P10-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P10-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P10-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-T06"></a>

### P10-T06: Add automatic receiving-hub acceptance inside approved rules, pending human approval for review-required work, and rejection for hard-denied work

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Add automatic receiving-hub acceptance inside approved rules, pending human approval for review-required work, and rejection for hard-denied work. Enforce any onward delegation/export separately.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Add automatic receiving-hub acceptance inside approved rules, pending human approval for review-required work, and rejection for hard-denied work. Enforce any onward delegation/export separately.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T06-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Add automatic receiving-hub acceptance inside approved rules, pending human approval for review-required work, and rejection for hard-denied work. Enforce any onward delegation/export separately.
2. P10-T06-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P10-T06-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P10-T06-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-T07"></a>

### P10-T07: Qualify and enable the remote-hub modes of P09 delegate, inspect-hub, and review-results skills on real connected hubs and supported clients

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Qualify and enable the remote-hub modes of P09 delegate, inspect-hub, and review-results skills on real connected hubs and supported clients. Their earlier local qualification does not count as federation evidence.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Qualify and enable the remote-hub modes of P09 delegate, inspect-hub, and review-results skills on real connected hubs and supported clients. Their earlier local qualification does not count as federation evidence.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T07-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Qualify and enable the remote-hub modes of P09 delegate, inspect-hub, and review-results skills on real connected hubs and supported clients. Their earlier local qualification does not count as federation evidence.
2. P10-T07-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P10-T07-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P10-T07-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-T08"></a>

### P10-T08: Use separate persistent JetStream domains for hubs that must operate autonomously

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Use separate persistent JetStream domains for hubs that must operate autonomously. Share selected authorized records and views, preserve origin task versus receiver execution authority, and reconcile replication gaps without treating mirrors or merged sources as a shared mutable task.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Use separate persistent JetStream domains for hubs that must operate autonomously. Share selected authorized records and views, preserve origin task versus receiver execution authority, and reconcile replication gaps without treating mirrors or merged sources as a shared mutable task.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T08-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Use separate persistent JetStream domains for hubs that must operate autonomously. Share selected authorized records and views, preserve origin task versus receiver execution authority, and reconcile replication gaps without treating mirrors or merged sources as a shared mutable task.
2. P10-T08-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P10-T08-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P10-T08-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-T09"></a>

### P10-T09: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T09-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P10-T09-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P10-T09-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P10-T09-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-T10"></a>

### P10-T10: Populate LOCAL-01 status with authorized configured/connected hubs, trust scope, last observation and known delegated/reserved work

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Populate LOCAL-01 status with authorized configured/connected hubs, trust scope, last observation and known delegated/reserved work. Separate NATS link reachability from federation readiness, permission and capacity.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Populate LOCAL-01 status with authorized configured/connected hubs, trust scope, last observation and known delegated/reserved work. Separate NATS link reachability from federation readiness, permission and capacity.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P10-T10-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Populate LOCAL-01 status with authorized configured/connected hubs, trust scope, last observation and known delegated/reserved work. Separate NATS link reachability from federation readiness, permission and capacity.
2. P10-T10-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P10-T10-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P10-T10-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-JEV-010"></a>

### P10-JEV-010: Acceptance-criterion ambiguity

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Acceptance-criterion ambiguity
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P10-JEV-010-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P10-JEV-010-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P10-JEV-010-AC03: Preserve this item-specific boundary: Jev flags the issue; a user or generator writes revised criteria.
4. P10-JEV-010-AC04: Report Reopened work; clarification usefulness on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P10-JEV-010-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P10-JEV-010-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-FEDERATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-010",
  "group": "planning",
  "title": "Acceptance-criterion ambiguity",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Planning and orchestration plugins",
  "decision": "Criterion text → observable, ambiguous, contradictory, or missing evidence definition.",
  "saving": "Obtain targeted clarification before expensive implementation.",
  "boundary": "Jev flags the issue; a user or generator writes revised criteria.",
  "metric": "Reopened work; clarification usefulness",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-JEV-032"></a>

### P10-JEV-032: Partner-hub suitability

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Partner-hub suitability
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P10-JEV-032-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P10-JEV-032-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P10-JEV-032-AC03: Preserve this item-specific boundary: Origin ownership and accepted/unknown reservations remain protected.
4. P10-JEV-032-AC04: Report Unnecessary delegations and rework on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P10-JEV-032-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P10-JEV-032-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-FEDERATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-032",
  "group": "placement",
  "title": "Partner-hub suitability",
  "primitives": [
    "S",
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Orchestration and resource owners",
  "decision": "Approved hubs and shareable task summary → rank fit or no suitable receiver.",
  "saving": "Avoid exploratory delegation to several teams.",
  "boundary": "Origin ownership and accepted/unknown reservations remain protected.",
  "metric": "Unnecessary delegations and rework",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-JEV-043"></a>

### P10-JEV-043: Stage handoff readiness advice

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Stage handoff readiness advice
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P10-JEV-043-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P10-JEV-043-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P10-JEV-043-AC03: Preserve this item-specific boundary: The owner checks actual artifacts, tests, approvals, and state transitions.
4. P10-JEV-043-AC04: Report Rejected handoffs and coordination turns on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P10-JEV-043-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P10-JEV-043-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-FEDERATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-043",
  "group": "coordination",
  "title": "Stage handoff readiness advice",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Conversation, event, and orchestration plugins",
  "decision": "Declared deliverables and current evidence → missing prerequisites or apparent readiness.",
  "saving": "Avoid premature handoffs and redundant coordinator reviews.",
  "boundary": "The owner checks actual artifacts, tests, approvals, and state transitions.",
  "metric": "Rejected handoffs and coordination turns",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-VIDEO-05"></a>

### P10-VIDEO-05: Federated questions before artifact transfer

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Federated questions before artifact transfer
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P10-VIDEO-05-AC01: Deny confidential membership/existence questions and unauthorized provider destinations before inference.
2. P10-VIDEO-05-AC02: Lost/duplicate responses preserve unknown and reservation states; authorized findings and artifact transfer have independently enforced visibility.
3. P10-VIDEO-05-AC03: Preserve source boundary: A typed answer can disclose confidential facts. Receiver-controlled query templates, output policy, quotas and provider permission are required. Evaluation at Hub B does not imply a local Jev model. Unavailable is not no; origin ownership and reserved disconnected work are unaffected.
4. P10-VIDEO-05-AC04: Measure Bytes and downstream tokens per useful result; relevance recall; latency; unauthorized-inference tests.
5. P10-VIDEO-05-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P10-VIDEO-05-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-FEDERATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-05",
  "title": "Federated questions before artifact transfer",
  "kind": "New federation extension",
  "level": 9,
  "time": "23:39",
  "seconds": 1419,
  "prior": [
    "JEV-027",
    "JEV-032",
    "JEV-076"
  ],
  "owner": "Federation and evidence-owner plugins",
  "proposal": "Hub A sends a scoped question to Hub B, such as whether an approved project contains a relevant CODESYS library migration example. Hub B evaluates only permitted evidence and returns authorized typed findings and artifact references. Hub A requests the useful artifacts afterward.",
  "delta": "Moves the initial semantic investigation to the hub that owns the evidence, before deciding what to transfer.",
  "benefit": "Reduces raw artifact transfer, duplicate source reading and premature specialist delegation.",
  "boundary": "A typed answer can disclose confidential facts. Receiver-controlled query templates, output policy, quotas and provider permission are required. Evaluation at Hub B does not imply a local Jev model. Unavailable is not no; origin ownership and reserved disconnected work are unaffected.",
  "metric": "Bytes and downstream tokens per useful result; relevance recall; latency; unauthorized-inference tests.",
  "priority": "Next",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=1419s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level09/ask-files.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-VIDEO-12"></a>

### P10-VIDEO-12: Cross-hub deliverable-meaning checks

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Cross-hub deliverable-meaning checks
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P10-VIDEO-12-AC01: Reviewed bilateral fixtures distinguish offline compilation from simulator evidence and flag missing named versions or acceptance artifacts.
2. P10-VIDEO-12-AC02: Semantic agreement never signs trust, transfers final acceptance or permits an operation; disagreements retain both source statements.
3. P10-VIDEO-12-AC03: Preserve source boundary: Versions, schema fields and permissions are checked in code. A model finding does not sign a trust agreement, expand scope, approve industrial operations or accept the final result.
4. P10-VIDEO-12-AC04: Measure Clarifications before execution; rejected deliveries; rework hours; added negotiation latency.
5. P10-VIDEO-12-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P10-VIDEO-12-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-FEDERATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-12",
  "title": "Cross-hub deliverable-meaning checks",
  "kind": "Federation refinement of existing use cases",
  "level": 4,
  "time": "8:50",
  "seconds": 530,
  "prior": [
    "JEV-010",
    "JEV-032",
    "JEV-041",
    "JEV-043",
    "JEV-049",
    "JEV-079"
  ],
  "owner": "Delegation contract plugin",
  "proposal": "Compare the origin's acceptance criteria with the receiver's proposed deliverables and explicit assumptions. Flag semantic mismatches such as offline compilation being offered where the request requires evidence from a named simulator version. Before enabling a workflow between hubs, run a shared set of synthetic, reviewed contract fixtures through both hubs and compare their interpretations in code.",
  "delta": "Adds a bilateral meaning check before expensive delegated execution starts. Shared-fixture qualification adds a repeatable compatibility check across separately administered definitions.",
  "benefit": "Avoids cross-team work that technically completes but fails the origin's intended acceptance criteria.",
  "boundary": "Versions, schema fields and permissions are checked in code. A model finding does not sign a trust agreement, expand scope, approve industrial operations or accept the final result.",
  "metric": "Clarifications before execution; rejected deliveries; rework hours; added negotiation latency.",
  "priority": "Next",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=530s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level05/agent-router.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-agentmux-jev-delegate"></a>

### P10-agentmux-jev-delegate: agentmux-jev-delegate

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-delegate
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P10-agentmux-jev-delegate-AC01: Origin owns final acceptance; lost acceptance replies and disconnected accepted work remain reserved; retries do not create duplicate execution.
2. P10-agentmux-jev-delegate-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P10-agentmux-jev-delegate-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P10-agentmux-jev-delegate-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P10-agentmux-jev-delegate-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P10-agentmux-jev-delegate-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST, EVAL-FEDERATION

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-delegate",
  "description": "Prepare and track scoped delegation, compare both sides' understanding, and reconcile execution records through Agentmux.",
  "useCase": "Delegate an approved investigation to a partner hub that agrees to return specific evidence.",
  "eval": "Origin owns final acceptance; lost acceptance replies and disconnected accepted work remain reserved; retries do not create duplicate execution."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-agentmux-jev-inspect-hub"></a>

### P10-agentmux-jev-inspect-hub: agentmux-jev-inspect-hub

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-inspect-hub
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P10-agentmux-jev-inspect-hub-AC01: Source-owner query, provider and disclosure rules apply; denied/partial/unavailable never becomes no evidence.
2. P10-agentmux-jev-inspect-hub-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P10-agentmux-jev-inspect-hub-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P10-agentmux-jev-inspect-hub-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P10-agentmux-jev-inspect-hub-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P10-agentmux-jev-inspect-hub-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST, EVAL-FEDERATION

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-inspect-hub",
  "description": "Ask an authorized partner hub bounded questions about its permitted sources before requesting relevant artifacts.",
  "useCase": "Check whether a partner's shared archive contains a useful investigation before transferring its reports.",
  "eval": "Source-owner query, provider and disclosure rules apply; denied/partial/unavailable never becomes no evidence."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-agentmux-jev-review-results"></a>

### P10-agentmux-jev-review-results: agentmux-jev-review-results

**Status:** planned. **Owner:** Codex.

**Dependencies:** P09-GATE, P10-T09.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-review-results
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P10-agentmux-jev-review-results-AC01: Receiver completion is distinct from origin acceptance; no fabricated tests or waived requirements; acceptance owner remains authoritative.
2. P10-agentmux-jev-review-results-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P10-agentmux-jev-review-results-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P10-agentmux-jev-review-results-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P10-agentmux-jev-review-results-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P10-agentmux-jev-review-results-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST, EVAL-FEDERATION

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-review-results",
  "description": "Map submitted artifacts and actual validation evidence to origin acceptance criteria and identify focused rework.",
  "useCase": "Review a partner's completed patch and test evidence against the requested outcome.",
  "eval": "Receiver completion is distinct from origin acceptance; no fabricated tests or waived requirements; acceptance owner remains authoritative."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P10-GATE"></a>

### P10-GATE: Verify and accept P10

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-T01, P10-T02, P10-T03, P10-T04, P10-T05, P10-T06, P10-T07, P10-T08, P10-T09, P10-T10, P10-JEV-010, P10-JEV-032, P10-JEV-043, P10-VIDEO-05, P10-VIDEO-12, P10-agentmux-jev-delegate, P10-agentmux-jev-inspect-hub, P10-agentmux-jev-review-results.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Federation state-machine and authority tests
2. Partition/reconciliation matrix
3. Cross-organization demo with auditable evidence
4. Independent-domain storage, retention-gap and older-origin recovery reports
5. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P10-GATE-AC01: Same-organization and cross-organization reference workflows both finish with origin-owned result acceptance.
2. P10-GATE-AC02: Accepted work stays reserved while disconnected. Missing acceptance acknowledgment remains ambiguous until reconciled, never automatically redispatched.
3. P10-GATE-AC03: Duplicate offer/result delivery creates one delegation/attempt outcome. Wrong executor, project, repository, or task version is rejected. Stale grants cannot authorize new effects. Authenticated historical results from previously authorized reserved work are retained for reconciliation or quarantine when current policy requires it; grant expiry cannot erase the obligation or its evidence.
4. P10-GATE-AC04: Unauthorized accounts cannot subscribe to private project subjects or fetch protected artifacts. Transitive hub connectivity grants no access.
5. P10-GATE-AC05: Reconnect recovers progress/results and durable revocations. A stop request is not reported as execution stopped until confirmed or clearly unknown.
6. P10-GATE-AC06: A leaf outage and independent local persistence produce the agreed offline behavior without treating broker connectivity as shared ownership.
7. P10-GATE-AC07: After a partition, mirror lag, retention gap or restoration of an older origin snapshot, hubs reconcile authoritative task and execution records before admitting overlapping work. Replication never grants write authority, and accepted or acceptance-unknown work remains reserved.
8. P10-GATE-AC08: Migration fixtures retain current hub verbs, five federation plugins, pending outbox/quarantine records, seen IDs, durable consumer positions, shared-board revisions, knowledge search/capture and code pointers. Existing account, credential and ACL installations have an approved migration path.
9. P10-GATE-AC09: Startup and refreshed summaries distinguish connected, disconnected, stale, unknown and not-configured hubs at the caller scope. A partition cannot appear as healthy federation, expose another tenant or release reserved work; broker reachability alone does not establish usable partner capacity.
10. P10-GATE-AC10: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
11. P10-GATE-AC11: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run at least three hubs and two independently administered organizations with real accounts/leaf links and isolated stores.
2. Inject partitions before/after offer acceptance, drop replies, duplicate deliveries, restart hubs, expire/revoke grants, and alter task versions.
3. Exercise explicit cancel/reassign with a possibly running old worker and document unavoidable external-effect uncertainty.
4. Snapshot the origin before a remote acceptance, let the receiver accept and continue, restore that older origin snapshot, and require reconciliation before overlapping admission. Verify one reservation and no duplicate execution.
5. Disconnect beyond configured stream-retention and deduplication horizons using short test limits, then prune, restart, and reconnect. Require gap detection, snapshot/reconciliation or explicit intervention, preserved reservations, and no duplicate effects.
6. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
7. Exercise FAIL-62 against two real hubs across reconnect, grant change and outage; compare terminal/dashboard snapshots and retained reservations.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P11. Industrial and vendor extension packages

Industrial workflows extend Agentmux through the same contracts as other domains.

**Epic acceptance criteria**

- **P11-AC01:** A selected industrial workflow completes through client, orchestration, tool plugin, evidence, and dashboard without kernel or generic task-model changes.
- **P11-AC02:** Standalone and nested installation of selected domain children behave as declared.
- **P11-AC03:** Every migrated existing integration has a parity/deprecation record, tested tool/platform matrix, and explicit missing capability status.
- **P11-AC04:** Equipment writes require the correct target/action/operation grant and any applicable human approval at the owning tool endpoint.
- **P11-AC05:** A vendor adapter passes with the actual required tool or a clearly labeled simulator. Simulated success is never sold as hardware qualification.
- **P11-AC06:** Every existing protocol, standalone library, CLI and dashboard integration has individual behavior evidence, including bounds and supported host/target versions. Narrowing the first demonstration does not retire an existing capability.

<a id="P11-T01"></a>

### P11-T01: Package industrial orchestration guidance, tools, schemas, UI renderers, and skills with explicitly independent or parent-owned children.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Package industrial orchestration guidance, tools, schemas, UI renderers, and skills with explicitly independent or parent-owned children.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Package industrial orchestration guidance, tools, schemas, UI renderers, and skills with explicitly independent or parent-owned children.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P11-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Package industrial orchestration guidance, tools, schemas, UI renderers, and skills with explicitly independent or parent-owned children.
2. P11-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P11-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P11-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Use protocol simulators and recorded fixtures, then controlled hardware/vendor environments for supported claims.
2. Test wrong device/project/version, timeout, partial writes, lost replies, credential failure, and disconnected grants.
3. Demonstrate missing Windows-native prerequisites as an actionable unsupported environment, not silent fallback.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-T02"></a>

### P11-T02: Migrate current Modbus, MQTT, network discovery, PROFINET snapshot/DCP, passive BOOTP, EtherNet/IP/Logix, ADS, EtherCAT diagnostics, CODESYS runtime tooling, PCAP analysis, and existing engineering wrappers to declared capability plugins.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Migrate current Modbus, MQTT, network discovery, PROFINET snapshot/DCP, passive BOOTP, EtherNet/IP/Logix, ADS, EtherCAT diagnostics, CODESYS runtime tooling, PCAP analysis, and existing engineering wrappers to declared capability plugins.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Migrate current Modbus, MQTT, network discovery, PROFINET snapshot/DCP, passive BOOTP, EtherNet/IP/Logix, ADS, EtherCAT diagnostics, CODESYS runtime tooling, PCAP analysis, and existing engineering wrappers to declared capability plugins.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P11-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Migrate current Modbus, MQTT, network discovery, PROFINET snapshot/DCP, passive BOOTP, EtherNet/IP/Logix, ADS, EtherCAT diagnostics, CODESYS runtime tooling, PCAP analysis, and existing engineering wrappers to declared capability plugins.
2. P11-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P11-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P11-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Use protocol simulators and recorded fixtures, then controlled hardware/vendor environments for supported claims.
2. Test wrong device/project/version, timeout, partial writes, lost replies, credential failure, and disconnected grants.
3. Demonstrate missing Windows-native prerequisites as an actionable unsupported environment, not silent fallback.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-T03"></a>

### P11-T03: Define CODESYS, Siemens, Rockwell, and related vendor integration slices with actual licensed tool/OS/hardware prerequisites and test environments.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Define CODESYS, Siemens, Rockwell, and related vendor integration slices with actual licensed tool/OS/hardware prerequisites and test environments.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Define CODESYS, Siemens, Rockwell, and related vendor integration slices with actual licensed tool/OS/hardware prerequisites and test environments.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P11-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Define CODESYS, Siemens, Rockwell, and related vendor integration slices with actual licensed tool/OS/hardware prerequisites and test environments.
2. P11-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P11-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P11-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Use protocol simulators and recorded fixtures, then controlled hardware/vendor environments for supported claims.
2. Test wrong device/project/version, timeout, partial writes, lost replies, credential failure, and disconnected grants.
3. Demonstrate missing Windows-native prerequisites as an actionable unsupported environment, not silent fallback.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-T04"></a>

### P11-T04: Add engineering build/migration/evidence skills and Jev definitions for diagnostics and source-preserving comparisons.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Add engineering build/migration/evidence skills and Jev definitions for diagnostics and source-preserving comparisons.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Add engineering build/migration/evidence skills and Jev definitions for diagnostics and source-preserving comparisons.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P11-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Add engineering build/migration/evidence skills and Jev definitions for diagnostics and source-preserving comparisons.
2. P11-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P11-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P11-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Use protocol simulators and recorded fixtures, then controlled hardware/vendor environments for supported claims.
2. Test wrong device/project/version, timeout, partial writes, lost replies, credential failure, and disconnected grants.
3. Demonstrate missing Windows-native prerequisites as an actionable unsupported environment, not silent fallback.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-T05"></a>

### P11-T05: Implement read/simulation-first reference workflows and per-action permissions for equipment changes

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement read/simulation-first reference workflows and per-action permissions for equipment changes. Resolve any Windows-native execution host arrangement explicitly.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement read/simulation-first reference workflows and per-action permissions for equipment changes. Resolve any Windows-native execution host arrangement explicitly.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P11-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement read/simulation-first reference workflows and per-action permissions for equipment changes. Resolve any Windows-native execution host arrangement explicitly.
2. P11-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P11-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P11-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Use protocol simulators and recorded fixtures, then controlled hardware/vendor environments for supported claims.
2. Test wrong device/project/version, timeout, partial writes, lost replies, credential failure, and disconnected grants.
3. Demonstrate missing Windows-native prerequisites as an actionable unsupported environment, not silent fallback.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-T06"></a>

### P11-T06: Inventory existing PCM600/ABB-related privilege hooks as integration requirements, preserving target/action confirmation and audit

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Inventory existing PCM600/ABB-related privilege hooks as integration requirements, preserving target/action confirmation and audit. Do not infer a complete vendor adapter from the existence of a guard hook.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Inventory existing PCM600/ABB-related privilege hooks as integration requirements, preserving target/action confirmation and audit. Do not infer a complete vendor adapter from the existence of a guard hook.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P11-T06-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Inventory existing PCM600/ABB-related privilege hooks as integration requirements, preserving target/action confirmation and audit. Do not infer a complete vendor adapter from the existence of a guard hook.
2. P11-T06-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P11-T06-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P11-T06-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Use protocol simulators and recorded fixtures, then controlled hardware/vendor environments for supported claims.
2. Test wrong device/project/version, timeout, partial writes, lost replies, credential failure, and disconnected grants.
3. Demonstrate missing Windows-native prerequisites as an actionable unsupported environment, not silent fallback.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-T07"></a>

### P11-T07: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P11-T07-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P11-T07-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P11-T07-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P11-T07-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Use protocol simulators and recorded fixtures, then controlled hardware/vendor environments for supported claims.
2. Test wrong device/project/version, timeout, partial writes, lost replies, credential failure, and disconnected grants.
3. Demonstrate missing Windows-native prerequisites as an actionable unsupported environment, not silent fallback.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-JEV-068"></a>

### P11-JEV-068: Engineering vendor/workflow selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Engineering vendor/workflow selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-JEV-068-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P11-JEV-068-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P11-JEV-068-AC03: Preserve this item-specific boundary: Exact product/version/platform compatibility and allowed operations use declarations.
4. P11-JEV-068-AC04: Report Wrong-tool avoidance and instruction tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P11-JEV-068-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-JEV-068-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-068",
  "group": "industrial",
  "title": "Engineering vendor/workflow selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Approved project description and installed vendor capabilities → likely applicable engineering path.",
  "saving": "Load relevant CODESYS/Siemens/Rockwell guidance instead of all vendor manuals.",
  "boundary": "Exact product/version/platform compatibility and allowed operations use declarations.",
  "metric": "Wrong-tool avoidance and instruction tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection",
  "reusesMechanismOf": [
    "JEV-004",
    "JEV-015"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-JEV-069"></a>

### P11-JEV-069: Offline compiler/build triage

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Offline compiler/build triage
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-JEV-069-AC01: Keep exact exit/status/protocol facts unchanged; classify only the residual unstructured evidence.
2. P11-JEV-069-AC02: Incomplete logs and uncertain external actions remain explicit; diagnosis does not replay a command or declare it stopped.
3. P11-JEV-069-AC03: Preserve this item-specific boundary: Validate through vendor tooling; interpretation grants no equipment access.
4. P11-JEV-069-AC04: Report Diagnostic quality and investigation tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P11-JEV-069-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-JEV-069-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-069",
  "group": "industrial",
  "title": "Offline compiler/build triage",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "First",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Sanitized engineering compiler diagnostics → missing library, version mismatch, symbol/type issue, or unknown.",
  "saving": "Avoid rereading whole project exports for common build problems.",
  "boundary": "Validate through vendor tooling; interpretation grants no equipment access.",
  "metric": "Diagnostic quality and investigation tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "diagnostic-classification",
  "reusesMechanismOf": [
    "JEV-044"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-JEV-070"></a>

### P11-JEV-070: Tag and entity alignment

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Tag and entity alignment
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-JEV-070-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P11-JEV-070-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P11-JEV-070-AC03: Preserve this item-specific boundary: Exact address, type, units, and equipment identity are independently checked.
4. P11-JEV-070-AC04: Report Mapping precision and review effort on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P11-JEV-070-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-JEV-070-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-070",
  "group": "industrial",
  "title": "Tag and entity alignment",
  "primitives": [
    "S",
    "N",
    "C"
  ],
  "stage": "Next",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Pre-extracted tags/IO descriptions and candidate mappings → semantic correspondence or none.",
  "saving": "Avoid generating or manually comparing every possible mapping.",
  "boundary": "Exact address, type, units, and equipment identity are independently checked.",
  "metric": "Mapping precision and review effort",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection",
  "reusesMechanismOf": [
    "JEV-021"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-JEV-071"></a>

### P11-JEV-071: Requirement-to-engineering-artifact mapping

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Requirement-to-engineering-artifact mapping
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-JEV-071-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P11-JEV-071-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P11-JEV-071-AC03: Preserve this item-specific boundary: A plausible match does not prove implementation or commissioning compliance.
4. P11-JEV-071-AC04: Report Evidence recall and engineer review time on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P11-JEV-071-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-JEV-071-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-071",
  "group": "industrial",
  "title": "Requirement-to-engineering-artifact mapping",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Engineering requirement and indexed program/test/document candidates → relevant evidence IDs.",
  "saving": "Reduce repeated scans of large engineering projects.",
  "boundary": "A plausible match does not prove implementation or commissioning compliance.",
  "metric": "Evidence recall and engineer review time",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection",
  "reusesMechanismOf": [
    "JEV-021",
    "JEV-023"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-JEV-072"></a>

### P11-JEV-072: Vendor manual passage selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Vendor manual passage selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-JEV-072-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P11-JEV-072-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P11-JEV-072-AC03: Preserve this item-specific boundary: Version-specific warnings and contraindications are protected evidence.
4. P11-JEV-072-AC04: Report Critical-warning recall and prompt tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P11-JEV-072-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-JEV-072-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-072",
  "group": "industrial",
  "title": "Vendor manual passage selection",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Task, exact product/version filters, and authorized manual passages → relevant sections.",
  "saving": "Keep large manuals out of each agent context.",
  "boundary": "Version-specific warnings and contraindications are protected evidence.",
  "metric": "Critical-warning recall and prompt tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection",
  "reusesMechanismOf": [
    "JEV-023",
    "JEV-026"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-JEV-073"></a>

### P11-JEV-073: Migration concern classification

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Migration concern classification
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-JEV-073-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P11-JEV-073-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P11-JEV-073-AC03: Preserve this item-specific boundary: No claim of compatible physical behavior without vendor tests and engineering validation.
4. P11-JEV-073-AC04: Report Missed concerns and repeated analysis on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P11-JEV-073-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-JEV-073-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-073",
  "group": "industrial",
  "title": "Migration concern classification",
  "primitives": [
    "C",
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Source/target versions, vendor notes, and proposed change → likely compatibility concern.",
  "saving": "Focus a specialist on affected migration issues.",
  "boundary": "No claim of compatible physical behavior without vendor tests and engineering validation.",
  "metric": "Missed concerns and repeated analysis",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change",
  "reusesMechanismOf": [
    "JEV-062"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-JEV-074"></a>

### P11-JEV-074: Commissioning evidence coverage

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Commissioning evidence coverage
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-JEV-074-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P11-JEV-074-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P11-JEV-074-AC03: Preserve this item-specific boundary: Cannot sign off equipment, infer safety, or manufacture an observed test result.
4. P11-JEV-074-AC04: Report Missed evidence gaps and review cost on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P11-JEV-074-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-JEV-074-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-074",
  "group": "industrial",
  "title": "Commissioning evidence coverage",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Checklist item and supplied signed/test evidence → supported relationship or gap.",
  "saving": "Reduce repetitive packet review and direct attention to missing evidence.",
  "boundary": "Cannot sign off equipment, infer safety, or manufacture an observed test result.",
  "metric": "Missed evidence gaps and review cost",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship",
  "reusesMechanismOf": [
    "JEV-047",
    "JEV-049"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-JEV-086"></a>

### P11-JEV-086: Engineering requirement semantic diff

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Engineering requirement semantic diff
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-JEV-086-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P11-JEV-086-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P11-JEV-086-AC03: Preserve this item-specific boundary: Preserve negation, exceptions, units, and source text; no automated engineering approval.
4. P11-JEV-086-AC04: Report Missed scope-changing clauses on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P11-JEV-086-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-JEV-086-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-086",
  "group": "industrial",
  "title": "Engineering requirement semantic diff",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Before/after clauses → stronger, weaker, changed condition, wording-only, or unclear.",
  "saving": "Focus engineering review on changed meaning instead of every unchanged page.",
  "boundary": "Preserve negation, exceptions, units, and source text; no automated engineering approval.",
  "metric": "Missed scope-changing clauses",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change",
  "reusesMechanismOf": [
    "JEV-006"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-JEV-088"></a>

### P11-JEV-088: Erratum and release-note applicability

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Erratum and release-note applicability
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-JEV-088-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P11-JEV-088-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P11-JEV-088-AC03: Preserve this item-specific boundary: Version ranges are computed; keep critical notices and independently validate applicability.
4. P11-JEV-088-AC04: Report Applicable-warning recall and review cost on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P11-JEV-088-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-JEV-088-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-088",
  "group": "industrial",
  "title": "Erratum and release-note applicability",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Exact installed versions, project features, and official note excerpts → plausible concern or insufficient evidence.",
  "saving": "Read only potentially relevant release-history sections in depth.",
  "boundary": "Version ranges are computed; keep critical notices and independently validate applicability.",
  "metric": "Applicable-warning recall and review cost",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection",
  "reusesMechanismOf": [
    "JEV-062",
    "JEV-072"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-industrial-jev-build"></a>

### P11-industrial-jev-build: industrial-jev-build

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: industrial-jev-build
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-industrial-jev-build-AC01: Uses actual exported text and compiler facts; does not assume access to Windows vendor tools from WSL or execute equipment operations.
2. P11-industrial-jev-build-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P11-industrial-jev-build-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P11-industrial-jev-build-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P11-industrial-jev-build-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-industrial-jev-build-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "name": "industrial-jev-build",
  "description": "Interpret authorized offline toolchain and compiler artifacts using vendor-specific question packages.",
  "useCase": "Triage a CODESYS build log against the exact toolchain version and relevant documentation.",
  "eval": "Uses actual exported text and compiler facts; does not assume access to Windows vendor tools from WSL or execute equipment operations."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-industrial-jev-migration"></a>

### P11-industrial-jev-migration: industrial-jev-migration

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: industrial-jev-migration
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-industrial-jev-migration-AC01: Version math and compatibility evidence are exact; similarity never proves interchangeability or safe deployment.
2. P11-industrial-jev-migration-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P11-industrial-jev-migration-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P11-industrial-jev-migration-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P11-industrial-jev-migration-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-industrial-jev-migration-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "name": "industrial-jev-migration",
  "description": "Review version-specific changes, requirement differences and proposed tag/entity mappings for engineering migrations.",
  "useCase": "Identify concerns when moving a project between supported library versions and suggest mappings for review.",
  "eval": "Version math and compatibility evidence are exact; similarity never proves interchangeability or safe deployment."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-industrial-jev-evidence"></a>

### P11-industrial-jev-evidence: industrial-jev-evidence

**Status:** planned. **Owner:** Codex.

**Dependencies:** P10-GATE, P11-T07.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: industrial-jev-evidence
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P11-industrial-jev-evidence-AC01: Does not invent observations, certify equipment safety or sign off commissioning.
2. P11-industrial-jev-evidence-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P11-industrial-jev-evidence-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P11-industrial-jev-evidence-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P11-industrial-jev-evidence-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P11-industrial-jev-evidence-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "name": "industrial-jev-evidence",
  "description": "Map engineering requirements to supplied test and commissioning evidence and identify missing or contradictory coverage.",
  "useCase": "Find acceptance requirements that lack corresponding observations in a commissioning packet.",
  "eval": "Does not invent observations, certify equipment safety or sign off commissioning."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P11-GATE"></a>

### P11-GATE: Verify and accept P11

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-T01, P11-T02, P11-T03, P11-T04, P11-T05, P11-T06, P11-T07, P11-JEV-068, P11-JEV-069, P11-JEV-070, P11-JEV-071, P11-JEV-072, P11-JEV-073, P11-JEV-074, P11-JEV-086, P11-JEV-088, P11-industrial-jev-build, P11-industrial-jev-migration, P11-industrial-jev-evidence.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Domain package and vendor compatibility matrix
2. Industrial workflow and permission report
3. Protocol parity and hardware qualification records
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P11-GATE-AC01: A selected industrial workflow completes through client, orchestration, tool plugin, evidence, and dashboard without kernel or generic task-model changes.
2. P11-GATE-AC02: Standalone and nested installation of selected domain children behave as declared.
3. P11-GATE-AC03: Every migrated existing integration has a parity/deprecation record, tested tool/platform matrix, and explicit missing capability status.
4. P11-GATE-AC04: Equipment writes require the correct target/action/operation grant and any applicable human approval at the owning tool endpoint.
5. P11-GATE-AC05: A vendor adapter passes with the actual required tool or a clearly labeled simulator. Simulated success is never sold as hardware qualification.
6. P11-GATE-AC06: Every existing protocol, standalone library, CLI and dashboard integration has individual behavior evidence, including bounds and supported host/target versions. Narrowing the first demonstration does not retire an existing capability.
7. P11-GATE-AC07: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
8. P11-GATE-AC08: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Use protocol simulators and recorded fixtures, then controlled hardware/vendor environments for supported claims.
2. Test wrong device/project/version, timeout, partial writes, lost replies, credential failure, and disconnected grants.
3. Demonstrate missing Windows-native prerequisites as an actionable unsupported environment, not silent fallback.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P12. Production hardening and first sellable release

Customers can install, operate, recover, and support the complete launch product.

**Epic acceptance criteria**

- **P12-AC01:** Every launch requirement is linked to passing evidence for the exact release candidate. Critical correctness/security defects are closed.
- **P12-AC02:** A new developer installs and completes the reference task using only published docs on every supported platform.
- **P12-AC03:** A team administrator enrolls two organizations, shares a scoped project, delegates work, survives a partition, and restores a backup.
- **P12-AC04:** The approved capacity/SLO targets and recovery drill pass without losing acknowledged durable records within the tested fault model.
- **P12-AC05:** Codex reviews release-readiness evidence and records provisional readiness plus all outstanding MERGE-01 requirements. P12 acceptance does not authorize merge or release; final branch acceptance requires every phase and safe bilateral orchestration between independently enrolled, agent-operated real hubs on the exact candidate.
- **P12-AC06:** The approved NATS storage profile passes record/checkpoint/artifact restore, projection rebuild, retention-gap and migration rollback drills under the declared process/host/disk/quorum failure model. Published RPO/RTO and capacity claims match observed evidence, and no unreviewed SQL authority remains.
- **P12-AC07:** Every component and behavior check has a reviewed release disposition. Required baseline/candidate comparisons and migration drills pass on the supported matrix; no skipped check, missing component or unapproved feature removal can be hidden by a successful new reference workflow.
- **P12-AC08:** Fresh-user and upgrade drills pass LOCAL-01 cold/warm/concurrent startup, actionable Docker failures, explicit stop, persistent data recovery and scoped hub status on the supported platform/client matrix. No launch silently upgrades an incompatible live stack, loses durable work or bypasses a required phase gate.

<a id="P12-T01"></a>

### P12-T01: Finish signed/reproducible distributions, dependency locks/SBOM, versioned configuration, upgrade/rollback, package verification, and support diagnostics.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE, P12-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Finish signed/reproducible distributions, dependency locks/SBOM, versioned configuration, upgrade/rollback, package verification, and support diagnostics.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Finish signed/reproducible distributions, dependency locks/SBOM, versioned configuration, upgrade/rollback, package verification, and support diagnostics.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Finish signed/reproducible distributions, dependency locks/SBOM, versioned configuration, upgrade/rollback, package verification, and support diagnostics.
2. P12-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P12-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P12-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-T02"></a>

### P12-T02: Complete self-hosted topology guides, backup/restore drills, durable retention/pruning, quotas/fairness, monitoring, alerts, incident procedures, and consented telemetry.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE, P12-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Complete self-hosted topology guides, backup/restore drills, durable retention/pruning, quotas/fairness, monitoring, alerts, incident procedures, and consented telemetry.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Complete self-hosted topology guides, backup/restore drills, durable retention/pruning, quotas/fairness, monitoring, alerts, incident procedures, and consented telemetry.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Complete self-hosted topology guides, backup/restore drills, durable retention/pruning, quotas/fairness, monitoring, alerts, incident procedures, and consented telemetry.
2. P12-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P12-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P12-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-T03"></a>

### P12-T03: Validate launch performance/capacity profiles, broker/storage failure recovery, long-running work, and cross-organization safety.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE, P12-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Validate launch performance/capacity profiles, broker/storage failure recovery, long-running work, and cross-organization safety.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Validate launch performance/capacity profiles, broker/storage failure recovery, long-running work, and cross-organization safety.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Validate launch performance/capacity profiles, broker/storage failure recovery, long-running work, and cross-organization safety.
2. P12-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P12-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P12-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-T04"></a>

### P12-T04: Finish onboarding, documentation, reference plugins, accessibility, support ownership, commercial licensing/provider eligibility, and pilot feedback.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE, P12-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Finish onboarding, documentation, reference plugins, accessibility, support ownership, commercial licensing/provider eligibility, and pilot feedback.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Finish onboarding, documentation, reference plugins, accessibility, support ownership, commercial licensing/provider eligibility, and pilot feedback.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Finish onboarding, documentation, reference plugins, accessibility, support ownership, commercial licensing/provider eligibility, and pilot feedback.
2. P12-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P12-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P12-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-T05"></a>

### P12-T05: Rehearse migration from v0.32.0 across board/run/hub/federation state, credentials, worktrees, and integrations

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE, P12-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Rehearse migration from v0.32.0 across board/run/hub/federation state, credentials, worktrees, and integrations. Keep an explicit compatibility retirement plan.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Rehearse migration from v0.32.0 across board/run/hub/federation state, credentials, worktrees, and integrations. Keep an explicit compatibility retirement plan.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T05-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Rehearse migration from v0.32.0 across board/run/hub/federation state, credentials, worktrees, and integrations. Keep an explicit compatibility retirement plan.
2. P12-T05-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P12-T05-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P12-T05-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-T06"></a>

### P12-T06: Restore an origin hub while a receiver continues accepted work and reconcile outstanding reservations before admitting replacements

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE, P12-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Restore an origin hub while a receiver continues accepted work and reconcile outstanding reservations before admitting replacements. Test backup-name collisions, JetStream/checkpoint restore, and local filesystem requirements for any remaining SQLite indexes or legacy migration inputs.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Restore an origin hub while a receiver continues accepted work and reconcile outstanding reservations before admitting replacements. Test backup-name collisions, JetStream/checkpoint restore, and local filesystem requirements for any remaining SQLite indexes or legacy migration inputs.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T06-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Restore an origin hub while a receiver continues accepted work and reconcile outstanding reservations before admitting replacements. Test backup-name collisions, JetStream/checkpoint restore, and local filesystem requirements for any remaining SQLite indexes or legacy migration inputs.
2. P12-T06-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P12-T06-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P12-T06-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-T07"></a>

### P12-T07: Qualify NATS storage capacity, retention, immutable artifact lifecycle, snapshot/archive integrity, sync policy and recovery time for solo and team profiles

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE, P12-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Qualify NATS storage capacity, retention, immutable artifact lifecycle, snapshot/archive integrity, sync policy and recovery time for solo and team profiles. Document every remaining SQL component as a rebuildable projection or an explicitly reviewed exception.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Qualify NATS storage capacity, retention, immutable artifact lifecycle, snapshot/archive integrity, sync policy and recovery time for solo and team profiles. Document every remaining SQL component as a rebuildable projection or an explicitly reviewed exception.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T07-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Qualify NATS storage capacity, retention, immutable artifact lifecycle, snapshot/archive integrity, sync policy and recovery time for solo and team profiles. Document every remaining SQL component as a rebuildable projection or an explicitly reviewed exception.
2. P12-T07-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P12-T07-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P12-T07-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-T08"></a>

### P12-T08: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T08-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P12-T08-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P12-T08-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P12-T08-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-T09"></a>

### P12-T09: Qualify LOCAL-01 installation, automatic launch, upgrade compatibility, data retention and recovery using the pinned Docker/Compose/OS/client matrix

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE, P12-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Qualify LOCAL-01 installation, automatic launch, upgrade compatibility, data retention and recovery using the pinned Docker/Compose/OS/client matrix. Document setup prerequisites, diagnosis, explicit stop and backup/restore without making runtime Docker socket access a general plugin capability.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Qualify LOCAL-01 installation, automatic launch, upgrade compatibility, data retention and recovery using the pinned Docker/Compose/OS/client matrix. Document setup prerequisites, diagnosis, explicit stop and backup/restore without making runtime Docker socket access a general plugin capability.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T09-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Qualify LOCAL-01 installation, automatic launch, upgrade compatibility, data retention and recovery using the pinned Docker/Compose/OS/client matrix. Document setup prerequisites, diagnosis, explicit stop and backup/restore without making runtime Docker socket access a general plugin capability.
2. P12-T09-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P12-T09-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P12-T09-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-T10"></a>

### P12-T10: Prepare the MERGE-01 two-instance, agent-operated rehearsal and evidence package

**Status:** planned. **Owner:** Codex.

**Dependencies:** P11-GATE, P12-T08.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Prepare the MERGE-01 two-instance, agent-operated rehearsal and evidence package. Final branch acceptance follows all required phases; no phase or final acceptance authorizes merging.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Prepare the MERGE-01 two-instance, agent-operated rehearsal and evidence package. Final branch acceptance follows all required phases; no phase or final acceptance authorizes merging.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P12-T10-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Prepare the MERGE-01 two-instance, agent-operated rehearsal and evidence package. Final branch acceptance follows all required phases; no phase or final acceptance authorizes merging.
2. P12-T10-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P12-T10-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P12-T10-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P12-GATE"></a>

### P12-GATE: Verify and accept P12

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-T01, P12-T02, P12-T03, P12-T04, P12-T05, P12-T06, P12-T07, P12-T08, P12-T09, P12-T10.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.
5. Preserve the assertions assigned to this task for AMX-BASE-006 in delivery/evidence/P00/baseline-findings.md. Re-run or port the actual fixtures at the changed authority boundary; preserve explicitly open broader acceptance requirements.

**Deliverables**

1. Release readiness dossier
2. Pilot and migration acceptance
3. Signed merge/release decision
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P12-GATE-AC01: Every launch requirement is linked to passing evidence for the exact release candidate. Critical correctness/security defects are closed.
2. P12-GATE-AC02: A new developer installs and completes the reference task using only published docs on every supported platform.
3. P12-GATE-AC03: A team administrator enrolls two organizations, shares a scoped project, delegates work, survives a partition, and restores a backup.
4. P12-GATE-AC04: The approved capacity/SLO targets and recovery drill pass without losing acknowledged durable records within the tested fault model.
5. P12-GATE-AC05: Codex reviews release-readiness evidence and records provisional readiness plus all outstanding MERGE-01 requirements. P12 acceptance does not authorize merge or release; final branch acceptance requires every phase and safe bilateral orchestration between independently enrolled, agent-operated real hubs on the exact candidate.
6. P12-GATE-AC06: The approved NATS storage profile passes record/checkpoint/artifact restore, projection rebuild, retention-gap and migration rollback drills under the declared process/host/disk/quorum failure model. Published RPO/RTO and capacity claims match observed evidence, and no unreviewed SQL authority remains.
7. P12-GATE-AC07: Every component and behavior check has a reviewed release disposition. Required baseline/candidate comparisons and migration drills pass on the supported matrix; no skipped check, missing component or unapproved feature removal can be hidden by a successful new reference workflow.
8. P12-GATE-AC08: Fresh-user and upgrade drills pass LOCAL-01 cold/warm/concurrent startup, actionable Docker failures, explicit stop, persistent data recovery and scoped hub status on the supported platform/client matrix. No launch silently upgrades an incompatible live stack, loses durable work or bypasses a required phase gate.
9. P12-GATE-AC09: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
10. P12-GATE-AC10: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run the complete release matrix, independent security review, load/soak tests, upgrade/restore rehearsal, and pilot acceptance.
2. Compare evidence manifests to the exact candidate digest and invalidate stale results after material changes.
3. Review support and commercial readiness with accountable owners.
4. Run qualified storage failure and recovery drills with pinned disk/sync/replication settings, including capacity exhaustion. Verify restored reservations before processing queued commands.
5. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.
6. Repeat FAIL-55–FAIL-62 with the exact packaged release, real federation and each advertised launch integration; record readiness deadlines, versions, volume identity and observed timing.
7. Review MERGE-01 evidence completeness and remaining required phases. Rehearsals may happen here, but repeat the final run on the exact final branch candidate after all required phases pass.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P13. Remaining Jev catalog and skill expansion

Every remaining research proposal receives a measured implementation decision.

**Epic acceptance criteria**

- **P13-AC01:** All 88 original uses, 14 video additions, four enablers, and 26 skills retain a traceable disposition and owning phase.
- **P13-AC02:** Each batch passes schema, access, failure, semantic holdout, host-capability, and end-to-end economic gates.
- **P13-AC03:** Compaction preserves mandatory obligations and active evidence and runs only on supported hosts.
- **P13-AC04:** No savings claim relies only on shortened context or a provider's confidence score. Outcome quality and total cost meet approved thresholds.
- **P13-AC05:** Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.

<a id="P13-T01"></a>

### P13-T01: Implement the complete remaining catalog in bounded batches using the coverage appendix, without duplicating overlapping video and original use cases.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Implement the complete remaining catalog in bounded batches using the coverage appendix, without duplicating overlapping video and original use cases.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Implement the complete remaining catalog in bounded batches using the coverage appendix, without duplicating overlapping video and original use cases.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P13-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Implement the complete remaining catalog in bounded batches using the coverage appendix, without duplicating overlapping video and original use cases.
2. P13-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P13-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P13-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Repeat the P08/P09 evaluation protocol per changed definition/skill and representative combined workflows.
2. Use stored factors for policy-only replay and record when a fresh inference is necessary.
3. Run regression tests for cache isolation, missing evidence, mandatory messages, provider failure, and decision drift.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-T02"></a>

### P13-T02: Complete general extract, compare, checkpoint, integrate, and optimize skills plus remaining Agentmux planning, coordination, diagnosis, knowledge, plugin review, and policy-tuning skills.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Complete general extract, compare, checkpoint, integrate, and optimize skills plus remaining Agentmux planning, coordination, diagnosis, knowledge, plugin review, and policy-tuning skills.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Complete general extract, compare, checkpoint, integrate, and optimize skills plus remaining Agentmux planning, coordination, diagnosis, knowledge, plugin review, and policy-tuning skills.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P13-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Complete general extract, compare, checkpoint, integrate, and optimize skills plus remaining Agentmux planning, coordination, diagnosis, knowledge, plugin review, and policy-tuning skills.
2. P13-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P13-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P13-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Repeat the P08/P09 evaluation protocol per changed definition/skill and representative combined workflows.
2. Use stored factors for policy-only replay and record when a fresh inference is necessary.
3. Run regression tests for cache isolation, missing evidence, mandatory messages, provider failure, and decision drift.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-T03"></a>

### P13-T03: Expand temporary bounded questions, semantic inventories, federated source inspection, compaction/retention controls, what-if replay, fidelity review, bilateral contract interpretation, and opportunity scorecards.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Expand temporary bounded questions, semantic inventories, federated source inspection, compaction/retention controls, what-if replay, fidelity review, bilateral contract interpretation, and opportunity scorecards.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Expand temporary bounded questions, semantic inventories, federated source inspection, compaction/retention controls, what-if replay, fidelity review, bilateral contract interpretation, and opportunity scorecards.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P13-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Expand temporary bounded questions, semantic inventories, federated source inspection, compaction/retention controls, what-if replay, fidelity review, bilateral contract interpretation, and opportunity scorecards.
2. P13-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P13-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P13-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Repeat the P08/P09 evaluation protocol per changed definition/skill and representative combined workflows.
2. Use stored factors for policy-only replay and record when a fresh inference is necessary.
3. Run regression tests for cache isolation, missing evidence, mandatory messages, provider failure, and decision drift.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-T04"></a>

### P13-T04: Promote only qualified definitions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Promote only qualified definitions. Record rejected or deferred cases with evidence, reasons, owner, and next review point.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Promote only qualified definitions. Record rejected or deferred cases with evidence, reasons, owner, and next review point.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P13-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Promote only qualified definitions. Record rejected or deferred cases with evidence, reasons, owner, and next review point.
2. P13-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P13-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P13-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Repeat the P08/P09 evaluation protocol per changed definition/skill and representative combined workflows.
2. Use stored factors for policy-only replay and record when a fresh inference is necessary.
3. Run regression tests for cache isolation, missing evidence, mandatory messages, provider failure, and decision drift.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-T05"></a>

### P13-T05: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P13-T05-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P13-T05-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P13-T05-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P13-T05-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Repeat the P08/P09 evaluation protocol per changed definition/skill and representative combined workflows.
2. Use stored factors for policy-only replay and record when a fresh inference is necessary.
3. Run regression tests for cache isolation, missing evidence, mandatory messages, provider failure, and decision drift.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-003"></a>

### P13-JEV-003: Project and repository disambiguation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Project and repository disambiguation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-003-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P13-JEV-003-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P13-JEV-003-AC03: Preserve this item-specific boundary: Never expand project access; ambiguous targets require confirmation before effects.
4. P13-JEV-003-AC04: Report Wrong-project suggestions on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-003-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-003-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-003",
  "group": "intake",
  "title": "Project and repository disambiguation",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Client integration and task-intake plugins",
  "decision": "User wording and authorized project descriptions → suggest a project or none.",
  "saving": "Avoid searching several repositories and loading unrelated context.",
  "boundary": "Never expand project access; ambiguous targets require confirmation before effects.",
  "metric": "Wrong-project suggestions",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-005"></a>

### P13-JEV-005: Potential duplicate task discovery

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Potential duplicate task discovery
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-005-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P13-JEV-005-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P13-JEV-005-AC03: Preserve this item-specific boundary: Similarity does not merge tasks, cancel work, or transfer reservations.
4. P13-JEV-005-AC04: Report Confirmed duplicates; false merges avoided on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-005-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-005-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-005",
  "group": "intake",
  "title": "Potential duplicate task discovery",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Client integration and task-intake plugins",
  "decision": "New request and a search shortlist of active tasks → flag semantically overlapping work.",
  "saving": "Avoid duplicate investigations after the owner reviews the match.",
  "boundary": "Similarity does not merge tasks, cancel work, or transfer reservations.",
  "metric": "Confirmed duplicates; false merges avoided",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-006"></a>

### P13-JEV-006: Request-change interpretation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Request-change interpretation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-006-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P13-JEV-006-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P13-JEV-006-AC03: Preserve this item-specific boundary: The actual latest user instruction remains available; owner approves plan changes.
4. P13-JEV-006-AC04: Report Unnecessary replans; missed scope changes on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-006-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-006-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-006",
  "group": "intake",
  "title": "Request-change interpretation",
  "primitives": [
    "C",
    "S"
  ],
  "stage": "Next",
  "owner": "Client integration and task-intake plugins",
  "decision": "Existing plan and a user amendment → additive detail, scope change, contradiction, or unclear.",
  "saving": "Focus replanning on affected work rather than reconstructing the entire plan.",
  "boundary": "The actual latest user instruction remains available; owner approves plan changes.",
  "metric": "Unnecessary replans; missed scope changes",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-007"></a>

### P13-JEV-007: Attention and urgency triage

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Attention and urgency triage
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-007-AC01: Mandatory lifecycle, failure, approval, ownership, completion, explicit user and addressed messages bypass suppression.
2. P13-JEV-007-AC02: Optional originals remain durable; delayed/grouped information preserves distinct concerns and stays within explicit time bounds.
3. P13-JEV-007-AC03: Preserve this item-specific boundary: Explicit deadlines, incident triggers, and mandatory notifications override interpretation.
4. P13-JEV-007-AC04: Report Missed urgent cases; intervention delay on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-007-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-007-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-007",
  "group": "intake",
  "title": "Attention and urgency triage",
  "primitives": [
    "C",
    "S"
  ],
  "stage": "Next",
  "owner": "Client integration and task-intake plugins",
  "decision": "Unstructured report and existing service categories → suggest review priority.",
  "saving": "Reduce repeated full-model triage of support and work queues.",
  "boundary": "Explicit deadlines, incident triggers, and mandatory notifications override interpretation.",
  "metric": "Missed urgent cases; intervention delay",
  "status": "proposed; not benchmarked",
  "decisionFamily": "attention-routing"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-009"></a>

### P13-JEV-009: Plan completeness check

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Plan completeness check
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-009-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-009-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-009-AC03: Preserve this item-specific boundary: Only checks specified concerns; complex plans still need expert or strong-model review.
4. P13-JEV-009-AC04: Report Missed gaps; prevented rework on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-009-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-009-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-009",
  "group": "planning",
  "title": "Plan completeness check",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Planning and orchestration plugins",
  "decision": "Proposed plan and known required concerns → identify missing investigation, validation, or delivery coverage.",
  "saving": "Catch gaps before multiple agents execute an incomplete plan.",
  "boundary": "Only checks specified concerns; complex plans still need expert or strong-model review.",
  "metric": "Missed gaps; prevented rework",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-011"></a>

### P13-JEV-011: Dependency suggestions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Dependency suggestions
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-011-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-011-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-011-AC03: Preserve this item-specific boundary: Build exact edges, cycle checks, and resource locks in code; a missed dependency is costly.
4. P13-JEV-011-AC04: Report Dependency recall against reviewed graphs on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-011-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-011-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-011",
  "group": "planning",
  "title": "Dependency suggestions",
  "primitives": [
    "N"
  ],
  "stage": "Research",
  "owner": "Planning and orchestration plugins",
  "decision": "Candidate task pairs and their described inputs/outputs → likely semantic dependency.",
  "saving": "Reduce planner effort in proposing task graph edges.",
  "boundary": "Build exact edges, cycle checks, and resource locks in code; a missed dependency is costly.",
  "metric": "Dependency recall against reviewed graphs",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-012"></a>

### P13-JEV-012: Parallel-work conflict screening

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Parallel-work conflict screening
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-012-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-012-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-012-AC03: Preserve this item-specific boundary: Never replaces file locks, ownership, or dependency enforcement.
4. P13-JEV-012-AC04: Report Avoided collisions; needless serialization on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-012-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-012-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-012",
  "group": "planning",
  "title": "Parallel-work conflict screening",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Research",
  "owner": "Planning and orchestration plugins",
  "decision": "Proposed parallel tasks, affected areas, and exact lock data → likely semantic coordination conflict.",
  "saving": "Avoid duplicative work or conflicting changes across agents.",
  "boundary": "Never replaces file locks, ownership, or dependency enforcement.",
  "metric": "Avoided collisions; needless serialization",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-013"></a>

### P13-JEV-013: Delegation granularity advice

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Delegation granularity advice
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-013-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P13-JEV-013-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P13-JEV-013-AC03: Preserve this item-specific boundary: Cost and capacity arithmetic stay in code; Jev cannot invent task decomposition.
4. P13-JEV-013-AC04: Report Cost and completion time per accepted task on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-013-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-013-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-013",
  "group": "planning",
  "title": "Delegation granularity advice",
  "primitives": [
    "C",
    "S"
  ],
  "stage": "Research",
  "owner": "Planning and orchestration plugins",
  "decision": "Bounded task descriptions and measured overhead → single worker, specialist review, or split candidate.",
  "saving": "Avoid spawning several agents whose context setup exceeds the useful work.",
  "boundary": "Cost and capacity arithmetic stay in code; Jev cannot invent task decomposition.",
  "metric": "Cost and completion time per accepted task",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-014"></a>

### P13-JEV-014: Additional specialist review selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Additional specialist review selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-014-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P13-JEV-014-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P13-JEV-014-AC03: Preserve this item-specific boundary: Mandatory reviewers remain mandatory regardless of Jev's answer.
4. P13-JEV-014-AC04: Report Defects found; unnecessary specialist turns on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-014-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-014-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-014",
  "group": "planning",
  "title": "Additional specialist review selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Planning and orchestration plugins",
  "decision": "Change description and available review specialties → suggest extra review expertise.",
  "saving": "Avoid asking every specialist to review every change.",
  "boundary": "Mandatory reviewers remain mandatory regardless of Jev's answer.",
  "metric": "Defects found; unnecessary specialist turns",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-018"></a>

### P13-JEV-018: Closed argument interpretation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Closed argument interpretation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-018-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P13-JEV-018-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P13-JEV-018-AC03: Preserve this item-specific boundary: Check cross-field compatibility in code; free-form values require another method.
4. P13-JEV-018-AC04: Report Argument correctness and repair turns on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-018-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-018-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-018",
  "group": "tools",
  "title": "Closed argument interpretation",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Natural language and valid enum values → operation mode, format, or known option.",
  "saving": "Avoid a generation call for arguments with finite allowed values.",
  "boundary": "Check cross-field compatibility in code; free-form values require another method.",
  "metric": "Argument correctness and repair turns",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-020"></a>

### P13-JEV-020: Approved tool-recipe selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Approved tool-recipe selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-020-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P13-JEV-020-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P13-JEV-020-AC03: Preserve this item-specific boundary: Jev selects existing code; it does not generate a script or authorize side effects.
4. P13-JEV-020-AC04: Report Roundtrips avoided; wrong recipe rate on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-020-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-020-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-020",
  "group": "tools",
  "title": "Approved tool-recipe selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Task and catalog of prevalidated read-only operation sequences → select a recipe.",
  "saving": "Replace repeated agent planning and intermediate tool-result roundtrips.",
  "boundary": "Jev selects existing code; it does not generate a script or authorize side effects.",
  "metric": "Roundtrips avoided; wrong recipe rate",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-022"></a>

### P13-JEV-022: Next evidence source selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Next evidence source selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-022-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P13-JEV-022-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P13-JEV-022-AC03: Preserve this item-specific boundary: Expected value is a hypothesis; cap probes and fall back when no option fits.
4. P13-JEV-022-AC04: Report Useful evidence gained per tool call on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-022-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-022-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-022",
  "group": "tools",
  "title": "Next evidence source selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Current evidence gap and permitted read-only probes → choose next useful diagnostic source.",
  "saving": "Avoid broad tool exploration or rereading the same evidence.",
  "boundary": "Expected value is a hypothesis; cap probes and fall back when no option fits.",
  "metric": "Useful evidence gained per tool call",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-028"></a>

### P13-JEV-028: Relevant prior memory selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Relevant prior memory selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-028-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P13-JEV-028-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P13-JEV-028-AC03: Preserve this item-specific boundary: Use current authoritative facts for permissions/state; old notes remain dated evidence.
4. P13-JEV-028-AC04: Report Useful memory precision and stale-use errors on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-028-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-028-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-028",
  "group": "context",
  "title": "Relevant prior memory selection",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Context and knowledge plugins",
  "decision": "Current task and authorized historical notes → rank useful prior facts or lessons.",
  "saving": "Reduce repeated rediscovery and indiscriminate memory injection.",
  "boundary": "Use current authoritative facts for permissions/state; old notes remain dated evidence.",
  "metric": "Useful memory precision and stale-use errors",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-029"></a>

### P13-JEV-029: Material context-change detection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Material context-change detection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-029-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P13-JEV-029-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P13-JEV-029-AC03: Preserve this item-specific boundary: Exact hashes bypass inference when bytes are unchanged; critical events bypass suppression.
4. P13-JEV-029-AC04: Report Missed material changes and refresh calls on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-029-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-029-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-029",
  "group": "context",
  "title": "Material context-change detection",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "Next",
  "owner": "Context and knowledge plugins",
  "decision": "Previous evidence packet and a bounded update → unchanged meaning, useful addition, conflict, or unclear.",
  "saving": "Refresh or replan only when new information changes the task.",
  "boundary": "Exact hashes bypass inference when bytes are unchanged; critical events bypass suppression.",
  "metric": "Missed material changes and refresh calls",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-030"></a>

### P13-JEV-030: Compaction coverage checking

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Compaction coverage checking
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-030-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-030-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-030-AC03: Preserve this item-specific boundary: Jev does not write the summary; preserve original sources and pinned constraints.
4. P13-JEV-030-AC04: Report Critical omissions and regeneration tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-030-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-030-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-030",
  "group": "context",
  "title": "Compaction coverage checking",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Context and knowledge plugins",
  "decision": "Existing summary and selected required source facts → identify omitted or distorted items.",
  "saving": "Repair narrow summary gaps instead of repeatedly regenerating full context.",
  "boundary": "Jev does not write the summary; preserve original sources and pinned constraints.",
  "metric": "Critical omissions and regeneration tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-033"></a>

### P13-JEV-033: Model or agent tier selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Model or agent tier selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-033-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P13-JEV-033-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P13-JEV-033-AC03: Preserve this item-specific boundary: Thresholds require task-specific outcome data; cost limits are numeric rules.
4. P13-JEV-033-AC04: Report Cost and quality per accepted outcome on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-033-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-033-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-033",
  "group": "placement",
  "title": "Model or agent tier selection",
  "primitives": [
    "C",
    "S"
  ],
  "stage": "Next",
  "owner": "Orchestration and resource owners",
  "decision": "Task characteristics and approved capability tiers → suggest execution tier.",
  "saving": "Reserve expensive reasoning for cases where it earns its cost.",
  "boundary": "Thresholds require task-specific outcome data; cost limits are numeric rules.",
  "metric": "Cost and quality per accepted outcome",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-035"></a>

### P13-JEV-035: Small-model result escalation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Small-model result escalation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-035-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-035-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-035-AC03: Preserve this item-specific boundary: Verifier errors can accept wrong work; mandatory tests/review still apply.
4. P13-JEV-035-AC04: Report Missed errors, escalation fraction, end-to-end cost on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-035-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-035-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-035",
  "group": "placement",
  "title": "Small-model result escalation",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Orchestration and resource owners",
  "decision": "A smaller model's output and source evidence → identify specific unsupported fields or claims.",
  "saving": "Call a stronger model only on cases or fields needing it.",
  "boundary": "Verifier errors can accept wrong work; mandatory tests/review still apply.",
  "metric": "Missed errors, escalation fraction, end-to-end cost",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-036"></a>

### P13-JEV-036: Previous work applicability

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Previous work applicability
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-036-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P13-JEV-036-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P13-JEV-036-AC03: Preserve this item-specific boundary: Exact artifact validity and permissions are checked; similarity is not safe response caching.
4. P13-JEV-036-AC04: Report Reuse success and stale reuse failures on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-036-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-036-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-036",
  "group": "placement",
  "title": "Previous work applicability",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Orchestration and resource owners",
  "decision": "New task and indexed prior result plus dependency versions → suggest reusable evidence/artifacts.",
  "saving": "Avoid repeating solved research or diagnostics.",
  "boundary": "Exact artifact validity and permissions are checked; similarity is not safe response caching.",
  "metric": "Reuse success and stale reuse failures",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-037"></a>

### P13-JEV-037: Optional message recipient selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Optional message recipient selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-037-AC01: Mandatory lifecycle, failure, approval, ownership, completion, explicit user and addressed messages bypass suppression.
2. P13-JEV-037-AC02: Optional originals remain durable; delayed/grouped information preserves distinct concerns and stays within explicit time bounds.
3. P13-JEV-037-AC03: Preserve this item-specific boundary: Persist the message; explicitly addressed and mandatory events bypass selection.
4. P13-JEV-037-AC04: Report Missed useful messages; consumed input tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-037-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-037-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-037",
  "group": "coordination",
  "title": "Optional message recipient selection",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "First",
  "owner": "Conversation, event, and orchestration plugins",
  "decision": "Message, current tasks, and allowed recipients → who needs this information now.",
  "saving": "Avoid waking every agent for every update.",
  "boundary": "Persist the message; explicitly addressed and mandatory events bypass selection.",
  "metric": "Missed useful messages; consumed input tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "attention-routing"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-038"></a>

### P13-JEV-038: Planner wake-up screening

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Planner wake-up screening
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-038-AC01: Mandatory lifecycle, failure, approval, ownership, completion, explicit user and addressed messages bypass suppression.
2. P13-JEV-038-AC02: Optional originals remain durable; delayed/grouped information preserves distinct concerns and stays within explicit time bounds.
3. P13-JEV-038-AC03: Preserve this item-specific boundary: Completion, approval, failure, and ownership events use deterministic delivery.
4. P13-JEV-038-AC04: Report Planner calls avoided; missed decisions on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-038-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-038-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-038",
  "group": "coordination",
  "title": "Planner wake-up screening",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "First",
  "owner": "Conversation, event, and orchestration plugins",
  "decision": "Optional progress update and relevant plan state → material change, routine progress, or unclear.",
  "saving": "Avoid an expensive planner turn for repetitive status chatter.",
  "boundary": "Completion, approval, failure, and ownership events use deterministic delivery.",
  "metric": "Planner calls avoided; missed decisions",
  "status": "proposed; not benchmarked",
  "decisionFamily": "attention-routing"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-039"></a>

### P13-JEV-039: Related update grouping

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Related update grouping
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-039-AC01: Mandatory lifecycle, failure, approval, ownership, completion, explicit user and addressed messages bypass suppression.
2. P13-JEV-039-AC02: Optional originals remain durable; delayed/grouped information preserves distinct concerns and stays within explicit time bounds.
3. P13-JEV-039-AC03: Preserve this item-specific boundary: Batch windows have time bounds; do not delay deadlines or requested messages.
4. P13-JEV-039-AC04: Report Agent turns and delayed important updates on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-039-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-039-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-039",
  "group": "coordination",
  "title": "Related update grouping",
  "primitives": [
    "C",
    "S"
  ],
  "stage": "Next",
  "owner": "Conversation, event, and orchestration plugins",
  "decision": "Bounded noncritical updates → topic or shared issue group.",
  "saving": "Create one source-backed update packet instead of many agent turns.",
  "boundary": "Batch windows have time bounds; do not delay deadlines or requested messages.",
  "metric": "Agent turns and delayed important updates",
  "status": "proposed; not benchmarked",
  "decisionFamily": "attention-routing"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-040"></a>

### P13-JEV-040: Clarification consolidation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Clarification consolidation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-040-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P13-JEV-040-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P13-JEV-040-AC03: Preserve this item-specific boundary: Preserve distinct questions; merging and wording need code or a generator.
4. P13-JEV-040-AC04: Report Duplicate questions and unanswered requirements on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-040-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-040-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-040",
  "group": "coordination",
  "title": "Clarification consolidation",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Conversation, event, and orchestration plugins",
  "decision": "Pending questions from agents → likely duplicates and related evidence needs.",
  "saving": "Reduce repeated questions and repeated context exchange with the user.",
  "boundary": "Preserve distinct questions; merging and wording need code or a generator.",
  "metric": "Duplicate questions and unanswered requirements",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-041"></a>

### P13-JEV-041: Cross-agent claim conflict detection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Cross-agent claim conflict detection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-041-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P13-JEV-041-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P13-JEV-041-AC03: Preserve this item-specific boundary: Agreement is not truth; differences in versions/scope must be retained.
4. P13-JEV-041-AC04: Report Conflict recall and adjudication cost on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-041-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-041-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-041",
  "group": "coordination",
  "title": "Cross-agent claim conflict detection",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "Next",
  "owner": "Conversation, event, and orchestration plugins",
  "decision": "Comparable claims with source references → agreement, conflict, or incomparable.",
  "saving": "Focus adjudication on genuine disagreements instead of full transcript reviews.",
  "boundary": "Agreement is not truth; differences in versions/scope must be retained.",
  "metric": "Conflict recall and adjudication cost",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-042"></a>

### P13-JEV-042: Ineffective-loop detection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Ineffective-loop detection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-042-AC01: Keep exact exit/status/protocol facts unchanged; classify only the residual unstructured evidence.
2. P13-JEV-042-AC02: Incomplete logs and uncertain external actions remain explicit; diagnosis does not replay a command or declare it stopped.
3. P13-JEV-042-AC03: Preserve this item-specific boundary: Process facts remain authoritative; never infer safe cancellation/retry of uncertain effects.
4. P13-JEV-042-AC04: Report Wasted turns and false loop alerts on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-042-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-042-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-042",
  "group": "coordination",
  "title": "Ineffective-loop detection",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Conversation, event, and orchestration plugins",
  "decision": "Bounded action/result history plus exact attempt counters → likely repeated ineffective approach.",
  "saving": "Stop wasting agent turns by proposing a different investigation or review.",
  "boundary": "Process facts remain authoritative; never infer safe cancellation/retry of uncertain effects.",
  "metric": "Wasted turns and false loop alerts",
  "status": "proposed; not benchmarked",
  "decisionFamily": "diagnostic-classification"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-045"></a>

### P13-JEV-045: Failure-log episode grouping

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Failure-log episode grouping
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-045-AC01: Keep exact exit/status/protocol facts unchanged; classify only the residual unstructured evidence.
2. P13-JEV-045-AC02: Incomplete logs and uncertain external actions remain explicit; diagnosis does not replay a command or declare it stopped.
3. P13-JEV-045-AC03: Preserve this item-specific boundary: Retain originals; exact duplicates group without Jev; preserve rare critical errors.
4. P13-JEV-045-AC04: Report Representative coverage and log tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-045-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-045-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-045",
  "group": "verification",
  "title": "Failure-log episode grouping",
  "primitives": [
    "S",
    "C"
  ],
  "stage": "Next",
  "owner": "Execution, validation, and review plugins",
  "decision": "Previously parsed error episodes → related symptoms or distinct failures.",
  "saving": "Show representative excerpts and counts instead of many repeated traces.",
  "boundary": "Retain originals; exact duplicates group without Jev; preserve rare critical errors.",
  "metric": "Representative coverage and log tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "diagnostic-classification"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-046"></a>

### P13-JEV-046: Additional test-family suggestions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Additional test-family suggestions
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-046-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-046-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-046-AC03: Preserve this item-specific boundary: Required tests cannot be skipped on a model judgment; prioritize rather than suppress.
4. P13-JEV-046-AC04: Report Defects detected and optional-test usefulness on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-046-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-046-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-046",
  "group": "verification",
  "title": "Additional test-family suggestions",
  "primitives": [
    "C",
    "S"
  ],
  "stage": "Next",
  "owner": "Execution, validation, and review plugins",
  "decision": "Change semantics and available test families → recommend extra targeted checks.",
  "saving": "Reduce broad exploratory testing and agent interpretation effort.",
  "boundary": "Required tests cannot be skipped on a model judgment; prioritize rather than suppress.",
  "metric": "Defects detected and optional-test usefulness",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-047"></a>

### P13-JEV-047: Requirement-to-change coverage

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Requirement-to-change coverage
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-047-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-047-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-047-AC03: Preserve this item-specific boundary: Code/tests establish actual behavior; semantic coverage is advisory.
4. P13-JEV-047-AC04: Report Missed requirements and broad rereview tokens on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-047-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-047-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-047",
  "group": "verification",
  "title": "Requirement-to-change coverage",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Execution, validation, and review plugins",
  "decision": "Acceptance criterion and patch/evidence references → likely addressed, gap, or uncertain.",
  "saving": "Target review and repair to uncovered requirements.",
  "boundary": "Code/tests establish actual behavior; semantic coverage is advisory.",
  "metric": "Missed requirements and broad rereview tokens",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-048"></a>

### P13-JEV-048: Review focus selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Review focus selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-048-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-048-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-048-AC03: Preserve this item-specific boundary: Mandatory scope retained; different reviewers may share essential context.
4. P13-JEV-048-AC04: Report Review cost and defect yield on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-048-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-048-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-048",
  "group": "verification",
  "title": "Review focus selection",
  "primitives": [
    "S",
    "C"
  ],
  "stage": "Next",
  "owner": "Execution, validation, and review plugins",
  "decision": "Changed areas and review findings → prioritize correctness, security, concurrency, or domain concerns.",
  "saving": "Prepare focused reviewer packets instead of full indiscriminate reanalysis.",
  "boundary": "Mandatory scope retained; different reviewers may share essential context.",
  "metric": "Review cost and defect yield",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-050"></a>

### P13-JEV-050: Narrow rework selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Narrow rework selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-050-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-050-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-050-AC03: Preserve this item-specific boundary: Dependency graph and invalidation rules decide which artifacts must be rechecked.
4. P13-JEV-050-AC04: Report Rework scope and escaped regressions on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-050-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-050-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-050",
  "group": "verification",
  "title": "Narrow rework selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Execution, validation, and review plugins",
  "decision": "Failed criteria and completed evidence → choose affected approved repair path.",
  "saving": "Avoid rerunning an entire workflow when only one bounded section failed.",
  "boundary": "Dependency graph and invalidation rules decide which artifacts must be rechecked.",
  "metric": "Rework scope and escaped regressions",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-051"></a>

### P13-JEV-051: Knowledge tagging and indexing

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Knowledge tagging and indexing
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-051-AC01: Authoritative statuses and source records stay visible and distinct from optional semantic labels.
2. P13-JEV-051-AC02: Schema-known renderers use deterministic selection; replays/viewers do not cause new inference or generated executable UI.
3. P13-JEV-051-AC03: Preserve this item-specific boundary: No automatic durable memory from unverified claims; preserve provenance.
4. P13-JEV-051-AC04: Report Retrieval usefulness and indexing cost on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-051-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-051-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-051",
  "group": "knowledge",
  "title": "Knowledge tagging and indexing",
  "primitives": [
    "C",
    "S"
  ],
  "stage": "Next",
  "owner": "Knowledge and artifact plugins",
  "decision": "Approved result or lesson → controlled topic/capability labels.",
  "saving": "Improve future retrieval and avoid repeated large-model indexing.",
  "boundary": "No automatic durable memory from unverified claims; preserve provenance.",
  "metric": "Retrieval usefulness and indexing cost",
  "status": "proposed; not benchmarked",
  "decisionFamily": "presentation-labeling"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-052"></a>

### P13-JEV-052: Knowledge duplication suggestions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Knowledge duplication suggestions
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-052-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P13-JEV-052-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P13-JEV-052-AC03: Preserve this item-specific boundary: Do not delete distinct source evidence or merge conflicting versions automatically.
4. P13-JEV-052-AC04: Report Confirmed duplicates and information loss on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-052-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-052-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-052",
  "group": "knowledge",
  "title": "Knowledge duplication suggestions",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Knowledge and artifact plugins",
  "decision": "Search shortlist of notes → duplicate, related, or distinct.",
  "saving": "Reduce repeated reading and fragmented redundant guidance.",
  "boundary": "Do not delete distinct source evidence or merge conflicting versions automatically.",
  "metric": "Confirmed duplicates and information loss",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-053"></a>

### P13-JEV-053: Stale or conflicting guidance flags

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Stale or conflicting guidance flags
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-053-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P13-JEV-053-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P13-JEV-053-AC03: Preserve this item-specific boundary: Deterministic version changes trigger review; Jev does not assert global freshness.
4. P13-JEV-053-AC04: Report Stale-guidance incidents on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-053-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-053-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-053",
  "group": "knowledge",
  "title": "Stale or conflicting guidance flags",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "Next",
  "owner": "Knowledge and artifact plugins",
  "decision": "Old guidance, current source excerpts, and exact version metadata → possible conflict.",
  "saving": "Prevent agents spending turns following obsolete guidance.",
  "boundary": "Deterministic version changes trigger review; Jev does not assert global freshness.",
  "metric": "Stale-guidance incidents",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-054"></a>

### P13-JEV-054: Document structure recovery

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Document structure recovery
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-054-AC01: Authoritative statuses and source records stay visible and distinct from optional semantic labels.
2. P13-JEV-054-AC02: Schema-known renderers use deterministic selection; replays/viewers do not cause new inference or generated executable UI.
3. P13-JEV-054-AC03: Preserve this item-specific boundary: Preserve original bytes; parser confidence and malformed documents need fallback.
4. P13-JEV-054-AC04: Report Structure fidelity and extraction errors on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-054-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-054-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-054",
  "group": "knowledge",
  "title": "Document structure recovery",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Research",
  "owner": "Knowledge and artifact plugins",
  "decision": "Text blocks from a parser → heading, list, code, continuation, or unknown.",
  "saving": "Enable exact extractive retrieval without a large-model reformatting pass.",
  "boundary": "Preserve original bytes; parser confidence and malformed documents need fallback.",
  "metric": "Structure fidelity and extraction errors",
  "status": "proposed; not benchmarked",
  "decisionFamily": "presentation-labeling"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-055"></a>

### P13-JEV-055: Knowledge ingestion triage

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Knowledge ingestion triage
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-055-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P13-JEV-055-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P13-JEV-055-AC03: Preserve this item-specific boundary: Do not erase source documents; compare against cheaper keyword/index baselines.
4. P13-JEV-055-AC04: Report Enrichment cost and retrieval recall on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-055-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-055-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-055",
  "group": "knowledge",
  "title": "Knowledge ingestion triage",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Research",
  "owner": "Knowledge and artifact plugins",
  "decision": "New approved document and knowledge objectives → which sections merit richer indexing.",
  "saving": "Avoid expensive per-section summarization/enrichment of irrelevant material.",
  "boundary": "Do not erase source documents; compare against cheaper keyword/index baselines.",
  "metric": "Enrichment cost and retrieval recall",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-057"></a>

### P13-JEV-057: Protected-kernel status interpretation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Protected-kernel status interpretation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-057-AC01: Keep exact exit/status/protocol facts unchanged; classify only the residual unstructured evidence.
2. P13-JEV-057-AC02: Incomplete logs and uncertain external actions remain explicit; diagnosis does not replay a command or declare it stopped.
3. P13-JEV-057-AC03: Preserve this item-specific boundary: Observer only; no cloud dependency in boot and no external kernel-write path.
4. P13-JEV-057-AC04: Report Diagnostic usefulness and support turns on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-057-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-057-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-057",
  "group": "operations",
  "title": "Protected-kernel status interpretation",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Surrounding diagnostics, setup, and operations plugins",
  "decision": "Approved published kernel-plugin startup/status records → likely diagnostic category.",
  "saving": "Avoid sending entire startup logs to a general agent for routine diagnosis.",
  "boundary": "Observer only; no cloud dependency in boot and no external kernel-write path.",
  "metric": "Diagnostic usefulness and support turns",
  "status": "proposed; not benchmarked",
  "decisionFamily": "diagnostic-classification"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-058"></a>

### P13-JEV-058: Setup-help selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Setup-help selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-058-AC01: Keep exact exit/status/protocol facts unchanged; classify only the residual unstructured evidence.
2. P13-JEV-058-AC02: Incomplete logs and uncertain external actions remain explicit; diagnosis does not replay a command or declare it stopped.
3. P13-JEV-058-AC03: Preserve this item-specific boundary: Exact OS/tool/version compatibility comes from code; show raw failure on uncertainty.
4. P13-JEV-058-AC04: Report Time to working setup on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-058-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-058-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-058",
  "group": "operations",
  "title": "Setup-help selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Surrounding diagnostics, setup, and operations plugins",
  "decision": "Deterministic environment probes and bounded error descriptions → relevant approved setup guide.",
  "saving": "Reduce long onboarding conversations and irrelevant setup instructions.",
  "boundary": "Exact OS/tool/version compatibility comes from code; show raw failure on uncertainty.",
  "metric": "Time to working setup",
  "status": "proposed; not benchmarked",
  "decisionFamily": "diagnostic-classification"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-059"></a>

### P13-JEV-059: Support incident grouping

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Support incident grouping
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-059-AC01: Keep exact exit/status/protocol facts unchanged; classify only the residual unstructured evidence.
2. P13-JEV-059-AC02: Incomplete logs and uncertain external actions remain explicit; diagnosis does not replay a command or declare it stopped.
3. P13-JEV-059-AC03: Preserve this item-specific boundary: Grouping cannot hide an independent incident; respect tenant boundaries.
4. P13-JEV-059-AC04: Report Useful grouping and missed incidents on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-059-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-059-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-059",
  "group": "operations",
  "title": "Support incident grouping",
  "primitives": [
    "S",
    "C"
  ],
  "stage": "Next",
  "owner": "Surrounding diagnostics, setup, and operations plugins",
  "decision": "Sanitized support reports and known incident candidates → likely grouping.",
  "saving": "Reduce duplicate triage and repeated expensive diagnosis.",
  "boundary": "Grouping cannot hide an independent incident; respect tenant boundaries.",
  "metric": "Useful grouping and missed incidents",
  "status": "proposed; not benchmarked",
  "decisionFamily": "diagnostic-classification"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-060"></a>

### P13-JEV-060: Operational symptom interpretation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Operational symptom interpretation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-060-AC01: Keep exact exit/status/protocol facts unchanged; classify only the residual unstructured evidence.
2. P13-JEV-060-AC02: Incomplete logs and uncertain external actions remain explicit; diagnosis does not replay a command or declare it stopped.
3. P13-JEV-060-AC03: Preserve this item-specific boundary: Thresholds, paging obligations, and recovery commands are deterministic.
4. P13-JEV-060-AC04: Report Investigation time and wrong diagnosis rate on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-060-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-060-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-060",
  "group": "operations",
  "title": "Operational symptom interpretation",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Surrounding diagnostics, setup, and operations plugins",
  "decision": "Already-detected metric anomaly with relevant log snippets → likely investigation direction.",
  "saving": "Use a short diagnostic decision before a long incident-agent run.",
  "boundary": "Thresholds, paging obligations, and recovery commands are deterministic.",
  "metric": "Investigation time and wrong diagnosis rate",
  "status": "proposed; not benchmarked",
  "decisionFamily": "diagnostic-classification"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-061"></a>

### P13-JEV-061: Provider degradation classification

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Provider degradation classification
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-061-AC01: Keep exact exit/status/protocol facts unchanged; classify only the residual unstructured evidence.
2. P13-JEV-061-AC02: Incomplete logs and uncertain external actions remain explicit; diagnosis does not replay a command or declare it stopped.
3. P13-JEV-061-AC03: Preserve this item-specific boundary: 401/429/timeouts and retry budgets use code; do not model known protocol facts.
4. P13-JEV-061-AC04: Report Unnecessary retries and support effort on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-061-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-061-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-061",
  "group": "operations",
  "title": "Provider degradation classification",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Next",
  "owner": "Surrounding diagnostics, setup, and operations plugins",
  "decision": "Unstructured provider responses after exact status handling → categorized diagnostic.",
  "saving": "Avoid repeated agent reasoning over equivalent service failures.",
  "boundary": "401/429/timeouts and retry budgets use code; do not model known protocol facts.",
  "metric": "Unnecessary retries and support effort",
  "status": "proposed; not benchmarked",
  "decisionFamily": "diagnostic-classification"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-062"></a>

### P13-JEV-062: Plugin-update impact triage

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Plugin-update impact triage
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-062-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P13-JEV-062-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P13-JEV-062-AC03: Preserve this item-specific boundary: Manifest permission expansion always requires policy handling, regardless of semantics.
4. P13-JEV-062-AC04: Report Missed impacts and upgrade review effort on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-062-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-062-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-062",
  "group": "operations",
  "title": "Plugin-update impact triage",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Surrounding diagnostics, setup, and operations plugins",
  "decision": "Versioned manifest diff, release notes, and installed usage → likely affected capabilities.",
  "saving": "Focus upgrade review and relevant regression testing.",
  "boundary": "Manifest permission expansion always requires policy handling, regardless of semantics.",
  "metric": "Missed impacts and upgrade review effort",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-063"></a>

### P13-JEV-063: Registered presentation selection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Registered presentation selection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-063-AC01: Authoritative statuses and source records stay visible and distinct from optional semantic labels.
2. P13-JEV-063-AC02: Schema-known renderers use deterministic selection; replays/viewers do not cause new inference or generated executable UI.
3. P13-JEV-063-AC03: Preserve this item-specific boundary: Known schemas choose renderers directly in code; no generated executable UI.
4. P13-JEV-063-AC04: Report Renderer correctness and generation calls on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-063-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-063-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-PRESENTATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-063",
  "group": "interface",
  "title": "Registered presentation selection",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Research",
  "owner": "Interface and presentation plugins",
  "decision": "Unstructured permitted result and registered view descriptions → suitable renderer or generic view.",
  "saving": "Avoid generating UI code or verbose prose for a familiar result type.",
  "boundary": "Known schemas choose renderers directly in code; no generated executable UI.",
  "metric": "Renderer correctness and generation calls",
  "status": "proposed; not benchmarked",
  "decisionFamily": "presentation-labeling"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-064"></a>

### P13-JEV-064: Dashboard attention annotation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Dashboard attention annotation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-064-AC01: Mandatory lifecycle, failure, approval, ownership, completion, explicit user and addressed messages bypass suppression.
2. P13-JEV-064-AC02: Optional originals remain durable; delayed/grouped information preserves distinct concerns and stays within explicit time bounds.
3. P13-JEV-064-AC03: Preserve this item-specific boundary: Keep Jev annotations separate from authoritative status and mandatory alerts.
4. P13-JEV-064-AC04: Report Useful attention signals and false alarms on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-064-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-064-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-PRESENTATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-064",
  "group": "interface",
  "title": "Dashboard attention annotation",
  "primitives": [
    "S",
    "C"
  ],
  "stage": "Next",
  "owner": "Interface and presentation plugins",
  "decision": "Optional activity descriptions → suggested attention category.",
  "saving": "Replace repetitive generated status narratives with structured displays.",
  "boundary": "Keep Jev annotations separate from authoritative status and mandatory alerts.",
  "metric": "Useful attention signals and false alarms",
  "status": "proposed; not benchmarked",
  "decisionFamily": "attention-routing"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-066"></a>

### P13-JEV-066: Optional notification grouping

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Optional notification grouping
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-066-AC01: Mandatory lifecycle, failure, approval, ownership, completion, explicit user and addressed messages bypass suppression.
2. P13-JEV-066-AC02: Optional originals remain durable; delayed/grouped information preserves distinct concerns and stays within explicit time bounds.
3. P13-JEV-066-AC03: Preserve this item-specific boundary: Do not suppress explicit user requests, required alerts, or distinct events.
4. P13-JEV-066-AC04: Report Noise reduction and missed useful notices on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-066-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-066-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-PRESENTATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-066",
  "group": "interface",
  "title": "Optional notification grouping",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Interface and presentation plugins",
  "decision": "Noncritical notifications and recent delivered messages → redundant or related.",
  "saving": "Avoid repeated natural-language notification generation and recipient processing.",
  "boundary": "Do not suppress explicit user requests, required alerts, or distinct events.",
  "metric": "Noise reduction and missed useful notices",
  "status": "proposed; not benchmarked",
  "decisionFamily": "attention-routing"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-067"></a>

### P13-JEV-067: Conversation navigation labels

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Conversation navigation labels
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-067-AC01: Authoritative statuses and source records stay visible and distinct from optional semantic labels.
2. P13-JEV-067-AC02: Schema-known renderers use deterministic selection; replays/viewers do not cause new inference or generated executable UI.
3. P13-JEV-067-AC03: Preserve this item-specific boundary: Original messages remain visible; labels confer no access or authority.
4. P13-JEV-067-AC04: Report Search success and history-read volume on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-067-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-067-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-PRESENTATION

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-067",
  "group": "interface",
  "title": "Conversation navigation labels",
  "primitives": [
    "C",
    "S"
  ],
  "stage": "Next",
  "owner": "Interface and presentation plugins",
  "decision": "Visible messages and a controlled topic taxonomy → topic/filter labels.",
  "saving": "Help users and agents retrieve relevant exchanges without full-history summaries.",
  "boundary": "Original messages remain visible; labels confer no access or authority.",
  "metric": "Search success and history-read volume",
  "status": "proposed; not benchmarked",
  "decisionFamily": "presentation-labeling"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-075"></a>

### P13-JEV-075: Suspicious-instruction annotation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Suspicious-instruction annotation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-075-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-075-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-075-AC03: Preserve this item-specific boundary: Never a sole injection defense or permission grant; untrusted text stays untrusted.
4. P13-JEV-075-AC04: Report Attack misses and extra-review load on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-075-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-075-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-075",
  "group": "security",
  "title": "Suspicious-instruction annotation",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "Research",
  "owner": "Policy and review plugins; deterministic controls remain authoritative",
  "decision": "Already-permitted content and tool/task context → potentially manipulative instructions.",
  "saving": "Prioritize bounded extra review instead of a general-model security debate on every item.",
  "boundary": "Never a sole injection defense or permission grant; untrusted text stays untrusted.",
  "metric": "Attack misses and extra-review load",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-076"></a>

### P13-JEV-076: Data-handling review assistance

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Data-handling review assistance
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-076-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-076-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-076-AC03: Preserve this item-specific boundary: Do not send potentially prohibited raw data to a hosted classifier to decide if export is safe.
4. P13-JEV-076-AC04: Report Missed concerns and review effort on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-076-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-076-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-076",
  "group": "security",
  "title": "Data-handling review assistance",
  "primitives": [
    "C",
    "N"
  ],
  "stage": "Research",
  "owner": "Policy and review plugins; deterministic controls remain authoritative",
  "decision": "Locally minimized, export-permitted descriptions → potential data-classification concern.",
  "saving": "Focus human review and avoid broad agent processing of sensitive materials.",
  "boundary": "Do not send potentially prohibited raw data to a hosted classifier to decide if export is safe.",
  "metric": "Missed concerns and review effort",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-077"></a>

### P13-JEV-077: Proposed-effect ambiguity detection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Proposed-effect ambiguity detection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-077-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-077-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-077-AC03: Preserve this item-specific boundary: Hard denials and required approvals remain unconditional; low concern never grants authority.
4. P13-JEV-077-AC04: Report Effect mismatches caught on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-077-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-077-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-077",
  "group": "security",
  "title": "Proposed-effect ambiguity detection",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "Next",
  "owner": "Policy and review plugins; deterministic controls remain authoritative",
  "decision": "User intent and a tool's declared effect summary → likely mismatch or missing clarity.",
  "saving": "Catch costly wrong-action proposals before execution review.",
  "boundary": "Hard denials and required approvals remain unconditional; low concern never grants authority.",
  "metric": "Effect mismatches caught",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-078"></a>

### P13-JEV-078: Evaluation-case prioritization

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Evaluation-case prioritization
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-078-AC01: Held-out labels/outcomes are absent from tested inputs; predictions and measured quality are separate artifacts.
2. P13-JEV-078-AC02: Sampling includes apparently successful and random cases; retained final holdout and prospective outcomes prevent circular promotion.
3. P13-JEV-078-AC03: Preserve this item-specific boundary: Keep random sampling too; avoid only labeling model-selected cases.
4. P13-JEV-078-AC04: Report Coverage of failure modes and label cost on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-078-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-078-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-078",
  "group": "improvement",
  "title": "Evaluation-case prioritization",
  "primitives": [
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Evaluation and decision-definition plugins",
  "decision": "Permitted decision failures/disagreements → informative candidate cases for human labeling.",
  "saving": "Spend evaluation and expert time on useful examples rather than random large-model review.",
  "boundary": "Keep random sampling too; avoid only labeling model-selected cases.",
  "metric": "Coverage of failure modes and label cost",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evaluation-features"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-079"></a>

### P13-JEV-079: Decision-definition candidate evaluation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Decision-definition candidate evaluation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-079-AC01: Held-out labels/outcomes are absent from tested inputs; predictions and measured quality are separate artifacts.
2. P13-JEV-079-AC02: Sampling includes apparently successful and random cases; retained final holdout and prospective outcomes prevent circular promotion.
3. P13-JEV-079-AC03: Preserve this item-specific boundary: A generator proposes questions; an independent harness measures results; review and held-out outcomes control promotion.
4. P13-JEV-079-AC04: Report Held-out error, coverage, and cost on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-079-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-079-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-079",
  "group": "improvement",
  "title": "Decision-definition candidate evaluation",
  "primitives": [
    "N",
    "S",
    "C"
  ],
  "stage": "Research",
  "owner": "Evaluation and decision-definition plugins",
  "decision": "Run candidate definitions against case inputs; Jev returns typed predictions; evaluation code compares them with held-out labels kept out of the inference request.",
  "saving": "Use a generator occasionally to propose rules, then cheaply evaluate bounded alternatives.",
  "boundary": "A generator proposes questions; an independent harness measures results; review and held-out outcomes control promotion.",
  "metric": "Held-out error, coverage, and cost",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evaluation-features"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-080"></a>

### P13-JEV-080: Outcome-model feature extraction

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Outcome-model feature extraction
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-080-AC01: Held-out labels/outcomes are absent from tested inputs; predictions and measured quality are separate artifacts.
2. P13-JEV-080-AC02: Sampling includes apparently successful and random cases; retained final holdout and prospective outcomes prevent circular promotion.
3. P13-JEV-080-AC03: Preserve this item-specific boundary: No customer fine-tuning of Jev is implied; avoid leakage, causal overclaims, and self-reinforcing routing.
4. P13-JEV-080-AC04: Report Prospective outcome improvement and inference overhead on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-080-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-080-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-080",
  "group": "improvement",
  "title": "Outcome-model feature extraction",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Research",
  "owner": "Evaluation and decision-definition plugins",
  "decision": "Task text and fixed questions → bounded semantic features for an independently validated outcome model.",
  "saving": "Potentially improve placement/escalation choices with fewer broad reasoning calls.",
  "boundary": "No customer fine-tuning of Jev is implied; avoid leakage, causal overclaims, and self-reinforcing routing.",
  "metric": "Prospective outcome improvement and inference overhead",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evaluation-features"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-081"></a>

### P13-JEV-081: Conflicting plugin guidance

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Conflicting plugin guidance
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-081-AC01: Distinguish wording-only edits from changed negation, scope, target, version or obligations using reviewed paired fixtures.
2. P13-JEV-081-AC02: Similarity never silently merges tasks/artifacts, cancels reservations, or rewrites authoritative instructions.
3. P13-JEV-081-AC03: Preserve this item-specific boundary: Instruction precedence stays explicit; the model cannot override user or administrator rules.
4. P13-JEV-081-AC04: Report Missed conflicts and correction turns on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-081-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-081-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-081",
  "group": "tools",
  "title": "Conflicting plugin guidance",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "Next",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Enabled task-relevant instruction clauses → compatible, overlapping, contradictory, or unclear, with clause IDs.",
  "saving": "Avoid injecting conflicting domain instructions and paying for agent confusion.",
  "boundary": "Instruction precedence stays explicit; the model cannot override user or administrator rules.",
  "metric": "Missed conflicts and correction turns",
  "status": "proposed; not benchmarked",
  "decisionFamily": "semantic-change",
  "reusesMechanismOf": [
    "JEV-041"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-082"></a>

### P13-JEV-082: Capability-description consistency

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Capability-description consistency
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-082-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-082-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-082-AC03: Preserve this item-specific boundary: Text consistency does not verify actual executable behavior or confinement.
4. P13-JEV-082-AC04: Report Confirmed documentation defects on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-082-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-082-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-082",
  "group": "tools",
  "title": "Capability-description consistency",
  "primitives": [
    "N",
    "C"
  ],
  "stage": "Next",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Tool documentation plus declared schema/effects → apparent read/write, scope, or platform mismatch.",
  "saving": "Find misleading capability descriptions before agents repeatedly misuse them.",
  "boundary": "Text consistency does not verify actual executable behavior or confinement.",
  "metric": "Confirmed documentation defects",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship",
  "reusesMechanismOf": [
    "JEV-077"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-083"></a>

### P13-JEV-083: Plugin example/fixture gap detection

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Plugin example/fixture gap detection
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-083-AC01: Seed supported, unsupported, contradictory and insufficient-evidence cases; report per-class confusion and independent evidence.
2. P13-JEV-083-AC02: A positive judgment cannot manufacture passing tests, verify a claim by repetition or waive the authoritative acceptance criteria.
3. P13-JEV-083-AC03: Preserve this item-specific boundary: Mechanical schema and required contract tests remain mandatory.
4. P13-JEV-083-AC04: Report Useful gaps found and authoring effort on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-083-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-083-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-083",
  "group": "tools",
  "title": "Plugin example/fixture gap detection",
  "primitives": [
    "N",
    "S"
  ],
  "stage": "Next",
  "owner": "Extension, capability, and tool-owner plugins",
  "decision": "Contribution contract and existing examples → missing scenario from a controlled checklist.",
  "saving": "Focus authoring on uncovered cases instead of regenerating an entire example/test set.",
  "boundary": "Mechanical schema and required contract tests remain mandatory.",
  "metric": "Useful gaps found and authoring effort",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-relationship",
  "reusesMechanismOf": [
    "JEV-009"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-085"></a>

### P13-JEV-085: Minimal support-packet assembly

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Minimal support-packet assembly
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-085-AC01: Seed a small critical exception and contradiction in a large irrelevant source set; selected evidence preserves it or explicitly reports incomplete coverage.
2. P13-JEV-085-AC02: Partial/unreadable evidence does not become absent evidence; every returned span or artifact ID resolves to the evaluated version.
3. P13-JEV-085-AC03: Preserve this item-specific boundary: Export approval precedes hosted selection; users can inspect exact selected evidence.
4. P13-JEV-085-AC04: Report Follow-up cycles and necessary-evidence recall on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-085-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-085-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-085",
  "group": "operations",
  "title": "Minimal support-packet assembly",
  "primitives": [
    "C",
    "S",
    "N"
  ],
  "stage": "Next",
  "owner": "Surrounding diagnostics, setup, and operations plugins",
  "decision": "Locally minimized permitted diagnostics and required support fields → select evidence and missing categories.",
  "saving": "Avoid repeated support conversations and oversized uploads/prompts.",
  "boundary": "Export approval precedes hosted selection; users can inspect exact selected evidence.",
  "metric": "Follow-up cycles and necessary-evidence recall",
  "status": "proposed; not benchmarked",
  "decisionFamily": "evidence-selection",
  "reusesMechanismOf": [
    "JEV-002",
    "JEV-025",
    "JEV-027"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-JEV-087"></a>

### P13-JEV-087: Part and variant relationship suggestions

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Part and variant relationship suggestions
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-JEV-087-AC01: An ineligible or nonexistent option cannot be returned as an executable choice.
2. P13-JEV-087-AC02: Missing or inadequate candidates produce no-fit/unknown; exact routing/arithmetic uses code without an unnecessary Jev call.
3. P13-JEV-087-AC03: Preserve this item-specific boundary: Similarity does not establish interchangeability or authorize hardware substitution.
4. P13-JEV-087-AC04: Report False same-record/interchangeability implications on representative untouched cases and complete accepted workflows, with baseline and failure slices.
5. P13-JEV-087-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-JEV-087-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-INDUSTRIAL

**Original proposal and item-specific boundaries**

```json
{
  "id": "JEV-087",
  "group": "industrial",
  "title": "Part and variant relationship suggestions",
  "primitives": [
    "C",
    "S",
    "N"
  ],
  "stage": "Research",
  "owner": "Industrial domain and vendor plugins",
  "decision": "Exact manufacturer/version filters plus catalog descriptions → same record, related variant, different, or uncertain.",
  "saving": "Reduce repeated catalog comparison and irrelevant project context.",
  "boundary": "Similarity does not establish interchangeability or authorize hardware substitution.",
  "metric": "False same-record/interchangeability implications",
  "status": "proposed; not benchmarked",
  "decisionFamily": "bounded-selection",
  "reusesMechanismOf": [
    "JEV-070"
  ]
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-VIDEO-04"></a>

### P13-VIDEO-04: Incremental semantic inventories

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Incremental semantic inventories
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-VIDEO-04-AC01: Changing content, relevant dependency, question, model, candidate order or access scope invalidates an affected judgment.
2. P13-VIDEO-04-AC02: Unchanged eligible entries reuse prior results without pretending to establish current correctness beyond the evaluated question.
3. P13-VIDEO-04-AC03: Preserve source boundary: Cache keys include content digest, question/rubric, model, relevant dependency state and access scope. Task-specific relevance cannot reuse a generic answer. Never use stale annotations as proof of current correctness.
4. P13-VIDEO-04-AC04: Measure Useful cache-hit rate; calls avoided; invalidation correctness; stale-answer incidents.
5. P13-VIDEO-04-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-VIDEO-04-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-04",
  "title": "Incremental semantic inventories",
  "kind": "New operational extension",
  "level": 9,
  "time": "23:39",
  "seconds": 1419,
  "prior": [
    "JEV-029",
    "JEV-036",
    "JEV-051"
  ],
  "owner": "Repository knowledge plugin",
  "proposal": "Maintain authorized per-file judgments for stable questions such as architectural role, ownership concern or use of a deprecated integration. Re-evaluate changed files and invalidated dependents instead of rescanning the project for every developer.",
  "delta": "Adds a maintained, versioned materialization of semantic file judgments to the on-demand scout.",
  "benefit": "Amortizes repeated classification across tasks and authorized team members.",
  "boundary": "Cache keys include content digest, question/rubric, model, relevant dependency state and access scope. Task-specific relevance cannot reuse a generic answer. Never use stale annotations as proof of current correctness.",
  "metric": "Useful cache-hit rate; calls avoided; invalidation correctness; stale-answer incidents.",
  "priority": "Next",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=1419s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level09/ask-files.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-VIDEO-06"></a>

### P13-VIDEO-06: Adaptive compaction timing

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Adaptive compaction timing
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-VIDEO-06-AC01: Skip semantic evaluation when deterministic context or in-flight-operation checks already settle timing.
2. P13-VIDEO-06-AC02: On each supported host, checkpoint/compaction preserves required facts; unsupported native operations return advice only.
3. P13-VIDEO-06-AC03: Preserve source boundary: Use real client capabilities and thresholds calibrated to that agent. Enforce hard token limits, safe checkpoints and cooldowns in code. Jev does not write the summary. Unsupported external sessions receive advice rather than a promise of control.
4. P13-VIDEO-06-AC04: Measure Total context/compaction cost; recovery errors; repeated evidence reads; task quality.
5. P13-VIDEO-06-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-VIDEO-06-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-06",
  "title": "Adaptive compaction timing",
  "kind": "New explicit decision",
  "level": 7,
  "time": "17:34",
  "seconds": 1054,
  "prior": [
    "JEV-029",
    "JEV-030",
    "JEV-043"
  ],
  "owner": "Managed-agent context plugin",
  "proposal": "Combine measured context use with Jev judgments about a task change, a completed work unit, dependence on earlier work and an unfinished edit. Return continue, suggest compaction, or request a safe checkpoint before compaction.",
  "delta": "Our previous coverage check asked whether compaction lost facts. This decides when compaction is appropriate.",
  "benefit": "Can reduce repeated history consumption and context degradation without compacting during fragile work.",
  "boundary": "Use real client capabilities and thresholds calibrated to that agent. Enforce hard token limits, safe checkpoints and cooldowns in code. Jev does not write the summary. Unsupported external sessions receive advice rather than a promise of control.",
  "metric": "Total context/compaction cost; recovery errors; repeated evidence reads; task quality.",
  "priority": "First",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=1054s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level07/should-compact.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-VIDEO-07"></a>

### P13-VIDEO-07: Active-work retention boundaries

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Active-work retention boundaries
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-VIDEO-07-AC01: Preserve an early binding instruction, unresolved approval and contradictory evidence outside the selected recent work episode.
2. P13-VIDEO-07-AC02: Resume from stored source/work-unit references and measure correct next actions after compaction and retrieval.
3. P13-VIDEO-07-AC03: Preserve source boundary: A selected turn is a suggestion, not a valid deletion boundary. Preserve earlier binding instructions, open approvals, contradictory evidence and linked tasks independently; keep full source history retrievable.
4. P13-VIDEO-07-AC04: Measure Pinned-fact retention; missed dependency rate; context size; follow-up retrieval/rework.
5. P13-VIDEO-07-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-VIDEO-07-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-07",
  "title": "Active-work retention boundaries",
  "kind": "New explicit decision",
  "level": 7,
  "time": "17:34",
  "seconds": 1054,
  "prior": [
    "JEV-028",
    "JEV-030"
  ],
  "owner": "Managed-agent context plugin",
  "proposal": "Before compaction or an agent handoff, select which task episode and linked evidence remain active. For example, retain the current firmware migration, its unresolved exception and earlier customer constraint while compressing completed discovery.",
  "delta": "Adds selection of the retained work boundary, separately from triggering compaction or checking its coverage.",
  "benefit": "Reduces unnecessary history while lowering costly rediscovery of still-active facts.",
  "boundary": "A selected turn is a suggestion, not a valid deletion boundary. Preserve earlier binding instructions, open approvals, contradictory evidence and linked tasks independently; keep full source history retrievable.",
  "metric": "Pinned-fact retention; missed dependency rate; context size; follow-up retrieval/rework.",
  "priority": "Next",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=1054s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level07/pick-cut-point.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-VIDEO-09"></a>

### P13-VIDEO-09: Narrow hypothesis challenges during implementation

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Narrow hypothesis challenges during implementation
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-VIDEO-09-AC01: Use independently reviewed supporting, contradictory and insufficient evidence, including a persuasive wrong hypothesis.
2. P13-VIDEO-09-AC02: Repeated agreement cannot substitute for actual tests; track wrong-path edits and total calls per accepted repair.
3. P13-VIDEO-09-AC03: Preserve source boundary: Do not turn repeated agreement between models into verification. Use independent fixtures and actual test results for acceptance. Stop repeated equivalent questions and broaden evidence when both answers are weak or conflicting.
4. P13-VIDEO-09-AC04: Measure Wrong-path edits; rework cycles; missed defects; added inference per accepted fix.
5. P13-VIDEO-09-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-VIDEO-09-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-EVIDENCE

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-09",
  "title": "Narrow hypothesis challenges during implementation",
  "kind": "Deeper implementation of existing use cases",
  "level": 10,
  "time": "29:28",
  "seconds": 1768,
  "prior": [
    "JEV-035",
    "JEV-047",
    "JEV-049",
    "JEV-050"
  ],
  "owner": "Agent reasoning support plugin",
  "proposal": "Let an agent submit a falsifiable hypothesis and bounded evidence before committing to a repair. Ask separately whether the evidence supports a rounding-error explanation and whether it contradicts that explanation. Repeat on the changed snapshot for a targeted regression concern.",
  "delta": "Applies evidence assessment to agent-authored hypotheses at the moment of uncertainty, with an explicit counterevidence question.",
  "benefit": "May prevent expensive wrong-path edits and repeated reviewer cycles.",
  "boundary": "Do not turn repeated agreement between models into verification. Use independent fixtures and actual test results for acceptance. Stop repeated equivalent questions and broaden evidence when both answers are weak or conflicting.",
  "metric": "Wrong-path edits; rework cycles; missed defects; added inference per accepted fix.",
  "priority": "Next",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=1768s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/extensions/ask-jev.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-VIDEO-10"></a>

### P13-VIDEO-10: Policy what-if analysis using saved factor judgments

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Policy what-if analysis using saved factor judgments
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-VIDEO-10-AC01: Changing only code-owned weights/thresholds reuses unchanged factors with zero new inference.
2. P13-VIDEO-10-AC02: Hard grants, required review, budgets and capacity cannot be averaged away; unobserved outcomes remain unknown.
3. P13-VIDEO-10-AC03: Preserve source boundary: Reuse only unchanged evidence, rubrics and model scope; changing their meanings needs new evaluation. Normalize scales explicitly. Hard permissions, required review, capacity and budgets remain outside compensating weighted sums. Historical replay predicts routing changes, not unobserved real-world outcomes.
4. P13-VIDEO-10-AC04: Measure Inference avoided during tuning; decisions changed; held-out quality; measured production outcomes after controlled rollout.
5. P13-VIDEO-10-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-VIDEO-10-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-10",
  "title": "Policy what-if analysis using saved factor judgments",
  "kind": "New operator capability",
  "level": 3,
  "time": "6:20",
  "seconds": 380,
  "prior": [
    "JEV-007",
    "JEV-031",
    "JEV-032",
    "JEV-048",
    "JEV-079"
  ],
  "owner": "Policy analysis plugin and dashboard feature",
  "proposal": "Store separate semantic factor judgments and recompute alternative weighting/threshold policies in code. For example, compare a faster-delivery policy with a lower-cost policy using the same eligible work-placement candidates, without another Jev call.",
  "delta": "Adds counterfactual policy inspection and replay, rather than merely calculating one composite score.",
  "benefit": "Makes tuning explainable and avoids inference when only arithmetic policy parameters change.",
  "boundary": "Reuse only unchanged evidence, rubrics and model scope; changing their meanings needs new evaluation. Normalize scales explicitly. Hard permissions, required review, capacity and budgets remain outside compensating weighted sums. Historical replay predicts routing changes, not unobserved real-world outcomes.",
  "metric": "Inference avoided during tuning; decisions changed; held-out quality; measured production outcomes after controlled rollout.",
  "priority": "Next",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=380s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level03/ticket-priority.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-VIDEO-13"></a>

### P13-VIDEO-13: Implementation-alternative scorecards

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Implementation-alternative scorecards
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-VIDEO-13-AC01: Compare evidence-backed eligible alternatives; compute all weights and numeric constraints in code.
2. P13-VIDEO-13-AC02: Insufficient evidence and reject-all remain usable; unsupported polished claims do not beat verified evidence automatically.
3. P13-VIDEO-13-AC03: Preserve source boundary: Jev does not generate the designs, prove their properties or perform engineering calculations. Include insufficient evidence and reject-all. Keep raw factors visible; weights are explicit preferences. Human/project governance owns acceptance.
4. P13-VIDEO-13-AC04: Measure Time to a justified decision; unresolved evidence surfaced; later design reversals; total deliberation cost.
5. P13-VIDEO-13-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-VIDEO-13-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-13",
  "title": "Implementation-alternative scorecards",
  "kind": "New decision application",
  "level": 3,
  "time": "6:20",
  "seconds": 380,
  "prior": [
    "JEV-008",
    "JEV-048",
    "JEV-073"
  ],
  "owner": "Architecture or engineering planning plugin",
  "proposal": "Compare already-proposed, eligible implementation approaches against explicit evidence and rubrics for maintainability, testability, reversibility and migration disruption. For example, compare two plugin interface proposals or two offline engineering-project conversion approaches.",
  "delta": "Produces a durable comparison of proposed implementations, beyond selecting an existing workflow, worker or tool.",
  "benefit": "Concentrates stronger reasoning on disputed tradeoffs and missing evidence rather than repeatedly debating all dimensions.",
  "boundary": "Jev does not generate the designs, prove their properties or perform engineering calculations. Include insufficient evidence and reject-all. Keep raw factors visible; weights are explicit preferences. Human/project governance owns acceptance.",
  "metric": "Time to a justified decision; unresolved evidence surfaced; later design reversals; total deliberation cost.",
  "priority": "Research",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=380s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level03/idea-verdict.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-VIDEO-14"></a>

### P13-VIDEO-14: Qualify proposed plugin investments

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Implement or extend a versioned definition/capability for: Qualify proposed plugin investments
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-VIDEO-14-AC01: Use verified requests, usage and support evidence; counts/commercial facts are copied or calculated in code.
2. P13-VIDEO-14-AC02: The outcome is a reviewed opportunity/prototype proposal, without invented demand, spending commitments or marketplace commitments.
3. P13-VIDEO-14-AC03: Preserve source boundary: Counts and commercial facts come from verified records. The model cannot invent demand, certify vendor support or commit funds. This can be a customer plugin and does not commit Agentmux to a marketplace.
4. P13-VIDEO-14-AC04: Measure Duplicate effort avoided; prototype outcomes; eventual adoption; time to a testable proposal.
5. P13-VIDEO-14-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-VIDEO-14-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SEMANTIC, EVAL-ECONOMICS

**Original proposal and item-specific boundaries**

```json
{
  "id": "VIDEO-14",
  "title": "Qualify proposed plugin investments",
  "kind": "New decision application",
  "level": 3,
  "time": "6:20",
  "seconds": 380,
  "prior": [
    "JEV-005",
    "JEV-015",
    "JEV-055",
    "JEV-078",
    "JEV-080"
  ],
  "owner": "Product-planning or internal developer-platform plugin",
  "proposal": "Evaluate supplied requests and support evidence to distinguish a reusable extension opportunity, an improvement to an existing plugin, a project-specific script or insufficient evidence. Score demonstrated need, reuse potential, capability overlap and clarity of a testable value proposition.",
  "delta": "Adds evidence-based selection of what extension hypothesis deserves a prototype.",
  "benefit": "Avoids repeated broad product triage and duplicate plugin development; directs expensive research toward the uncertainties.",
  "boundary": "Counts and commercial facts come from verified records. The model cannot invent demand, certify vendor support or commit funds. This can be a customer plugin and does not commit Agentmux to a marketplace.",
  "metric": "Duplicate effort avoided; prototype outcomes; eventual adoption; time to a testable proposal.",
  "priority": "Research",
  "videoUrl": "https://www.youtube.com/watch?v=_U-O5lYhJ7Q&t=380s",
  "codeSource": "https://github.com/disler/ten-levels-of-jev/blob/777adaf47d37ae0553220d35b2f15b3a3a063305/apps/ten-levels/src/levels/level03/idea-verdict.ts"
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-jev-extract"></a>

### P13-jev-extract: jev-extract

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-extract
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-jev-extract-AC01: Returns a real candidate or unknown; preserves exact source value; does not invent arbitrary strings or perform version math in the model.
2. P13-jev-extract-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-jev-extract-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-jev-extract-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-jev-extract-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-jev-extract-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-extract",
  "description": "Select exact values, entities or spans from candidates extracted by ordinary parsers and normalize them in code.",
  "useCase": "Choose the correct supported firmware version from a document containing product, document and firmware version numbers.",
  "eval": "Returns a real candidate or unknown; preserves exact source value; does not invent arbitrary strings or perform version math in the model.",
  "first": false
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-jev-compare"></a>

### P13-jev-compare: jev-compare

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-compare
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-jev-compare-AC01: Preserves hard constraints; explains factor evidence; computes weights exactly; does not favor polished prose without support.
2. P13-jev-compare-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-jev-compare-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-jev-compare-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-jev-compare-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-jev-compare-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-compare",
  "description": "Compare supplied, eligible options using explicit semantic factors and deterministic weights, with insufficient-evidence and reject-all outcomes.",
  "useCase": "Compare two plugin interface proposals on testability, reversibility and migration disruption.",
  "eval": "Preserves hard constraints; explains factor evidence; computes weights exactly; does not favor polished prose without support.",
  "first": false
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-jev-checkpoint"></a>

### P13-jev-checkpoint: jev-checkpoint

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-checkpoint
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-jev-checkpoint-AC01: Keeps earlier binding instructions and unresolved work; respects in-flight operations; returns advice when native compaction is unavailable.
2. P13-jev-checkpoint-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-jev-checkpoint-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-jev-checkpoint-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-jev-checkpoint-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-jev-checkpoint-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-checkpoint",
  "description": "Assess compaction timing and active-work retention, prepare a checkpoint, and invoke compaction only through a supported host operation.",
  "useCase": "A long session finishes diagnosis and starts a new phase; preserve open obligations while compressing completed work.",
  "eval": "Keeps earlier binding instructions and unresolved work; respects in-flight operations; returns advice when native compaction is unavailable.",
  "first": false
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-jev-integrate"></a>

### P13-jev-integrate: jev-integrate

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-integrate
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-jev-integrate-AC01: Uses documented interfaces; isolates execution from inference; implements timeouts, cancellation and permission-preserving fallbacks.
2. P13-jev-integrate-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-jev-integrate-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-jev-integrate-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-jev-integrate-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-jev-integrate-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-integrate",
  "description": "Add an approved decision definition to an application or agent tool using the shared runtime and the target host's real interfaces.",
  "useCase": "Add a bounded file-inspection tool to Pi or expose it through MCP for a desktop client.",
  "eval": "Uses documented interfaces; isolates execution from inference; implements timeouts, cancellation and permission-preserving fallbacks.",
  "first": false
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-jev-optimize"></a>

### P13-jev-optimize: jev-optimize

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: jev-optimize
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-jev-optimize-AC01: Counts each avoided call once; includes all Jev/agent attempts and missing billing; validates quality alongside cost and latency.
2. P13-jev-optimize-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-jev-optimize-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-jev-optimize-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-jev-optimize-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-jev-optimize-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "jev-optimize",
  "description": "Analyze observed usage and propose changes to batching, caching, question scope, thresholds or model-call placement.",
  "useCase": "Determine whether a context filter actually saves money after accounting for broken prompt caching and rework.",
  "eval": "Counts each avoided call once; includes all Jev/agent attempts and missing billing; validates quality alongside cost and latency.",
  "first": false
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-agentmux-jev-plan"></a>

### P13-agentmux-jev-plan: agentmux-jev-plan

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-plan
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-agentmux-jev-plan-AC01: Preserves user requirements; inferred dependencies remain proposals; planning does not change task ownership.
2. P13-agentmux-jev-plan-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-agentmux-jev-plan-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-agentmux-jev-plan-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-agentmux-jev-plan-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-agentmux-jev-plan-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-plan",
  "description": "Use bounded assessments to check scope, readiness, evidence and ambiguity while preparing reviewable work packets.",
  "useCase": "Prepare API, dashboard and test work packets for one feature and identify missing acceptance criteria.",
  "eval": "Preserves user requirements; inferred dependencies remain proposals; planning does not change task ownership."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-agentmux-jev-coordinate"></a>

### P13-agentmux-jev-coordinate: agentmux-jev-coordinate

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-coordinate
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-agentmux-jev-coordinate-AC01: Mandatory protocol events, failures and explicitly addressed messages bypass semantic suppression; originals remain available.
2. P13-agentmux-jev-coordinate-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-agentmux-jev-coordinate-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-agentmux-jev-coordinate-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-agentmux-jev-coordinate-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-agentmux-jev-coordinate-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-coordinate",
  "description": "Route optional findings, consolidate related clarification needs and surface developments that merit planner attention.",
  "useCase": "Coordinate several workers without sending each routine progress update to all of them.",
  "eval": "Mandatory protocol events, failures and explicitly addressed messages bypass semantic suppression; originals remain available."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-agentmux-jev-diagnose-run"></a>

### P13-agentmux-jev-diagnose-run: agentmux-jev-diagnose-run

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-diagnose-run
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-agentmux-jev-diagnose-run-AC01: Cannot infer failure of an unknown action, authorize its replay or issue commands to protected kernel plugins.
2. P13-agentmux-jev-diagnose-run-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-agentmux-jev-diagnose-run-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-agentmux-jev-diagnose-run-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-agentmux-jev-diagnose-run-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-agentmux-jev-diagnose-run-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-diagnose-run",
  "description": "Interpret actual run, plugin and published kernel status records to recommend the next permitted diagnostic step.",
  "useCase": "Explain whether a stalled run reflects a provider failure, unavailable capability, missing approval or unresolved remote state.",
  "eval": "Cannot infer failure of an unknown action, authorize its replay or issue commands to protected kernel plugins."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-agentmux-jev-curate-knowledge"></a>

### P13-agentmux-jev-curate-knowledge: agentmux-jev-curate-knowledge

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-curate-knowledge
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-agentmux-jev-curate-knowledge-AC01: Keeps conjecture separate from validated outcomes; similarity does not merge incompatible environments or grant cross-project access.
2. P13-agentmux-jev-curate-knowledge-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-agentmux-jev-curate-knowledge-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-agentmux-jev-curate-knowledge-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-agentmux-jev-curate-knowledge-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-agentmux-jev-curate-knowledge-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-curate-knowledge",
  "description": "Preserve accepted findings as scoped reusable knowledge while identifying hypotheses, stale versions and conflicts.",
  "useCase": "Retain a verified reconnection fix so future agents can find it without repeating the investigation.",
  "eval": "Keeps conjecture separate from validated outcomes; similarity does not merge incompatible environments or grant cross-project access."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-agentmux-jev-review-plugin"></a>

### P13-agentmux-jev-review-plugin: agentmux-jev-review-plugin

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-review-plugin
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-agentmux-jev-review-plugin-AC01: Schema/dependency checks remain code-driven; flags conflicting guidance; cannot grant capabilities or claim sandbox isolation.
2. P13-agentmux-jev-review-plugin-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-agentmux-jev-review-plugin-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-agentmux-jev-review-plugin-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-agentmux-jev-review-plugin-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-agentmux-jev-review-plugin-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-review-plugin",
  "description": "Review proposed plugin guidance, capability descriptions and decision packages for consistency with validated manifests and extension contracts.",
  "useCase": "Find a child plugin whose instructions ask for operations outside its declared or granted capabilities.",
  "eval": "Schema/dependency checks remain code-driven; flags conflicting guidance; cannot grant capabilities or claim sandbox isolation."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-agentmux-jev-tune-policies"></a>

### P13-agentmux-jev-tune-policies: agentmux-jev-tune-policies

**Status:** planned. **Owner:** Codex.

**Dependencies:** P12-GATE, P13-T05.

**Implementation plan**

1. Inspect the original proposal, related records, controls and evaluation gates preserved in sourceRecord. Identify shared implementations first; this record does not require a separate service, model call or additive savings claim.
2. Use the skill-creator workflow to author the declared trigger, inputs, outputs, use case, safe failure behavior and host-specific packaging: agentmux-jev-tune-policies
3. Preserve the item's exact source boundary, permissions and required facts. Use deterministic checks before optional inference, scoped evidence/cache identities, explicit abstention and bounded time/cost. Keep the feature disabled or advisory until qualified.
4. Build item-specific positive, negative and near-miss fixtures, then an untouched holdout set. Test the listed acceptance criteria on each claimed host; mocks qualify mechanics only. Use capped live calls only with the required local credentials and budget authorization.
5. Compare the ordinary workflow, tools-only workflow and tools-plus-skill workflow where relevant. Record quality, accepted outcomes, downstream tokens, total billed cost, retries, latency and rework using the item's own metrics.
6. Record the implementation/disposition and evidence for this exact ID. A failed or uneconomic experiment stays tracked with its owner and next review point; it is not silently counted as shipped. Preserve any later expansion or remote qualification dependencies.

**Deliverables**

1. Versioned implementation or explicit evaluated disposition
2. Item-specific fixtures, holdout results and host/cost evidence

**Acceptance criteria**

1. P13-agentmux-jev-tune-policies-AC01: Permissions and required review are never weighted away; stale evidence is rejected; unknown counterfactual outcomes stay unknown.
2. P13-agentmux-jev-tune-policies-AC02: Suite-wide positive/near-miss/no-inference prompts choose the intended workflow without loading unrelated full skill bodies.
3. P13-agentmux-jev-tune-policies-AC03: Paired ordinary-workflow/tools-only/tools-plus-skill results meet declared quality targets on an untouched release set for each supported host.
4. P13-agentmux-jev-tune-policies-AC04: Sources, tools and provider failures retain scope, outcome and evidence semantics; no silent direct-provider or native-hook fallback.
5. P13-agentmux-jev-tune-policies-AC05: All required controls and evaluation gates in sourceRecord have explicit evidence; unknown or failed results prevent default activation.
6. P13-agentmux-jev-tune-policies-AC06: Related records retain their IDs and shared implementation links; no overlapping benefit is counted twice.

**Verification**

1. Run the item's required evaluation gates: EVAL-CONTRACT, EVAL-SKILL, EVAL-SEMANTIC, EVAL-ECONOMICS, EVAL-HOST

**Original proposal and item-specific boundaries**

```json
{
  "name": "agentmux-jev-tune-policies",
  "description": "Replay candidate routing and review policies over scoped stored judgments and known outcomes before proposing a revision.",
  "useCase": "Compare delivery-speed and lower-cost routing preferences without rerunning unchanged Jev questions.",
  "eval": "Permissions and required review are never weighted away; stale evidence is rejected; unknown counterfactual outcomes stay unknown."
}
```

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P13-GATE"></a>

### P13-GATE: Verify and accept P13

**Status:** planned. **Owner:** Codex.

**Dependencies:** P13-T01, P13-T02, P13-T03, P13-T04, P13-T05, P13-JEV-003, P13-JEV-005, P13-JEV-006, P13-JEV-007, P13-JEV-009, P13-JEV-011, P13-JEV-012, P13-JEV-013, P13-JEV-014, P13-JEV-018, P13-JEV-020, P13-JEV-022, P13-JEV-028, P13-JEV-029, P13-JEV-030, P13-JEV-033, P13-JEV-035, P13-JEV-036, P13-JEV-037, P13-JEV-038, P13-JEV-039, P13-JEV-040, P13-JEV-041, P13-JEV-042, P13-JEV-045, P13-JEV-046, P13-JEV-047, P13-JEV-048, P13-JEV-050, P13-JEV-051, P13-JEV-052, P13-JEV-053, P13-JEV-054, P13-JEV-055, P13-JEV-057, P13-JEV-058, P13-JEV-059, P13-JEV-060, P13-JEV-061, P13-JEV-062, P13-JEV-063, P13-JEV-064, P13-JEV-066, P13-JEV-067, P13-JEV-075, P13-JEV-076, P13-JEV-077, P13-JEV-078, P13-JEV-079, P13-JEV-080, P13-JEV-081, P13-JEV-082, P13-JEV-083, P13-JEV-085, P13-JEV-087, P13-VIDEO-04, P13-VIDEO-06, P13-VIDEO-07, P13-VIDEO-09, P13-VIDEO-10, P13-VIDEO-13, P13-VIDEO-14, P13-jev-extract, P13-jev-compare, P13-jev-checkpoint, P13-jev-integrate, P13-jev-optimize, P13-agentmux-jev-plan, P13-agentmux-jev-coordinate, P13-agentmux-jev-diagnose-run, P13-agentmux-jev-curate-knowledge, P13-agentmux-jev-review-plugin, P13-agentmux-jev-tune-policies.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Catalog disposition register
2. Per-batch holdout and economics
3. Complete skill-suite release matrix
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P13-GATE-AC01: All 88 original uses, 14 video additions, four enablers, and 26 skills retain a traceable disposition and owning phase.
2. P13-GATE-AC02: Each batch passes schema, access, failure, semantic holdout, host-capability, and end-to-end economic gates.
3. P13-GATE-AC03: Compaction preserves mandatory obligations and active evidence and runs only on supported hosts.
4. P13-GATE-AC04: No savings claim relies only on shortened context or a provider's confidence score. Outcome quality and total cost meet approved thresholds.
5. P13-GATE-AC05: Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.
6. P13-GATE-AC06: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
7. P13-GATE-AC07: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Repeat the P08/P09 evaluation protocol per changed definition/skill and representative combined workflows.
2. Use stored factors for policy-only replay and record when a fresh inference is necessary.
3. Run regression tests for cache isolation, missing evidence, mandatory messages, provider failure, and decision drift.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded

## P14. Sandboxed plugins and ecosystem expansion

Untrusted third-party plugins gain a tested containment option.

**Epic acceptance criteria**

- **P14-AC01:** Adversarial plugins fail to escape their declared profile or access unauthorized host/team data in the supported threat model.
- **P14-AC02:** Sandboxed and trusted implementations pass the same language-neutral domain contract tests.
- **P14-AC03:** Required native/device integrations declare and enforce narrower support or an explicitly trusted execution host.
- **P14-AC04:** Security review and per-platform tests pass before claiming untrusted-plugin support. Marketplace availability requires this gate or a clearly restricted trusted catalog.
- **P14-AC05:** Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.

<a id="P14-T01"></a>

### P14-T01: Choose and threat-model isolated execution profiles, process/container/WASM options, host brokers, and platform limitations against actual plugin needs.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P13-GATE, P14-T05.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Choose and threat-model isolated execution profiles, process/container/WASM options, host brokers, and platform limitations against actual plugin needs.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Choose and threat-model isolated execution profiles, process/container/WASM options, host brokers, and platform limitations against actual plugin needs.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P14-T01-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Choose and threat-model isolated execution profiles, process/container/WASM options, host brokers, and platform limitations against actual plugin needs.
2. P14-T01-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P14-T01-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P14-T01-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run exploit-oriented confinement, resource exhaustion, cross-tenant, lifecycle, dependency, and upgrade tests on each supported profile.
2. Review residual risk and performance/compatibility effects with independent security expertise.
3. Re-run representative local, team, federation, UI, and industrial workflows.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P14-T02"></a>

### P14-T02: Enforce declared filesystem/network/process/device access, secret isolation, quotas, termination, and package provenance at runtime.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P13-GATE, P14-T05.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Enforce declared filesystem/network/process/device access, secret isolation, quotas, termination, and package provenance at runtime.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Enforce declared filesystem/network/process/device access, secret isolation, quotas, termination, and package provenance at runtime.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P14-T02-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Enforce declared filesystem/network/process/device access, secret isolation, quotas, termination, and package provenance at runtime.
2. P14-T02-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P14-T02-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P14-T02-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run exploit-oriented confinement, resource exhaustion, cross-tenant, lifecycle, dependency, and upgrade tests on each supported profile.
2. Review residual risk and performance/compatibility effects with independent security expertise.
3. Re-run representative local, team, federation, UI, and industrial workflows.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P14-T03"></a>

### P14-T03: Qualify UI contribution isolation and publisher/distribution controls before enabling a public plugin ecosystem.

**Status:** planned. **Owner:** Codex.

**Dependencies:** P13-GATE, P14-T05.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Qualify UI contribution isolation and publisher/distribution controls before enabling a public plugin ecosystem.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Qualify UI contribution isolation and publisher/distribution controls before enabling a public plugin ecosystem.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P14-T03-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Qualify UI contribution isolation and publisher/distribution controls before enabling a public plugin ecosystem.
2. P14-T03-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P14-T03-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P14-T03-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run exploit-oriented confinement, resource exhaustion, cross-tenant, lifecycle, dependency, and upgrade tests on each supported profile.
2. Review residual risk and performance/compatibility effects with independent security expertise.
3. Re-run representative local, team, federation, UI, and industrial workflows.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P14-T04"></a>

### P14-T04: Retain trusted native profiles only with clear administrator choice

**Status:** planned. **Owner:** Codex.

**Dependencies:** P13-GATE, P14-T05.

**Implementation plan**

1. Inspect the existing source and callers for this exact work item: Retain trusted native profiles only with clear administrator choice. Assess future hosted service and native Windows as separate product decisions.
2. Record inputs, outputs, authority, failure states and compatibility constraints for this scope. Use the phase's approved contracts; resolve any blocking design decision before changing its implementation.
3. Implement the scoped work in a reviewable slice behind existing entry points where compatible. Preserve legacy assertions, stable IDs, data relationships and user configuration; record a justified replacement or migration where reuse is insufficient.
4. Add or reuse focused fixtures for the successful path and the applicable denial, malformed input, retry, cancellation and crash boundaries. Start with the smallest failing test, then run affected integration checks.
5. Attach the resulting artifacts and source-bound evidence. Update affected pattern and component records. Hand the result to the phase verification task without claiming the whole phase is accepted.

**Deliverables**

1. Retain trusted native profiles only with clear administrator choice. Assess future hosted service and native Windows as separate product decisions.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P14-T04-AC01: The scoped deliverable is implemented or, for a decision/review item, explicitly decided with alternatives and consequences: Retain trusted native profiles only with clear administrator choice. Assess future hosted service and native Windows as separate product decisions.
2. P14-T04-AC02: Every named capability in the scope has a passing focused check or a recorded, unresolved environment/decision gap. A gap prevents this task being marked done; a smaller successful example cannot stand in for the entire scope.
3. P14-T04-AC03: Affected existing behavior has a baseline/candidate comparison or an approved behavior-change record; no capability, required assertion or stored identity is silently removed.
4. P14-T04-AC04: Evidence identifies the candidate commit, actual environment, command and result for each task criterion; secrets and private agent reasoning are excluded. Known limitations, migration and recovery behavior are documented.

**Verification**

1. Run exploit-oriented confinement, resource exhaustion, cross-tenant, lifecycle, dependency, and upgrade tests on each supported profile.
2. Review residual risk and performance/compatibility effects with independent security expertise.
3. Re-run representative local, team, federation, UI, and industrial workflows.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P14-T05"></a>

### P14-T05: Apply ADD-01 and the component preservation matrix to every changed source file and affected caller

**Status:** planned. **Owner:** Codex.

**Dependencies:** P13-GATE.

**Implementation plan**

1. Review the phase-owned components in the preservation matrix and identify every changed caller, command, route, state record, integration and UI action; also include cross-phase callers affected by this work.
2. Record retain/wrap/extract/extend/replace decisions with reasons. Map each old assertion and data identity to its target. Capture missing characterization fixtures before refactoring.
3. Run the available baseline checks and define the candidate, migration/rollback and added-functionality checks. Candidate execution belongs to the implementation and final phase gate, so this preparation does not depend on future code being finished.
4. Maintain the inventory and behavior ownership throughout the phase. Missing environments stay open. Codex reviews any capability change against the complete user-authorized scope; autonomy does not permit silent scope reduction.

**Deliverables**

1. Apply ADD-01 and the component preservation matrix to every changed source file and affected caller. Record reuse, intentional behavior changes, migration needs and the specific added functionality before editing implementation.
2. Focused regression evidence and affected compatibility/migration records

**Acceptance criteria**

1. P14-T05-AC01: Every phase-owned component and affected cross-phase caller has a recorded scope, existing behavior and owner; no changed source is unmapped.
2. P14-T05-AC02: Baseline evidence distinguishes passing, failing, unavailable and historical results. Any gap that prevents a safe planned change remains blocking.
3. P14-T05-AC03: Reuse and migration decisions name alternatives, preserved IDs/assertions and rollback boundaries; required approval exists before any capability reduction.
4. P14-T05-AC04: Candidate comparison, added-functionality and migration fixtures are assigned to implementation and phase verification tasks. This preflight does not claim that future candidate tests already passed.

**Verification**

1. Run exploit-oriented confinement, resource exhaustion, cross-tenant, lifecycle, dependency, and upgrade tests on each supported profile.
2. Review residual risk and performance/compatibility effects with independent security expertise.
3. Re-run representative local, team, federation, UI, and industrial workflows.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="P14-GATE"></a>

### P14-GATE: Verify and accept P14

**Status:** planned. **Owner:** Codex.

**Dependencies:** P14-T01, P14-T02, P14-T03, P14-T04, P14-T05.

**Implementation plan**

1. Confirm every phase task and prerequisite is complete; inspect the actual deliverables and limitations rather than relying on a done label.
2. Run the phase's full acceptance, failure, preservation and rollback checks on the exact candidate and supported environments. Retain per-criterion evidence using gate-record.template.json.
3. Codex reviews actual deliverables and subagent findings and records the advancement decision. Parallelize bounded subagent work only within this phase. Missing evidence remains blocking; no human approval is required.
4. Commit all phase changes and evidence to feat/agentmux-platform-rearchitecture, push, and verify the remote commit. Record that commit before the next phase starts. MERGE-01 remains separate.

**Deliverables**

1. Sandbox threat model and test report
2. Profile compatibility matrix
3. Ecosystem launch decision
4. Component reuse decisions, baseline/candidate results, gain evidence and approved exceptions for ADD-01

**Acceptance criteria**

1. P14-GATE-AC01: Adversarial plugins fail to escape their declared profile or access unauthorized host/team data in the supported threat model.
2. P14-GATE-AC02: Sandboxed and trusted implementations pass the same language-neutral domain contract tests.
3. P14-GATE-AC03: Required native/device integrations declare and enforce narrower support or an explicitly trusted execution host.
4. P14-GATE-AC04: Security review and per-platform tests pass before claiming untrusted-plugin support. Marketplace availability requires this gate or a clearly restricted trusted catalog.
5. P14-GATE-AC05: Every affected existing component retains its documented behavior through reused code or a justified replacement. Its baseline and candidate checks, migration checks, and added capability evidence are reviewed before advancement. Missing environments remain open. Codex reviews intended behavior and migration changes against the full user scope; autonomous delivery does not authorize capability removal, reduced scope or weaker verification.
6. P14-GATE-AC06: All assigned failure scenarios and component checks have reviewed evidence for the candidate; missing or skipped required checks remain blocking.
7. P14-GATE-AC07: The required reviewer and advancement decision are recorded, and the phase commit is verified on the current remote feature branch. No merge is performed.

**Verification**

1. Run exploit-oriented confinement, resource exhaustion, cross-tenant, lifecycle, dependency, and upgrade tests on each supported profile.
2. Review residual risk and performance/compatibility effects with independent security expertise.
3. Re-run representative local, team, federation, UI, and industrial workflows.
4. Run the component coverage validator, review newly added or changed entry points, and attach the owning component checks to the phase gate. Compare existing and candidate behavior in isolated environments; do not run old and new writers against the same live records.

**Evidence:** not yet recorded

**Commits:** not yet recorded


<a id="MERGE-01"></a>

### MERGE-01: Autonomous final feature-branch acceptance and verified push

**Status:** planned. **Owner:** Codex.

**Dependencies:** P00-GATE, P01-GATE, P02-GATE, P03-GATE, P04-GATE, P05-GATE, P06-GATE, P07-GATE, P08-GATE, P09-GATE, P10-GATE, P11-GATE, P12-GATE, P13-GATE, P14-GATE.

**Implementation plan**

1. Verify every approved phase against the exact candidate and supported environments; collect the phase-by-phase evidence index and resolve every required gap.
2. Use agent-operated, independently enrolled running hubs with distinct administration identities. Demonstrate automatic Compose start and reuse, instance identity, readiness and scoped hub status.
3. Connect those hubs with explicit scoped grants. Run the plan's read-only fixture orchestration in both directions, with origin-owned acceptance in each direction.
4. Preserve fixture checksums, artifact digests, task/delegation/attempt/result identities and terminal/dashboard observations. Verify bounded outputs and unchanged inputs; rerun affected checks after material changes.
5. Codex reviews the actual evidence and subagent findings, records its dated final acceptance of this exact candidate and verifies the pushed feature-branch commit. Record mergeAuthorized=false; this acceptance never permits a merge.

**Deliverables**

1. Completed final acceptance record and linked real-instance evidence
2. Dated Codex review, verified remote commit and mergeAuthorized=false

**Acceptance criteria**

1. MERGE-01-AC01: Every required P00–P14 criterion and environment has reviewed, current evidence with no unresolved required gap.
2. MERGE-01-AC02: Two agent-operated, independently enrolled real hubs complete the non-destructive orchestration in both directions, including explicit origin acceptance.
3. MERGE-01-AC03: The complete finalMergeGate evidence bundle identifies the exact candidate, scopes, operations, artifacts, checksums and before/after observations.
4. MERGE-01-AC04: Codex reviews that evidence and accepts the exact candidate after verifying the remote feature-branch commit. No human review is required and no merge is authorized.

**Verification**

1. Execute every step of implementation-plan.md, MERGE-01, on the final candidate.

**Evidence:** not yet recorded

**Commits:** not yet recorded
