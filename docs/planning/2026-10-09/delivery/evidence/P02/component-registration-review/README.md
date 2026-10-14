# P02 component registration review

This is a standalone proposal for the root reviewer, not a metadata update or acceptance record. It maps 85 actual foundation files at this snapshot to one primary component, one behavior check and one task owner each. Shared tests can supply evidence for dependent checks without assigning the same check to several tasks. The detailed proposal includes every file hash, current registration state, exact function declarations and public Go types to inspect.

## Registration findings

- 66 scoped files are absent from the component inventory. Register actual files in both the owning component manifest and inventory; preserve every baseline blob, original file row and history entry.
- 37 scoped runtime surfaces are eligible under the actual guard. Thirty lack records. Four existing records are stale: assembly verify.go, Docker driver docker.go, runtime snapshot_linux.go and supervisor.go. Append their previous complete records to history before recording reviewed current declarations and hashes.
- Tests, runtime testdata and YAML still need ownership even when they are excluded from the runtime surface index. The two dedicated Docker test files use the explicit agentmux_bootstrap_docker build tag; no authorization means failure, not a skipped qualification.
- KERN-02, KERN-04 and PLAT-03 already have accepted preflight proposals but are absent from the global manifest. Add those reserved IDs with their actual current files. Preserve their original planned assertions and path history. Deployment was implemented as platform/deployment, rather than a static deploy/compose tree; record that placement instead of inventing files at the planned location.
- Append KERN-03-C02 for the actual protected codec/credential/transport boundary, owned by P02-T03. Preserve KERN-03-C01's existing account/permission assertion.
- Append REPO-03-C02 for the actual native foundation workflow/collector, owned by P02-T01 with qualificationPhase P02. Preserve REPO-03's P01 owner/check and historical results. A new workflow is not historical P01 execution evidence.

The current coverage check fails with seven errors. Its exact output is retained here. The four platform staleness errors and missing files belong to this proposal. Concurrent review-server files and stale review UI modules are separately owned work; do not overwrite them as part of this registration task. Source coverage checks references and hashes; it does not prove behavior.

## Primary ownership

| Current source family | Component/check | Exactly one owner |
| --- | --- | --- |
| Module pins; signed installed release; private enrolled profile; host loader; fixed broker preflight | PLAT-01-C01 | P02-T01 |
| Assembly manifests, exact member/root/size validation | KERN-01-C01 | P02-T01 |
| Kernel entry point, boot actor, real actor/process readiness fixtures | KERN-01-C02 | P02-T02 |
| Runtime images, owned process handles, StopRole, parent EOF/leases, actual host-death fixture | PLAT-02-C01 | P02-T02 |
| Protected lifecycle actor | KERN-02-C01 | P02-T02 |
| Account config and communication actor | KERN-03-C01 | P02-T03 |
| Shared stateless protocol, closed JSON/alias guards, per-role credential loading and bounded transport | KERN-03-C02 (additive) | P02-T03 |
| Protected exported snapshot/update actor | KERN-04-C01 (reserved) | P02-T04 |
| Doctor, read-only kernel observer, owner-scoped status and Session adapter | PLAT-01-C03 | P02-T04 |
| Local storage/health config, real persistence probe, read-only health observer, private Compose renderer | PLAT-03-C01 (reserved) | P02-T05 |
| Docker context/env/inspector, advisory lock, composed Bootstrap, orchestration test | PLAT-01-C02 | P02-T07 |
| Actual tagged Compose fixture/config/volume/cleanup helper | PLAT-03-C02 (reserved) | P02-T07 |
| Go surface guard fixtures | PLAT-04-C01; retain C02 independently | P02-T01 |
| Native workflow and closed candidate-bound artifact collector | REPO-03-C02 (additive) | P02-T01 |

Existing checks and their current task owners are listed unchanged in proposal.json. This proposal does not rewrite any existing assertion. In particular, HUB-15-C01/C02 remain assigned exactly once to P02-T06. Its preflight acceptance must not be treated as executed stream/KV/TLS/revocation qualification. The root gate needs a separate exact-source historical-evidence reuse review or fresh declared-environment evidence for those original requirements. Do not silently remove them or accept a narrow health stream instead.

## Current qualification gaps

1. Native Darwin execution still fails closed. Linux sealed-image evidence and Darwin research do not prove macOS product boot. The protected-install proposal is only research. Native macOS Compose/boot/shutdown and the accepted platform matrix remain mandatory.
2. The initial lifecycle actor observes peers and accepts announce only. Runtime StopRole and EOF ownership are actual process controls, but they are not proof of the full planned protected lifecycle/recovery contract over its approved interfaces. Keep KERN-02-C01 open until the original requirements are satisfied or precisely reconciled without weakening them.
3. kernel-info is deliberately narrower than caller-scoped L04. Preserve the reserved KERN-04-C01 snapshot/update/gap/reconnect/stale/slow-consumer assertion using the accepted outer reply, while keeping protected kernel data publication distinct from surrounding status mapping. The current startup_status and startup_session sources are under active review; this proposal grants no L04, signing, caller authorization, full-service or fresh persistence-write acceptance.
4. The local storage factory/health stream does not implement business state, R3 replication, completion reserve or a whole team connection profile. Keep the team profile portion of PLAT-03-C01 and P02-T05 explicit. The current host loader and Bootstrap accept local profiles only; a remote declaration test is not actual team connection qualification.
5. The actual composed attempt reached cold/concurrent/warm/readiness/persistence/owner recovery, then failed its volume-inspector helper. The original exit1 remains failed. Separately authorized exact-ID cleanup retained the volume and original 15-container baseline. The one-brace template repair has unit/compile/vet proof but no passing full composed run yet. PLAT-01-C02 and PLAT-03-C02 remain unaccepted.
6. The cold/warm status adapter must preserve actual invocation identity and receipt time. A warm read or retained in-memory record cannot certify a fresh write or invent work/hub state. Finish current integration/evidence review before qualifying PLAT-01-C03 or P02-AC08.
7. The current public entry points are Go APIs plus the internal supervised kernel executable. There is no actual source at the preflight's proposed public platform command path. Register only actual source. Review whether the P02 opt-in launcher/doctor/installer skeleton still needs an invocable entry point; terminal automatic activation and full package installation stay under their original later-phase owners.
8. FAIL-01/02 and FAIL-55â€“59, bad context/ports/releases/partial startup, NATS loss and protected-role failure need their complete required real-environment evidence. Initial permission, unit and fixture slices do not replace these checks.
9. Candidate-bound native foundation CI is prepared, but this proposal is not a GitHub run. Commit/push a reviewed checkpoint and inspect actual Linux/macOS artifacts. Keep native Darwin research separate and retain failures. A checkpoint is not phase advancement.

## Historical evidence and renewal

Keep all raw failures and earlier partial passes. The exact changed-source boundary determines what must be renewed; never refresh a digest to relabel old execution.

- The protected account builder and advisory lock still have the reviewed frozen hashes. Their narrow real-NATS and lock evidence can be referenced for the recorded WSL environment after exact input comparison. Their complete cross-platform checks remain open.
- Initial protected-runtime evidence predates the sealed-descriptor rehash, held-root symlink/read-boundary repair, parent EOF/lease ownership and StopRole additions. Preserve it as history. Use the later runtime/assembly/parent-lifetime and exact current source-bound evidence, then qualify the native candidate.
- Initial actor evidence predates exact JSON field-name/alias guards. The later protocol/boot race evidence covers the reviewed codec candidate, but it does not independently qualify the new L04 mapper or a changed composed Bootstrap candidate.
- Early Docker/inline configuration/inspector evidence predates strict closed JSON, actual private config inspection and current composed behavior. Retain the refined negative controls and source-bound results; renew affected launcher tests on the frozen candidate.
- Host loader/release/profile evidence must bind the current closed decoder and complete admission source, including later size/member/root changes. The previous combined launcher pass is historical after profile or Bootstrap changes.
- The original actual Compose run and its exact helper error remain historical failed evidence. Do not treat repaired-template unit tests or manual cleanup as a new end-to-end pass. The outer status/session additions are also a changed source boundary for future integrated status qualification.
- The source guard preserves its original Python/JS/TS/mjs eligibility checks. Its missing/stale/duplicate Go controls are additive P02 evidence. The native collector/workflow and any new public Go surface are current additions, not accepted P01 surfaces.

Seventeen directly affected legacy runtime, installer, dependency and CI inputs were compared byte for byte against accepted P01 commit 2740e31. All are exact at this snapshot. This supports preservation review; it does not itself rerun their behaviors or accept later phase checks. Retain the original phase owners for harness/terminal integrations, federation, dashboard and installation.

## Live-source changes recorded during the audit

The candidate continued changing while the proposal was built. Two actual new test files were inspected and appended: deployment/sync_policy_test.go belongs to PLAT-03-C01/P02-T05, and launcher/startup_session_lifecycle_test.go belongs to PLAT-01-C03/P02-T04. Deployment now adds an explicit always-sync policy; its prior profile/test hashes remain as historical snapshots in this proposal. Bootstrap and the status/session adapter also changed. Do not apply stale declaration positions or treat earlier evidence as qualification of these changes. The root writer must inspect the final frozen bytes and append reviewed current surface records/history.

## Root writer sequence

1. Freeze the candidate or record the live L04 boundary explicitly. Review each exact declaration, exported type, subject/HTTP surface and evidence limit in the proposal.
2. Append actual files and reserved components; add the two new checks. Append old surface records/history before deliberate replacements. Keep all existing definitions and statuses.
3. Assign every new check exactly once to the proposed task. Add direct test paths to existingTests without deleting older references. Register YAML/testdata/test ownership as well as runtime source.
4. Reconcile task sourceHashes deliberately; render and validate the tracker, then run component and pattern governance. Root alone owns those edits. Separately resolve concurrently owned review UI metadata.
5. Run affected stable-source suites and real native candidate jobs, review raw results and renew actual missing integration evidence. Record no task or phase acceptance from this planning proposal.

No Docker call, source implementation edit, global metadata edit, credential/profile read, provider prompt, commit or push was performed for this audit.
