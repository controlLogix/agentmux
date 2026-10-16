# Agentmux implementation review package

Prepared October 9, 2026. Status reviewed October 14, 2026: P00 and corrected P01 are complete and accepted by Codex. P02 code is present, but six implementation tasks and full phase qualification remain open; its preservation preflight is complete. P03–P14 and MERGE-01 remain planned. No merge or release is authorized. See the [live status board](implementation-status.md) for task counts and the [plan status](implementation-plan.md) for the current code checkpoint. Later descriptions of the original review package retain their historical context; the live tracker records current delivery status and authority.

Start with the revised presentation, then review the full plan and individual gate criteria. STATE-01 records the approved NATS-backed shared-persistence direction, with optional rebuildable SQL views and qualification gates. The original presentation remains preserved as the earlier review version.

The initial beta targets native macOS ARM64 only under [PLATFORM-SCOPE-03](delivery/decisions/PLATFORM-SCOPE-03-macos-arm64-beta.md). Linux and macOS AMD64 qualification are deferred expansion work, not beta blockers or passing checks. Preserve their code, assertions, historical evidence and original visual assets. All product, security, recovery and preservation gates remain required; the structured tasks and gates use this current target.

- [Before/after and phase presentation](agentmux-implementation-review-v3.pptx)
- [Dashboard and AI terminal concept images](concept-images/README.md)
- [Single-file HTML visual review for Nick](agentmux-visual-review.html) · [Sharing and review instructions](review-site/README.md)
- [Component preservation and gains](component-preservation.md)
- [Complete source file inventory](component-inventory.json)
- [Phased implementation plan](implementation-plan.md)
- [Live phase and task status](implementation-status.md) · [Detailed task backlog](delivery/task-details.md) · [Tracking procedure](delivery/README.md)
- [Structured phases and 99 acceptance criteria](phases.json)
- [Complete functionality, Jev, video, and skill coverage](coverage.md)
- [Structured Jev coverage and evaluation gates](jev-coverage.json)
- [62 failure scenarios and verification procedure](verification-matrix.md)
- [Structured failure scenarios](verification-matrix.json)
- [Blank evidence record for a future phase gate](gate-record.template.json)
- [Baseline findings and their resolutions](known-baseline-blockers.md)
- [Governance repairs and upgrade procedure](governance-repairs.md) · [Executed evidence](governance-repair-evidence.json)

P00 resolves and approves the implementation contract. P01–P12 form the proposed first sellable release, including same- and cross-organization federation. P13 expands the remaining evaluated Jev/skill catalog. P14 adds separately qualified untrusted-plugin confinement.

The launch worker execution boundary is part of P04. Deferring third-party plugin sandboxing does not defer isolation between users and projects.

All product changes belong on `feat/agentmux-platform-rearchitecture`. A passing phase gate authorizes only the agreed progression. Merging still requires Ryan's review with Nick and Ryan's explicit authorization.

This package describes the future platform and one completed baseline repair pass. Historical tests, synthetic examples and documentation checks do not prove the full planned platform is implemented or qualified.

The six baseline defects are repaired under Ryan's explicit authorization. The evidence includes 119 passing hub tests with a real local NATS server, nine selected dashboard tests and syntax checks. The repair record preserves prior findings and identifies the untested environments and remaining P00/P01 work. These results do not authorize phase advancement or merging.

ADD-01 requires preservation of current functionality and justified code reuse decisions in every phase. Run `python docs/planning/2026-10-09/verify-component-coverage.py` from the repository root to check inventory and planning links. Static coverage is not runtime qualification. Both earlier deck versions remain preserved.

LOCAL-01 requires automatic Docker Compose startup or verified reuse when a configured Agentmux-enabled terminal launches, followed by a consistent instance and authorized hub summary. See the updated plan and FAIL-55–FAIL-62. Existing slide decks and concept images are preserved dated snapshots from before LOCAL-01; the current plan and rebuilt HTML contain the newer requirement. Image provenance hashes remain those of their original generation inputs.

MERGE-01 is the final branch-wide gate: complete the entire approved plan, pass its required checks, and record successful non-destructive orchestration from Ryan to Nick and from Nick to Ryan using their own real instances. Both review the evidence; Ryan explicitly authorizes merging afterward. Passing P12 alone does not allow an early merge. See the plan and `finalMergeGate` in the evidence template. No run or approval is recorded yet.
