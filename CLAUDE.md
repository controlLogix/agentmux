## Architecture and code review

Follow the existing architecture and explain material design choices in code review. Review changed behavior, security boundaries and affected callers. Do not require local pattern registries, generated diagrams or evidence gates merely to complete a bounded Jira issue.

## Plain English for All Communication

Always use plain English for human-readable chat responses and generated content in this repository. Read and follow [the plain-language rules](.claude/rules/plain-language.md). This includes progress updates, documentation, plans, presentations, UI text, comments, and descriptions or labels in generated data.

Preserve technical meaning and exact code, commands, identifiers, schemas, and source quotations. Apply the same rules to delegated work. Use the language the user requests while keeping the writing clear.

## Development work and review

[Jira project AMUX](https://adag-csai.atlassian.net/jira/software/c/projects/AMUX) is the sole authority for development tasks, acceptance criteria, dependencies, status, blockers and review outcomes. Migrate and reconcile all existing tasks and acceptance criteria into AMUX before removing the local tracker. Do not maintain a local task ledger or generated status board.

Before creating a decision task or reporting a blocker, check the accepted product decisions and later scope changes. Older open questions do not override accepted choices. For this migration, read `docs/planning/2026-10-09/delivery/decisions/acceptance.md` and the decision documents it accepts. The initial SDK languages are Python and TypeScript; do not report that choice as undecided. Preserve the difference between a design decision and an implemented or tested capability.

For catalog and skill tasks, expand referenced shared controls and evaluation gates from `docs/planning/2026-10-09/jev-coverage.json` into readable product requirements or links to their full requirements in the owning Jira epic. IDs alone do not preserve acceptance criteria.

Prefer one complete copy of repeated shared requirements in the owning epic, with direct links and the exact applicable criterion IDs in each task. Keep each task's own scope, acceptance criteria, exceptions and activation conditions complete. Read back the shared text and its task links; do not substitute an ID or local file path for the requirement.

Work on the explicitly assigned, bounded Jira issue and its acceptance criteria. Report blockers and review findings in that issue. Do not autonomously continue through all phases or create source-hash, evidence-bookkeeping or phase-advancement loops. Use focused tests, relevant integration tests and code review; follow [the local testing workflow](docs/LOCAL_TESTING.md). Do not add verification scaffolding or prepare new fixtures without task scope that calls for them.

All platform rearchitecture work stays on `feat/agentmux-platform-rearchitecture`. The current beta targets native macOS ARM64 only; Linux, macOS AMD64 and Windows/WSL are not qualified by that work. Do not run CI builds or verification; the existing CI prohibition remains in effect. Do not merge, squash, cherry-pick or transfer this work to `main` or another integration/release branch, enable automatic merging, or release it.

These changes concern development tracking and verification workflow only. Preserve product authorization, authentication, security, data retention, ownership, recovery and task-management behavior. Product requirements and issue acceptance criteria are not waived by removing development bookkeeping.
