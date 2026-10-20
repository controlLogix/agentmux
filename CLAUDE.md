## Architecture and code review

Follow the existing architecture and explain material design choices in code review. Review changed behavior, security boundaries and affected callers. Do not require local pattern registries, generated diagrams or evidence gates merely to complete a bounded Jira issue.

When extending a shared contract for an existing caller, inspect that caller's actual arguments, guarded operation variants and returned values. Include its supported form in focused verification before accepting the prerequisite. A simplified contract fixture does not establish compatibility with the actual caller; preserve its existing guards and original records when correcting a mismatch.

## Plain English for All Communication

Always use plain English for human-readable chat responses and generated content in this repository. Read and follow [the plain-language rules](.claude/rules/plain-language.md). This includes progress updates, documentation, plans, presentations, UI text, comments, and descriptions or labels in generated data.

Preserve technical meaning and exact code, commands, identifiers, schemas, and source quotations. Apply the same rules to delegated work. Use the language the user requests while keeping the writing clear.

## Epic order and dependency checks

Work in the order defined by the owning Jira epic. Before starting, resuming, or delegating a task, read the epic's current order, the task's dependencies, and the status of its prerequisites. Choose the earliest unfinished eligible task. Do not infer order from ticket numbers or chat titles.

- Finish the current task's accepted scope, focused verification, and review before advancing to dependent work. Partial implementation, a passing subset of tests, or an idle worker does not complete a prerequisite.
- Before accepting a prerequisite or dispatching dependent work, read its latest material review comments and outcomes, including those from other coordinating sessions. Resolve demonstrated open findings before acceptance; a passing batch or an earlier completion comment does not clear a later reproduction. Recheck contradictory status with the current issue and latest review evidence rather than assuming a stale projection.
- Work on a later task in parallel only when its prerequisites are complete and its scope is independent of unfinished earlier tasks. Check actual implementation and verification dependencies as well as Jira links; a missing dependency link is not proof of independence.
- Before using that exception, record a brief explanation in the later Jira issue naming the unfinished earlier tasks and why this work does not depend on them. Independent files or an available worker alone do not justify advancing.
- Verify the later task's actual prerequisites before creating or dispatching its implementation session. Do not start a worker to discover whether the task is eligible. A later task that would unblock the current task is not automatically independent; a missing owner contract or an unfinished prerequisite keeps it inactive. Record the dependency and return to the earliest eligible work unless the user explicitly changes the order.
- If the earliest task is blocked, fix its blocker or record the concrete blocker in Jira. Continue only with another task that meets the independence rule; do not skip ahead merely to keep workers busy.
- Give every worker the issue ID, owning epic, relevant prerequisites, and any justified independence exception. Apply the same rule when reusing an existing session.
- Reusing a session does not preserve permission to continue its previous assignment. Recheck its actual current issue against epic order before resuming it; do not rely on its title, old handoff, or available capacity. The coordinating agent is responsible for this check.
- Do not let a prerequisite repair grow into implementation of later tasks. If current work exposes a missing dependency, identify its owning Jira issue, stop dependent work, and complete the bounded prerequisite first. Do not repeatedly widen a later issue to build the unfinished foundation it needs.
- Passing an isolated component, finishing a review, or completing an installed test does not establish that the whole prerequisite is complete. Check its full accepted scope and recorded Jira outcome before using it to justify later work. Do not substitute worker activity, test counts, or repeated progress reports for completing the earliest eligible issue.
- If ongoing work is found to depend on unfinished earlier work, stop it at a safe checkpoint, preserve changes, join or retain owned processes safely, and return to the earliest eligible task. Do not discard useful work or claim dependent tasks complete.
- Follow an explicit user-approved change to the order, and record that change in Jira. Broad permission to work autonomously or in parallel does not override epic order.

Keep ordering, dependencies, blockers, and exceptions in Jira. Do not create a local task ledger or a separate phase-advancement process.

### Extract blocking work before advancing

Record each demonstrated implementation blocker in a bounded Jira subtask of the earliest task that needs the fix. Search for and reuse an existing matching subtask first. This includes blockers found within the current task, not only work assigned to a later task. When work must move from a later task, extract only the necessary prerequisite. This is the user's standing instruction for correcting task ownership and order; it does not activate the rest of the later task.

- Search for an existing matching subtask first. Reuse it when it already owns the complete prerequisite; otherwise create a bounded subtask with the observed blocker, source or reproduction, acceptance criteria, inherited product safeguards, owner, prerequisites and verification needed.
- Add explicit Jira dependency links: each prerequisite blocks the extracted subtask, and the extracted subtask blocks the affected work. Record unresolved blockers and check for circular dependencies. Keep unaffected work eligible only under the existing independence rule.
- Update the source task's description and acceptance criteria, and any affected children, to remove the transferred implementation responsibility and reference the new owner. Map each transferred criterion to the receiving subtask; keep later integration and qualification where they belong. Do not duplicate implementation, silently drop criteria or mark transferred work complete.
- Comment on both the source and receiving tasks explaining what moved, why it is needed earlier, what remains, and how dependencies and execution order changed. For a blocker split out of the current task, explain that split even when no later task loses work. Read back the updated scope, acceptance criteria and links before dispatching implementation.
- Apply this to each new blocker discovered within an extracted subtask as well. Do not start a later task to resolve it, widen the current task into unrelated later scope, or create a separate local tracker. Safe non-blocking improvements still follow the deferred-issue rule.

## Parallel delegation within dependency order

Use parallel subagents for eligible, independent subtasks. Keep the earliest unfinished eligible task moving while other workers complete independent branches. Apply the epic-order rule to both tasks and their subtasks; available capacity alone does not make work eligible.

- Before dispatch, read the current parent scope, acceptance criteria, subtask dependencies and prerequisite outcomes in Jira. Check actual implementation and verification dependencies as well as links. An unfinished parent does not block its own implementation subtasks merely because it is open; the subtasks' actual prerequisites determine eligibility. A dependent task must still wait for the full prerequisite scope to be accepted.
- Split large tasks into bounded Jira subtasks when that enables useful parallel work. Reuse existing matching subtasks. Give each subtask its own acceptance criteria, verification and explicit dependency links, and map its criteria to the parent requirements. Preserve shared safeguards and leave final integration and parent acceptance with a named owner. Finish recording that task's breakdown before moving to another task's breakdown.
- Dispatch only subtasks whose prerequisites are implemented, verified, reviewed and recorded complete. Keep blocked subtasks queued. When work bypasses an unfinished earlier sibling or task, record the independence explanation in the later Jira issue before dispatch, naming the unfinished work and why there is no dependency on it.
- Give each worker the parent and subtask IDs, owning epic, scope, acceptance criteria, prerequisite outcomes, relevant rules, verification command or plan, file responsibilities and any independence exception. A worker handling only a slice of a subtask must know what remains with other owners; its handoff does not complete the whole subtask.
- Assign one implementation owner per subtask and separate responsibilities among workers within it. Agree on shared interfaces before concurrent edits. Name one owner for shared files and serialize conflicting edits and live tests. Separate files alone do not establish independence. Preserve existing work and coordinate with its owner before taking it over.
- Freeze shared imported modules and their contracts before starting affected verification. Coordinate readers as well as writers: do not change a shared import, registry or schema while another worker's affected test is running or preparing to import it. Confirm that every affected writer has acknowledged a coherent, paused source before granting the test window; a queued message or a completed earlier test does not establish that pause. Distinguish releasing a test process from permission to resume source edits. Tell the test owner when the complete change is consistent and ready; join the original test before another edit or retry.
- Confirm each worker started and follow the worker check-in rules below. Workers must report blockers and cross-owner dependencies promptly and must not select another issue on their own. The coordinator resolves routine needs within the user's authorized scope.
- Review the actual changes and test results before accepting a subtask. Complete the parent's remaining integration, verification and review before closing it or unlocking dependent work. When a prerequisite is accepted, recheck Jira and dispatch the next eligible branch within available capacity.
- If a new dependency appears, safely checkpoint only the affected work, preserve its changes and owned processes, and use the blocker-extraction rule above. Independent eligible branches may continue. Do not widen a later task or bypass an unfinished prerequisite to keep workers busy.

## One session per Jira task

Use one dedicated implementation session for each Jira task. Name it `<ISSUE-ID> — <Jira summary>`, using the current Jira title. Create the session when the task becomes eligible under the epic-order rule, not for the entire backlog in advance.

- Reuse that session when resuming the same task. Check for an existing session before creating another.
- Do not repurpose a task session for another issue or leave a misleading old task name on it. Keep cross-task coordination in the orchestration session.
- Give review or implementation subagents bounded work within that session's issue or its linked subtasks. Identify both the parent and assigned subtask in their assignments. Keep this work coordinated within the parent session; do not create a duplicate implementation session for every worker or review. Workers do not independently advance to another task.
- When a task is complete or safely checkpointed, preserve its handoff in that session and its authoritative status in Jira. Start or resume the next eligible task in its own correctly named session.

## Worker check-ins and stalled work

The coordinating agent owns follow-through for every delegated task. Use both regular coordinator checks and worker reports; do not rely on either alone.

- While coordinating active work, check every active worker at least every five minutes, and before reporting its status or advancing dependent work. Prefer compact session or agent status reads. After dispatching work, confirm that the intended worker actually started.
- At assignment, tell workers to report a blocker, needed decision, missing dependency, failed verification, or cross-owner handoff promptly. At meaningful milestones, report the result, next action, and any help needed. Do not interrupt useful work for repetitive status messages.
- If progress appears stalled, inspect the latest work and the exact original process or session. Send one focused check-in asking what is running, what prevents progress, and what help is needed. Use the answer to resolve the blocker, provide a bounded handoff, or adjust the assignment within its accepted scope.
- An observation timeout, quiet output, or unchanged status does not prove a worker stopped. Recheck the same live handle; do not start duplicate work or replace an owner solely because a poll timed out. Resume interrupted or terminal work only after checking its actual state and retained resources.
- Give each verification attempt a distinct private log. Preserve failed or uncertain output; a later run must not overwrite it or be used to infer an uncaptured earlier cause.
- Act on worker requests without leaving them waiting unnecessarily. Coordinate shared files and serialized live tests explicitly. Record material blockers, review findings and outcomes in the owning Jira issue; routine check-ins need no separate log or tracker.
- Keep worker activity distinct from accepted completion. A running session, a worker's completion claim, or a successful subset of tests does not satisfy the issue's remaining acceptance criteria.

## CodeGraph code navigation

Use the local `codegraph-agentmux` MCP server for symbol, caller, dependency and code-flow navigation in this project. Its `codegraph_explore` tool reads the local index and watches for source changes. Subagents or clients without this MCP tool can use `/Users/ryan/.local/bin/codegraph explore --help` for the CLI equivalent from the repository directory.

Treat graph results as navigation, not proof that a Jira requirement is complete. Check relevant current source and test results when reviewing changed behavior, authorization or recovery. CodeGraph does not replace Jira task order or dependencies. Keep its generated `.codegraph/` index out of version control.

## Development work and review

[Jira project AMUX](https://adag-csai.atlassian.net/jira/software/c/projects/AMUX) is the sole authority for development tasks, acceptance criteria, dependencies, status, blockers and review outcomes. Migrate and reconcile all existing tasks and acceptance criteria into AMUX before removing the local tracker. Do not maintain a local task ledger or generated status board.

Before creating a decision task or reporting a blocker, check the accepted product decisions and later scope changes. Older open questions do not override accepted choices. For this migration, read `docs/planning/2026-10-09/delivery/decisions/acceptance.md` and the decision documents it accepts. The initial SDK languages are Python and TypeScript; do not report that choice as undecided. Preserve the difference between a design decision and an implemented or tested capability.

For catalog and skill tasks, expand referenced shared controls and evaluation gates from `docs/planning/2026-10-09/jev-coverage.json` into readable product requirements or links to their full requirements in the owning Jira epic. IDs alone do not preserve acceptance criteria.

Prefer one complete copy of repeated shared requirements in the owning epic, with direct links and the exact applicable criterion IDs in each task. Keep each task's own scope, acceptance criteria, exceptions and activation conditions complete. Read back the shared text and its task links; do not substitute an ID or local file path for the requirement.

Work on the explicitly assigned, bounded Jira issue and its acceptance criteria. Report blockers and review findings in that issue. Do not autonomously continue through all phases or create source-hash, evidence-bookkeeping or phase-advancement loops. Use focused tests, relevant integration tests and code review; follow [the local testing workflow](docs/LOCAL_TESTING.md). Do not add verification scaffolding or prepare new fixtures without task scope that calls for them.

All platform rearchitecture work stays on `feat/agentmux-platform-rearchitecture`. The current beta targets native macOS ARM64 only; Linux, macOS AMD64 and Windows/WSL are not qualified by that work. Do not run CI builds or verification; the existing CI prohibition remains in effect. Do not merge, squash, cherry-pick or transfer this work to `main` or another integration/release branch, enable automatic merging, or release it.

These changes concern development tracking and verification workflow only. Preserve product authorization, authentication, security, data retention, ownership, recovery and task-management behavior. Product requirements and issue acceptance criteria are not waived by removing development bookkeeping.
