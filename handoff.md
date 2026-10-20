# Agentmux MVP handoff to Nick

Prepared October 20, 2026. Development work is checkpointed for transfer.

**Remove this file after you have read it, checked the current repository and Jira state, and actually resumed the assignment.** Include its removal in your next development commit. Keep ongoing task status, blockers and review outcomes in Jira; this temporary handoff is not a second tracker.

## Start here

1. Use `feat/agentmux-platform-rearchitecture` in `controlLogix/agentmux`. Check `git status` and the latest commit before editing. This handoff accompanies a large checkpoint of previously uncommitted source and tests; it is not a finished release.
2. Read `AGENTS.md`, `CLAUDE.md`, `.claude/rules/plain-language.md` and `docs/LOCAL_TESTING.md`. The user authorized this checkpoint commit/push. That does not authorize CI, merging or releases beyond development.
3. Connect through the official Atlassian Rovo MCP at `https://mcp.atlassian.com/v2/mcp`. Use your authorized account. Jira is the authority; read the current descriptions, dependency links and latest material review comments before resuming.
4. Start with [AMUX-725](https://adag-csai.atlassian.net/browse/AMUX-725), especially checkpoint comment **13687** and the evidence in comments **13676–13686**. Its implementation belongs to parent [AMUX-58](https://adag-csai.atlassian.net/browse/AMUX-58), in epic [AMUX-6](https://adag-csai.atlassian.net/browse/AMUX-6).
5. Confirm that you have sole implementation ownership. The previous implementation/review sessions are checkpointed, with all source/import/test/native holds released. Recheck this if another coordinator has resumed since this document was written.

## The approved MVP

Deliver and verify core orchestration for one user on one native macOS ARM64 Mac:

- Select a repository and enrolled profile.
- Run a real Codex or Claude coding agent in tmux. Codex is the client exercised so far; Claude has not been qualified by this work.
- Assign work through the existing durable Work queue; exchange and retain messages, progress and results.
- Validate the actual code change and test evidence, then explicitly complete the original Work item as its owner.
- Stop, resume or reconcile safely while retaining original operation, Work, attempt, session and generation identities.

Preserve authentication, current permissions/revocation, repository/profile isolation, retained data, uncertainty and owned cleanup. A worker's text, queue receipt, process exit or raw database state does not establish successful user-facing completion.

The user explicitly chose the **Work-queue MVP**. Full board/Task/run/reviewer-approval integration, new plugin/Process execution, public SDK completeness and broader platform work remain outside this first dev MVP unless an actual required flow proves a dependency. Do not restart full-epic completion.

## Remaining order

There are three known remaining MVP issues, with this dependency order:

1. **AMUX-725 — Complete installed first spawn registration and original-operation recovery.** In Progress and still blocking. Finish and accept its entire scope first.
2. [**AMUX-724 — Activate a declared first worker's own Work and message routes after registration**](https://adag-csai.atlassian.net/browse/AMUX-724). Backlog. Source/tests/docs largely exist, but native first-worker activation and access are not accepted. It waits for 725.
3. [**AMUX-699 — Qualify the core orchestration dev MVP on one native Mac**](https://adag-csai.atlassian.net/browse/AMUX-699). Checkpointed despite its In Progress status. Complete one real software task, actual messages/results, owner validation/completion and lifecycle recovery through normal installed commands. It waits for 724.

This is the known scope, not a guarantee that final integration will reveal no additional blockers. AMUX-721/722/723 are deferred broader-route work. Old links from them to 699 are explicitly superseded in the issue descriptions/comments; do not treat them as current Work-MVP prerequisites. AMUX-45 and other broader epic work are not accepted by this checkpoint.

## Exact AMUX-725 state

The latest reviewed functional candidate is `3809ddbc0362fba6d684fd41fff29b74f3186727799924468b7eeb0b778fb330`. Its installed/package/source match was verified before the last run.

The last normal installed run **failed** overall:

- Real Codex launch recovered successfully on the second identical call with its original operation ID and worker generation.
- Physical stop and the original retained state updates completed. The next stop call used the same ID and arguments and did not repeat the physical effect; retained records were unchanged.
- **Supported kill CLI confirmation still failed.** Do not substitute the completed database records for this missing result.
- The completed-only query repair removed the previously measured final-gate queue delay: maintenance admission was about 1 ms and transport acquisition about 8 microseconds in the measured replay.
- That request entered the final database/current check with **2.103979 seconds** of original validity left. The check spent about **2.9103 seconds**, then refused with `current-after-expired` at about **-0.806239 seconds**.
- This locates the remaining delay inside the final current/native check. It does not identify a particular internal native subcall as the cause. The completed-record snapshot comparison follows that check and was not reached on this refusal.
- The initial stop dispatch had already expired and is separate evidence. Do not retroactively assign these replay timings to older failed runs.

The original Hub exited successfully, all owned qualification processes/services/panes were joined or confirmed stopped, and the shared launcher was restored. No emergency cleanup was needed. The previous implementation owner and reviewer are idle and have released their holds. The historical driver's `qualificationComplete: true` means the spawn stage only; its failed overall exit and `original_kill_cli_reconciliation_unconfirmed` remain decisive.

Raw logs, test enrollments, selections and protected installations remain private on the original Mac. Jira comment 13687 locates them. They are not included in this public repository. Host-bound paths, native selections and credentials are not portable enrollment for Nick's machine.

## Next action for Nick

Use the smallest existing reproduction to diagnose the cost inside the final current/native check, rather than repeating full installed runs hoping for a pass:

- Follow `Hub._check_work_request_current` → `identify_qualified` → `_identify_native_core` in `hub/server.py`, and the actual helpers in `hub/native_core_context.py` and `native_security/`.
- Inspect complete ancestry, kernel peer, selected tool/image custody, tmux inventory and the cold non-connectable endpoint proof comparison before changing their execution. The last trace measures the combined check, not individual helper costs.
- Preserve the fresh full final classification, current source/grant/target checks, original five-second caller validity, selected envelope limit and signed validity minima. Do not renew a published proof, cache stale authority, infer identity from labels or extend deadlines to obtain a pass.
- Diagnose and repair the demonstrated responsible layer. If it needs a genuinely distinct missing owner contract, search/reuse or extract a bounded Jira prerequisite under the earliest affected task before widening implementation.
- Review the actual fix and affected callers, run focused expiry/refusal/replay/cancellation/cleanup checks, then use a matching reviewed package for normal installed qualification. Successful supported CLI reconciliation and joined cleanup are required before accepting 725 or starting 724.

## Source map and preserved repairs

- `hub/server.py`: selected native request admission, late source verification, authenticated dispatch, physical lifecycle ownership, current/final reply checks and bounded private timing samples.
- `capability_owner/work_maintenance.py`: exact-parent admission reservation; release before physical work; original phase records; fair foreground final check; completed-only parent query; exact target/source/metadata/state/lifecycle validation.
- `capability_owner/work_lifecycle_client.py`: current signed inspect and original outcome query; completed-only reload while preserving the ordinary execution path.
- `hub/core_endpoint.py`: removal of a redundant preliminary native kill source read. The required source verification after identity remains.
- `capability_owner/first_worker.py`: retained AMUX-724 implementation; not yet accepted native integration.
- `docs/PLATFORM_INSTALLATION.md`: supported installed preparation, profile/repository selection, commands and recovery instructions.

Relevant tests include `test_completed_kill_query.py`, `test_hub_kill_recovery.py`, `test_kill_admission_turn.py`, `test_kill_final_turn.py`, `test_kill_reply_timing.py`, `test_native_kill_preflight.py` and `test_native_work_scheduling.py` under `capability_owner/`.

The completed-only recovery path makes a **current** signed inspect/outcome query on the original parent admission turn, without a physical child, callback or state write. It keeps the original validity minimum and rechecks exact completed records/target on the final Store worker after native classification. Incomplete, uncertain, conflicting or still-active originals retain their existing handling. No generic child reentrancy was added.

Focused runs and independent reviews are recorded in Jira. Keep their scope accurate: a latest custody batch had 17 passes and one registration-setup error (`capability_resource_stale`) before that kill case ran; its isolated uncertainty/reconstruction case passed. The isolated pass does not explain or erase the batch setup error. Earlier failed logs remain separate. Component tests do not establish installed or MVP completion.

## Environment and working rules

- Qualify only native macOS ARM64. Use existing prepared runtimes and dependencies; inspect `docs/LOCAL_TESTING.md` before setup or tests. Missing tools are not passing results, and downloading tools needs an applicable existing authorization.
- The original machine used packaged CPython 3.14.4 and its prepared dependencies, native NATS 2.15.0, nsc, and pinned native tmux/Codex tools. Resolve paths and admit tools for the receiving machine; do not copy another machine's protected registrations or enrollment secrets.
- Use the CodeGraph MCP for source navigation. Its generated `.codegraph/` index is local and ignored. Graph results are navigation, not proof of acceptance.
- Keep Jira authoritative. Fix release blockers; record safe optional improvements as linked open `post-initial-release` issues. No local task ledger, generated advancement gate, broad unrelated test batch or mandatory pattern registry is needed.
- Use one implementation session for the owning Jira task and bounded reviewers/subagents for its eligible subtasks. Check prerequisites before delegation, separate file ownership, serialize shared imports/live fixtures, confirm workers started, and check active workers at least every five minutes.
- The local-helper instruction-cap failure previously produced no run ID. Do not blindly relaunch it or truncate instructions. This native identity/authorization repair is lead-owned with independent review under the recorded security-boundary exception.
- Keep exact original process/future handles through wait/output completion. A CLI timeout does not prove server work stopped. Preserve failed logs and uncertainty; never start a replacement solely because observation timed out.
- The existing reviewed qualification driver allows four total identical calls per original operation within 180 seconds. It stops on explicit refusal, preserves IDs/arguments, joins the original Hub/services and restores the shared launcher. Inspect its exact recovery-format handling before reuse.
- Shared launcher changes can affect existing registrations. Use the documented owned test window and restore the original launcher on success or failure. If unresolved emergency cleanup is truly needed, join the original Hub first, then revalidate only the exact owned resource; emergency cleanup is not a qualification pass.
- The web UI shown during development was an auto-refreshing **disconnected preview**, not evidence of a connected or usable MVP.

After revalidating ownership, current Jira state and the receiving environment, resume AMUX-725 and remove this handoff file as requested.
