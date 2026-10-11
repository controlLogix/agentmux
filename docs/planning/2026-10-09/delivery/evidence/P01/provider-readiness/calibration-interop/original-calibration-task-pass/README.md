# Original calibration task result

The actual Windows Codex worker passed the unchanged original calibration at candidate 36cc149. All E1-E6 checks passed. The task produced commit e33bd02f11a64f4f072ac9988c7b93984c9c7449 (add median), five passing tests, an independent empty-input ValueError check and a clean worktree. Read-only hub events identify the same worker for acknowledgement, claim and completion.

The original hub automatically handled the folder-trust prompt. No reviewer or worker supplied manual terminal input or completed the task for the model. Ordinary Windows-owned profile persistence is allowed; this run does not prove whether its trust decision changed the profile.

Final supervisor reporting is missing after tmux teardown. The successful task therefore has no final exact-job accounting or Windows config comparison. Known parent absence and no observed fixture processes are useful observations; they do not replace that missing record. No cleanup acceptance is claimed.

The allowlist excludes model pane reasoning, personal profiles, credentials, token files, hub database, client logs, SQLite and demo Git directories. The compact score retains all original checks and outcomes; archive.json records the original full report digest without copying its pane tails. All 67 runtime references match exact Git blobs at the candidate.

Team, crossrepo and swarm remain open and require a Windows-owned Grok credential source. This result does not pass P01-T04, the phase gate or P06 host integration.
