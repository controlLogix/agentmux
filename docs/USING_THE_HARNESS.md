# Using the harness

For the opt-in macOS ARM64 platform runtime, see [installation](PLATFORM_INSTALLATION.md) and [local startup diagnostics and recovery](BOOTSTRAP_RECOVERY.md). The board commands below use the existing harness.

One page, start to finish: put work on the board, give it to agents, watch it, and
get it back. Everything here was executed against a live board while it was written,
and the scenario sweeps that prove each section are named at the end.

If you read nothing else: **the board refuses things on purpose, and every refusal
tells you the command that fixes it.** A refusal is the harness working. Read it.

```
$ agentmux task done TM-014
coordination: TM-014 cannot close: missing evidence
  fix: agentmux task evidence TM-014 <path-or-url>
```

---

## 1. Start the board

```bash
cd /mnt/c/Dev/agentmux
bash <(tr -d '\r' < dashboard/restart.sh)      # http://127.0.0.1:8787
```

`--fresh-db` comes up empty and moves the old database aside into
`cc.db.aside-<stamp>/` rather than deleting it. The dashboard and the CLI are two
views of the same store, so anything below can be done from either.

Point the CLI at a different board with `AGENTMUX_DASHBOARD=http://127.0.0.1:PORT`.
That is how the scenario sweeps test against a throwaway board without touching
yours, and it is the safe way to try anything you are unsure of.

## 2. Put work on it

```bash
agentmux epic new "Machine survey" --active
agentmux task new "Catalog every local project" \
  --type story --body "what and why" \
  --ac "the catalog is written" --ac "a pointer exists in CLAUDE.md"
```

**Why a body and criteria are not optional.** They are what an agent is briefed
from, and what a reviewer checks against. A card with neither cannot be handed to
anybody, so the board refuses it at creation rather than letting you discover that
later. The gates are configurable (`requireOnCreate`, `requireOnStart`,
`requireOnDone`) but the defaults are the useful ones.

The card also decides **how big a team it gets** — see §5.

## 3. Move it

```bash
agentmux task start TM-014
agentmux task ac TM-014 --tick 1
agentmux task evidence TM-014 dashboard/test_board.py
agentmux task done TM-014
```

| You will be refused when | Because |
| --- | --- |
| starting a card with no body or criteria | nothing to brief an agent from |
| starting one while `wipLimit` cards are already in progress | park or finish one first |
| starting one whose blocker is still open | `agentmux task dep` recorded it |
| closing with a criterion unticked | `requireAcceptance` |
| closing with no evidence or no actor | `requireOnDone` |
| **blocking or parking with no `--reason`** | "stopped" is not information |

That last one is new. `blocked` and `parked` are the two statuses whose entire
content is the reason, and it used to be optional — a card could sit on the board
saying blocked with nothing anywhere saying what would unblock it.

The status shorthands are `start`, `done`, `block`, `park`, `todo` and `backlog`;
`agentmux task block TM-014` without a reason is now refused rather than silently
leaving the card mute.

```bash
agentmux task block TM-014 --reason "waiting on the licence server"
```

## 4. Claim before you edit

Binding the moment two agents are running. A claim is an `O_EXCL` file, so a race
has exactly one winner; a message asking nicely stops nothing.

```bash
agentmux claims                                  # who holds what, right now
agentmux claim taskmgmt/run.py --note "adding backoff"
agentmux release taskmgmt/run.py
```

Refused tells you the holder, their note and when it expires — talk to them. Leases
expire (default 1800s) so a dead agent frees its work. **Split work by FILE**, so two
agents cannot want the same claim. Releasing something nobody holds is a no-op, not
an error.

## 5. Give it to a team

These five reach the board through `agentmux` as of this pass. On an older
checkout they answer `unknown command` and have to be run as
`python3 taskmgmt/coordination.py recruit TM-100`.

```bash
agentmux recruit TM-100                 # the board proposes a roster
agentmux approve TM-100 --member catalog-lead --member scan-dev
agentmux hire TM-100 --name catalog-lead     # spawns a real tmux pane
agentmux roster TM-100
```

**The card sizes the team.** `choose_roster` reads the card: distinct top-level
`touches`, whether it is a story, how many acceptance criteria — then caps at
`teamMaxWorkers`. A four-agent team is a lead plus three workers, so that setting
must be at least 3. Workers are ranked by the capabilities the lead does not cover,
and then by the card's own labels, so label the card with what it is about and give
your definitions matching `capabilities`.

Two settings gate hiring, both off by default and deliberately:

```bash
agentmux board config dashboardMayHire true    # what actually spawns panes
agentmux board config dispatchEnabled true
```

`teamRequireApproval false` makes recruiting approve as it proposes — one step
instead of two. It is on by default, and approval is a real decision: `hire` only
ever accepts an approved row.

**Taking a team off** — including from a finished card, which is exactly when you
want to:

```bash
agentmux retire TM-100 --member scan-dev --member catalog-lead
```

It refuses a member whose pane is still running, and names the pane to kill. Kill it
first; off the roster but still running is not retired, it is abandoned.

## 6. Watch it, and unstick it

```bash
agentmux list                      # every pane, its CLI, its posture
agentmux read tm-100-lead --lines 40
agentmux attach tm-100-lead        # or the Terminals view at :8787
```

**When a pane stops responding, it is usually a modal.** Every provider shows them —
codex nags about updates and asks about directory trust, claude shows three dialogs
in a row on a fresh pane. `send` refuses to type into one, because Enter would
actuate whatever is highlighted, and the highlighted option is routinely hostile:
codex preselects *"Update now (runs npm install -g)"* and claude preselects
*"No, exit"*, which kills the agent.

```bash
agentmux unblock --dry-run         # what it would press, and why
agentmux unblock                   # answer every pane it can
```

It answers only prompts it can positively identify, always with the option that
declines or keeps the current state. Everything else it leaves alone and says why:

```
tm-100-lead    NEEDS A PERSON - a consent decision, and its default is "No, exit"
               look:   agentmux read tm-100-lead --lines 12
               answer: agentmux key tm-100-lead <Escape|Down|Enter|2>
```

Answer those yourself with `key`, which sends no implicit Enter. `key` takes tmux key
names (`Enter`, `Escape`, `Down`) or a single character for a numbered menu
(`agentmux key tm-100-lead 2`). **Never `send` at a modal** — it appends Enter.

## 7. Talk to them

```bash
agentmux courier start                              # once; queueing is not delivery
agentmux post scan-dev --kind request "start with /mnt/c/Dev"
agentmux inbox                                      # replies to you, the orchestrator
```

You are `orchestrator` and have no pane, so replies land in
`~/.agentmux/inbox/orchestrator.jsonl`. Tell agents to reply with
`agentmux post orchestrator --kind reply '...'`. A recipient showing a modal is
retried, never forced, and dead-lettered after five attempts rather than dropped.

## 8. Runs, and who is allowed to say "done"

A run is the reviewed unit of work: a worker submits, a **different** agent verdicts,
and nothing completes until every job is verified.

```bash
agentmux run start "rewrite the parser"
agentmux run assign <run> --worker dev --reviewer rev --task TM-014
# the next two are typed BY those agents, in their own panes
agentmux run submit <run>/1 --files taskmgmt/run.py
agentmux run verdict <run>/1 --pass --reason "matches the brief"
agentmux run status <run>
agentmux run complete <run>
```

**You never type who you are.** `--by` is taken from `$AGENTMUX_AGENT` and passing it
is refused, the same way `agentmux task` refuses `--agent` and `agentmux claim`
refuses `--holder`. Identity is a property of the pane, not an argument — a `--by` the
caller can set is "a worker cannot mark its own homework" with its one input handed to
the worker. `submit` and `verdict` are run by the worker and the reviewer, each in
their own pane; `assign` names them, and that naming is what the check compares
against.

- A worker **cannot verdict its own job**, and only the named reviewer can verdict it.
- **A rejection needs a reason.** A `--fail` with nothing to act on burns an attempt
  against `MAX_ATTEMPTS` and tells the worker nothing. A pass needs none.
- `--force` exists for a run whose agents died. It is a person's call.

### The one distinction worth understanding

**A person at a terminal is the approval.** You may complete a verified run without
approving it in the browser first — being there is the approval. What still refuses
you is a decision you *made* and then defied: if you recorded "changes requested",
completion is refused until you record a new decision, and `--force` will not
override your own objection.

**A warranted orchestrator must have an explicit approval.** It wrote the brief the
reviewer checked against, so a passing review only says the job matched the brief —
it cannot say the brief was right. If the orchestrator misread what you wanted, every
job passes and the run is still wrong, and you are the only one who can catch that.
So it is refused until you approve in the Runs view, and `--force` is not available
to it at all.

**An approval pins bytes.** Change an approved file afterwards and completion is
refused, naming the files that drifted — an approval that covered different bytes was
never an approval of this.

## 9. Finish

```bash
agentmux kill --all                 # panes
agentmux retire TM-100 --member ... # roster
agentmux board config dashboardMayHire false
```

Turn hiring back off. It is the setting that lets anything with socket access spawn
an unrestricted agent.

---

## When something looks wrong

```bash
agentmux board doctor            # what the board thinks is wrong with itself
agentmux read <pane> --lines 40  # what the agent actually sees
agentmux claims                  # whether two agents are on one file
agentmux courier status          # what is queued and why it has not arrived
bash <(tr -d '\r' < dashboard/run_tests.sh)      # the whole gate, ~25 min
```

A suite that reports `passed N, failed 0` has checked something. One that reports
`SKIP` has said why it checked nothing. Both are answers; silence is not.

---

## What proves this page

| Section | Sweep |
| --- | --- |
| 2, 3 — creation, movement, every gate | `scen1_gates.sh` (45 checks) |
| 5 — roster, approval, hiring gates, config validation | `scen3_approval.sh` (28) |
| 8 — run lifecycle, reviewer separation, rejection reasons | `scen4_runs.sh` (24) |
| 8 — person versus orchestrator, drift | `scen5_gate.sh` (11) |
| 3, 4 — hostile input, boundaries, claims | `scen6_edges.sh` (48) |
| 6 — which modals may be answered, and which may not | `dashboard/test_modal_guard.sh` |
