# Frozen contracts: agent definitions, rosters and teams

Every parallel task in this build implements against this file. It is frozen before
any pane starts, because parallel work against an unwritten API diverges and the
divergence is only discovered at integration, which is the most expensive moment to
find it.

Changes follow the owning Jira issue and its accepted product decisions. This file
describes the compatibility contract; it is not a separate approval authority.

Architecture: https://claude.ai/artifact/TDiV2FDxYyzs9kdeTtdn4P

## Amendments

If you read this file before an entry below, re-read the section it names.

| When | What changed | Why |
| --- | --- | --- |
| 2026-10-16 | **C1/C3/C4/C7/C8**: explicit project lead proposals, saved roster definitions, revision warnings and additive migration. | [AMUX-41](https://adag-csai.atlassian.net/browse/AMUX-41) preserves imported definitions and approved teams while adding project selection. |
| 2026-09-23 | **C5**: the pane-name suffix is the ROLE, not the agent name. **C1**: `name` allows hyphens (`^[a-z][a-z0-9-]{0,63}$`); `description` cap raised 280 → 2048. | The original banned hyphens in names so the suffix could carry one, but four of the five definitions that must load unchanged are hyphenated, and `hr-recruiter`'s description is 320 characters. The two acceptance criteria contradicted each other. Found by the TM-040 worker, which blocked the card rather than guessing. |

---

## C0 — The rule that is not about code

`taskmgmt/coordination.py` reaches the board over **HTTP at `$DASHBOARD`**
(127.0.0.1:8787), not by opening `cc.db`. `dashboard/run_tests.sh` repoints the live
server's `AGENTMUX_HOME` at a temporary directory for the duration of the suite and
restores it in an EXIT trap.

**Therefore: no board command may run while the gate is running.** A `task-new` issued
during a suite lands in a store that is deleted minutes later, and reports success while
doing it. Run the gate, let it finish, then touch the board.

**A dispatched worker must NOT run the full `run_tests.sh`.** This is not a style
preference. The suite repoints the *live, shared* server, so one worker running it
blacks out the board for every other worker and for the orchestrator at the same time —
`tasks` reports "no open tasks", a known epic reports "not found", and a `task-new`
silently lands in a store that is about to be deleted. Nothing warns you; it simply looks
as though the board lost your work.

Run **your own suite** instead — `bash <(tr -d '\r' < dashboard/<your-suite>.sh)` or
`python3 dashboard/<your-suite>.py` — and attach that as evidence. The orchestrator runs
the full gate, once, after collecting the wave. If your card's acceptance says "the full
gate is green", that criterion is the orchestrator's to verify, not yours.

---

## C1 — `taskmgmt/agentdefs.py`

Stdlib only. **No PyYAML**: the repo declares no Python dependencies anywhere (no
`requirements.txt`, no `pyproject.toml`, no `setup.py`) and every module is stdlib. The
frontmatter schema below is kept flat so a small hand-written parser is sufficient, and
`server.py` must never gain an import that can fail on a fresh machine.

```python
SCOPES = ("claude", "global", "repo")   # ascending precedence for DISCOVERY only

@dataclass(frozen=True)
class AgentSpec:
    name: str                       # ^[a-z][a-z0-9-]{0,63}$  -- hyphens ARE allowed, see C5
    scope: str                      # one of SCOPES
    path: str                       # absolute path of the .md it came from
    description: str                # <= 2048 chars, single line (no newlines)
    cli: str                        # ccboard.CLI_RE: ^[A-Za-z0-9_-]{1,32}$
    model: str | None
    auth: str | None                # a method id from dashboard/auth.json, NEVER a credential
    posture: str                    # "read-only" | "workspace-write" | "unrestricted"
    tools: tuple[str, ...]          # claude-only; degrades with a visible warning
    tools_deny: tuple[str, ...]
    persona: str                    # the markdown body; <= 4096 (must fit BRIEF_MAX 8192)
    role: str                       # "lead" | "worker" | "reviewer" | "researcher"
    capabilities: tuple[str, ...]   # <= 16 tags, ^[a-z][a-z0-9-]{0,23}$
    worktree: str                   # "per-member" | "integration" | "none"
    max_instances: int              # 1..8
    checksum: str                   # "sha256:<hex>" of raw file bytes -- drives 409 on stale write

def load_all(repo_root=None, *, home=None, global_root=None) -> tuple[dict[str, AgentSpec], list[dict]]:
    """Never raises. problems: [{"path", "scope", "error"}]."""

def resolve(name, repo_root=None, *, home=None, global_root=None) -> AgentSpec | None
def choose_roster(task, specs, cfg, cli_override=None, *, dependencies=None,
                  approved_lead=None) -> list[AgentSpec]   # lead first
```

The definition domain adapter in `taskmgmt/definition_team.py` wraps this parser.
`DefinitionPlugin` requires explicit project, home and global roots. Its versioned
manifests retain every `AgentSpec` field, exact original source bytes, path, scope
and source checksum from the same checked read. Package identity and optional parent
package identity are explicit; they do not authorize a definition. Import diagnostics
remain available, including unsupported keys. Legacy callers retain their process
root defaults through `load_all`.

`toolIntent` reports requested and denied tool names separately from names a host can
enforce. With no host support supplied, all named tool restrictions are advisory.
Host support does not grant permission. Existing `tools` and `tools_deny` fields stay
unchanged; CLI arguments alone are not proof of an effective security boundary.

### Search order

1. `<repo>/.agentmux/agents/*.md` — tracked, committed with the code
2. `~/.agentmux/agents/*.md` — machine-local
3. `<repo>/.claude/agents/*.md`
4. `~/.claude/agents/*.md`

`*.md` only — this deliberately does not match the `*.md.bak_*` files already sitting in
`~/.claude/agents/`.

### Collisions are a hard error in every scope

A name defined twice anywhere makes **both** entries unusable and produces one
`problems` row naming both paths. There is no shadowing and no nearest-wins.

Verified free at the time of freezing: `~/.claude/agents/` holds five definitions
(hr-recruiter, plc-dev, plc-test-engineer, scheduler, senior-reviewer) and no other scope
directory exists. Nothing to rename.

### Frontmatter is flat, and compatible with `.claude/agents`

```markdown
---
name: reviewer
description: Reads a diff and finds what is wrong with it. Never edits.
role: reviewer
cli: claude
posture: read-only
tools: Read, Grep, Glob, Bash(git diff:*)
tools-deny: Write, Edit, NotebookEdit
capabilities: review, security
worktree: none
---

You review, you do not fix...
```

`tools` is a **comma-separated string**, exactly the shape `~/.claude/agents/*.md`
already uses — not a nested `tools.allow`/`tools.deny` map. That is what keeps a stdlib
parser honest and makes the existing five definitions load unchanged.

### Defaults

`role` → `worker`. `cli` → board `dispatchCli`. `auth` → the CLI's active method.
`model` → CLI default. `worktree` → `per-member` for workers, `integration` for leads.
`max_instances` → 1. `capabilities` → empty.

**`posture` → `workspace-write`**, deliberately *not* today's `unrestricted`: a definition
that says nothing should tighten, never loosen.

### Validation philosophy

Allowlist the declared keys and **name every rejection**. An unknown key still loads the
file, with the key listed in `problems`; a bad `name` or a missing `description` does not
load and lands in `problems` with its path and reason. Both reach the UI verbatim. This
follows `applyTheme` (`app.js:2057-2093`): a half-defined thing that silently inherits is
harder to debug than one that fails visibly.

### Hardening

These files are read by a server and rendered in a browser. 64 KiB per file; `*.md` only;
`Path.is_file()` and reject symlinks (the posture `read_field()` takes at
`server.py:817`); cap the directory listing at 200 files; reject control characters in
every string field; **the filename stem must equal `name`**, or the collision check is
bypassed by naming two files differently.

---

## C2 — `GET /api/board/agents`

```json
{"agents": [{"name": "reviewer", "scope": "repo", "description": "...",
             "cli": "claude", "model": null, "auth": null,
             "posture": "read-only", "tools": ["Read", "Grep"], "tools_deny": ["Write"],
             "role": "reviewer", "capabilities": ["review"], "worktree": "none",
             "max_instances": 1, "path": "/abs/path.md",
             "checksum": "sha256:...", "editable": true}],
 "scopes": ["claude", "global", "repo"],
 "problems": [{"path": "/abs/bad.md", "scope": "global", "error": "unknown key 'tool'"}],
 "count": 7}
```

**`persona` is not in the list payload.** Bodies are stripped from lists everywhere else
on this board. Editing fetches it with `GET /api/board/agents?name=<n>`.

`editable` is false for `scope: claude` — those files belong to Claude Code and agentmux
only reads them.

---

## C3 — `choose_roster` lives in `agentdefs.py`, not `dispatch.py`

It is pure selection over specs with no dispatch state. Keeping it here is what allows
the whole of stage 1 to be built without claiming `taskmgmt/dispatch.py`, which is the
critical-path file for stages 2, 5 and 6. `dispatch.py` imports it.

**Stage-1 contract:** with no definitions on disk, `choose_roster` returns exactly one
spec whose `cli` resolves identically to today (`cli_override or cfg["dispatchCli"] or
"codex"`). That is what makes the first wave shippable with zero behaviour change.

**Project lead selection:** discovered lead definitions never win by alphabetical
order. `approved_lead` supplies the selected definition to the pure rule function.
The legacy board proposes a deliberate `lead` name through recruitment, then uses the
existing approval action. With no explicit name, recruitment keeps its approved lead
snapshot when available, otherwise the existing built-in compatibility lead. That
fallback carries a visible gap; it does not approve a discovered persona. A different
lead or changed lead revision cannot replace a hired lead until it has been stopped
and retired. A legacy hired lead without a saved definition also requires retirement
before replacement.

The team domain adapter has a stricter boundary: without an approved project lead
reference, it returns no members and an approval-required gap. It admits only explicit
project definition revision references before running the existing deterministic
rules. References bind both the source checksum and all resolved definition fields,
so changes to CLI/model/auth defaults cannot silently reuse an old approval. This
eligibility step does not depend on Jev ranking.

The existing board and dispatcher run through `TeamPlugin.propose_legacy`, which
returns the existing list-compatible `Roster` and gaps unchanged. Recruitment and
dispatch, including reconstruction of a saved compatibility lead, use this production
boundary. It may propose discovered workers; it does not mark them approved. The
board keeps its existing approval policy and saved-definition transaction. This
legacy path is separate from `TeamPlugin.propose` and its strict approved-revision
inputs. Remove it only after those legacy consumers have migrated to a scoped
project approval service and the preserved proposal and dispatch checks pass. Do
not silently replace legacy discovery with approval or relax the strict method to
accommodate legacy callers.

**Stage-2 contract:** selection remains pure and deterministic, returns the lead
first, and recruits available definitions using existing card fields. A `Roster`
is list-compatible (dispatch can continue taking `[0]`) and carries a `gaps` list.
No card or definition fields are added.

- Distinct top-level directories in `touches` request one worker each (root files
  do not create directory requests); the minimum is one worker. Five or more
  `acceptance` entries add one. Stories and spikes request at least two workers;
  spikes may use researcher definitions as workers.
- Bugs request one worker and one reviewer, taking precedence over directory and
  acceptance sizing. Reviewers count toward `teamMaxWorkers`, as do all non-leads.
- Labels are exact capability requirements, including unknown labels: every label
  must be covered or reported as a gap. Workers rank by uncovered label matches,
  then name. Additional matching specialists can fill remaining configured slots.
  This deliberately treats workflow labels as requirements too, rather than
  silently guessing which unknown tags are irrelevant.
- A `blockedBy` path of three or more edges is deep. The board passes an optional
  dependency adjacency map to the selector; traversal is cycle-safe and stops at
  this threshold. Deep chains request only one worker (plus a reviewer for bugs)
  and never widen for labels. They prefer senior definitions before capability
  count. With no seniority field, the explicit proxy is a `senior`, `expert`, or
  `principal` capability tag or hyphen-delimited name component; name breaks ties.
- The configured `teamMaxWorkers` (default two, range zero through eight) caps all
  non-leads. Each definition is selected at most once, which is also within its
  `max_instances`: board roster identity is unique by `(entity_key, agent_name)`.
  Values above one do not permit duplicate roster rows or invented aliases.
  Unfilled role requests and uncovered capabilities report gaps, including when
  a cap prevents coverage. This is proposal sizing, not global running-instance
  accounting. Empty definitions still return exactly the stage-1 fallback lead.

`recruit` stores diagnostics in its existing history detail alongside member names;
`roster`, `approve`, and `hire` responses return the saved proposal's `gaps`. Reads
therefore do not drift with definitions or card edits. Re-recruitment refreshes
both rows and diagnostics; identical retries preserve history and proposal IDs.
The Teams view renders gaps as text beside the proposed members, before approval.

---

## C4 — Board ops

All must match `^[a-z]{1,16}$` — one lowercase word, no digits, no hyphens. **`/api/agents`
is already taken** by the live pane snapshot at `server.py:1887`, so definitions live
under `/api/board/<op>`.

| op | verb | body / query |
| --- | --- | --- |
| `agents` | GET | `?name=<n>` optional (adds `persona`) |
| `roster` | GET | `?id=TM-042` |
| `agentdef` | POST | the full definition + `checksum` of the version being replaced |
| `agentdrop` | POST | `{scope, name}` |
| `recruit` | POST | `{id, actor, lead?}` — a deliberate lead proposal |
| `approve` | POST | `{id, actor, members: [...]}` |
| `hire` | POST | `{id, name}` — **and nothing else**, see C8 |

The definition and team CLI surface for skills is `python3 taskmgmt/coordination.py`:

```text
agents [NAME] [--json]
agentdef SCOPE NAME [--description TEXT] [--cli CLI] [--model MODEL]
         [--auth AUTH] [--posture POSTURE] [--role ROLE] [--worktree MODE]
         [--tools [TOOL ...]] [--tools-deny [TOOL ...]]
         [--capabilities [CAPABILITY ...]] [--max-instances N]
         [--persona TEXT] [--checksum CHECKSUM] [--json]
agentdrop SCOPE NAME [--checksum CHECKSUM] [--json]
roster KEY [--json]
recruit KEY [--lead NAME] [--agent ACTOR] [--json]
approve KEY --member NAME [--member NAME ...] [--agent ACTOR] [--json]
hire KEY --name NAME [--json]
```

The definition commands map directly to the three definition ops above; `agents NAME` URL-encodes
`name` and returns the full definition including persona and checksum. `agentdef`
creates or **replaces the full definition**, not a partial update: send all desired
fields and the fetched checksum when editing. Omit checksum for creation. List flags
accept separate arguments (not comma-separated strings); a flag with no values sends
an empty list. `--tools-deny` and `--max-instances` map to `tools_deny` and
`max_instances`. `agentdrop` optionally guards deletion with a checksum.
All three default to human-readable output; `--json` emits the unmodified API payload
on stdout. Refusals exit nonzero and print the board's message and fix hints on stderr
through `board_call`. Validation stays on the server. These are coordination.py
subcommands; they do not require an `agentmux agent` shell wrapper.

The team commands map directly to their four board ops. `roster` URL-encodes `id`;
`recruit` and `approve` send the resolved pane/orchestrator identity as `actor`.
`recruit --lead NAME` deliberately proposes an available lead definition; the Teams
view offers the same choice with an empty default, followed by the existing approval
step. Omitting it preserves the existing compatibility path, never selects the first
discovered lead. These legacy actor labels are attribution, not authenticated HTTP
user identity.
Repeat `--member` for each approved definition name. `hire` sends only `id` and
`name`: no cli, cwd, model, argv, or actor overrides are exposed. All four default
to a readable roster; `--json` preserves the API payload. Every refusal goes
through `board_call`, including the board's 403 hiring explanation and 409 fix
hints, with nonzero exit and no retry or configuration workaround.

Handlers delegate from `server.py` into `dashboard/boardagents.py` and
`dashboard/boardteams.py`. `server.py` holds delegation lines only, no logic.

---

## C5 — Worker naming

```python
ROLES = ("lead", "worker", "reviewer", "researcher")   # closed vocabulary, no hyphens
WORKER_RE = re.compile(r"(ep|tm|adr|sp|cap)-[0-9]{3,9}(?:-([a-z][a-z0-9]{0,15}))?")

def worker_name(key) -> str                  # "tm-042"            -- the LEAD, unchanged
def member_name(key, role, ordinal=1) -> str # "tm-042-reviewer", "tm-042-worker2"
def key_of_worker(name) -> str | None        # "TM-042"
def role_of_worker(name) -> str              # group(3) minus any ordinal, or "lead"
```

**The suffix must start with a letter.** Without that, `tm-042-7` is ambiguous with card
key `TM-0427`, and `key_of_worker` silently attributes a member to the wrong card.

**The suffix is the ROLE, never the agent name.** *(Amended — the original contract made it
the agent name and therefore banned hyphens in `AgentSpec.name`. That was wrong: four of
the five definitions this build must load unchanged are hyphenated — `hr-recruiter`,
`plc-dev`, `plc-test-engineer`, `senior-reviewer` — and since the filename must equal the
name, no normalisation could satisfy both. Caught by the TM-040 worker before anything was
built on it.)*

Roles are a closed vocabulary with no hyphens, so the grammar stays unambiguous while the
name is free to look like a Claude Code agent name, which is the point of reading that
roster at all. Two members sharing a role take an ordinal: `worker`, `worker2`, `worker3`.

The cost is that a pane name no longer says *which definition* it is running, only what
part it plays. That is recoverable two ways and neither is a guess: `board_roster` maps
`member_name` to `agent_name`, and the pane writes its own `run/<name>.agentdef` sidecar.

`.` is forbidden throughout: tmux reads it as a target separator (`agentmux.sh:464`).
Longest name `tm-999999999-researcher` is 23 characters, inside the 64 limit.

---

## C6 — Namespaced claims

```python
def claim_resource(worker: str, path: str) -> str:
    return f"{worker}/{path}"        # path-shaped. NOT "worker::path".
```

**Verified:** `coordination.RESOURCE_PATTERN` is `[A-Za-z0-9_./-]{1,200}` — a colon is
**rejected**, `..` is refused, and `/` is already legal. So a worktree-namespaced claim
validates with **zero changes to `coordination.py`**. `flatten()` turns it into
`tm-042-reviewer%2Fdashboard%2Fapp.js`.

`len(worker) + 1 + len(path)` must stay ≤ 200.

Division of responsibility:

- The **lead** claims the card's full `touches` set **unnamespaced**, exactly as today, so
  `dispatchable()`'s greedy disjoint pass (`ccboard.py:1665`) and `busy_paths()` (`:1677`)
  keep computing over the same namespace and the queue math does not regress.
- **Members** claim inside their own worktree namespace.
- Anything **outside** a worktree (`~/.agentmux`, shared state) is claimed unnamespaced by
  every member, preserving cross-team protection.

Note `coordination.py claim` takes **one resource per invocation**. All-or-nothing is
`dispatch.claim_for`'s rollback loop (`dispatch.py:249`), not a property of the CLI — a
pane claiming by hand must roll back its own partial set.

---

## C7 — `board_roster`

```sql
CREATE TABLE IF NOT EXISTS board_roster (
    id INTEGER PRIMARY KEY,
    entity_key  TEXT NOT NULL,                     -- TM-042
    agent_name  TEXT NOT NULL,                     -- AgentSpec.name
    role        TEXT NOT NULL,                     -- lead | worker | reviewer | researcher
    position    INTEGER NOT NULL,                  -- lead is 0
    status      TEXT NOT NULL DEFAULT 'proposed',  -- proposed|approved|rejected|hired|finished
    member_name TEXT,                              -- pane name, set at dispatch
    worktree    TEXT, branch TEXT,
    proposed_by TEXT, approved_by TEXT, approved_at TEXT,
    at TEXT NOT NULL, updated_at TEXT);

CREATE UNIQUE INDEX IF NOT EXISTS board_roster_slot   ON board_roster(entity_key, agent_name);
CREATE INDEX        IF NOT EXISTS board_roster_entity ON board_roster(entity_key, position);
```

Keyed on `entity_key` alone, matching every other `board_*` child table
(`ccboard.py:193-216`) — that is how a new record type inherits labels, comments, history
and evidence for free. Goes in `NEW_TABLES`; `migrate()` (`:256`) picks it up unchanged.

AMUX-41 adds one table without rewriting existing roster rows:

```sql
CREATE TABLE IF NOT EXISTS board_roster_definitions (
    roster_id INTEGER PRIMARY KEY REFERENCES board_roster(id) ON DELETE CASCADE,
    project_root TEXT NOT NULL,
    spec_json TEXT NOT NULL);
```

Recruitment saves the exact resolved definition, including its persona, with schema
version `1.0.0` and the canonical project root. Approval retains this snapshot;
definition edits never refresh it. Re-proposal removes snapshots belonging to replaced
non-hired rows and keeps hired rows and their snapshots. Snapshot JSON is private and
never appears in roster list responses.

Public rows expose `definitionRevision` with name, scope, path, source checksum,
project root and a digest of all saved fields. `definitionState` reports `current`,
`changed`, `unavailable`, `builtin` or `approval_required`. Teams and human CLI output
explain changed or unavailable sources while retaining the saved revision. Dispatch
uses only an approved lead with the same project and full resolved revision; changed
or unavailable imported leads require deliberate recruitment and approval again.

Existing rows keep their IDs, approvers, timestamps and history. Migration does not
invent an old definition snapshot. A row without one cannot be hired: recruit and
approve again before hiring. A hired legacy row must first follow the existing stop
and retire flow. Do not repair this by copying the current file into an old approval.

Every transition goes through `_record()` (`:383`) so approval lands in `board_history`.

`tasks.worktree` / `tasks.branch` (`ccboard.py:240`) stay scalar and keep naming **the lead
only** — `in_flight()` keys on `tasks.agent IS NOT NULL` and widening it would force
`collect_all`, `doctor`'s over-WIP warning and the dashboard to change together.

---

## C8 — Spawn flags, sidecars, and the hire bound

```
agentmux spawn <name> --cli C --cwd D [--model M] [--auth A]
                      [--agentdef NAME] [--posture read-only|workspace-write|unrestricted]
                      [--persona-file PATH] [--tools CSV] [--deny-tools CSV]
                      [--team TM-042] [--role lead|worker|reviewer|researcher]
```

```python
FIELDS = ("cli", "perms", "cwd", "launch", "started", "task", "auth",
          "agentdef", "posture", "team", "role")      # server.py:84
```

Sidecars: one line, ≤512 bytes, no control characters (`read_field` rejects otherwise).
`.perms` keeps its existing two values so current readers do not break; `.posture` is the
new three-value field.

Persona is a **file**, never inlined into the tmux command: copied to
`$RUNDIR/<name>.persona` at mode 0600.

### Posture enforcement

| posture | codex | claude | grok |
| --- | --- | --- | --- |
| `unrestricted` | `--dangerously-bypass-approvals-and-sandbox` | `bypassPermissions` | `--permission-mode bypassPermissions` |
| `workspace-write` | `--sandbox workspace-write` | `acceptEdits` + denies | verify at implementation |
| `read-only` | `--sandbox read-only` | `default` + deny Write/Edit/Bash | verify at implementation |

Two rules that must hold:

- **A posture that cannot be enforced fails the spawn.** It never silently downgrades.
  This inverts the existing refusal at `agentmux.sh:141`: never *report* a posture you did
  not *achieve*. Named tool allowlists are claude-only; on codex and grok they are recorded
  with a `degraded` marker and restated as prose in the persona.
- **`AGENTMUX_NO_BYPASS=1` is a ceiling**, clamping any requested posture down and logging
  the clamp. A definition must never escape the machine-wide brake.

`claude_config_dir()` (`agentmux.sh:91-148`) becomes **per-agent**
(`$ROOT/claude-config/<agent>/`). This is also a bug fix: today it writes one shared dir
and regenerates it on every spawn, so two concurrent spawns already race. Keep the
prove-it check at `:139-144` and generalise it — grep the written file for the posture it
claims and `die` if absent. Add a GC pass pruning dirs with no live pane.

### The hire bound

`POST /api/board/hire` takes `{id, name}` and **nothing else**. No argv, cwd, cli, model
or flags ever cross the wire; the server uses the exact saved definition attached to
the approved roster row. Later file or default-setting edits cannot replace that
persona, CLI, model, auth method, posture or tool intent. A body carrying launch
fields has them **ignored, and a test asserts it**. Missing or invalid saved definitions
fail with guidance to recruit and approve again.

Four more bounds: the name must have an `approved` roster row for that card (else 409);
both `dispatchEnabled` and `dashboardMayHire` must be on (else 403); a
`BoundedSemaphore(2)` caps concurrency (exhausted → 503); the posture is the definition's,
clamped by `AGENTMUX_NO_BYPASS`.

**The honest limit, which must be written in the code:** port 8787 is unauthenticated.
`read_cc_body`'s Origin allowlist stops a *browser* on another origin and nothing else — a
non-browser client omits the header and is treated as same-origin, which is exactly how
`test_board.py:505` drives it. Any local process that can open a socket can hire. The five
bounds are defence in depth, not authentication. `dashboardMayHire` must hard-fail if the
server is ever bound off `127.0.0.1`.

---

## C9 — `window.CCC`

`app.js` is a classic script, not a module, so globals are shared.

```js
window.CCC = { el, getJSON, post, say, deleteButton, collapsible, settingEditor,
               registerView };
// registerView(name, loaderFn, pollMs?) writes els.views[name], VIEW_LOADERS[name]
//                                       and VIEW_POLL_MS[name] in one call
```

New views live in their own files (`agents.js`, `agents.css`, `teams.js`, `teams.css`) so
`app.js`, `index.html` and `style.css` are each claimed exactly once, in the scaffold task.

**`server.py`'s static allowlist must be extended in the same scaffold task.** It is an
`elif path in ("/app.js", "/fitmatrix.js")` list at `server.py:1893` — a new `.js` or
`.css` **404s** until it is added, and the failure is silent in the browser.

Conventions that still apply: `textContent` only, never `innerHTML` (descriptions and
personas are user-authored); relative paths (`'api/board/agents'`); no modal system, so
`window.confirm` plus an inline `<details>`; any new CSS grid needs `align-items: start`;
nothing that scrolls may carry `zoom`.

---

## C10 — New config keys

Each must be registered in the matching one of `CONFIG_BOOLS` / `CONFIG_NUMBERS` /
`CONFIG_CLIS` (`ccboard.py:123-130`) or `board/config` rejects writes to it.

| key | type | default | bounds |
| --- | --- | --- | --- |
| `teamMaxAgents` | number | 8 | 1–32 — total live panes |
| `teamMaxWorkers` | number | 2 | 0–8 — per team, excluding the lead |
| `teamRequireApproval` | bool | `true` | |
| `dashboardMayHire` | bool | **`false`** | |

`dispatchWip` keeps its current meaning — **cards** in flight, not panes — so there is no
config migration and no surprise for an existing board. `pool_once` counts leads against
`dispatchWip` and total panes against `teamMaxAgents`.

**Delete `dispatchReviewCli`** while in `DEFAULT_CONFIG` / `CONFIG_CLIS` / `DISPATCH_KEYS`.
It is declared, validated, exposed — and read by nothing. Removing it now is cheap;
leaving it beside four new keys is a standing invitation to assume it works.

---

## C11 — Test conventions

Non-negotiable, and each one has drawn blood before:

- Set `AGENTMUX_HOME` to a temp dir **before** importing `ccboard` / `ccstore` / `server`.
  Import order is load-bearing — `ccstore.HOME_DIR` resolves at import time
  (`test_board.py:41-48`).
- HTTP suites bind **port 0** (`ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)`,
  `test_board.py:505-523`) so they run beside the live dashboard.
- The **last** line printed is `passed N, failed 0`. `run_tests.sh` reads the final line;
  a trailing `store: <path>` line once made a passing suite read as failed
  (`test_board.py:606-608`).
- Register every new suite in `run_tests.sh:155-177`. A suite nothing invokes is
  decoration — that file says so about `test_board.py` itself.
- Every new board op satisfies the checklist at `test_board.py:525-603`: 200 + expected
  keys; gate refusal 409 **with hints**; wrong verb 405; unknown op 404/405 and **never
  500**; missing `application/json` 415; unknown name 404; malformed name 400; over-long
  query 400.
- Assert the ambiguity regression explicitly: `key_of_worker("tm-042-dev") == "TM-042"`
  **and** `key_of_worker("tm-0427") == "TM-0427"`.

### Two traps that have now caught two suites each

**Never `cd "$(dirname "$0")/.."` in a `.sh` suite.** Every shell suite here is invoked as
`bash <(tr -d '\r' < dashboard/<suite>.sh)` — the CR strip is the repo's invocation
convention — so `$0` is `/dev/fd/63`, `dirname` is `/dev/fd`, and that `cd` lands the suite
in `/dev`. It then fails with something misleading like `FileNotFoundError:
/dev/agentmux.sh`. `run_tests.sh` already runs from the repo root: use repo-relative paths
and do not `cd` at all.

**`node` is not on the PATH in a non-login WSL shell.** A suite that shells out to node dies
with `node: command not found` and takes the gate with it. Resolve it the way
`agentmux.sh:57 node_bin()` does — `ls -d "$HOME"/.nvm/versions/node/*/bin | sort -V | tail -1`,
prepended to `PATH` — and fall back to the guarded skip that `test_frontend.sh:129` uses
(`if command -v node; then … else` report and skip) so a machine without node degrades
instead of failing.
