#!/usr/bin/env python3
"""Dispatch: turning a board card into a running agent, and back again.

WHY THIS EXISTS
---------------
The board could say what was ready and agentmux could run an agent, and nothing
joined the two. So "use the task board" meant a person reading the queue, picking
a card, typing `spawn`, typing `claim`, pasting a brief, and remembering to move
the status. Every one of those is a step a machine should take, and every one of
them got skipped under load - which is how a board full of startable work came to
sit next to three idle agents.

This module is that join and nothing more. It does not decide what is ready:
`/api/board/dispatchable` does, because readiness is board policy and a dispatcher
that re-derived it would be a second opinion able to disagree with the gates. It
does not run agents: `agentmux spawn` does. It owns exactly the sequence between
them, and the sequence back.

THE SEQUENCE, AND WHY IT IS THIS ORDER
--------------------------------------
    spawn -> claim -> start -> brief

Claiming before spawning is impossible: a claim must be held by a LIVE agent
(coordination.resolve_identity), and a name nobody has spawned is not live.
Briefing before claiming is too late: the agent is already reading the card. So
the worker is spawned, claims its files while still sitting at an empty prompt,
and is briefed only once those files are actually its own. If a claim is refused,
the worker is killed and the card is left exactly as it was found.

`start` goes through the board's own gate. This module never writes a status it
has decided is allowed - it asks, and a refusal (HTTP 409) is the answer rather
than an error to route around. That is why an unready card cannot be dispatched
even by calling this directly: the gate is not in this file.

WHAT COLLECT DOES NOT DO
------------------------
It never closes a task. A worker that finished is a worker that CLAIMS to have
finished, and `requireOnDone` wants evidence and an actor. Collect reconciles the
world - releases claims, reaps the pane, parks what died - and leaves the closing
judgement to the gate, the only thing entitled to make it.

    python3 taskmgmt/dispatch.py dispatch [TM-014] [--cli codex] [--dry-run]
    python3 taskmgmt/dispatch.py collect  [TM-014] [--all]
    python3 taskmgmt/dispatch.py pool     once|start|stop|status|resume
    python3 taskmgmt/dispatch.py status   [--json]
"""
import argparse
import errno
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import coordination                                    # noqa: E402  reuse, do not restate
import agentdefs                                       # noqa: E402
import definition_team                                 # noqa: E402

ROOT = Path(os.environ.get("AGENTMUX_HOME", str(Path.home() / ".agentmux")))
DISPATCH_DIR = ROOT / "dispatch"
POOL_PID = DISPATCH_DIR / "pool.pid"
POOL_LOG = DISPATCH_DIR / "pool.log"
POOL_STATE = DISPATCH_DIR / "pool.state.json"

REPO = Path(__file__).resolve().parent.parent
KEY_RE = coordination.KEY_RE

# A dispatched worker is named for the card it holds, lowercased. That is not
# cosmetic: `collect` must be able to tell a worker this module started from one a
# person spawned by hand, and the alternative - a registry file - is a second
# source of truth that can disagree with tmux. The name IS the registry.
ROLES = ("lead", "worker", "reviewer", "researcher")
WORKER_RE = re.compile(r"(ep|tm|adr|sp|cap)-([0-9]{3,9})(?:-([a-z][a-z0-9]{0,15}))?")
BRIEF_MAX = 8192
POOL_STALE_S = 120


def now():
    return coordination.now()


def worker_name(key):
    return key.lower()


def member_name(key, role, ordinal=1):
    """Name a role on a card, with an ordinal for additional members."""
    if role not in ROLES:
        raise ValueError("unknown member role: %r" % (role,))
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 1:
        raise ValueError("member ordinal must be a positive integer")
    lead = worker_name(key)
    if not KEY_RE.fullmatch(lead.upper()):
        raise ValueError("invalid card key: %r" % (key,))
    suffix = role + (str(ordinal) if ordinal > 1 else "")
    name = lead + "-" + suffix
    if len(name) > 64 or not WORKER_RE.fullmatch(name):
        raise ValueError("member name exceeds the worker naming limits")
    return name


def key_of_worker(name):
    """The card a worker name refers to, or None if it is not a dispatched worker."""
    match = WORKER_RE.fullmatch(name or "")
    if not match:
        return None
    key = (match.group(1) + "-" + match.group(2)).upper()
    return key if KEY_RE.fullmatch(key) else None


def role_of_worker(name):
    """Return the role without its ordinal; unsuffixed names are leads."""
    match = WORKER_RE.fullmatch(name or "")
    if not match:
        raise ValueError("invalid worker name: %r" % (name,))
    return re.sub(r"[0-9]+$", "", match.group(3)) if match.group(3) else "lead"


# True only inside the detached pool loop, where pool_start has already pointed
# stdout AT the log file. Without it every line the pool writes lands twice - once
# through print, once through the append below - and a log that repeats itself
# reads like the loop is running twice, which is the wrong thing to debug at the
# moment you are reading a log to find out what happened.
_STDOUT_IS_LOG = False


def log(message):
    """One line on stdout, and in the pool log unless stdout already is it."""
    line = "%s  %s" % (now(), message)
    print(line, flush=True)
    if _STDOUT_IS_LOG:
        return
    try:
        DISPATCH_DIR.mkdir(parents=True, exist_ok=True)
        with POOL_LOG.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


# ── the board side ───────────────────────────────────────────────────────────

def board(method, path, body=None):
    """A board call whose failure is a message rather than a traceback."""
    return coordination.board_call(method, path, body)


def dispatch_view(limit=10):
    return board("GET", "board/dispatchable?limit=%d" % limit)


def entity(key):
    return board("GET", "board/entity?id=" + key)


def set_status(key, status, actor, session=None, reason=None):
    body = {"id": key, "status": status, "actor": actor}
    if session:
        body["session"] = session
    if reason:
        body["reason"] = reason
    return board("POST", "board/status", body)


def comment(key, text, actor):
    return board("POST", "board/comment", {"id": key, "text": text[:1000], "actor": actor})


# ── the agentmux side ────────────────────────────────────────────────────────

def agentmux_bin():
    """How to invoke agentmux from here.

    The repo copy carries CRLF line endings (this checkout lives on a Windows
    drive) and bash will not run that - it reports a missing command named for a
    carriage return. The installed copy is already clean, so it is preferred; the
    repo copy is the fallback and is stripped on the way in, the same way
    restart.sh does it.
    """
    explicit = os.environ.get("AGENTMUX_BIN")
    if explicit:
        return [explicit]
    found = shutil.which("agentmux")
    if found:
        return [found]
    local = Path.home() / ".local" / "bin" / "agentmux"
    if local.is_file():
        return [str(local)]
    script = 'exec bash <(tr -d "\\r" < "$0") "$@"'
    return ["bash", "-c", script, str(REPO / "agentmux.sh")]


def agentmux(*args, timeout=180):
    """Run one agentmux verb. Returns (rc, stdout, stderr)."""
    cmd = agentmux_bin() + list(args)
    try:
        # Every dispatch verb goes through here, spawn included, so one missing
        # argument would drain the stdin of anything driving dispatch from a script.
        done = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as err:
        return 1, "", str(err)
    return done.returncode, done.stdout or "", done.stderr or ""


def live_agents():
    return coordination.live_agents()


# ── briefs ───────────────────────────────────────────────────────────────────

def brief_path(key):
    return DISPATCH_DIR / ("%s.md" % key)


def brief_text(task, spec=None):
    """The handoff, on disk.

    Deliberately a FILE the agent is pointed at rather than text typed into the
    pane. A brief pasted as keystrokes is at the mercy of the CLI's input handling
    - bracketed paste, autocomplete, a modal that eats the first line - and a
    truncated brief is worse than none, because the agent acts on the half it got.
    """
    key = task["id"]
    lines = [
        "# %s  %s" % (key, task.get("title") or ""),
        "",
        "You are a dispatched worker. This card is yours and its files are claimed",
        "in your name. RULE #-0.7 applies: claim before editing anything outside the",
        "list below, journal what you do, and do not touch another agent's files.",
        "",
        "- board key: **%s**" % key,
        "- epic: %s" % (task.get("epic") or "-"),
        "- priority: %s" % (task.get("priority") or "-"),
        "- type: %s" % (task.get("type") or "-"),
        "",
    ]
    if task.get("body"):
        lines += ["## What and why", "", str(task["body"]).strip(), ""]
    acceptance = task.get("acceptance") or []
    if acceptance:
        lines += ["## Acceptance criteria", ""]
        for index, item in enumerate(acceptance):
            text = item.get("text") if isinstance(item, dict) else str(item)
            ticked = bool(item.get("done")) if isinstance(item, dict) else False
            lines.append("%d. [%s] %s" % (index, "x" if ticked else " ", text))
        lines.append("")
    touches = task.get("touches") or []
    if touches:
        lines += ["## Files claimed for you", ""]
        lines += ["- `%s`" % item for item in touches]
        lines.append("")
    lines += [
        "## When you are done",
        "",
        "Attach evidence and say so on the board, then stop. Do NOT close the card",
        "yourself - the gate wants evidence and an actor, and the orchestrator",
        "collects:",
        "",
        "    agentmux task evidence %s <path-or-url>" % key,
        "    agentmux task comment  %s \"what you did\"" % key,
        "",
        "If you are blocked, say why on the card and stop rather than guessing:",
        "",
        "    agentmux task block %s --reason \"...\"" % key,
        "",
    ]
    text = "\n".join(lines)
    remaining = BRIEF_MAX - len(text.encode("utf-8"))
    if remaining < 0:
        raise ValueError("task brief exceeds BRIEF_MAX; acceptance and claims cannot be truncated")
    persona = spec.persona if spec is not None else ""
    heading = "\n## Persona\n\n"
    if persona and remaining > len(heading.encode("utf-8")):
        # Spend only the space left by the complete task. Decode at a UTF-8
        # boundary so a multibyte persona never breaks the file or the bound.
        budget = remaining - len(heading.encode("utf-8")) - 1
        excerpt = persona.encode("utf-8")[:budget].decode("utf-8", errors="ignore")
        text += heading + excerpt + "\n"
    return text


def write_brief(task, spec=None):
    """Write the bounded handoff without ever clipping acceptance or claims."""
    text = brief_text(task, spec)
    key = task["id"]
    DISPATCH_DIR.mkdir(parents=True, exist_ok=True)
    brief_path(key).write_text(text, encoding="utf-8")
    return brief_path(key)


# ── claims ───────────────────────────────────────────────────────────────────

def claim_resource(worker, path):
    """C6: a member's repository path, within the coordination resource bound.

    Shared state must be passed to claim_for without a namespace. Never infer
    that a shared resource is private merely because a member requested it.
    """
    if not isinstance(worker, str) or not WORKER_RE.fullmatch(worker):
        raise ValueError("invalid worker namespace")
    if (not isinstance(path, str) or path.startswith("/")
            or any(part in ("", ".", "..") for part in path.split("/"))):
        raise ValueError("member claims require a repository-relative path")
    resource = worker + "/" + path
    if not coordination.RESOURCE_PATTERN.fullmatch(resource) or ".." in resource:
        raise ValueError("invalid member resource or combined length exceeds 200")
    return resource


def claim_for(worker, key, paths, note, namespace=None):
    """Claim all paths or roll back; leads/shared state omit namespace.

    Validate the entire set before acquiring anything, including the combined
    namespace/path length. Return rollback failures to the caller for recovery.
    """
    try:
        resources = list(dict.fromkeys(
            claim_resource(namespace, path) if namespace is not None else path
            for path in paths))
        if any(not isinstance(path, str)
               or not coordination.RESOURCE_PATTERN.fullmatch(path) or ".." in path
               for path in resources):
            raise ValueError("invalid claim resource")
    except (ValueError, TypeError) as err:
        return False, str(err)
    taken = []
    for path in resources:
        rc, out, err = agentmux("claim", path, "--for", worker,
                                "--task", key, "--note", note[:200])
        if rc != 0:
            failures = []
            for done in reversed(taken):
                released, _, _ = agentmux("release", done, "--for", worker)
                if released:
                    failures.append(done)
            reason = (err or out or "claim refused").strip() or "claim refused"
            if failures:
                reason += "; rollback failed for " + ", ".join(failures)
            return False, reason
        taken.append(path)
    return True, ""


def release_all(worker, paths, namespace=None):
    resources = [claim_resource(namespace, path) if namespace is not None else path
                 for path in paths]
    # Include claims acquired after dispatch, not only the original touches.
    resources += [claim["resource"] for claim in coordination.all_claims(include_expired=True)
                  if claim.get("holder") == worker]
    failed = []
    for path in dict.fromkeys(resources):
        rc, _, _ = agentmux("release", path, "--for", worker)
        if rc:
            failed.append(path)
    return not failed


# Worktree helpers are called by the roster/hire path with its board transaction.
# Creating a tree precedes spawn; claiming follows spawn (only live panes claim).
# The caller owns commit/rollback and must remove a newly created tree if a later
# spawn or board transaction fails. Successful branches survive collection so
# the lead can merge them. No agentmux worktree verb is needed.
def _git(*args):
    try:
        done = subprocess.run(["git", "-C", str(REPO), *args],
                              # git reads stdin for some subcommands and will happily
                              # consume a script it was never meant to see.
                              stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as err:
        raise RuntimeError("worktree git failed: %s" % err) from err
    if done.returncode:
        raise RuntimeError((done.stderr or done.stdout or "git failed").strip())
    return done.stdout.strip()


def create_worktree(worker, base="HEAD"):
    """Create an external tree and branch; refuse existing names, never reset."""
    if not isinstance(worker, str) or not WORKER_RE.fullmatch(worker):
        raise ValueError("invalid worktree member name")
    repo = Path(_git("rev-parse", "--show-toplevel")).resolve()
    common = Path(_git("rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
    identity = hashlib.sha256(str(common).encode()).hexdigest()[:16]
    root = (ROOT / "worktrees" / identity).resolve()
    if root == repo or repo in root.parents:
        raise ValueError("worktrees must live outside the repository")
    root.mkdir(parents=True, exist_ok=True)
    path = root / worker
    branch = "agentmux/" + worker
    # git refuses an existing branch or destination; neither is ours to erase.
    _git("worktree", "add", "-b", branch, str(path), base)
    return {"member_name": worker, "worktree": str(path), "branch": branch}


def remove_worktree(worktree):
    """Remove a clean tree, retaining its branch for integration/recovery.

    Git's normal dirty/untracked checks are intentional. Never force removal of
    a member's unfinished work, and never delete its branch during collection.
    """
    path = Path(worktree).resolve()
    registered = [Path(line[9:]).resolve()
                  for line in _git("worktree", "list", "--porcelain").splitlines()
                  if line.startswith("worktree ")]
    if path not in registered and not path.exists():
        return
    _git("worktree", "remove", str(path))


def integrate_members(key, task, members):
    """Merge completed branches in the lead tree, leaving conflicts for review.

    Returns submitted/parked/unresolved. Only branches proven integrated are
    deleted; a conflict or dirty tree preserves all remaining work for recovery.
    """
    lead = worker_name(key)
    lead_row = next((row for row in members if row.get("member_name") == lead), {})
    tree = task.get("worktree") or lead_row.get("worktree") or str(REPO)
    expected_branch = task.get("branch") or lead_row.get("branch")
    def git(*args):
        return _git("-C", str(tree), *args)

    try:
        branch = git("symbolic-ref", "--short", "HEAD")
        if expected_branch and branch != expected_branch:
            raise RuntimeError("lead worktree is not on its integration branch")
        if git("status", "--porcelain"):
            raise RuntimeError("lead integration worktree has uncommitted changes")
        for member in members:
            source = member.get("branch")
            if not source or member.get("member_name") == lead:
                continue
            if not source.startswith("agentmux/"):
                raise RuntimeError("refusing unmanaged member branch: " + source)
            if not git("branch", "--list", source):
                if member.get("worktree") and Path(member["worktree"]).exists():
                    raise RuntimeError("member branch missing while its worktree exists")
                continue  # Already integrated and torn down on an earlier collect.
            if member.get("worktree") and Path(member["worktree"]).exists():
                if _git("-C", member["worktree"], "status", "--porcelain"):
                    raise RuntimeError("member has uncommitted work: " + source)
            try:
                git("merge", "--no-edit", "--", source)
            except RuntimeError:
                conflicts = git("diff", "--name-only", "--diff-filter=U")
                if not conflicts:
                    raise
                # Aborting restores the integration branch; it resolves nothing.
                # Keep both branches and the member tree for manual recovery.
                reason = "merge conflict integrating %s into %s: %s" % (
                    source, branch, ", ".join(conflicts.splitlines()))
                reported = comment(key, reason, lead)
                parked = set_status(key, "parked", lead, reason=reason)
                git("merge", "--abort")
                return "parked" if reported is not None and parked is not None else "unresolved"
        # Defer all teardown until every merge succeeds.
        for member in members:
            if member.get("member_name") and member["member_name"] != lead:
                teardown_member(member, tree)
    except RuntimeError as err:
        comment(key, "integration/teardown requires recovery: " + str(err), lead)
        return "unresolved"
    return "submitted"


def teardown_member(member, integration_tree):
    """Idempotent cleanup; never discard commits absent from integration HEAD."""
    branch = member.get("branch")
    if branch and _git("branch", "--list", branch):
        if not branch.startswith("agentmux/"):
            raise RuntimeError("refusing unmanaged member branch: " + branch)
        _git("-C", str(integration_tree), "merge-base", "--is-ancestor", branch, "HEAD")
    if member.get("worktree"):
        remove_worktree(member["worktree"])
    if branch and _git("branch", "--list", branch):
        # Ancestry above is against the integration tree, which need not be REPO.
        _git("branch", "-D", branch)
    if not release_all(member["member_name"], []):
        raise RuntimeError("member claims could not be released")


def prepare_member_worktree(db, key, agent_name, worker, base="HEAD"):
    """Create a member tree and record it on the existing approved roster row.

    Used by hire inside its transaction; no status/approval decision is made
    here. The returned metadata supplies spawn's cwd and subsequent cleanup.
    """
    if key_of_worker(worker) != key:
        raise ValueError("member name does not belong to the card")
    row = db.execute("SELECT id,status,member_name,worktree,branch FROM board_roster "
                     "WHERE entity_key=? AND agent_name=?", (key, agent_name)).fetchone()
    if row is None or row[1] != "approved":
        raise ValueError("member must have an approved roster row")
    if any(row[index] for index in (2, 3, 4)):
        raise ValueError("member already has worktree metadata")
    # The board module owns history formatting, just as for roster approval.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dashboard"))
    import ccboard
    metadata = None
    db.execute("SAVEPOINT member_worktree")
    try:
        metadata = create_worktree(worker, base)
        db.execute("UPDATE board_roster SET member_name=?,worktree=?,branch=?,updated_at=? "
                   "WHERE id=?", (worker, metadata["worktree"], metadata["branch"], now(), row[0]))
        ccboard._record(db, key, "worktree", worker, detail=metadata)
        db.execute("RELEASE member_worktree")
    except Exception:
        db.execute("ROLLBACK TO member_worktree")
        db.execute("RELEASE member_worktree")
        if metadata is not None:
            remove_worktree(metadata["worktree"])
            _git("branch", "-d", metadata["branch"])
        raise
    return metadata


# ── dispatch ─────────────────────────────────────────────────────────────────

def pick(view, wanted=None):
    """The card to dispatch, or (None, reason)."""
    tasks = view.get("tasks") or []
    if wanted:
        for task in tasks:
            if task["id"] == wanted:
                return task, ""
        return None, "%s is not dispatchable right now" % wanted
    if not tasks:
        return None, "nothing ready for an agent"
    return tasks[0], ""


def served_home():
    """The home of the dashboard process this checkout would talk to, or None.

    Separate from foreign_board so the decision can be tested without a running
    server: a check whose verdict depends on what happens to be listening on the
    machine is one that passes or fails for reasons the suite cannot state.
    """
    try:
        sys.path.insert(0, str(REPO / "dashboard"))
        import suite_server           # noqa: PLC0415 - lazy, and optional
        from urllib.parse import urlsplit  # noqa: PLC0415
        # The server at the URL this process would POST to - not "any dashboard".
        # The gate now runs a private one beside the operator's (TM-223), and an
        # unscoped scan would see two homes, raise, and fail open: the guard off.
        port = urlsplit(coordination.DASHBOARD).port or 80
        return suite_server.server_home(port)
    except Exception:                 # noqa: BLE001 - see FAIL OPEN in foreign_board
        return None


def foreign_board():
    """Why this process must not dispatch, or "" when it may.

    AGENTMUX_HOME AND AGENTMUX_DASHBOARD ARE RESOLVED INDEPENDENTLY.
    coordination.py reads the home at :46 and the dashboard at :51, with no relation
    between them - so relocating the home does NOT relocate the board. A test with a
    throwaway AGENTMUX_HOME still POSTs to whatever answers on 8787, which is normally
    the operator's live dashboard.

    That is not hypothetical. A pool test running against a mktemp home dispatched two
    real cards off the operator's board, moved them to in_progress and spawned two real
    codex agents for them. AGENTMUX_HOME looked like isolation and was not, and nothing
    anywhere said so.

    Dispatch is the right place for the check because it is the destructive one: it
    claims a card, creates a worktree and starts an agent. A read against the wrong
    board is confusing; a dispatch against the wrong board is someone else's work.

    FAIL OPEN, DELIBERATELY. This refuses only when the two are positively known to
    disagree. If the server is not running, or /proc cannot be read, or this is not
    Linux, it returns "" and the dispatch proceeds - a guard that blocks on a guess
    would break every legitimate setup it cannot introspect, and run_tests.sh's
    pattern (relocate the SERVER's home to the same temp dir, keep port 8787) is
    exactly such a setup and must keep working.
    """
    if os.environ.get("AGENTMUX_ALLOW_FOREIGN_BOARD") == "1":
        return ""
    if "AGENTMUX_HOME" not in os.environ:
        return ""                    # not relocated: the default pairing is correct
    served = served_home()
    if not served:
        return ""
    try:
        ours = Path(ROOT).resolve()
        theirs = Path(served).resolve()
    except OSError:
        return ""
    if ours == theirs:
        return ""
    return ("refusing to dispatch: AGENTMUX_HOME is %s but the dashboard at %s is "
            "serving %s.\n"
            "  Relocating the home does not relocate the board, so this would claim "
            "cards and spawn agents\n"
            "  on someone else's store. Point AGENTMUX_DASHBOARD at a server for this "
            "home, or set\n"
            "  AGENTMUX_ALLOW_FOREIGN_BOARD=1 if you meant it."
            % (ours, coordination.DASHBOARD, theirs))


def approved_project_lead(key, specs, cfg=None):
    """Use only the board's approved revision, refusing a changed local import."""
    payload = board("GET", "board/roster?id=" + key)
    if payload is None:
        raise ValueError("cannot read approved project roster")
    rows = [row for row in payload.get("members", []) if row.get("role") == "lead"
            and row.get("status") in ("approved", "hired")]
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError("project roster has multiple approved leads")
    row = rows[0]
    revision = row.get("definitionRevision")
    if not isinstance(revision, dict):
        raise ValueError("recruit and approve this roster again to save its definition")
    if revision.get("projectRoot") != str(REPO.resolve()):
        raise ValueError("approved lead belongs to another project")
    spec = (definition_team.TeamPlugin().propose_legacy({}, {}, cfg or {})[0]
            if row.get("definitionState") == "builtin" else
            specs.get(row.get("agent_name")))
    if spec is None or revision != dict(name=spec.name, scope=spec.scope,
                                        path=spec.path, checksum=spec.checksum, projectRoot=str(REPO.resolve()),
                                        snapshotDigest=definition_team.snapshot_digest(spec)):
        raise ValueError("approved lead definition changed; recruit and approve its new revision")
    return spec


def dispatch_one(key=None, cli=None, dry_run=False, limit=10, quiet=False):
    """Hand one card to a fresh agent. Returns the worker name, or None.

    `quiet` suppresses the "nothing ready" line. The pool asks on every tick and an
    empty queue is its normal state, so logging it would write a line every
    dispatchPoll seconds forever - a log that is almost entirely the word "no" is
    one nobody reads, which defeats having one. A person who typed `dispatch` is
    owed the answer, so the default stays loud.
    """
    refusal = foreign_board()
    if refusal:
        log(refusal)
        return None

    view = dispatch_view(limit)
    if view is None:
        return None
    cfg = view.get("config") or {}
    task, why = pick(view, key)
    if task is None:
        if not quiet:
            log("dispatch: " + why)
        return None

    key = task["id"]
    worker = worker_name(key)

    if worker in live_agents():
        log("dispatch: %s already has a worker (%s)" % (key, worker))
        return None

    # The full record, because the list payload has its body stripped and the body
    # is most of the brief.
    full = entity(key)
    if full is None:
        return None
    task = full.get("task") or full.get("entity") or full

    specs, problems = agentdefs.load_all(REPO)
    for problem in problems:
        log("dispatch: agent definition %s: %s" % (problem["path"], problem["error"]))
    try:
        approved_lead = approved_project_lead(key, specs, cfg)
    except ValueError as error:
        log("dispatch: " + str(error))
        return None
    spec = definition_team.TeamPlugin().propose_legacy(
        task, specs, cfg, cli_override=cli, lead=approved_lead)[0]
    cli = spec.cli
    log("dispatch: lead %s (%s), cli=%s, posture=%s" %
        (spec.name, spec.path or "built-in fallback", cli, spec.posture))
    if spec.posture != "unrestricted" or os.environ.get("AGENTMUX_NO_BYPASS") == "1":
        log("dispatch: sandbox posture is incompatible with coordination for %s; "
            "tmux socket and claim/journal state are outside the workspace. "
            "Configure an unrestricted lead and disable AGENTMUX_NO_BYPASS to dispatch."
            % key)
        return None
    try:
        brief_text(task, spec)
    except ValueError as err:
        log("dispatch: %s cannot be briefed: %s" % (key, err))
        return None

    if dry_run:
        log("dispatch: would spawn %s [%s] for %s - %s"
            % (worker, cli, key, task.get("title") or ""))
        return worker

    spawn_args = ["spawn", worker, "--cli", cli, "--cwd", str(REPO),
                  "--posture", spec.posture]
    if spec.model:
        spawn_args += ["--model", spec.model]
    if spec.auth:
        spawn_args += ["--auth", spec.auth]
    rc, out, err = agentmux(*spawn_args)
    if rc != 0:
        log("dispatch: spawn failed for %s: %s" % (key, (err or out).strip()[:200]))
        return None

    touches = list(task.get("touches") or [])
    ok, refusal = claim_for(worker, key, touches, "dispatched for " + key)
    if not ok:
        # Someone else holds a file this card needs. Leave the card untouched and
        # take the worker away again - a spawned agent with no work and no claim is
        # a context leak, and the next poll will retry.
        agentmux("kill", worker)
        log("dispatch: %s not claimable (%s)" % (key, refusal[:160]))
        return None

    started = set_status(key, "in_progress", worker, session=worker)
    if started is None:
        release_all(worker, touches)
        agentmux("kill", worker)
        log("dispatch: board refused to start %s; worker withdrawn" % key)
        return None

    board("POST", "board/update", {"id": key, "actor": worker,
                                   "patch": {"assignee": worker, "session": worker}})
    path = write_brief(task, spec)

    # Let the CLI finish coming up before typing at it. A fresh pane is the most
    # likely moment for a modal - a directory-trust dialog, an update prompt, a
    # rate-limit notice - and `send` correctly refuses to type into one, because
    # Enter would actuate the prompt's default instead of talking to the agent.
    agentmux("wait", worker, "--timeout", "60", "--quiet", "3", timeout=90)
    pointer = "Read %s and do the work it describes. It is your brief." % path
    rc, out, err = agentmux("send", worker, pointer)
    if rc != 0:
        # UNDELIVERED IS NOT DISPATCHED. Leaving a worker up with a brief it never
        # received is the worst outcome available: the card reads in_progress, its
        # files are claimed, a slot is consumed, and the agent is sitting at a
        # prompt doing nothing. On the board that is indistinguishable from
        # progress, and it holds the queue behind it.
        #
        # But a refused send is usually a MODAL, not a dead agent - a fresh pane is
        # the likeliest moment for a directory-trust dialog, an update prompt or a
        # rate-limit notice, and `send` refuses rather than press Enter on someone
        # else's dialog. That is a wait, not a failure, and the courier already
        # solves waiting: it retries a recipient that is down or showing a modal,
        # and dead-letters after five attempts rather than dropping it silently.
        #
        # So the fast path is a direct send, and the fallback is the queue. Only a
        # failure to even QUEUE the brief is a failure to dispatch.
        queued, qout, qerr = agentmux("post", worker, "--kind", "request", pointer)
        if queued != 0:
            withdraw(worker, key, touches,
                     "brief could not be delivered or queued: "
                     + (qerr or qout or err or "send refused").strip().splitlines()[0])
            return None
        comment(key, "brief queued for %s rather than typed: the pane was showing a "
                     "prompt. The courier will deliver it." % worker, "orchestrator")
        log("dispatch: %s -> %s [%s] (brief queued - pane busy)  %s"
            % (key, worker, cli, task.get("title") or ""))
        return worker
    log("dispatch: %s -> %s [%s]  %s" % (key, worker, cli, task.get("title") or ""))
    return worker


def withdraw(worker, key, touches, reason):
    """Undo a dispatch that did not take. Leaves the card exactly as it was found."""
    release_all(worker, touches)
    agentmux("kill", worker)
    set_status(key, "open", "orchestrator")
    # Clear the assignee too. A card that reads open but still names a worker that
    # was killed is a board saying two things at once, and the next reader believes
    # the wrong one.
    board("POST", "board/update", {"id": key, "actor": "orchestrator",
                                   "patch": {"assignee": None, "session": None}})
    comment(key, "dispatch withdrawn: " + reason, "orchestrator")
    log("dispatch: %s withdrawn - %s" % (key, reason[:200]))


# ── collect ──────────────────────────────────────────────────────────────────

def dispatched_now():
    """Workers this module started, as {worker: key}, from tmux and nowhere else."""
    out = {}
    for name in live_agents():
        key = key_of_worker(name)
        if key:
            out[name] = key
    return out


def collect_one(key, task=None):
    """Reconcile one dispatched card with the world. Never closes it."""
    task = task or (entity(key) or {}).get("task") or entity(key)
    if not task:
        return None
    lead = worker_name(key)
    touches = list(task.get("touches") or [])
    live = live_agents()
    roster = board("GET", "board/roster?id=" + key)
    if roster is None:
        return {"id": key, "outcome": "unresolved"}
    rows = roster.get("members") or []
    members = sorted({name for name in live
                      if key_of_worker(name) == key and name != lead}
                     | {row["member_name"] for row in rows
                        if row.get("member_name") and row["member_name"] != lead})
    alive = lead in live
    status = task.get("status")
    lead_state = None
    if alive and status == "in_progress":
        lead_state, _, _ = agentmux("wait", lead, "--timeout", "3", timeout=30)
    lead_dead = not alive or lead_state == 3

    def reap(name, pane_alive=True):
        # Do not release a live pane's claims if killing it failed, or reap the
        # lead while a member could still be writing. Preserve branches until
        # integration succeeds, or for recovery after an orphaned team parks.
        if pane_alive:
            rc, _, _ = agentmux("kill", name)
            if rc and name in live_agents():
                return False
        return release_all(name, touches, namespace=name if name != lead else None)

    # Every role belongs to the card, including reviewers and researchers.
    # Members are always reaped before the lead. Card evidence alone cannot
    # justify reaping a busy member: it may be evidence from a different member.
    remaining = False
    cleanup_failed = False
    for member in members:
        member_state = None
        if member in live and not lead_dead and status == "in_progress":
            member_state, _, _ = agentmux("wait", member, "--timeout", "3", timeout=30)
            if member_state != 3 and not (member_state == 0 and task.get("evidence")):
                remaining = True
                continue
        if not reap(member, pane_alive=member in live):
            cleanup_failed = True
    if cleanup_failed:
        return {"id": key, "outcome": "unresolved"}
    if remaining:
        return {"id": key, "outcome": "working"}

    if not lead_dead and status == "in_progress":
        if lead_state != 0:
            return {"id": key, "outcome": "working"}
        if not task.get("evidence"):
            # Idle without evidence is not proof of completion.
            return {"id": key, "outcome": "idle"}
        integration = integrate_members(key, task, rows) if any(
            row.get("branch") for row in rows) else "submitted"
        if integration != "submitted":
            if integration == "parked" and not reap(lead):
                integration = "unresolved"
            return {"id": key, "outcome": integration}
        if not reap(lead):
            return {"id": key, "outcome": "unresolved"}
        comment(key, "worker %s finished and was reaped; evidence attached, "
                     "card left in_progress for review." % lead, "orchestrator")
        log("collect: %s submitted by %s; claims released, pane reaped" % (key, lead))
        return {"id": key, "outcome": "submitted"}

    if not reap(lead, pane_alive=alive):
        return {"id": key, "outcome": "unresolved"}
    if status in ("done", "deleted", "blocked"):
        try:
            lead_row = next((row for row in rows if row.get("member_name") == lead), {})
            tree = task.get("worktree") or lead_row.get("worktree") or str(REPO)
            for row in rows:
                if row.get("member_name") and row["member_name"] != lead:
                    teardown_member(row, tree)
        except RuntimeError as err:
            comment(key, "teardown requires recovery: " + str(err), "orchestrator")
            return {"id": key, "outcome": "unresolved"}
        log("collect: %s %s; team reaped, claims released" % (key, status))
        return {"id": key, "outcome": status}

    # An orphaned team must not keep consuming panes and claims. Park rather
    # than reopen, which would silently redispatch failed work forever.
    reason = "dispatched lead %s exited without completing" % lead
    if members and lead_dead:
        reason += "; orphaned members reaped"
    if set_status(key, "parked", "orchestrator", reason=reason) is not None:
        comment(key, reason + ". Brief: %s" % brief_path(key), "orchestrator")
        log("collect: %s parked (%s)" % (key, reason))
        return {"id": key, "outcome": "parked"}
    return {"id": key, "outcome": "unresolved"}


def collect_all():
    """Every card that is in flight or was, as far as the board is concerned."""
    view = dispatch_view(1)
    if view is None:
        return []
    results = []
    for row in view.get("inFlight") or []:
        key = row.get("key")
        if key and key_of_worker(worker_name(key)):
            outcome = collect_one(key)
            if outcome:
                results.append(outcome)
    return results


# ── the pool ─────────────────────────────────────────────────────────────────

def read_state():
    try:
        return json.loads(POOL_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_state(patch):
    state = read_state()
    state.update(patch)
    DISPATCH_DIR.mkdir(parents=True, exist_ok=True)
    POOL_STATE.write_text(json.dumps(state), encoding="utf-8")
    return state


def pool_alive():
    """The live pool's pid, or None. A pid file alone proves nothing."""
    try:
        pid = int(POOL_PID.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:
            return None
        if err.errno != errno.EPERM:
            return None
    return pid


def pool_once():
    """One tick: collect what finished, then fill the free slots.

    Collect runs FIRST, always. Dispatching before collecting counts a dead
    worker's slot as occupied, so a pool whose workers all died would sit at its
    WIP limit forever, doing nothing, reporting itself full.
    """
    collected = collect_all()
    view = dispatch_view(20)
    if view is None:
        return {"collected": collected, "dispatched": [], "error": "board unreachable"}
    cfg = view.get("config") or {}
    if not cfg.get("dispatchEnabled"):
        return {"collected": collected, "dispatched": [], "disabled": True}
    wip = int(cfg.get("dispatchWip") or 0)
    # The dispatch view exposes only DISPATCH_KEYS; team policy lives in meta.
    if "teamMaxAgents" not in cfg:
        meta = board("GET", "board/meta")
        if meta is None:
            return {"collected": collected, "dispatched": [], "error": "board unreachable"}
        cfg = {**cfg, "teamMaxAgents": (meta.get("config") or {}).get("teamMaxAgents", 8)}
    max_agents = int(cfg["teamMaxAgents"])
    started = []
    while True:
        # Refresh both counters after each spawn: hires and manual panes can
        # appear between dispatches. Count each card once, and every live pane
        # (including panes outside the dispatch pool) against the global cap.
        live = set(live_agents()) | set(started)
        cards = {key_of_worker(name) for name in live
                 if key_of_worker(name) and role_of_worker(name) == "lead"}
        if len(cards) >= wip or len(live) >= max_agents:
            break
        worker = dispatch_one(cli=cfg.get("dispatchCli"), limit=20, quiet=True)
        if not worker:
            break
        started.append(worker)
    return {"collected": collected, "dispatched": started}


def pool_loop():
    """The detached loop. Config is re-read every tick, on purpose: turning the
    pool off should not require finding and killing a process."""
    write_state({"startedAt": now(), "failures": 0, "paused": False})
    idle_since = time.time()
    # ONCE, BEFORE THE LOOP, not on every tick. Rewriting it each pass was the second
    # half of the start race: two loops took turns owning the file, so pool_alive()
    # reported whichever had written most recently and pool_stop killed that one,
    # leaving the other dispatching with no pid naming it. Writing once keeps a
    # directly-invoked `dispatch.py pool run-loop` discoverable without the fight.
    POOL_PID.write_text(str(os.getpid()), encoding="utf-8")
    while True:
        state = read_state()
        result = pool_once()
        if result.get("error"):
            failures = int(state.get("failures") or 0) + 1
            write_state({"failures": failures, "lastError": result["error"]})
            view_cfg = {}
        else:
            failures = 0
            write_state({"failures": 0, "lastTick": now()})
        view = dispatch_view(1) or {}
        cfg = view.get("config") or {}
        if failures and failures >= int(cfg.get("dispatchMaxFailures") or 3):
            log("pool: %d consecutive failures; pausing" % failures)
            write_state({"paused": True})
            break
        if result.get("dispatched") or result.get("collected"):
            idle_since = time.time()
        idle_exit = int(cfg.get("dispatchIdleExit") or 0)
        if idle_exit and (time.time() - idle_since) > idle_exit * 60:
            log("pool: idle for %d minutes; exiting" % idle_exit)
            break
        time.sleep(max(5, int(cfg.get("dispatchPoll") or 20)))
    POOL_PID.unlink(missing_ok=True)


def pool_start():
    """Start the detached loop, exactly once.

    THIS WAS CHECK-THEN-ACT, AND courier.py ALREADY CARRIED THE FIX FOR IT.

    pool_alive() was consulted, then Popen ran, then the pid was written - seconds
    apart. Two `pool start` calls, or an auto-start racing a manual one, both saw no
    pool, both spawned, and the second write clobbered the first. The courier's own
    pidfile comment describes the identical race: "two parallel spawns both see 'not
    running' and both launch one... EVERY MESSAGE IS DELIVERED TWICE."

    Here it is worse than duplicate delivery: both loops call pool_once ->
    dispatch_one on the same ready card, so one card gets two worktrees and two
    agents, and pool_stop kills only whichever pid the file happens to hold.

    THE FIRST ATTEMPT AT THIS FIX WAS ALSO WRONG, AND TEN CONCURRENT STARTS SAID SO.
    Claiming with O_CREAT|O_EXCL and writing the child pid AFTER Popen leaves the
    file briefly EMPTY. pool_alive() cannot parse an empty file, returns None, and
    every loser reads that as a stale pidfile, unlinks it and claims again - eight of
    ten starts won. The window shrank from seconds to microseconds and the bug
    survived, which is the whole reason the concurrent case gets a test.

    So the pidfile is never empty while claimed: our own pid goes in the instant the
    claim succeeds, and it stays there until the child's pid replaces it. A loser
    then reads a live pid and stands down. And the takeover path distinguishes the
    two reasons pool_alive() says None - an unreadable file is a claim in progress
    and must be respected; only a parseable pid that is genuinely gone is stale.
    """
    DISPATCH_DIR.mkdir(parents=True, exist_ok=True)

    def claim():
        fd = os.open(POOL_PID, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        # Ours immediately, so the file is never a readable-but-empty invitation.
        os.write(fd, str(os.getpid()).encode())
        return fd

    try:
        fd = claim()
    except FileExistsError:
        existing = pool_alive()
        if existing:
            return "pool already running (pid %d)" % existing
        try:
            held = POOL_PID.read_text(encoding="utf-8").strip()
        except OSError:
            held = ""
        if not held.isdigit():
            # Empty or half-written: another starter is claiming right now. Taking it
            # over is exactly the bug above.
            return "another pool start is claiming the pidfile"
        POOL_PID.unlink(missing_ok=True)
        try:
            fd = claim()
        except (OSError, FileExistsError):
            return "another pool start won the race"

    try:
        handle = POOL_LOG.open("a", encoding="utf-8")
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "pool", "run-loop"],
            stdout=handle, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)
    except BaseException:
        # Never leave a claimed pidfile behind for a pool that did not start.
        os.close(fd)
        POOL_PID.unlink(missing_ok=True)
        raise

    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, str(process.pid).encode())
    os.close(fd)
    return "pool started (pid %d), log %s" % (process.pid, POOL_LOG)

def pool_stop():
    pid = pool_alive()
    if not pid:
        POOL_PID.unlink(missing_ok=True)
        return "no pool running"
    try:
        os.kill(pid, 15)
    except OSError as err:
        return "could not stop pid %d: %s" % (pid, err)
    POOL_PID.unlink(missing_ok=True)
    return "pool stopped (pid %d)" % pid


def pool_status():
    view = dispatch_view(20) or {}
    cfg = view.get("config") or {}
    running = dispatched_now()
    state = read_state()
    return {
        "pid": pool_alive(),
        "enabled": bool(cfg.get("dispatchEnabled")),
        "wip": cfg.get("dispatchWip"),
        "workers": running,
        "ready": [task["id"] for task in view.get("tasks") or []],
        "paused": bool(state.get("paused")),
        "failures": state.get("failures") or 0,
        "log": str(POOL_LOG),
    }


# ── CLI ──────────────────────────────────────────────────────────────────────

def cmd_dispatch(args):
    worker = dispatch_one(args.id, args.cli, args.dry_run)
    return 0 if worker else 1


def cmd_collect(args):
    if args.id:
        result = collect_one(args.id)
        if result is None:
            return 1
        print("%s: %s" % (result["id"], result["outcome"]))
        return 0
    results = collect_all()
    if not results:
        print("nothing in flight")
    for result in results:
        print("%s: %s" % (result["id"], result["outcome"]))
    return 0


def cmd_pool(args):
    action = args.action
    if action == "run-loop":                 # internal: what pool_start execs
        global _STDOUT_IS_LOG
        _STDOUT_IS_LOG = True                # stdout is already POOL_LOG; see log()
        pool_loop()
        return 0
    if action == "once":
        result = pool_once()
        if result.get("disabled"):
            print("pool: dispatch is off "
                  "(agentmux board config dispatchEnabled true)")
        print(json.dumps(result, indent=2))
        return 0
    if action == "start":
        print(pool_start())
        return 0
    if action == "stop":
        print(pool_stop())
        return 0
    if action == "resume":
        write_state({"paused": False, "failures": 0})
        print("pool brake released")
        return 0
    status = pool_status()
    if args.json:
        print(json.dumps(status, indent=2))
        return 0
    print("pool:     %s" % ("running (pid %d)" % status["pid"] if status["pid"]
                            else "not running"))
    print("dispatch: %s" % ("on" if status["enabled"] else "off"))
    print("workers:  %d/%s  %s" % (len(status["workers"]), status["wip"],
                                   ", ".join(sorted(status["workers"])) or "-"))
    print("ready:    %s" % (", ".join(status["ready"]) or "-"))
    if status["paused"]:
        print("PAUSED after %d failures - agentmux pool resume" % status["failures"])
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="board-to-agent dispatch")
    sub = parser.add_subparsers(dest="command", required=True)

    one = sub.add_parser("dispatch", help="hand one ready card to a fresh agent")
    one.add_argument("id", nargs="?", default=None, help="TM-014; default is the top of the queue")
    one.add_argument("--cli", default=None)
    one.add_argument("--dry-run", action="store_true")
    one.set_defaults(func=cmd_dispatch)

    gather = sub.add_parser("collect", help="reconcile dispatched cards; never closes one")
    gather.add_argument("id", nargs="?", default=None)
    gather.add_argument("--all", action="store_true")
    gather.set_defaults(func=cmd_collect)

    pool = sub.add_parser("pool", help="the pickup loop")
    pool.add_argument("action", nargs="?", default="status",
                      choices=("once", "start", "stop", "status", "resume", "run-loop"))
    pool.add_argument("--json", action="store_true")
    pool.set_defaults(func=cmd_pool)

    status = sub.add_parser("status", help="what is dispatched right now")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_pool, action="status")

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except coordination.TmuxUnavailable as err:
        log(str(err))
        return 2


if __name__ == "__main__":
    sys.exit(main())
