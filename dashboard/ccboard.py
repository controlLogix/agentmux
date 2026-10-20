"""The task-management domain: keys, the full task record, gates and queries.

WHY THIS FILE EXISTS
--------------------
The Control Center board stored a title, a status, an agent and an integer primary
key. That is a list, not a task management system. An integer primary key is not an
identifier anybody can say out loud, write in a commit message, or put in a branch
name - it is a row number, it is not stable across a restore from backup, and two
boards both have a task 7.

This mirrors the identifier and record model of the bytedesk-marketplace
`task-management` plugin (ByteDeskAI/bytedesk-marketplace), which solves exactly
that: every entity carries a minted, zero-padded, never-reused key - EP-001,
TM-014, ADR-0007, SP-002, CAP-0003 - and a record rich enough that the key is worth
having. Same prefixes, same padding, same status vocabulary, same gate semantics.

WHAT IS DELIBERATELY DIFFERENT
------------------------------
Upstream persists one markdown file per entity and derives an index. Here the store
is SQLite in `cc.db`, because that is what every existing Control Center endpoint,
the CLI and the test suites already read, and because `dashboard/SPEC_CC.md` binds
this project to the Python 3 standard library with no pip. So:

  * `nextId` reads a directory for max+1 under a file lock. Here a `board_counters`
    row is bumped inside the same transaction as the insert, which is stronger:
    the number cannot be handed out twice even under concurrent writers, and it is
    never reused after a delete because the counter only ever moves forward.
  * Upstream soft-deletes by writing `status: deleted` into the file. That is kept
    exactly - `delete` sets the status, the row stays, and the key stays burned.

The vocabularies below are the upstream ones verbatim. They are duplicated in
app.js and in coordination.py; all three must agree or a value one accepts is
rejected by another, which is the failure smoke.sh already guards for statuses.
"""

import datetime as dt
import json
import os
import re


# ── vocabulary ───────────────────────────────────────────────────────────────
#
# lib/paths.mjs KINDS, verbatim: prefix and zero-padding width.
KINDS = {
    "epic": ("EP", 3),
    "task": ("TM", 3),
    "adr": ("ADR", 4),
    "sprint": ("SP", 3),
    "capability": ("CAP", 4),
}
KEY_RE = re.compile(r"^(EP|TM|ADR|SP|CAP)-([0-9]{3,9})$")

# dashboard/src/lib/types.ts Status. One vocabulary for every kind, as upstream.
STATUSES = ("backlog", "open", "in_progress", "blocked", "parked", "done", "deleted")
RESOLVED = frozenset(("done", "deleted"))
# lib/store.mjs PRIORITIES - most urgent first; the queue order reads this.
PRIORITIES = ("highest", "high", "medium", "low", "lowest")
# lib/issue.mjs TYPES. `subtask` is not a type - parentage is the `parent` field.
TYPES = ("task", "bug", "story", "spike", "chore")
ADR_STATUSES = ("proposed", "accepted", "superseded")
LINK_TYPES = ("relates", "duplicates", "blocks", "causes", "implements")
CAP_LEVELS = ("high", "medium", "low")

# lib/completeness.mjs
TRIAGE_LABELS = ("needs-triage", "needs-info", "ready-for-agent", "ready-for-human", "wontfix")
DECISION_MAP = "decision:map"
DECISION_KIND = ("decision:interview", "decision:research", "decision:prototype", "decision:unblock")
# Labels that hand the next move to a person. decision:research is absent on
# purpose: it is the one decision an agent can answer on its own.
NOT_FOR_AGENTS = ("ready-for-human", "needs-info", "wontfix", "human-gate",
                  "decision:interview", "decision:prototype", "decision:unblock", DECISION_MAP)
LABEL_CATALOG = tuple(sorted(set(TRIAGE_LABELS) | set(DECISION_KIND) | {DECISION_MAP, "human-gate"}))

# The status an entity is born in, per kind. Upstream stamps `status: "open"` in
# create() for everything and lets the ADR verb override it.
BIRTH_STATUS = {"epic": "open", "task": "open", "adr": "proposed",
                "sprint": "open", "capability": "open"}

MAX_TITLE = 256
# The HTTP surface caps a request body at four digits of Content-Length
# (server.py read_cc_body), so a markdown body larger than this could be
# stored but never posted. The limit is set where it can actually be met.
MAX_BODY = 8192
MAX_TEXT = 8192
MAX_REF = 512
MAX_LIST = 200
NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
LABEL_RE = re.compile(r"[A-Za-z0-9_.:-]{1,48}")
PATH_RE = re.compile(r"[^\x00-\x1f]{1,512}")

# lib/config defaults. Stored per board in board_config so a project can change
# them; the names are upstream's so a reader of either codebase recognises them.
DEFAULT_CONFIG = {
    "requireOnCreate": ["body", "acceptance"],
    "requireOnStart": ["body", "acceptance"],
    "requireOnDone": ["body", "acceptance", "evidence", "actor"],
    "requireAcceptance": True,
    "requireEpic": True,
    "wipLimit": 3,
    "autoCloseEpic": True,
    "autoReady": "label",
    # ── dispatch ─────────────────────────────────────────────────────────────
    #
    # The board decides what may be handed to an agent; agentmux decides how to
    # run one. These settings are the seam. They live here rather than in a
    # dispatcher-local file for the same reason the gates do: a policy the board
    # cannot see is a policy the board cannot enforce, and `doctor` should be
    # able to report on it.
    #
    # dispatchEnabled is OFF by default, deliberately. Spawning agent processes
    # that write to a repository is not something a fresh checkout should start
    # doing because a server came up.
    "dispatchEnabled": False,
    "dispatchWip": 3,
    "dispatchPoll": 20,
    "dispatchIdleExit": 30,
    "dispatchMaxFailures": 3,
    "dispatchCli": "codex",
    "teamMaxAgents": 8,
    "teamMaxWorkers": 2,
    "teamRequireApproval": True,
    "dashboardMayHire": False,
    # ── the CCC orchestrator ─────────────────────────────────────────────────
    #
    # OFF by default, for the same reason dispatchEnabled is: an LLM that opens runs,
    # spawns agents and closes cards is not something a fresh checkout should start
    # doing because a server came up.
    #
    # Deliberately NOT here: orchestratorCli, model and posture. Those come from the
    # on-disk agent definition via agentdefs.resolve(), because `hire`'s bound is
    # "only id and name are read from the wire" - a config key that overrode the
    # definition would make that bound decorative. Nor orchestratorWip: one
    # orchestrator at a time is an INVARIANT enforced against live_agents(), and a
    # fourth number that can disagree with dispatchWip and the slot semaphore is a
    # bug generator.
    "orchestratorEnabled": False,
    "orchestratorAgent": "",
    "orchestratorScope": "goal",
    "orchestratorNotify": True,
    "orchestratorNotifyCommand": "",
}
CONFIG_BOOLS = {"requireAcceptance", "requireEpic", "autoCloseEpic", "dispatchEnabled",
                "teamRequireApproval", "dashboardMayHire", "orchestratorEnabled",
                "orchestratorNotify"}
CONFIG_LISTS = {"requireOnCreate", "requireOnStart", "requireOnDone"}
# name -> (low, high). Whole numbers, bounded where an unbounded one would be a
# denial of service against this machine rather than a configuration choice.
CONFIG_NUMBERS = {"wipLimit": (0, 999), "dispatchWip": (0, 32),
                  "dispatchPoll": (5, 3600), "dispatchIdleExit": (0, 1440),
                  "dispatchMaxFailures": (1, 99),
                  "teamMaxAgents": (1, 32), "teamMaxWorkers": (0, 8)}
CONFIG_CLIS = {"dispatchCli"}
# The dispatch half of the config, as one list, so a caller that only wants
# the dispatcher's policy does not have to know which names those are.
DISPATCH_KEYS = ("dispatchEnabled", "dispatchWip", "dispatchPoll",
                 "dispatchIdleExit", "dispatchMaxFailures",
                 "dispatchCli")
# The same idea for the orchestrator, so `doctor` can ask for this policy without
# knowing which names carry it.
ORCHESTRATOR_KEYS = ("orchestratorEnabled", "orchestratorAgent", "orchestratorScope",
                     "orchestratorNotify", "orchestratorNotifyCommand")
# Enrolled orchestration reads this separate closed policy collection. The legacy
# scalar keys above remain visible during migration, but they are presentation and
# compatibility settings; they never select a user, project, resource or environment.
ORCHESTRATOR_POLICIES = "orchestratorPolicies"
# An agent NAME, which may be empty - the definition is resolved from disk, and an
# empty value means "use the default".
CONFIG_NAMES = {"orchestratorAgent"}
# A shell command the operator typed, run with the notice on stdin. Bounded in length
# only: it is never parsed here, and notify.py splits it once with shlex and runs it
# with shell=False, so nothing in a notice can introduce metacharacters.
CONFIG_FREETEXT = {"orchestratorNotifyCommand"}
# The CLI name reaches `agentmux spawn --cli`, which puts it in a launch command.
# A subset of what spawn accepts, chosen so nothing here can carry shell syntax.
CLI_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")


class Invalid(ValueError):
    """A request that is malformed. Carries a message safe to return to a client."""


class NotFound(Exception):
    pass


class Refused(Exception):
    """A gate said no. `missing` names the gaps and the verb that fills each one."""

    def __init__(self, message, missing=None):
        super().__init__(message)
        self.missing = missing or []


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


# ── schema ───────────────────────────────────────────────────────────────────
#
# The existing `epics` and `tasks` tables are EXTENDED rather than replaced. Every
# endpoint, the CLI and four test suites already read them by name; a parallel set
# of tables would have meant two answers to "what is on the board" and a sync path
# between them, which is the drift upstream's index.json is careful to make
# disposable. The columns added here are the upstream frontmatter fields, one
# column per scalar, one child table per list.
NEW_TABLES = (
    # A key is minted by bumping this row inside the inserting transaction. The
    # counter only ever moves forward, so a deleted key is never handed out again.
    """CREATE TABLE IF NOT EXISTS board_counters (
        prefix TEXT PRIMARY KEY, last INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS adrs (
        id INTEGER PRIMARY KEY, key TEXT UNIQUE, title TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'proposed', body TEXT NOT NULL DEFAULT '',
        epic_key TEXT, deciders TEXT, supersedes TEXT, decision_key TEXT,
        created_at TEXT, updated_at TEXT, closed_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS sprints (
        id INTEGER PRIMARY KEY, key TEXT UNIQUE, title TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open', body TEXT NOT NULL DEFAULT '',
        ends TEXT, created_at TEXT, updated_at TEXT, closed_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS capabilities (
        id INTEGER PRIMARY KEY, key TEXT UNIQUE, title TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open', body TEXT NOT NULL DEFAULT '',
        area TEXT, impact TEXT, effort TEXT, confidence TEXT, source TEXT,
        task_key TEXT, shipped TEXT, dropped_reason TEXT,
        created_at TEXT, updated_at TEXT, closed_at TEXT)""",
    # ── the list-valued fields ───────────────────────────────────────────────
    # Polymorphic on the entity KEY, not on a table-and-id pair: a key already
    # says which kind it belongs to (that is what the prefix is for), so one
    # child table serves every kind and `kind_of(key)` is the only lookup.
    """CREATE TABLE IF NOT EXISTS board_acceptance (
        id INTEGER PRIMARY KEY, entity_key TEXT NOT NULL, position INTEGER NOT NULL,
        text TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, at TEXT)""",
    """CREATE TABLE IF NOT EXISTS board_labels (
        entity_key TEXT NOT NULL, label TEXT NOT NULL, at TEXT,
        PRIMARY KEY (entity_key, label))""",
    """CREATE TABLE IF NOT EXISTS board_deps (
        entity_key TEXT NOT NULL, blocked_by TEXT NOT NULL, at TEXT,
        PRIMARY KEY (entity_key, blocked_by))""",
    """CREATE TABLE IF NOT EXISTS board_evidence (
        id INTEGER PRIMARY KEY, entity_key TEXT NOT NULL, ref TEXT NOT NULL, at TEXT)""",
    """CREATE TABLE IF NOT EXISTS board_commits (
        id INTEGER PRIMARY KEY, entity_key TEXT NOT NULL, ref TEXT NOT NULL, at TEXT)""",
    """CREATE TABLE IF NOT EXISTS board_touches (
        entity_key TEXT NOT NULL, path TEXT NOT NULL, at TEXT,
        PRIMARY KEY (entity_key, path))""",
    """CREATE TABLE IF NOT EXISTS board_roster (
        id INTEGER PRIMARY KEY,
        entity_key TEXT NOT NULL, agent_name TEXT NOT NULL,
        role TEXT NOT NULL, position INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'proposed', member_name TEXT,
        worktree TEXT, branch TEXT, proposed_by TEXT, approved_by TEXT,
        approved_at TEXT, at TEXT NOT NULL, updated_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS board_roster_definitions (
        roster_id INTEGER PRIMARY KEY REFERENCES board_roster(id) ON DELETE CASCADE,
        project_root TEXT NOT NULL, spec_json TEXT NOT NULL)""",
    "CREATE UNIQUE INDEX IF NOT EXISTS board_roster_slot ON board_roster(entity_key, agent_name)",
    "CREATE INDEX IF NOT EXISTS board_roster_entity ON board_roster(entity_key, position)",
    """CREATE TABLE IF NOT EXISTS board_comments (
        id INTEGER PRIMARY KEY, entity_key TEXT NOT NULL, author TEXT,
        at TEXT NOT NULL, text TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS board_links (
        id INTEGER PRIMARY KEY, entity_key TEXT NOT NULL, link_type TEXT NOT NULL,
        target TEXT NOT NULL, at TEXT)""",
    # events.jsonl, in a table. Append-only, like `journal`: it is the audit log,
    # and `tasks history` and the task inspector's History section read it.
    """CREATE TABLE IF NOT EXISTS board_history (
        id INTEGER PRIMARY KEY, at TEXT NOT NULL, entity_key TEXT,
        event TEXT NOT NULL, actor TEXT, session TEXT, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS board_config (
        name TEXT PRIMARY KEY, value TEXT NOT NULL)""",
    # state.json: active epic, active sprint, the one-shot gate override.
    """CREATE TABLE IF NOT EXISTS board_state (
        name TEXT PRIMARY KEY, value TEXT NOT NULL, at TEXT)""",
)

NEW_INDEXES = (
    "CREATE UNIQUE INDEX IF NOT EXISTS board_tasks_key ON tasks(key)",
    "CREATE INDEX IF NOT EXISTS board_hist_entity ON board_history(entity_key, id)",
    "CREATE INDEX IF NOT EXISTS board_acc_entity ON board_acceptance(entity_key, position)",
    "CREATE INDEX IF NOT EXISTS board_ev_entity ON board_evidence(entity_key, id)",
    "CREATE INDEX IF NOT EXISTS board_cm_entity ON board_comments(entity_key, id)",
)

# column name -> DDL type, added to an existing table if absent.
EPIC_COLUMNS = {"body": "TEXT NOT NULL DEFAULT ''", "plan": "TEXT",
                "closed_at": "TEXT", "actor": "TEXT"}
TASK_COLUMNS = {
    "key": "TEXT", "body": "TEXT NOT NULL DEFAULT ''", "type": "TEXT",
    "priority": "TEXT", "estimate": "REAL", "rank": "REAL", "actor": "TEXT",
    "session": "TEXT", "branch": "TEXT", "worktree": "TEXT",
    "blocked_reason": "TEXT", "parked_reason": "TEXT", "triaged_by": "TEXT",
    "goal_doc": "TEXT", "sprint_key": "TEXT", "parent_key": "TEXT",
    "capability_key": "TEXT", "closed_at": "TEXT",
}

# The rows already on the board were written against the old vocabulary. Mapping
# is recorded in board_history, so a status that was `archived` is not silently
# rewritten with no trace of what it was.
STATUS_MIGRATION = {"todo": "open", "cancelled": "deleted", "archived": "done"}


def columns(db, table):
    return {row[1] for row in db.execute("PRAGMA table_info(" + table + ")")}


def migrate(db):
    """Bring a Control Center database up to the task-management schema.

    Idempotent and safe on an empty database: every statement is IF NOT EXISTS or
    guarded by a PRAGMA read, so this runs on every connection the way the base
    schema already does. It does three things a plain CREATE cannot:

      1. adds the upstream frontmatter columns to `epics` and `tasks`,
      2. mints a key for every row that has none - in id order, so the oldest
         epic is EP-001 and the numbering reads as a history rather than a
         shuffle,
      3. maps the retired status words onto the upstream vocabulary.
    """
    for statement in NEW_TABLES:
        db.execute(statement)
    have = columns(db, "epics")
    for name, ddl in EPIC_COLUMNS.items():
        if name not in have:
            db.execute("ALTER TABLE epics ADD COLUMN " + name + " " + ddl)
    have = columns(db, "tasks")
    for name, ddl in TASK_COLUMNS.items():
        if name not in have:
            db.execute("ALTER TABLE tasks ADD COLUMN " + name + " " + ddl)
    for statement in NEW_INDEXES:
        db.execute(statement)
    _migrate_statuses(db)
    _backfill_keys(db)
    _seed_config(db)


def _migrate_statuses(db):
    stamp = now()
    for table, kind in (("epics", "epic"), ("tasks", "task")):
        for old, new in STATUS_MIGRATION.items():
            rows = db.execute(
                "SELECT id,key,status FROM " + table + " WHERE status=?", (old,)).fetchall()
            if not rows:
                continue
            db.execute("UPDATE " + table + " SET status=? WHERE status=?", (new, old))
            for row in rows:
                _record(db, row["key"], "status-migrated", "migration", None,
                        {"kind": kind, "row": row["id"], "from": old, "to": new})


def _backfill_keys(db):
    """Mint a key for every pre-existing row, oldest first.

    An epic may already carry a `key` - the column predates this and took free
    text, typically a Jira-ish project tag. A value that is already a well-formed
    EP key is kept. Anything else is replaced and the previous value recorded in
    board_history as `rekeyed`, because two epics called PLATFORM is exactly the
    collision a minted key exists to prevent, and silently discarding what
    somebody typed is worse than replacing it loudly.
    """
    for table, kind in (("epics", "epic"), ("tasks", "task"), ("adrs", "adr"),
                        ("sprints", "sprint"), ("capabilities", "capability")):
        prefix = KINDS[kind][0]
        rows = db.execute("SELECT id,key FROM " + table + " ORDER BY id").fetchall()
        pending = []
        for row in rows:
            existing = row["key"]
            if isinstance(existing, str):
                match = KEY_RE.match(existing)
                if match and match.group(1) == prefix:
                    _observe(db, prefix, int(match.group(2)))
                    continue
            pending.append((row["id"], existing))
        # Observed numbers are absorbed before any is minted, so a board that
        # already holds EP-007 never hands EP-007 to the row next to it.
        for row_id, existing in pending:
            key = mint(db, kind)
            db.execute("UPDATE " + table + " SET key=? WHERE id=?", (key, row_id))
            _record(db, key, "rekeyed" if existing else "keyed", "migration", None,
                    {"kind": kind, "row": row_id, "was": existing})


def _observe(db, prefix, seq):
    """Never hand out a number at or below one already in use."""
    db.execute("INSERT INTO board_counters (prefix,last) VALUES (?,?)"
               " ON CONFLICT(prefix) DO UPDATE SET last=MAX(last,excluded.last)",
               (prefix, seq))


def _seed_config(db):
    for name, value in DEFAULT_CONFIG.items():
        db.execute("INSERT OR IGNORE INTO board_config (name,value) VALUES (?,?)",
                   (name, json.dumps(value)))


def mint(db, kind):
    """The next key for `kind`, reserved by the same transaction that will use it.

    This is the whole reason the board can be addressed. Upstream takes max+1 from
    a directory listing under a file lock, having measured eight concurrent creates
    minting three duplicate ids without it. A counter row bumped inside the
    caller's transaction is the same guarantee without the lock file: SQLite
    serialises the write, so two racing creates get two numbers.
    """
    if kind not in KINDS:
        raise Invalid("unknown kind: " + str(kind))
    prefix, pad = KINDS[kind]
    db.execute("INSERT OR IGNORE INTO board_counters (prefix,last) VALUES (?,0)", (prefix,))
    db.execute("UPDATE board_counters SET last=last+1 WHERE prefix=?", (prefix,))
    seq = db.execute("SELECT last FROM board_counters WHERE prefix=?", (prefix,)).fetchone()[0]
    return prefix + "-" + str(seq).zfill(pad)


def kind_of(key):
    """Which kind a key belongs to, or None.

    Takes anything: plenty of history rows carry no key at all, and callers should
    not have to guard before asking."""
    if not isinstance(key, str):
        return None
    match = KEY_RE.match(key)
    if not match:
        return None
    for kind, (prefix, _) in KINDS.items():
        if match.group(1) == prefix:
            return kind
    return None


TABLE_OF = {"epic": "epics", "task": "tasks", "adr": "adrs",
            "sprint": "sprints", "capability": "capabilities"}


def _record(db, key, event, actor=None, session=None, detail=None):
    """One row in the audit log. Never raises on a detail that will not encode."""
    try:
        blob = json.dumps(detail, allow_nan=False) if detail is not None else None
    except (TypeError, ValueError, RecursionError):
        blob = None
    db.execute("INSERT INTO board_history (at,entity_key,event,actor,session,detail)"
               " VALUES (?,?,?,?,?,?)", (now(), key, event, actor, session, blob))


# ── validation ───────────────────────────────────────────────────────────────
#
# Every value that reaches a write goes through one of these. They reject rather
# than coerce, and their messages name the field and the bound without ever
# echoing what was submitted, so a rejection is safe to return over HTTP.

def text(value, name, maximum=MAX_TEXT, required=False, pattern=None, choices=None):
    if value is None:
        if required:
            raise Invalid("missing " + name)
        return None
    if not isinstance(value, str):
        raise Invalid("invalid " + name)
    if len(value) > maximum:
        raise Invalid(name + " is longer than " + str(maximum) + " characters")
    if "\x00" in value or any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise Invalid("invalid " + name)
    if required and not value.strip():
        raise Invalid("missing " + name)
    if pattern is not None and value and not pattern.fullmatch(value):
        raise Invalid("invalid " + name)
    if choices is not None and value not in choices:
        raise Invalid(name + " must be one of: " + ", ".join(choices))
    return value


def key_field(value, name="key", kind=None, required=False):
    """A board key, optionally constrained to one kind. `none` clears a reference."""
    if value is None or value == "":
        if required:
            raise Invalid("missing " + name)
        return None
    if value == "none":
        return None
    if not isinstance(value, str) or not KEY_RE.match(value):
        raise Invalid(name + " must be a board key such as TM-014")
    found = kind_of(value)
    if kind is not None and found != kind:
        raise Invalid(name + " must be a " + kind + " key")
    return value


def number(value, name, low, high, integer=False):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Invalid("invalid " + name)
    if integer and int(value) != value:
        raise Invalid(name + " must be a whole number")
    if not low <= value <= high:
        raise Invalid(name + " must be between " + str(low) + " and " + str(high))
    return int(value) if integer else float(value)


def string_list(value, name, pattern=None, maximum=MAX_REF):
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > MAX_LIST:
        raise Invalid("invalid " + name)
    return [text(item, name, maximum, required=True, pattern=pattern) for item in value]


# ── config and state ─────────────────────────────────────────────────────────

def config(db):
    """The gate policy, defaults merged with whatever this board overrode."""
    out = dict(DEFAULT_CONFIG)
    for row in db.execute("SELECT name,value FROM board_config"):
        if row["name"] not in DEFAULT_CONFIG:
            continue
        try:
            out[row["name"]] = json.loads(row["value"])
        except ValueError:
            pass
    return out


def set_config(db, name, value, actor=None):
    if name not in DEFAULT_CONFIG:
        raise Invalid("unknown setting: " + str(name)[:40])
    if name in CONFIG_BOOLS:
        if not isinstance(value, bool):
            raise Invalid(name + " must be true or false")
    elif name in CONFIG_LISTS:
        known = ("body", "acceptance", "evidence", "actor")
        if not isinstance(value, list) or any(item not in known for item in value):
            raise Invalid(name + " must be a list drawn from: " + ", ".join(known))
    elif name in CONFIG_NUMBERS:
        low, high = CONFIG_NUMBERS[name]
        value = number(value, name, low, high, integer=True)
    elif name in CONFIG_CLIS:
        value = text(value, name, 32, required=True, pattern=CLI_RE)
    elif name == "autoReady":
        value = text(value, name, 16, required=True, choices=("label", "off"))
    elif name == "orchestratorScope":
        value = text(value, name, 16, required=True,
                     choices=("goal", "epic", "queue"))
    elif name in CONFIG_NAMES:
        value = text(value, name, 64, required=False, pattern=NAME_RE) or ""
    elif name in CONFIG_FREETEXT:
        value = text(value, name, 500) or ""
    db.execute("INSERT INTO board_config (name,value) VALUES (?,?)"
               " ON CONFLICT(name) DO UPDATE SET value=excluded.value",
               (name, json.dumps(value)))
    _record(db, None, "config", actor, None, {"name": name, "value": value})
    return {name: value}


def _orchestration_ref(value):
    return (isinstance(value, dict) and set(value) == {"id", "ownerHubId", "revision"}
            and all(isinstance(value[key], str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,95}", value[key])
                    for key in ("id", "ownerHubId"))
            and isinstance(value["revision"], int) and not isinstance(value["revision"], bool)
            and 0 <= value["revision"] <= 9_007_199_254_740_991)


def _orchestration_policy(value):
    """Validate behavior selected for one enrolled project policy resource."""
    fields = {"resourceRef", "scope", "environmentRef", "enabled", "agent",
              "workScope", "notify", "notifyCommand"}
    if not isinstance(value, dict) or set(value) != fields:
        raise Invalid("invalid scoped orchestration policy")
    scope = value["scope"]
    if (not isinstance(scope, dict)
            or set(scope) != {"organizationId", "projectId", "workspaceId"}
            or not all(isinstance(scope[key], str)
                       and re.fullmatch(r"[a-z][a-z0-9_-]{0,95}", scope[key])
                       for key in ("organizationId", "projectId"))
            or scope["workspaceId"] is not None
            and (not isinstance(scope["workspaceId"], str)
                 or not re.fullmatch(r"[a-z][a-z0-9_-]{0,95}", scope["workspaceId"]))
            or not _orchestration_ref(value["resourceRef"])
            or value["environmentRef"] is not None
            and not _orchestration_ref(value["environmentRef"])
            or value["environmentRef"] is not None
            and value["environmentRef"]["ownerHubId"] != value["resourceRef"]["ownerHubId"]
            or type(value["enabled"]) is not bool or type(value["notify"]) is not bool):
        raise Invalid("invalid scoped orchestration policy")
    agent = text(value["agent"], "agent", 64, required=False, pattern=NAME_RE) or ""
    work_scope = text(value["workScope"], "workScope", 16, required=True,
                      choices=("goal", "epic", "queue"))
    notify_command = text(value["notifyCommand"], "notifyCommand", 500) or ""
    return {**value, "scope": dict(scope), "resourceRef": dict(value["resourceRef"]),
            "environmentRef": (None if value["environmentRef"] is None
                               else dict(value["environmentRef"])),
            "agent": agent, "workScope": work_scope, "notifyCommand": notify_command}


def orchestration_policies(db):
    """Return explicit enrolled policies; legacy global scalars never become authority."""
    row = db.execute("SELECT value FROM board_config WHERE name=?",
                     (ORCHESTRATOR_POLICIES,)).fetchone()
    if row is None:
        return []
    try:
        values = json.loads(row["value"])
        if not isinstance(values, list) or len(values) > 64:
            raise ValueError()
        policies = [_orchestration_policy(value) for value in values]
        keys = [(json.dumps(item["scope"], sort_keys=True),
                 json.dumps(item["environmentRef"], sort_keys=True)) for item in policies]
        if len(keys) != len(set(keys)):
            raise ValueError()
        return policies
    except (ValueError, TypeError, Invalid):
        raise Invalid("invalid retained scoped orchestration policy") from None


def set_orchestration_policies(db, values, actor):
    """Replace the explicit policy set after the enrolled owner authorizes the write."""
    if not isinstance(values, list) or len(values) > 64 or not actor:
        raise Invalid("invalid scoped orchestration policy")
    policies = [_orchestration_policy(value) for value in values]
    keys = [(json.dumps(item["scope"], sort_keys=True),
             json.dumps(item["environmentRef"], sort_keys=True)) for item in policies]
    if len(keys) != len(set(keys)):
        raise Invalid("duplicate scoped orchestration policy")
    db.execute("INSERT INTO board_config (name,value) VALUES (?,?)"
               " ON CONFLICT(name) DO UPDATE SET value=excluded.value",
               (ORCHESTRATOR_POLICIES, json.dumps(policies, separators=(",", ":"))))
    _record(db, None, "config", actor, None,
            {"name": ORCHESTRATOR_POLICIES, "count": len(policies)})
    return policies


STATE_NAMES = ("activeEpic", "activeSprint", "override")


def state(db):
    out = {"activeEpic": None, "activeSprint": None, "override": None}
    for row in db.execute("SELECT name,value FROM board_state"):
        if row["name"] in out:
            try:
                out[row["name"]] = json.loads(row["value"])
            except ValueError:
                pass
    return out


def set_state(db, name, value, actor=None):
    """Board-wide state: the active epic, the active sprint, the armed override.

    TWO THINGS THIS DID NOT DO, AND BOTH MATTER MORE HERE THAN ALMOST ANYWHERE.

    It took no actor and wrote no history row - the only board write of the twenty-odd
    in this module that left no trace at all. set_config, which is the same shape, has
    always recorded one. So `activeEpic` could be repointed, changing the epic every
    later `task new` files into, and nothing anywhere said who did it or when.

    And it never checked the destination existed. A well-formed key for an epic that
    is not there is accepted, and then every `task new` without an explicit --epic
    hits _resolve_epic, raises NotFound and returns 404 - card creation wedged
    board-wide, with no history to explain it. move_task and _resolve_epic both
    already refuse an absent key; this is the same check, taken before the write.
    """
    if name not in STATE_NAMES:
        raise Invalid("unknown state: " + str(name)[:40])
    if value is not None and name in ("activeEpic", "activeSprint"):
        table = "epics" if name == "activeEpic" else "sprints"
        if db.execute(f"SELECT 1 FROM {table} WHERE key=?", (value,)).fetchone() is None:
            raise NotFound("not found: " + str(value)[:40])
    db.execute("INSERT INTO board_state (name,value,at) VALUES (?,?,?)"
               " ON CONFLICT(name) DO UPDATE SET value=excluded.value,at=excluded.at",
               (name, json.dumps(value), now()))
    _record(db, None, "state", actor, None, {"name": name, "value": value})
    return {name: value}


def enforcing(db):
    """Gates are on unless the environment says otherwise.

    Upstream's switch is `TM_ENFORCE=off`. Both names are honoured: a repository
    that already exports the upstream one should not have to learn a second."""
    for name in ("CC_ENFORCE", "TM_ENFORCE"):
        if str(os.environ.get(name, "")).strip().lower() == "off":
            return False
    return True


def set_override(db, reason, actor=None):
    """Arm exactly one bypass, with a reason, logged. Upstream's `tm override`."""
    reason = text(reason, "reason", 256, required=True)
    set_state(db, "override", {"reason": reason, "at": now(), "actor": actor})
    _record(db, None, "override", actor, None, {"reason": reason})
    return state(db)["override"]


def take_override(db):
    """Consume the armed bypass, if there is one. One gate, once."""
    current = state(db)["override"]
    if not current:
        return None
    set_state(db, "override", None)
    _record(db, None, "override-used", None, None, current)
    return current


# ── the record ───────────────────────────────────────────────────────────────
#
# Column names are snake_case because that is how the rest of this schema reads;
# payload names are upstream's camelCase, because the whole point is that a client
# written against either board sees the same shape. The translation is here and
# nowhere else.

def _rows(db, sql, args=()):
    return [dict(row) for row in db.execute(sql, args)]


def acceptance_of(db, key):
    return [{"text": row["text"], "done": bool(row["done"])}
            for row in db.execute("SELECT text,done FROM board_acceptance"
                                  " WHERE entity_key=? ORDER BY position,id", (key,))]


def labels_of(db, key):
    return [row["label"] for row in db.execute(
        "SELECT label FROM board_labels WHERE entity_key=? ORDER BY label", (key,))]


def _simple_list(db, table, column, key):
    # ORDER BY rowid, not id: board_deps and board_touches have a composite
    # primary key and so no `id` column. rowid is on every one of these tables
    # and orders by insertion, which is the order these lists are meant to read in.
    return [row[0] for row in db.execute(
        "SELECT " + column + " FROM " + table + " WHERE entity_key=? ORDER BY rowid", (key,))]


def comments_of(db, key):
    return [{"author": row["author"], "ts": row["at"], "text": row["text"]}
            for row in db.execute("SELECT author,at,text FROM board_comments"
                                  " WHERE entity_key=? ORDER BY id", (key,))]


def links_of(db, key):
    return [{"type": row["link_type"], "id": row["target"]}
            for row in db.execute("SELECT link_type,target FROM board_links"
                                  " WHERE entity_key=? ORDER BY id", (key,))]


def type_of(task):
    """How a task's type is decided - same order as upstream `typeOf`.

    Stored field, then a recognised label (the pre-field encoding), then `task`."""
    stored = task.get("type")
    if stored in TYPES:
        return stored
    for label in task.get("labels") or []:
        low = str(label).lower()
        if low in TYPES and low != "task":
            return low
    return "task"


def _payload_task(db, row):
    key = row["key"]
    out = {
        "id": key, "key": key, "row": row["id"], "kind": "task",
        "title": row["title"], "status": row["status"],
        "epic": None, "epicRow": row["epic_id"],
        "created": row["created_at"], "updated": row["updated_at"],
        "closed": row["closed_at"],
        "acceptance": acceptance_of(db, key), "labels": labels_of(db, key),
        "blockedBy": _simple_list(db, "board_deps", "blocked_by", key),
        "evidence": _simple_list(db, "board_evidence", "ref", key),
        "commits": _simple_list(db, "board_commits", "ref", key),
        "touches": _simple_list(db, "board_touches", "path", key),
        "comments": comments_of(db, key), "links": links_of(db, key),
        "assignee": row["agent"], "actor": row["actor"], "session": row["session"],
        "branch": row["branch"], "worktree": row["worktree"],
        "blockedReason": row["blocked_reason"], "parkedReason": row["parked_reason"],
        "priority": row["priority"], "estimate": row["estimate"], "rank": row["rank"],
        "parent": row["parent_key"], "sprint": row["sprint_key"],
        "capability": row["capability_key"], "goalDoc": row["goal_doc"],
        "triagedBy": row["triaged_by"], "jira_key": row["jira_key"],
        "type": row["type"],
    }
    out["type"] = type_of(out)
    # Always carried, stripped once by board(). The completeness check reads it,
    # and a payload that omits it reads as "no body" - which is how next_tasks
    # came to return an empty queue on a board full of startable work.
    out["body"] = row["body"] or ""
    return out


def _payload_epic(db, row):
    key = row["key"]
    out = {"id": key, "key": key, "row": row["id"], "kind": "epic",
           "title": row["title"], "status": row["status"],
           "created": row["created_at"], "updated": row["updated_at"],
           "closed": row["closed_at"], "plan": row["plan"],
           "labels": labels_of(db, key), "comments": comments_of(db, key),
           "actor": row["actor"], "jira_key": row["jira_key"],
           "notes": row["notes"]}
    out["body"] = row["body"] or ""
    return out


def _payload_adr(db, row):
    key = row["key"]
    deciders = []
    if row["deciders"]:
        try:
            deciders = json.loads(row["deciders"])
        except ValueError:
            deciders = []
    out = {"id": key, "key": key, "row": row["id"], "kind": "adr",
           "title": row["title"], "status": row["status"], "epic": row["epic_key"],
           "created": row["created_at"], "updated": row["updated_at"],
           "date": row["created_at"], "deciders": deciders,
           "supersedes": row["supersedes"], "decisionKey": row["decision_key"],
           "labels": labels_of(db, key)}
    out["body"] = row["body"] or ""
    return out


def _payload_sprint(db, row):
    key = row["key"]
    out = {"id": key, "key": key, "row": row["id"], "kind": "sprint",
           "title": row["title"], "status": row["status"], "ends": row["ends"],
           "created": row["created_at"], "updated": row["updated_at"],
           "closed": row["closed_at"], "labels": labels_of(db, key),
           "report": sprint_counts(db, key)}
    out["body"] = row["body"] or ""
    return out


def _payload_capability(db, row):
    key = row["key"]
    out = {"id": key, "key": key, "row": row["id"], "kind": "capability",
           "title": row["title"], "status": row["status"], "area": row["area"],
           "impact": row["impact"], "effort": row["effort"],
           "confidence": row["confidence"], "source": row["source"],
           "task": row["task_key"], "shipped": row["shipped"],
           "droppedReason": row["dropped_reason"],
           "created": row["created_at"], "updated": row["updated_at"],
           "evidence": _simple_list(db, "board_evidence", "ref", key),
           "labels": labels_of(db, key), "score": capability_score(row)}
    out["body"] = row["body"] or ""
    return out


PAYLOAD = {"task": _payload_task, "epic": _payload_epic, "adr": _payload_adr,
           "sprint": _payload_sprint, "capability": _payload_capability}


def capability_score(row):
    """impact x ease x confidence, 1-27. Derived, never stored - upstream's rule."""
    scale = {"high": 3, "medium": 2, "low": 1}
    ease = {"high": 1, "medium": 2, "low": 3}
    impact = scale.get(row["impact"])
    effort = ease.get(row["effort"])
    confidence = scale.get(row["confidence"])
    if impact is None or effort is None or confidence is None:
        return None
    return impact * effort * confidence


def sprint_counts(db, key):
    """Sized points only. Unsized cards are counted separately and never as zero -
    calling an unestimated card 0 points makes a sprint look finished early."""
    rows = db.execute("SELECT status,estimate FROM tasks WHERE sprint_key=?", (key,)).fetchall()
    committed = 0.0
    done = 0.0
    unsized = 0
    for row in rows:
        if row["estimate"] is None:
            unsized += 1
            continue
        committed += row["estimate"]
        if row["status"] == "done":
            done += row["estimate"]
    return {"cards": len(rows), "committed": committed, "done": done, "unsized": unsized}


def row_for(db, key):
    kind = kind_of(key)
    if kind is None:
        raise Invalid("unknown prefix: " + str(key)[:24])
    row = db.execute("SELECT * FROM " + TABLE_OF[kind] + " WHERE key=?", (key,)).fetchone()
    if row is None:
        raise NotFound("not found: " + key)
    return kind, row


def entity(db, key):
    """One entity in full, body included. The board's list payload is the same
    shape with the body stripped."""
    kind, row = row_for(db, key)
    out = PAYLOAD[kind](db, row)
    if kind == "task" and row["epic_id"] is not None:
        epic = db.execute("SELECT key FROM epics WHERE id=?", (row["epic_id"],)).fetchone()
        out["epic"] = epic["key"] if epic else None
    return out


# ── completeness ─────────────────────────────────────────────────────────────
#
# A task used to be closable with nothing but a status change: no body, no
# criteria, no proof, no name on the work. The board then accumulated cards that
# recorded THAT something happened and nothing else. These are the upstream
# checks (lib/completeness.mjs), and each one names the exact verb that fills the
# gap, so the refusal, the doctor report and the CLI all give the same remedy.

def _empty(value):
    return not str(value or "").strip()


COMPLETENESS = {
    # The body is the context: what and why. A title alone is a rumour.
    "body": (lambda t: _empty(t.get("body")), "agentmux task edit {key} --body"),
    # At least one criterion must EXIST. Whether they are ticked is the done
    # gate's separate requireAcceptance check, which an empty list passes.
    "acceptance": (lambda t: not (t.get("acceptance") or []), 'agentmux task ac {key} "..."'),
    # Proof, not claims: test output, a log path, a screenshot.
    "evidence": (lambda t: not (t.get("evidence") or []), "agentmux task evidence {key} <path>"),
    # Who did the work. `actor` is stamped by start; `assignee` is the stored
    # field. Either one attributes the close.
    "actor": (lambda t: _empty(t.get("actor")) and _empty(t.get("assignee")),
              "agentmux task assign {key} <who>"),
}
SPOKEN = {"acceptance": "acceptance criteria"}


def missing_fields(task, required):
    """The gaps in `task` against a config field list.

    An unknown field name is skipped rather than raised on: a typo in config is
    the doctor's finding to report, not a reason to fail a transition."""
    out = []
    for field in required or []:
        spec = COMPLETENESS.get(field)
        if spec and spec[0](task):
            out.append({"field": field,
                        "hint": spec[1].format(key=task.get("id") or "<id>")})
    return out


def agent_readiness(task, cfg):
    """Is this task specified well enough to hand to an agent?

    Status and dependencies are deliberately not consulted. The label means
    "specified"; whether it is startable right now is a separate question, and
    folding it in would flip the label every time a blocker opened or closed."""
    missing = [SPOKEN.get(item["field"], item["field"])
               for item in missing_fields(task, cfg.get("requireOnStart"))]
    if cfg.get("requireEpic") and not task.get("epic"):
        missing.append("epic")
    labels = task.get("labels") or []
    for label in NOT_FOR_AGENTS:
        if label in labels:
            missing.append("label " + label)
    return {"ready": not missing, "missing": missing}


def triage_sync(db, key, cfg=None):
    """Re-derive the triage label for one task, inside the write that changed it.

    THE HUMAN VETO OUTRANKS THE COMPUTATION, PERMANENTLY. Once a person has set or
    cleared a triage label the task is stamped `triagedBy: human` and this never
    touches it again - no later write and no triage sweep can put a task back in
    the agents' queue after somebody took it out. That is upstream's rule and it
    is the only reason the computed label is safe to run on every write."""
    if kind_of(key) != "task":
        return None
    cfg = cfg if cfg is not None else config(db)
    if cfg.get("autoReady") != "label":
        return None
    row = db.execute("SELECT status,triaged_by FROM tasks WHERE key=?", (key,)).fetchone()
    if row is None or row["status"] in RESOLVED or row["triaged_by"] == "human":
        return None
    task = entity(db, key)
    verdict = agent_readiness(task, cfg)
    wanted = "ready-for-agent" if verdict["ready"] else "needs-triage"
    stale = "needs-triage" if verdict["ready"] else "ready-for-agent"
    db.execute("DELETE FROM board_labels WHERE entity_key=? AND label=?", (key, stale))
    db.execute("INSERT OR IGNORE INTO board_labels (entity_key,label,at) VALUES (?,?,?)",
               (key, wanted, now()))
    db.execute("UPDATE tasks SET triaged_by='auto' WHERE key=?", (key,))
    return {"label": wanted, "missing": verdict["missing"]}


def attach_triage(db, task, cfg):
    if task.get("kind") == "task":
        task["triageMissing"] = agent_readiness(task, cfg)["missing"]
        task["hasAnswer"] = "## Answer" in (task.get("body") or "")
    return task


# ── gates ────────────────────────────────────────────────────────────────────

def _bypassed(db):
    """Is this transition exempt? Enforcement off, or one armed override."""
    if not enforcing(db):
        return {"reason": "enforcement disabled"}
    return take_override(db)


def _refuse(db, message, missing):
    bypass = _bypassed(db)
    if bypass:
        return bypass
    raise Refused(message, missing)


def gate_create(db, draft, cfg, mirror=False):
    """An explicit create carries its own details.

    Mirrors are exempt, as upstream: a native todo list cannot carry a body and
    acceptance criteria, so mirroring stays frictionless and `doctor` reports the
    thin cards instead of the hook refusing them."""
    if mirror:
        return None
    gaps = missing_fields(draft, cfg.get("requireOnCreate"))
    if not gaps:
        return None
    # A create has no key to name yet, so the hint names the create verb and the
    # flag that fills each gap rather than an edit against an id that does not exist.
    flag = {"body": "--body \"what and why\"", "acceptance": "--ac \"the check that closes it\""}
    for gap in gaps:
        gap["hint"] = 'agentmux task new "<title>" ' + flag.get(gap["field"], "--" + gap["field"])
    return _refuse(db, "a new task needs " + " and ".join(g["field"] for g in gaps), gaps)


def gate_start(db, task, cfg, actor=None):
    gaps = missing_fields(task, cfg.get("requireOnStart"))
    if gaps:
        return _refuse(db, task["id"] + " is not specified well enough to start", gaps)
    open_deps = [dep for dep in task.get("blockedBy") or []
                 if _status_of(db, dep) not in RESOLVED]
    if open_deps:
        return _refuse(db, task["id"] + " is blocked by " + ", ".join(open_deps),
                       [{"field": "blockedBy", "hint": "agentmux task dep " + task["id"]
                         + " --clear " + open_deps[0]}])
    limit = cfg.get("wipLimit") or 0
    if limit:
        if actor:
            running = db.execute(
                "SELECT COUNT(*) FROM tasks WHERE status='in_progress' AND actor=? AND key<>?",
                (actor, task["id"])).fetchone()[0]
        else:
            running = db.execute(
                "SELECT COUNT(*) FROM tasks WHERE status='in_progress' AND key<>?",
                (task["id"],)).fetchone()[0]
        if running >= limit:
            return _refuse(db, "WIP limit reached: " + str(running) + " task(s) already in progress"
                           + (" for " + actor if actor else "") + ", limit is " + str(limit),
                           [{"field": "wipLimit",
                             "hint": "finish or park one, or raise wipLimit in board settings"}])
    return None


def gate_done(db, task, cfg):
    gaps = missing_fields(task, cfg.get("requireOnDone"))
    if cfg.get("requireAcceptance"):
        unticked = [item for item in task.get("acceptance") or [] if not item["done"]]
        if unticked:
            gaps.append({"field": "acceptance",
                         "hint": "agentmux task ac " + task["id"] + " --tick <n>"})
    if not gaps:
        return None
    return _refuse(db, task["id"] + " cannot close: missing "
                   + ", ".join(sorted({g["field"] for g in gaps})), gaps)


def _status_of(db, key):
    kind = kind_of(key)
    if kind is None:
        return None
    row = db.execute("SELECT status FROM " + TABLE_OF[kind] + " WHERE key=?", (key,)).fetchone()
    return row["status"] if row else None


# ── creating ─────────────────────────────────────────────────────────────────

def _resolve_epic(db, value, cfg, required):
    """A task's epic, as a key. Falls back to the active epic, which is what
    makes `task new` a one-liner in normal use."""
    if value is None:
        value = state(db)["activeEpic"]
    key = key_field(value, "epic", "epic")
    if key is None:
        if required:
            raise Refused("no epic: open one with `agentmux epic new \"<title>\"`,"
                          " or pass --epic EP-00n",
                          [{"field": "epic", "hint": "agentmux epic new \"<title>\""}])
        return None, None
    row = db.execute("SELECT id,status FROM epics WHERE key=?", (key,)).fetchone()
    if row is None:
        raise NotFound("not found: " + key)
    return key, row["id"]


def create(db, kind, fields, actor=None, session=None, mirror=False):
    """Mint a key and write the entity. The key is reserved by this transaction."""
    if kind not in KINDS:
        raise Invalid("unknown kind: " + str(kind)[:24])
    cfg = config(db)
    stamp = now()
    title = text(fields.get("title"), "title", MAX_TITLE, required=True)
    body = text(fields.get("body"), "body", MAX_BODY) or ""
    acceptance = string_list(fields.get("acceptance"), "acceptance", maximum=MAX_TEXT) or []
    labels = string_list(fields.get("labels"), "labels", pattern=LABEL_RE, maximum=48) or []

    if kind == "task":
        epic_key, epic_id = _resolve_epic(db, fields.get("epic"), cfg, cfg.get("requireEpic"))
        draft = {"id": None, "title": title, "body": body, "epic": epic_key,
                 "acceptance": [{"text": item, "done": False} for item in acceptance],
                 "labels": labels}
        gate_create(db, draft, cfg, mirror)
        key = mint(db, "task")
        db.execute(
            "INSERT INTO tasks (key,epic_id,title,status,agent,jira_key,body,type,priority,"
            "estimate,rank,actor,session,branch,worktree,sprint_key,parent_key,capability_key,"
            "goal_doc,triaged_by,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, epic_id, title, text(fields.get("status"), "status", 16,
                                       choices=STATUSES) or BIRTH_STATUS["task"],
             text(fields.get("assignee"), "assignee", 64, pattern=NAME_RE),
             text(fields.get("jira_key"), "jira_key", 64, pattern=NAME_RE),
             body, text(fields.get("type"), "type", 16, choices=TYPES),
             text(fields.get("priority"), "priority", 16, choices=PRIORITIES),
             number(fields.get("estimate"), "estimate", 0, 10000),
             number(fields.get("rank"), "rank", -1e9, 1e9),
             actor, session,
             text(fields.get("branch"), "branch", 255),
             text(fields.get("worktree"), "worktree", MAX_REF),
             key_field(fields.get("sprint"), "sprint", "sprint"),
             key_field(fields.get("parent"), "parent", "task"),
             key_field(fields.get("capability"), "capability", "capability"),
             text(fields.get("goalDoc"), "goalDoc", MAX_REF),
             "human" if fields.get("human") else None,
             stamp, stamp))
    elif kind == "epic":
        key = mint(db, "epic")
        db.execute(
            "INSERT INTO epics (key,title,status,jira_key,notes,body,plan,actor,"
            "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (key, title, text(fields.get("status"), "status", 16,
                              choices=STATUSES) or BIRTH_STATUS["epic"],
             text(fields.get("jira_key"), "jira_key", 64, pattern=NAME_RE),
             text(fields.get("notes"), "notes", MAX_BODY), body,
             text(fields.get("plan"), "plan", MAX_REF), actor, stamp, stamp))
    elif kind == "adr":
        key = mint(db, "adr")
        deciders = string_list(fields.get("deciders"), "deciders", pattern=NAME_RE, maximum=64)
        db.execute(
            "INSERT INTO adrs (key,title,status,body,epic_key,deciders,supersedes,"
            "decision_key,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (key, title, text(fields.get("status"), "status", 16,
                              choices=ADR_STATUSES) or BIRTH_STATUS["adr"],
             body, key_field(fields.get("epic"), "epic", "epic"),
             json.dumps(deciders) if deciders else None,
             key_field(fields.get("supersedes"), "supersedes", "adr"),
             text(fields.get("decisionKey"), "decisionKey", 64), stamp, stamp))
    elif kind == "sprint":
        key = mint(db, "sprint")
        db.execute(
            "INSERT INTO sprints (key,title,status,body,ends,created_at,updated_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (key, title, text(fields.get("status"), "status", 16,
                              choices=STATUSES) or BIRTH_STATUS["sprint"],
             body, text(fields.get("ends"), "ends", 64), stamp, stamp))
    else:
        key = mint(db, "capability")
        db.execute(
            "INSERT INTO capabilities (key,title,status,body,area,impact,effort,"
            "confidence,source,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (key, title, text(fields.get("status"), "status", 16,
                              choices=STATUSES) or BIRTH_STATUS["capability"],
             body, text(fields.get("area"), "area", 64),
             text(fields.get("impact"), "impact", 16, choices=CAP_LEVELS),
             text(fields.get("effort"), "effort", 16, choices=CAP_LEVELS),
             text(fields.get("confidence"), "confidence", 16, choices=CAP_LEVELS),
             text(fields.get("source"), "source", MAX_REF), stamp, stamp))

    for index, item in enumerate(acceptance):
        db.execute("INSERT INTO board_acceptance (entity_key,position,text,done,at)"
                   " VALUES (?,?,?,0,?)", (key, index, item, stamp))
    for label in labels:
        db.execute("INSERT OR IGNORE INTO board_labels (entity_key,label,at) VALUES (?,?,?)",
                   (key, label, stamp))
    if labels and kind == "task" and not fields.get("human"):
        # A triage label typed at creation is a person's decision, same as one
        # typed later. Anything else leaves the label to the computation.
        if any(label in TRIAGE_LABELS for label in labels):
            db.execute("UPDATE tasks SET triaged_by='human' WHERE key=?", (key,))
    _record(db, key, "create", actor, session, {"kind": kind, "title": title})
    triage_sync(db, key, cfg)
    return entity(db, key)


# ── editing ──────────────────────────────────────────────────────────────────

# patch field -> (column, validator). Only these can be written by an edit; a
# status change goes through set_status, which is where the gates live, and a
# refile goes through move_task, because both epics' lifecycles depend on it.
TASK_PATCH = {
    "title": ("title", lambda v: text(v, "title", MAX_TITLE, required=True)),
    "body": ("body", lambda v: text(v, "body", MAX_BODY) or ""),
    "assignee": ("agent", lambda v: text(v, "assignee", 64, pattern=NAME_RE)),
    "actor": ("actor", lambda v: text(v, "actor", 64, pattern=NAME_RE)),
    "session": ("session", lambda v: text(v, "session", 128)),
    "branch": ("branch", lambda v: text(v, "branch", 255)),
    "worktree": ("worktree", lambda v: text(v, "worktree", MAX_REF)),
    "priority": ("priority", lambda v: text(v, "priority", 16, choices=PRIORITIES)),
    "type": ("type", lambda v: text(v, "type", 16, choices=TYPES)),
    "estimate": ("estimate", lambda v: number(v, "estimate", 0, 10000)),
    "rank": ("rank", lambda v: number(v, "rank", -1e9, 1e9)),
    "sprint": ("sprint_key", lambda v: key_field(v, "sprint", "sprint")),
    "parent": ("parent_key", lambda v: key_field(v, "parent", "task")),
    "capability": ("capability_key", lambda v: key_field(v, "capability", "capability")),
    "goalDoc": ("goal_doc", lambda v: text(v, "goalDoc", MAX_REF)),
    "jira_key": ("jira_key", lambda v: text(v, "jira_key", 64, pattern=NAME_RE)),
    "blockedReason": ("blocked_reason", lambda v: text(v, "blockedReason", 512)),
    "parkedReason": ("parked_reason", lambda v: text(v, "parkedReason", 512)),
}
EPIC_PATCH = {
    "title": ("title", lambda v: text(v, "title", MAX_TITLE, required=True)),
    "body": ("body", lambda v: text(v, "body", MAX_BODY) or ""),
    "notes": ("notes", lambda v: text(v, "notes", MAX_BODY)),
    "plan": ("plan", lambda v: text(v, "plan", MAX_REF)),
    "jira_key": ("jira_key", lambda v: text(v, "jira_key", 64, pattern=NAME_RE)),
}
ADR_PATCH = {
    "title": ("title", lambda v: text(v, "title", MAX_TITLE, required=True)),
    "body": ("body", lambda v: text(v, "body", MAX_BODY) or ""),
    "epic": ("epic_key", lambda v: key_field(v, "epic", "epic")),
    "supersedes": ("supersedes", lambda v: key_field(v, "supersedes", "adr")),
    "decisionKey": ("decision_key", lambda v: text(v, "decisionKey", 64)),
}
SPRINT_PATCH = {
    "title": ("title", lambda v: text(v, "title", MAX_TITLE, required=True)),
    "body": ("body", lambda v: text(v, "body", MAX_BODY) or ""),
    "ends": ("ends", lambda v: text(v, "ends", 64)),
}
CAP_PATCH = {
    "title": ("title", lambda v: text(v, "title", MAX_TITLE, required=True)),
    "body": ("body", lambda v: text(v, "body", MAX_BODY) or ""),
    "area": ("area", lambda v: text(v, "area", 64)),
    "impact": ("impact", lambda v: text(v, "impact", 16, choices=CAP_LEVELS)),
    "effort": ("effort", lambda v: text(v, "effort", 16, choices=CAP_LEVELS)),
    "confidence": ("confidence", lambda v: text(v, "confidence", 16, choices=CAP_LEVELS)),
    "source": ("source", lambda v: text(v, "source", MAX_REF)),
    "task": ("task_key", lambda v: key_field(v, "task", "task")),
    "droppedReason": ("dropped_reason", lambda v: text(v, "droppedReason", 512)),
}
PATCHES = {"task": TASK_PATCH, "epic": EPIC_PATCH, "adr": ADR_PATCH,
           "sprint": SPRINT_PATCH, "capability": CAP_PATCH}


def update(db, key, patch, actor=None, session=None):
    kind, _ = row_for(db, key)
    allowed = PATCHES[kind]
    if not isinstance(patch, dict) or not patch:
        raise Invalid("nothing to change")
    unknown = patch.keys() - allowed.keys()
    if unknown:
        raise Invalid("cannot edit: " + ", ".join(sorted(unknown))[:120])
    assignments = []
    values = []
    for field, raw in patch.items():
        column, check = allowed[field]
        assignments.append(column + "=?")
        values.append(check(raw))
    values.append(now())
    values.append(key)
    db.execute("UPDATE " + TABLE_OF[kind] + " SET " + ",".join(assignments)
               + ",updated_at=? WHERE key=?", values)
    _record(db, key, "edit", actor, session, {"fields": sorted(patch.keys())})
    triage_sync(db, key)
    return entity(db, key)


# ── status ───────────────────────────────────────────────────────────────────

def _close_stamp(db, kind, key, status):
    column = "closed_at"
    if status in RESOLVED:
        db.execute("UPDATE " + TABLE_OF[kind] + " SET " + column + "=? WHERE key=?", (now(), key))
    else:
        db.execute("UPDATE " + TABLE_OF[kind] + " SET " + column + "=NULL WHERE key=?", (key,))


def auto_close_epic(db, epic_key, cfg, actor=None):
    """Close an epic whose every task has resolved.

    An epic with no tasks does not close: zero tasks is not an achievement."""
    if not epic_key or not cfg.get("autoCloseEpic"):
        return False
    row = db.execute("SELECT id,status FROM epics WHERE key=?", (epic_key,)).fetchone()
    if row is None or row["status"] in RESOLVED:
        return False
    counts = db.execute(
        "SELECT COUNT(*) total, SUM(CASE WHEN status IN ('done','deleted') THEN 1 ELSE 0 END) shut"
        " FROM tasks WHERE epic_id=?", (row["id"],)).fetchone()
    if not counts["total"] or counts["shut"] != counts["total"]:
        return False
    db.execute("UPDATE epics SET status='done',updated_at=?,closed_at=? WHERE key=?",
               (now(), now(), epic_key))
    _record(db, epic_key, "auto-closed", actor, None, {"reason": "all tasks resolved"})
    return True


def reopen_epic(db, epic_key, actor=None):
    """A finished epic containing live work is a lie the board should not tell."""
    if not epic_key:
        return False
    row = db.execute("SELECT status FROM epics WHERE key=?", (epic_key,)).fetchone()
    if row is None or row["status"] not in RESOLVED:
        return False
    db.execute("UPDATE epics SET status='open',updated_at=?,closed_at=NULL WHERE key=?",
               (now(), epic_key))
    _record(db, epic_key, "reopened", actor, None, {"reason": "unresolved task moved in"})
    return True


def set_status(db, key, status, actor=None, session=None, reason=None):
    """Move an entity, through whichever gate the destination owns.

    THERE IS NO BYPASS PARAMETER HERE, DELIBERATELY. There used to be one -
    `mirror=True` - borrowed from the create path, where it IS justified: a
    harness's own todo list cannot carry a body or acceptance criteria, so a thin
    CREATE is recorded and reported by `doctor` rather than refused, exactly as
    upstream treats them.

    That rationale never transferred. A status change carries no fields, so there
    is nothing a mirror "cannot carry"; what the flag actually did was skip
    gate_start and gate_done against the STORED record, which is the one thing
    those gates exist to read. And it was reachable from outside: any request body
    could set it (server.py board_write), and /api/status hard-wired it
    (ccstore.write). So the board ran a second bypass beside its designed one,
    with none of that one's four properties.

    The designed bypass is `set_override`: it demands a reason, stamps the actor,
    writes an audit row, and is consumed once, by one gate. Anything that must
    move a card past a gate arms that, and is answerable for it.
    """
    kind, row = row_for(db, key)
    vocabulary = ADR_STATUSES if kind == "adr" else STATUSES
    status = text(status, "status", 16, required=True, choices=vocabulary)
    reason = text(reason, "reason", 512)
    cfg = config(db)
    was = row["status"]
    result = {"id": key, "from": was, "to": status}

    # A CARD STOPS, AND NOBODY IS TOLD WHY.
    #
    # blocked and parked are the two statuses whose entire content is the reason -
    # "stopped" is not information, "stopped waiting on the licence server" is - and
    # the reason was optional. `task-status TM-014 blocked` succeeded and wrote
    # blocked_reason = NULL, so the card sat on the board saying blocked with nothing
    # anywhere saying what would unblock it. The CLI's own help has always called the
    # flag "required reading for blocked/parked"; nothing enforced it.
    #
    # Gated here rather than in the CLI because the HTTP endpoint is the other caller
    # and the dashboard reaches it directly. Refused rather than defaulted: inventing
    # "no reason given" would satisfy the field and lose the point.
    #
    # TASKS ONLY, and that is a limit rather than an oversight. blocked_reason and
    # parked_reason are columns on `tasks`; an epic has neither, so demanding a reason
    # for a blocked EPIC would refuse the caller and then throw the reason away -
    # asking for something the board has nowhere to keep. The first draft of this gate
    # did exactly that, and smoke.sh caught it on the next full run. If epics ever
    # want the same guard they need the same two columns first.
    if (kind == "task" and status in ("blocked", "parked") and status != was
            and not (reason or "").strip()):
        raise Refused(f"{status} needs a reason", [
            {"field": "reason",
             "hint": f"agentmux task {status} {key} --reason '<what would unblock it>'"}])

    if kind == "task":
        task = entity(db, key)
        if status == "in_progress" and was != "in_progress":
            bypass = gate_start(db, task, cfg, actor)
            if bypass:
                result["bypassed"] = bypass
        elif status == "done" and was != "done":
            bypass = gate_done(db, task, cfg)
            if bypass:
                result["bypassed"] = bypass

    stamp = now()
    db.execute("UPDATE " + TABLE_OF[kind] + " SET status=?,updated_at=? WHERE key=?",
               (status, stamp, key))
    _close_stamp(db, kind, key, status)
    if kind == "task":
        if status == "in_progress":
            if actor:
                db.execute("UPDATE tasks SET actor=? WHERE key=?", (actor, key))
            if session:
                db.execute("UPDATE tasks SET session=? WHERE key=?", (session, key))
        if status == "blocked":
            db.execute("UPDATE tasks SET blocked_reason=? WHERE key=?", (reason, key))
        elif status == "parked":
            db.execute("UPDATE tasks SET parked_reason=? WHERE key=?", (reason, key))
        elif was in ("blocked", "parked"):
            db.execute("UPDATE tasks SET blocked_reason=NULL,parked_reason=NULL WHERE key=?", (key,))
    _record(db, key, "status", actor, session,
            {"from": was, "to": status, "reason": reason})

    if kind == "task":
        epic_key = entity(db, key).get("epic")
        if status in RESOLVED and auto_close_epic(db, epic_key, cfg, actor):
            result["closed"] = epic_key
        elif status not in RESOLVED and reopen_epic(db, epic_key, actor):
            result["reopened"] = epic_key
        triage_sync(db, key, cfg)
    result["entity"] = entity(db, key)
    return result


def move_task(db, key, epic, actor=None, session=None):
    """Refile a task under a different epic, or under none.

    A move is not just a field write, because both epics' lifecycles depend on
    their children: an unfinished task moved into a finished epic reopens it, and
    the epic it left gets the same auto-close check finishing a task would give."""
    kind, row = row_for(db, key)
    if kind != "task":
        raise Invalid(key + " is not a task")
    cfg = config(db)
    dest_key = key_field(epic, "epic", "epic")
    dest_id = None
    if dest_key is not None:
        found = db.execute("SELECT id FROM epics WHERE key=?", (dest_key,)).fetchone()
        if found is None:
            raise NotFound("not found: " + dest_key)
        dest_id = found["id"]
    from_key = entity(db, key).get("epic")
    if from_key == dest_key:
        return {"id": key, "from": from_key, "to": dest_key, "changed": False}
    db.execute("UPDATE tasks SET epic_id=?,updated_at=? WHERE key=?", (dest_id, now(), key))
    _record(db, key, "moved", actor, session, {"from": from_key, "to": dest_key})
    result = {"id": key, "from": from_key, "to": dest_key, "changed": True}
    if dest_key and row["status"] not in RESOLVED and reopen_epic(db, dest_key, actor):
        result["reopened"] = dest_key
    if from_key and auto_close_epic(db, from_key, cfg, actor):
        result["closed"] = from_key
    triage_sync(db, key, cfg)
    result["entity"] = entity(db, key)
    return result


def delete(db, key, actor=None, session=None):
    """Soft delete, upstream's way: the status becomes `deleted`, the row stays,
    and the key stays burned. A board whose numbers get reused is a board whose
    history stops meaning anything."""
    kind, existing = row_for(db, key)
    # Deleting twice is not idempotent here, it is a mistake worth reporting. The
    # row survives a soft delete, so without this the second call "succeeds",
    # re-stamps closed_at, and tells the caller it removed something it did not.
    if existing["status"] == "deleted":
        raise NotFound(key + " is already deleted")
    if kind == "epic":
        # Only LIVE children cascade. A task deleted on its own is already gone;
        # counting it again would report a cascade larger than the work actually
        # affected, which is the number a caller uses to decide whether to worry.
        orphans = [row["key"] for row in db.execute(
            "SELECT t.key FROM tasks t JOIN epics e ON t.epic_id=e.id"
            " WHERE e.key=? AND t.status<>'deleted'", (key,))]
        for child in orphans:
            db.execute("UPDATE tasks SET status='deleted',updated_at=?,closed_at=? WHERE key=?",
                       (now(), now(), child))
            _record(db, child, "status", actor, session,
                    {"to": "deleted", "reason": "epic " + key + " deleted"})
        db.execute("UPDATE epics SET status='deleted',updated_at=?,closed_at=? WHERE key=?",
                   (now(), now(), key))
        _record(db, key, "deleted", actor, session, {"cascaded": orphans})
        return {"id": key, "kind": kind, "cascaded": orphans}
    db.execute("UPDATE " + TABLE_OF[kind] + " SET status='deleted',updated_at=?,closed_at=?"
               " WHERE key=?", (now(), now(), key))
    _record(db, key, "deleted", actor, session, None)
    return {"id": key, "kind": kind, "cascaded": []}


# ── the list-valued fields ───────────────────────────────────────────────────

def add_acceptance(db, key, item, actor=None):
    row_for(db, key)
    item = text(item, "acceptance", MAX_TEXT, required=True)
    position = db.execute("SELECT COALESCE(MAX(position),-1)+1 FROM board_acceptance"
                          " WHERE entity_key=?", (key,)).fetchone()[0]
    db.execute("INSERT INTO board_acceptance (entity_key,position,text,done,at)"
               " VALUES (?,?,?,0,?)", (key, position, item, now()))
    _record(db, key, "acceptance", actor, None, {"added": item[:120]})
    _touch(db, key)
    triage_sync(db, key)
    return entity(db, key)


def tick_acceptance(db, key, index, done=True, actor=None):
    row_for(db, key)
    index = number(index, "index", 1, MAX_LIST, integer=True)
    rows = db.execute("SELECT id FROM board_acceptance WHERE entity_key=?"
                      " ORDER BY position,id", (key,)).fetchall()
    if index > len(rows):
        raise NotFound("no acceptance criterion " + str(index) + " on " + key)
    db.execute("UPDATE board_acceptance SET done=?,at=? WHERE id=?",
               (1 if done else 0, now(), rows[index - 1]["id"]))
    _record(db, key, "acceptance", actor, None, {"index": index, "done": bool(done)})
    _touch(db, key)
    return entity(db, key)


def drop_acceptance(db, key, index, actor=None):
    row_for(db, key)
    index = number(index, "index", 1, MAX_LIST, integer=True)
    rows = db.execute("SELECT id FROM board_acceptance WHERE entity_key=?"
                      " ORDER BY position,id", (key,)).fetchall()
    if index > len(rows):
        raise NotFound("no acceptance criterion " + str(index) + " on " + key)
    db.execute("DELETE FROM board_acceptance WHERE id=?", (rows[index - 1]["id"],))
    _record(db, key, "acceptance", actor, None, {"removed": index})
    _touch(db, key)
    triage_sync(db, key)
    return entity(db, key)


def set_label(db, key, label, present=True, actor=None):
    """Add or remove a label.

    Touching a triage label by hand is a person's decision and stamps the task
    `triagedBy: human`, which the computation then never overrides - including
    the decision to have NO triage label, so clearing one sticks."""
    row_for(db, key)
    label = text(label, "label", 48, required=True, pattern=LABEL_RE)
    if present:
        db.execute("INSERT OR IGNORE INTO board_labels (entity_key,label,at) VALUES (?,?,?)",
                   (key, label, now()))
    else:
        db.execute("DELETE FROM board_labels WHERE entity_key=? AND label=?", (key, label))
    human = label in TRIAGE_LABELS
    if human and kind_of(key) == "task":
        if present:
            # The computation's label is displaced, not left beside this one. A
            # card cannot be both taken out of the queue by a person and offered
            # to agents, and the human stamp below means nothing would ever come
            # back to tidy it up.
            for computed in ("ready-for-agent", "needs-triage"):
                if computed != label:
                    db.execute("DELETE FROM board_labels WHERE entity_key=? AND label=?",
                               (key, computed))
        db.execute("UPDATE tasks SET triaged_by='human' WHERE key=?", (key,))
    _record(db, key, "label", actor, None,
            {"label": label, "present": bool(present), "by": "human" if human else "auto"})
    _touch(db, key)
    if not human:
        triage_sync(db, key)
    return entity(db, key)


def set_dep(db, key, other, present=True, actor=None):
    row_for(db, key)
    other = key_field(other, "blockedBy", "task", required=True)
    if other == key:
        raise Invalid("a task cannot block itself")
    row_for(db, other)
    if present:
        if _creates_cycle(db, key, other):
            raise Invalid(key + " already blocks " + other + ": that would be a cycle")
        db.execute("INSERT OR IGNORE INTO board_deps (entity_key,blocked_by,at) VALUES (?,?,?)",
                   (key, other, now()))
    else:
        db.execute("DELETE FROM board_deps WHERE entity_key=? AND blocked_by=?", (key, other))
    _record(db, key, "dep", actor, None, {"blockedBy": other, "present": bool(present)})
    _touch(db, key)
    return entity(db, key)


def _creates_cycle(db, key, other):
    """Would `key` depending on `other` close a loop? Walks what `other` waits on."""
    seen = set()
    frontier = [other]
    while frontier:
        current = frontier.pop()
        if current == key:
            return True
        if current in seen:
            continue
        seen.add(current)
        frontier.extend(row["blocked_by"] for row in db.execute(
            "SELECT blocked_by FROM board_deps WHERE entity_key=?", (current,)))
    return False


def _append(db, table, key, column, value, event, actor, pattern=None, maximum=MAX_REF):
    row_for(db, key)
    value = text(value, column, maximum, required=True, pattern=pattern)
    db.execute("INSERT INTO " + table + " (entity_key," + column + ",at) VALUES (?,?,?)",
               (key, value, now()))
    _record(db, key, event, actor, None, {column: value[:200]})
    _touch(db, key)
    return value


def add_evidence(db, key, ref, actor=None):
    _append(db, "board_evidence", key, "ref", ref, "evidence", actor)
    triage_sync(db, key)
    return entity(db, key)


def add_commit(db, key, ref, actor=None):
    _append(db, "board_commits", key, "ref", ref, "commit", actor)
    return entity(db, key)


def add_touch(db, key, path, actor=None):
    """Claim a path for a card, so dispatch can keep two workers off one file.

    This was the only list-append that wrote no history row and did not bump the
    card's updated_at - every sibling goes through _append, which does both. It also
    ACCEPTED an actor and threw it away, so the one write that decides whether two
    agents can run in parallel was anonymous, and a card could acquire touches without
    ever looking touched to a staleness view.

    Only a real insert is an event: INSERT OR IGNORE makes a repeated touch a no-op,
    and a history row for a no-op is noise in the log that matters most here.
    """
    row_for(db, key)
    path = text(path, "path", MAX_REF, required=True, pattern=PATH_RE)
    cursor = db.execute(
        "INSERT OR IGNORE INTO board_touches (entity_key,path,at) VALUES (?,?,?)",
        (key, path, now()))
    if cursor.rowcount:
        _record(db, key, "touch", actor, None, {"path": path[:200]})
        _touch(db, key)
    return entity(db, key)


def add_comment(db, key, body, author=None):
    row_for(db, key)
    body = text(body, "text", MAX_TEXT, required=True)
    db.execute("INSERT INTO board_comments (entity_key,author,at,text) VALUES (?,?,?,?)",
               (key, text(author, "author", 64, pattern=NAME_RE), now(), body))
    _record(db, key, "comment", author, None, {"chars": len(body)})
    _touch(db, key)
    return entity(db, key)


def set_link(db, key, link_type, target, present=True, actor=None):
    row_for(db, key)
    link_type = text(link_type, "type", 16, required=True, choices=LINK_TYPES)
    target = key_field(target, "id", required=True)
    row_for(db, target)
    if present:
        existing = db.execute("SELECT id FROM board_links WHERE entity_key=? AND link_type=?"
                              " AND target=?", (key, link_type, target)).fetchone()
        if existing is None:
            db.execute("INSERT INTO board_links (entity_key,link_type,target,at)"
                       " VALUES (?,?,?,?)", (key, link_type, target, now()))
    else:
        db.execute("DELETE FROM board_links WHERE entity_key=? AND link_type=? AND target=?",
                   (key, link_type, target))
    _record(db, key, "link", actor, None,
            {"type": link_type, "target": target, "present": bool(present)})
    _touch(db, key)
    return entity(db, key)


def _touch(db, key):
    kind = kind_of(key)
    if kind:
        db.execute("UPDATE " + TABLE_OF[kind] + " SET updated_at=? WHERE key=?", (now(), key))


# ── reading the board ────────────────────────────────────────────────────────

def _strip_body(rows):
    """The list payload carries what a card needs to render; a detail fetch
    carries the markdown. Stripping here, once, is why every internal caller can
    rely on the body being present."""
    for row in rows:
        row.pop("body", None)
    return rows


def _all(db, kind, cfg):
    rows = db.execute("SELECT * FROM " + TABLE_OF[kind] + " ORDER BY id").fetchall()
    return [PAYLOAD[kind](db, row) for row in rows]


def board(db, include_deleted=False):
    """Everything on the board, in one payload - upstream's `Board`.

    Bodies are stripped from the list payload, as upstream does: a detail fetch
    carries the markdown, a board fetch carries what a card needs to render."""
    cfg = config(db)
    epic_key_by_row = {row["id"]: row["key"] for row in db.execute("SELECT id,key FROM epics")}
    tasks = []
    for row in db.execute("SELECT * FROM tasks ORDER BY id"):
        task = _payload_task(db, row)
        task["epic"] = epic_key_by_row.get(row["epic_id"])
        tasks.append(attach_triage(db, task, cfg))
    epics = _all(db, "epic", cfg)
    payload = {
        "generated": now(),
        "epics": _strip_body(
            epics if include_deleted else [e for e in epics if e["status"] != "deleted"]),
        "tasks": _strip_body(
            tasks if include_deleted else [t for t in tasks if t["status"] != "deleted"]),
        "adrs": _strip_body(_all(db, "adr", cfg)),
        "sprints": _strip_body(_all(db, "sprint", cfg)),
        "capabilities": _strip_body(_all(db, "capability", cfg)),
        "state": state(db),
        "config": cfg,
        "labelCatalog": list(LABEL_CATALOG),
        "gates": {"enforce": enforcing(db), "override": state(db)["override"]},
        "counters": {row["prefix"]: row["last"]
                     for row in db.execute("SELECT prefix,last FROM board_counters")},
    }
    return payload


def find(db, query, limit=50):
    """Substring search over key, title and body, every kind at once."""
    needle = text(query, "q", 200, required=True).strip().lower()
    limit = number(limit, "limit", 1, 200, integer=True)
    hits = []
    for kind in KINDS:
        for row in db.execute("SELECT * FROM " + TABLE_OF[kind] + " ORDER BY id"):
            haystack = " ".join(str(row[column] or "").lower()
                                for column in ("key", "title", "body"))
            if needle in haystack:
                hits.append({"id": row["key"], "kind": kind, "title": row["title"],
                             "status": row["status"],
                             "labels": labels_of(db, row["key"])})
            if len(hits) >= limit:
                return hits
    return hits


def history(db, key=None, limit=200):
    limit = number(limit, "limit", 1, 1000, integer=True)
    if key is None:
        rows = db.execute("SELECT * FROM board_history ORDER BY id DESC LIMIT ?",
                          (limit,)).fetchall()
    else:
        row_for(db, key)
        rows = db.execute("SELECT * FROM board_history WHERE entity_key=?"
                          " ORDER BY id DESC LIMIT ?", (key, limit)).fetchall()
    out = []
    for row in rows:
        detail = None
        if row["detail"]:
            try:
                detail = json.loads(row["detail"])
            except ValueError:
                detail = None
        out.append({"ts": row["at"], "id": row["entity_key"], "event": row["event"],
                    "actor": row["actor"], "session": row["session"], "detail": detail})
    return out


def why(db, key):
    """Why this task is or is not startable, and what it is waiting on.

    The chain is walked breadth-first so the nearest blocker is named first -
    "waiting on TM-009" is actionable, "waiting on something six hops away" is
    not."""
    task = entity(db, key)
    if kind_of(key) != "task":
        raise Invalid(key + " is not a task")
    cfg = config(db)
    reasons = []
    for gap in missing_fields(task, cfg.get("requireOnStart")):
        reasons.append({"kind": "incomplete", "blocking": True,
                        "text": "missing " + SPOKEN.get(gap["field"], gap["field"])
                                + " - " + gap["hint"]})
    if cfg.get("requireEpic") and not task.get("epic"):
        reasons.append({"kind": "epic", "blocking": True,
                        "text": "no epic - agentmux task move " + key + " --epic EP-00n"})
    chain = []
    roots = []
    seen = {key}
    frontier = [(dep, 1) for dep in task.get("blockedBy") or []]
    while frontier:
        current, depth = frontier.pop(0)
        if current in seen or depth > 12:
            continue
        seen.add(current)
        status = _status_of(db, current)
        row = db.execute("SELECT title FROM tasks WHERE key=?", (current,)).fetchone()
        entry = {"id": current, "depth": depth, "status": status,
                 "title": row["title"] if row else None}
        if status is None:
            entry["reason"] = "referenced but not on this board"
        chain.append(entry)
        if status not in RESOLVED:
            if depth == 1:
                reasons.append({"kind": "blocked", "blocking": True,
                                "text": "blocked by " + current
                                        + " (" + str(status or "missing") + ")"})
            roots.append(current)
        frontier.extend((dep["blocked_by"], depth + 1) for dep in db.execute(
            "SELECT blocked_by FROM board_deps WHERE entity_key=?", (current,)))
    if task["status"] in RESOLVED:
        reasons.append({"kind": "status", "blocking": False,
                        "text": "already " + task["status"]})
    startable = not any(reason["blocking"] for reason in reasons)
    lines = [key + " is " + ("startable" if startable else "not startable")]
    lines.extend("  - " + reason["text"] for reason in reasons)
    return {"id": key, "title": task["title"], "status": task["status"],
            "startable": startable, "reasons": reasons, "chain": chain,
            "roots": sorted(set(roots)), "text": "\n".join(lines)}


def next_tasks(db, limit=10):
    """The queue: unblocked, unresolved, most urgent first.

    Priority order is upstream's PRIORITIES; within a priority the explicit
    `rank` wins, and an unranked card sorts after a ranked one rather than at
    zero - a card nobody ranked has not been judged, it is not judged lowest."""
    limit = number(limit, "limit", 1, 200, integer=True)
    cfg = config(db)
    order = {name: index for index, name in enumerate(PRIORITIES)}
    out = []
    for row in db.execute("SELECT * FROM tasks WHERE status IN ('backlog','open') ORDER BY id"):
        task = _payload_task(db, row)
        if any(_status_of(db, dep) not in RESOLVED for dep in task["blockedBy"]):
            continue
        if missing_fields(task, cfg.get("requireOnStart")):
            continue
        out.append(task)
    out.sort(key=lambda t: (order.get(t["priority"], len(PRIORITIES)),
                            (0, t["rank"]) if t["rank"] is not None else (1, 0),
                            t["id"]))
    return out[:limit]


def in_flight(db):
    """Tasks an agent is holding right now: in_progress with an assignee."""
    return _rows(db, "SELECT key,agent,session FROM tasks"
                     " WHERE status='in_progress' AND agent IS NOT NULL ORDER BY id")


def dispatchable(db, limit=10, busy=()):
    """The queue a dispatcher may actually hand out, most urgent first.

    next_tasks answers "what should a human pick up next" - it stops at unblocked
    and specified. Dispatch has two further conditions that next_tasks must NOT
    fold in, because they are about handing work to a *machine*:

      * agent_readiness - the labels that reserve a card for a person
        (NOT_FOR_AGENTS) and the epic requirement. A task can be perfectly well
        specified and still be one a person must answer.
      * file disjointness - two agents editing the same path is the collision
        RULE #-0.7's claims exist to make impossible. Claims make it *safe*: the
        loser is refused. Choosing disjoint work up front makes it *rare*, which
        is the difference between a pool that makes progress and one that spends
        its slots losing races.

    `busy` is the set of paths already being worked. Overlapping cards are not
    dropped - they are ranked after the disjoint ones, so a board whose every
    card touches the same file still drains, just one at a time.
    """
    limit = number(limit, "limit", 1, 200, integer=True)
    cfg = config(db)
    order = {name: index for index, name in enumerate(PRIORITIES)}
    taken = {str(path) for path in busy}
    # _payload_task leaves `epic` as None and carries the row id in `epicRow`;
    # only board() resolves it. agent_readiness asks for `epic`, so without this
    # map every card on a board with requireEpic set reads as epic-less and the
    # queue is always empty - which is exactly how this read first behaved.
    epic_key_by_row = {row["id"]: row["key"] for row in db.execute("SELECT id,key FROM epics")}
    candidates = []
    for row in db.execute("SELECT * FROM tasks WHERE status IN ('backlog','open') ORDER BY id"):
        task = _payload_task(db, row)
        task["epic"] = epic_key_by_row.get(row["epic_id"])
        if any(_status_of(db, dep) not in RESOLVED for dep in task["blockedBy"]):
            continue
        verdict = agent_readiness(task, cfg)
        if not verdict["ready"]:
            continue
        candidates.append(task)
    candidates.sort(key=lambda t: (order.get(t["priority"], len(PRIORITIES)),
                                   (0, t["rank"]) if t["rank"] is not None else (1, 0),
                                   t["id"]))
    # Greedy disjoint pass, then the rest in the same priority order. A card with
    # no touches recorded cannot be proven disjoint, so it is treated as
    # overlapping rather than assumed safe.
    first, rest = [], []
    for task in candidates:
        touches = set(task.get("touches") or [])
        if touches and not (touches & taken):
            taken |= touches
            first.append(task)
        else:
            rest.append(task)
    return _strip_body(first + rest)[:limit]


def busy_paths(db):
    """Every path an in-flight task has recorded touching."""
    out = set()
    for row in in_flight(db):
        out |= set(_simple_list(db, "board_touches", "path", row["key"]))
    return sorted(out)


def dispatch_view(db, limit=10):
    """Everything a dispatcher needs in one read: the queue, what is already
    running, and the policy. One call, so the queue and the in-flight set it was
    computed against cannot be from two different moments."""
    cfg = config(db)
    return {"tasks": dispatchable(db, limit, busy_paths(db)),
            "inFlight": in_flight(db),
            "config": {name: cfg[name] for name in DISPATCH_KEYS}}


def triage(db, sweep_all=False, dry_run=False, actor=None):
    """Backfill the computed triage label across existing tasks.

    Skips every task a person decided, permanently. `sweep_all` includes resolved
    tasks, which is only ever useful for a report."""
    cfg = config(db)
    changed = []
    for row in db.execute("SELECT key,status,triaged_by FROM tasks ORDER BY id"):
        if row["triaged_by"] == "human":
            continue
        if not sweep_all and row["status"] in RESOLVED:
            continue
        task = entity(db, row["key"])
        verdict = agent_readiness(task, cfg)
        wanted = "ready-for-agent" if verdict["ready"] else "needs-triage"
        if wanted in (task.get("labels") or []):
            continue
        changed.append({"id": row["key"], "label": wanted, "missing": verdict["missing"]})
        if not dry_run:
            triage_sync(db, row["key"], cfg)
    if changed and not dry_run:
        _record(db, None, "triage", actor, None, {"changed": len(changed)})
    return {"changed": changed, "dryRun": bool(dry_run)}


def graph(db):
    """Nodes and edges for the dependency view, plus the same thing as mermaid.

    The mermaid text is generated here rather than in the browser so the CLI and
    the dashboard cannot disagree about what the graph says."""
    nodes = []
    edges = []
    for row in db.execute("SELECT * FROM tasks WHERE status<>'deleted' ORDER BY id"):
        task = _payload_task(db, row)
        nodes.append({"id": row["key"], "title": row["title"], "status": row["status"],
                      "kind": "task"})
        for dep in task["blockedBy"]:
            edges.append({"from": dep, "to": row["key"], "type": "blocks"})
        for link in task["links"]:
            edges.append({"from": row["key"], "to": link["id"], "type": link["type"]})
    lines = ["graph LR"]
    for node in nodes:
        label = node["id"] + " " + str(node["title"] or "")[:40]
        lines.append('  ' + node["id"].replace("-", "_") + '["'
                     + label.replace('"', "'") + '"]')
    for edge in edges:
        if kind_of(edge["from"]) and kind_of(edge["to"]):
            lines.append("  " + edge["from"].replace("-", "_") + " --> "
                         + edge["to"].replace("-", "_"))
    return {"nodes": nodes, "edges": edges,
            "activeEpic": state(db)["activeEpic"], "mermaid": "\n".join(lines)}


def doctor(db):
    """What is wrong with this board, and whether anything can fix it for you.

    A thin card is a WARNING, never an error: mirrors are exempt from the create
    gate by design, so tasks without a body exist legitimately and reporting them
    as failures would train people to ignore the report."""
    cfg = config(db)
    findings = []

    def note(level, code, message, key=None, fixable=False):
        findings.append({"level": level, "code": code, "message": message,
                         "id": key, "fixable": fixable})

    known = set()
    for kind in KINDS:
        known.update(row["key"] for row in db.execute(
            "SELECT key FROM " + TABLE_OF[kind]))
    missing_key = [row["key"] for row in db.execute(
        "SELECT key FROM tasks WHERE key IS NULL OR key=''")]
    for _ in missing_key:
        note("error", "unkeyed", "a task row carries no key; restart the dashboard to"
             " run the migration", None, True)

    for row in db.execute("SELECT * FROM tasks WHERE status<>'deleted' ORDER BY id"):
        key = row["key"]
        task = _payload_task(db, row)
        epic = db.execute("SELECT key,status FROM epics WHERE id=?",
                          (row["epic_id"],)).fetchone() if row["epic_id"] else None
        task["epic"] = epic["key"] if epic else None
        if cfg.get("requireEpic") and not task["epic"]:
            note("warning", "no-epic", key + " has no epic", key, False)
        if epic is not None and epic["status"] in RESOLVED and row["status"] not in RESOLVED:
            note("error", "epic-closed", key + " is " + row["status"] + " under closed epic "
                 + epic["key"], key, True)
        for dep in task["blockedBy"]:
            if dep not in known:
                note("error", "dangling-dep", key + " is blocked by " + dep
                     + ", which is not on this board", key, False)
        for link in task["links"]:
            if link["id"] not in known:
                note("error", "dangling-link", key + " links to " + link["id"]
                     + ", which is not on this board", key, False)
        gaps = missing_fields(task, cfg.get("requireOnDone"))
        if row["status"] == "done" and gaps:
            note("warning", "incomplete-done", key + " closed without "
                 + ", ".join(gap["field"] for gap in gaps), key, False)
        elif row["status"] not in RESOLVED and missing_fields(task, cfg.get("requireOnStart")):
            note("warning", "incomplete-open", key + " is not specified well enough to start",
                 key, False)
        if task["sprint"] and task["sprint"] not in known:
            note("error", "dangling-sprint", key + " is committed to " + task["sprint"]
                 + ", which is not on this board", key, False)

    cycles = _cycles(db)
    for cycle in cycles:
        note("error", "cycle", "dependency cycle: " + " -> ".join(cycle), cycle[0], False)

    limit = cfg.get("wipLimit") or 0
    if limit:
        for row in db.execute("SELECT actor,COUNT(*) n FROM tasks WHERE status='in_progress'"
                              " GROUP BY actor"):
            if row["n"] > limit:
                note("warning", "over-wip", str(row["actor"] or "unattributed") + " holds "
                     + str(row["n"]) + " in-progress tasks, limit is " + str(limit), None, False)

    errors = sum(1 for f in findings if f["level"] == "error")
    warnings = len(findings) - errors
    text_lines = [f["level"][0].upper() + " " + f["code"] + ": " + f["message"]
                  for f in findings] or ["no problems found"]
    return {"findings": findings, "errors": errors, "warnings": warnings,
            "fixable": sum(1 for f in findings if f["fixable"]),
            "text": "\n".join(text_lines)}


def _cycles(db):
    """Every dependency cycle, each reported once from its lowest key."""
    graph_map = {}
    for row in db.execute("SELECT entity_key,blocked_by FROM board_deps"):
        graph_map.setdefault(row["entity_key"], []).append(row["blocked_by"])
    found = []
    seen_signature = set()

    def walk(node, path, visiting):
        for nxt in graph_map.get(node, []):
            if nxt in visiting:
                loop = path[path.index(nxt):] + [nxt]
                signature = tuple(sorted(set(loop)))
                if signature not in seen_signature:
                    seen_signature.add(signature)
                    found.append(loop)
                continue
            walk(nxt, path + [nxt], visiting | {nxt})

    for start in sorted(graph_map):
        walk(start, [start], {start})
    return found


def sprint_report(db, key):
    kind, row = row_for(db, key)
    if kind != "sprint":
        raise Invalid(key + " is not a sprint")
    tasks = [_payload_task(db, task) for task in db.execute(
        "SELECT * FROM tasks WHERE sprint_key=? ORDER BY id", (key,))]
    return {"id": key, "title": row["title"], "status": row["status"],
            "ends": row["ends"], "report": sprint_counts(db, key), "tasks": tasks}


def meta(db):
    """Vocabulary and identity, so no client hardcodes a list this file owns."""
    return {
        "kinds": {kind: {"prefix": prefix, "pad": pad}
                  for kind, (prefix, pad) in KINDS.items()},
        "vocab": {
            "statuses": list(STATUSES),
            "adrStatuses": list(ADR_STATUSES),
            "priorities": list(PRIORITIES),
            "types": list(TYPES),
            "linkTypes": list(LINK_TYPES),
            "capLevels": list(CAP_LEVELS),
            "triageLabels": list(TRIAGE_LABELS),
            "labelCatalog": list(LABEL_CATALOG),
            "resolved": sorted(RESOLVED),
        },
        "config": config(db),
        "state": state(db),
        "gates": {"enforce": enforcing(db), "override": state(db)["override"]},
        "counters": {row["prefix"]: row["last"]
                     for row in db.execute("SELECT prefix,last FROM board_counters")},
    }
