"""Bounded, stdlib-only agent definition discovery (CONTRACTS_agents.md C1).

This is deliberately a flat frontmatter reader, not a YAML implementation. Auth
and model None mean the CLI's native defaults. Discovery never mutates the board.
"""
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import unicodedata
import warnings

SCOPES = ("claude", "global", "repo")
NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")
CLI_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
CAP_RE = re.compile(r"[a-z][a-z0-9-]{0,23}")
KEYS = frozenset(("name", "description", "cli", "model", "auth", "posture",
                  "tools", "tools-deny", "role", "capabilities", "worktree",
                  "max_instances"))
MAX_BYTES = 64 * 1024
MAX_FILES = 200
MANIFEST = Path(__file__).resolve().parent.parent / "dashboard" / "auth.json"


@dataclass(frozen=True)
class AgentSpec:
    name: str
    scope: str
    path: str
    description: str
    cli: str
    model: str | None
    auth: str | None
    posture: str
    tools: tuple[str, ...]
    tools_deny: tuple[str, ...]
    persona: str
    role: str
    capabilities: tuple[str, ...]
    worktree: str
    max_instances: int
    checksum: str


def _string(value, field, multiline=False):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    # Markdown bodies need line breaks; every other control is rejected, including
    # tabs and Unicode direction/format controls. CRLF is normalized before here.
    if any((unicodedata.category(c) in ("Cc", "Cf", "Cs") and
            not (multiline and c == "\n")) or
           (not multiline and c in "\u2028\u2029") for c in value):
        raise ValueError(f"{field} contains control characters or line separators")
    return value


def _frontmatter(raw):
    text = raw.decode("utf-8").replace("\r\n", "\n")
    lines = text.split("\n")
    if not lines or lines[0] != "---":
        raise ValueError("missing opening frontmatter delimiter ---")
    fields = {}
    for i, line in enumerate(lines[1:], 1):
        if line == "---":
            return fields, "\n".join(lines[i + 1:]).strip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace() or ":" not in line:
            raise ValueError(f"frontmatter line {i + 1}: expected flat key: value")
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip(" ")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key):
            raise ValueError(f"invalid frontmatter key {key!r}")
        if key in fields:
            raise ValueError(f"duplicate frontmatter key {key!r}")
        if value.startswith('"'):
            try:
                value = json.loads(value)
            except ValueError as exc:
                raise ValueError(f"{key}: invalid quoted string") from exc
        elif value.startswith("'"):
            if len(value) < 2 or not value.endswith("'"):
                raise ValueError(f"{key}: unterminated quoted string")
            value = value[1:-1].replace("''", "'")
        elif value.startswith(("[", "{", "|", ">", "&", "*", "!")):
            raise ValueError(f"{key}: only flat string values are supported")
        fields[key] = _string(value, key)
    raise ValueError("missing closing frontmatter delimiter ---")


def _json(path):
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


def _defaults(root, problem):
    cli = "codex"
    dbpath = root / "cc.db"
    if dbpath.exists():
        try:
            db = sqlite3.connect(dbpath.absolute().as_uri() + "?mode=ro", uri=True)
            try:
                # A fresh store may predate board migration.
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='board_config'").fetchone():
                    row = db.execute("SELECT value FROM board_config WHERE name='dispatchCli'").fetchone()
                    if row:
                        cli = json.loads(row[0]) or "codex"
                if not isinstance(cli, str) or not CLI_RE.fullmatch(cli):
                    raise ValueError("invalid dispatchCli")
            finally:
                db.close()
        except Exception as exc:
            problem(dbpath, "global", f"cannot read dispatchCli: {exc}")
            cli = "codex"
    data = []
    for path in (root / "auth.json", MANIFEST):
        try:
            data.append(_json(path))
        except Exception as exc:
            problem(path, "global", f"cannot read auth configuration: {exc}")
            data.append({})
    return cli, data[0], data[1]


def _spec(path, scope, raw, fields, persona, cli_default, settings, manifest):
    name = fields.get("name", "")
    if not NAME_RE.fullmatch(name):
        raise ValueError("name must match ^[a-z][a-z0-9-]{0,63}$")
    if name != path.stem:
        raise ValueError("filename stem must equal name")
    description = fields.get("description", "")
    if not description.strip() or len(description) > 2048:
        raise ValueError("description is required and must be at most 2048 characters on one line")
    cli = fields.get("cli", cli_default)
    if not CLI_RE.fullmatch(cli):
        raise ValueError("cli must match ^[A-Za-z0-9_-]{1,32}$")
    role = fields.get("role", "worker")
    posture = fields.get("posture", "workspace-write")
    worktree = fields.get("worktree", "integration" if role == "lead" else "per-member")
    for key, value, choices in (
        ("role", role, ("lead", "worker", "reviewer", "researcher")),
        ("posture", posture, ("read-only", "workspace-write", "unrestricted")),
        ("worktree", worktree, ("per-member", "integration", "none")),
    ):
        if value not in choices:
            raise ValueError(f"{key} must be one of {', '.join(choices)}")
    count = fields.get("max_instances", "1")
    if not re.fullmatch(r"[1-8]", count):
        raise ValueError("max_instances must be an integer from 1 to 8")
    def csv(key):
        value = fields.get(key, "")
        if not value:
            return ()
        parts = tuple(part.strip() for part in value.split(","))
        if not all(parts):
            raise ValueError(f"{key} contains an empty item")
        return parts
    capabilities = csv("capabilities")
    if len(capabilities) > 16 or any(not CAP_RE.fullmatch(c) for c in capabilities):
        raise ValueError("capabilities must contain at most 16 tags matching ^[a-z][a-z0-9-]{0,23}$")
    _string(persona, "persona", multiline=True)
    if len(persona) > 4096:
        raise ValueError("persona must be at most 4096 characters")
    auth = fields.get("auth", settings.get("active", {}).get(cli)) or None
    if auth is not None:
        _string(auth, "auth")
        methods = {m["id"]: m for m in manifest.get("methods", [])}
        if auth not in methods or methods[auth].get("cli") != cli:
            # Do not echo a supplied credential into browser-visible diagnostics.
            raise ValueError("auth must name a method for this cli in dashboard/auth.json")
    model = fields.get("model", settings.get("methods", {}).get(auth, {}).get("model")) or None
    if model is not None:
        _string(model, "model")
    return AgentSpec(name, scope, str(path), description, cli, model, auth, posture,
                     csv("tools"), csv("tools-deny"), persona, role, capabilities,
                     worktree, int(count), "sha256:" + hashlib.sha256(raw).hexdigest())


def _read_source(path):
    """Read one bounded regular source without following a substituted link."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("definition must be a regular file, not a symlink")
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
        signature = lambda info: (info.st_dev, info.st_ino, info.st_size,
                                  info.st_mtime_ns, info.st_ctime_ns)
        if signature(before) != signature(after):
            raise ValueError("definition changed while reading")
    if len(raw) > MAX_BYTES:
        raise ValueError("definition exceeds 64 KiB")
    return raw


def _load_catalog(repo_root=None, *, home=None, global_root=None, _with_membership=False):
    """Return (specs, problems), including path and reason for every failed file.

    Names are reserved even by invalid files: a broken duplicate cannot cause a
    different definition to be selected accidentally. Duplicate groups yield one
    collision diagnostic containing all paths, with no discovery precedence.
    """
    specs, problems, groups, sources, membership = {}, [], {}, {}, {}
    def problem(path, scope, error):
        problems.append({"path": str(path), "scope": scope, "error": str(error)})
    try:
        home = Path(home) if home is not None else Path.home()
        root = (Path(global_root) if global_root is not None else
                Path(os.environ.get("AGENTMUX_HOME", str(home / ".agentmux"))))
        repo = Path(repo_root if repo_root is not None else Path.cwd()).absolute()
        default_cli, settings, manifest = _defaults(root, problem)
        directories = ((repo / ".agentmux/agents", "repo"), (root / "agents", "global"),
                       (repo / ".claude/agents", "claude"), (home / ".claude/agents", "claude"))
        seen = set()
        for directory, scope in directories:
            try:
                # Deduplicate the same physical directory when repo_root == home.
                identity = directory.resolve()
                if identity in seen:
                    continue
                seen.add(identity)
                paths = []
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            if entry.name.endswith(".md"):
                                paths.append(Path(entry.path).absolute())
                                if len(paths) > MAX_FILES:
                                    raise ValueError("directory exceeds 200 .md files; no definitions loaded from it")
                except FileNotFoundError:
                    continue
                for path in sorted(paths):
                    # Shipped examples are a catalogue, not implicit project
                    # membership. Other local definitions keep their old scope.
                    try:
                        from . import profile_packages
                    except ImportError:
                        import profile_packages
                    if (profile_packages.is_bundled_directory(directory)
                            and path.stem in profile_packages.NAMES):
                        continue
                    groups.setdefault(path.stem, []).append((path, scope))
                    try:
                        if path.is_symlink() or not path.is_file():
                            raise ValueError("definition must be a regular file, not a symlink")
                        # O_NOFOLLOW closes the check/open symlink race on Unix;
                        # O_NONBLOCK avoids blocking on a substituted FIFO.
                        raw = _read_source(path)
                        fields, persona = _frontmatter(raw)
                        for key in fields.keys() - KEYS:
                            problem(path, scope, f"unknown key {key!r}")
                        spec = _spec(path, scope, raw, fields, persona,
                                     default_cli, settings, manifest)
                        specs[spec.name] = spec
                        sources[spec.name] = raw
                    except Exception as exc:
                        problem(path, scope, str(exc))
            except Exception as exc:
                problem(directory, scope, str(exc))
        try:
            from . import profile_packages
        except ImportError:
            import profile_packages
        adopted, adoption_problems, adopted_sources, membership = profile_packages.adopted_catalog(repo)
        problems.extend(adoption_problems)
        for name, spec in adopted.items():
            groups.setdefault(name, []).append((Path(spec.path), "repo"))
            specs[name] = spec
            # Approved snapshots retain original bytes in the private record.
            # The public import manifest must still carry those same bytes.
            sources[name] = adopted_sources[name]
        for name, entries in groups.items():
            if len(entries) > 1:
                specs.pop(name, None)
                sources.pop(name, None)
                membership.pop(name, None)
                problem(entries[0][0], entries[0][1],
                        f"duplicate name {name!r}; all entries unusable: " +
                        ", ".join(str(path) for path, _ in entries))
    except Exception as exc:
        problem(str(repo_root), "repo", str(exc))
    if _with_membership:
        return specs, problems, sources, membership
    return specs, problems, sources


def load_all(repo_root=None, *, home=None, global_root=None):
    """Discover definitions using explicit roots, or the legacy process defaults."""
    specs, problems, _ = _load_catalog(repo_root, home=home, global_root=global_root)
    return specs, problems


def resolve(name, repo_root=None, *, home=None, global_root=None):
    return load_all(repo_root, home=home, global_root=global_root)[0].get(name)


class Roster(list):
    """List-compatible selection with proposal diagnostics (never launch specs)."""
    def __init__(self, members, gaps=()):
        super().__init__(members)
        self.gaps = list(gaps)


def _deep_chain(task, dependencies):
    """Three dependency edges are deep; bounded traversal also tolerates cycles."""
    frontier = [(task.get("blockedBy") or [], frozenset(filter(None, (task.get("key"), task.get("id")))), 0)]
    while frontier:
        keys, seen, depth = frontier.pop()
        for key in keys:
            if key in seen:
                continue
            if depth + 1 >= 3:
                return True
            frontier.append((dependencies.get(key, ()), seen | {key}, depth + 1))
    return False


def choose_roster(task, specs, cfg, cli_override=None, *, dependencies=None, approved_lead=None):
    """Select a deterministic lead, then bounded workers from existing card signals.

    dependencies maps board keys to blockedBy keys; callers resolve it, keeping
    selection independent of storage. C3 documents sizing, ranking and gaps.
    """
    if approved_lead is not None:
        if not isinstance(approved_lead, AgentSpec) or approved_lead.role != "lead":
            raise ValueError("approved lead must be a lead definition")
        lead = approved_lead
        if cli_override and cli_override != lead.cli:
            lead = replace(lead, cli=cli_override, auth=None, model=None)
    else:
        lead = AgentSpec("lead", "repo", "", "Default dispatch lead",
                         cli_override or cfg.get("dispatchCli") or "codex", None, None,
                         "unrestricted", (), (), "", "lead", (), "integration", 1, "")
    if lead.cli != "claude" and (lead.tools or lead.tools_deny):
        warnings.warn(f"{lead.name}: tools/tools-deny degrade on {lead.cli}; "
                      "named tool restrictions are Claude-only", UserWarning, stacklevel=2)
    labels = set(task.get("labels") or [])
    deep = _deep_chain(task, dependencies or {})
    directories = {parts[0] for path in task.get("touches") or []
                   if len(parts := path.replace("\\", "/").removeprefix("./").split("/")) > 1}
    kind = task.get("type")
    workers = max(1, len(directories), 2 if kind in ("story", "spike") else 1)
    if len(task.get("acceptance") or []) >= 5:
        workers += 1
    if kind == "bug" or deep:
        workers = 1
    limit = max(0, min(8, int(cfg.get("teamMaxWorkers", 2))))
    if deep or kind == "bug":
        limit = min(limit, 2 if kind == "bug" else 1)
    selected = [lead]
    candidates = [s for s in specs.values() if s.role != "lead" and
                  s.name != lead.name and s.max_instances >= 1]
    missing = labels - set(lead.capabilities)

    def rank(spec):
        # THE CARD'S OWN LABELS ARE THE TIEBREAK, and without them selection fell
        # through to alphabetical order.
        #
        # `missing` is what the LEAD does not cover, which is the right primary
        # signal - the point of a worker is to bring something the lead has not got.
        # But when the lead already matches the card well, `missing` is empty or
        # irrelevant, every candidate scores zero, and `spec.name` decides. A card
        # labelled inventory/catalog/filesystem, whose lead covered all three,
        # recruited hr-recruiter, plc-dev and plc-test-engineer - the first three
        # worker definitions in the alphabet - while the three scanners written for
        # exactly that card sat unproposed, because "scan-" sorts after "plc-".
        #
        # So: fill the lead's gaps first, and where that cannot separate them, prefer
        # the definitions that match what the card is ABOUT. Alphabetical order stays
        # as the final key, so selection is still deterministic and independent of
        # dict ordering.
        covered = set(spec.capabilities)
        senior = bool({"senior", "expert", "principal"} &
                      (covered | set(spec.name.split("-"))))
        return (-int(deep and senior), -len(missing & covered),
                -len(labels & covered), spec.name)

    # Reserve the second slot for a bug reviewer, if the configured cap allows it.
    requests = ["worker"] + (["reviewer"] if kind == "bug" else []) + ["worker"] * (workers - 1)
    shortages = ([] if approved_lead is not None else
                 ["Lead: no project-approved definition; using compatibility fallback"])
    for role in requests:
        pool = [s for s in candidates if s.role == role or
                (role == "worker" and kind == "spike" and s.role == "researcher")]
        if len(selected) - 1 >= limit:
            shortages.append(f"{role}: teamMaxWorkers limit ({limit})")
        elif not pool:
            shortages.append(f"{role}: no available definition (one instance per name)")
        else:
            member = min(pool, key=rank)
            selected.append(member)
            candidates.remove(member)
            missing.difference_update(member.capabilities)
    # Matched labels may recruit additional specialists within the same cap.
    while missing and len(selected) - 1 < limit:
        pool = [s for s in candidates if missing & set(s.capabilities)]
        if not pool:
            break
        member = min(pool, key=rank)
        selected.append(member)
        candidates.remove(member)
        missing.difference_update(member.capabilities)
    supplied = set().union(*(set(s.capabilities) for s in specs.values()))
    gaps = [f"Capability {label}: " + ("no definition provides it" if label not in supplied
            else "not covered by selected roster") for label in sorted(missing)]
    return Roster(selected, gaps + sorted(set(shortages)))
