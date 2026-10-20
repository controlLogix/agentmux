#!/usr/bin/env python3
"""Local agentmux dashboard with opt-in pane resizing, served on localhost:8787."""

import base64
import boardagents
from definition_commands import LocalDefinitionOutcomeUnconfirmed
from dashboard_commands import DashboardOutcomeUnconfirmed
from oidc_browser_login import oidc_browser_cookie
import chatter_feed
import codesys_panel
import github_panel
import fed_panel
import hub_panel
import boardteams
import ccboard
import ccstore
import datetime as dt
from agentmux_contracts import ContractError
import github_auth
import json
import mqtt
import mqtt_monitor
import modbus_poll
import netscan
import os
from pathlib import Path
import profinet
import runsview
import re
import secrets
import stat
import struct
import subprocess
import suite_server
import sys
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parent
# AGENTMUX_HOME, as everything else in this repo already honours it.
#
# #25, found while testing #21. agentmux.sh, courier.py, coordination.py and run.py all
# resolve their root as os.environ.get("AGENTMUX_HOME", ~/.agentmux); these two files
# hardcoded ~/.agentmux. So the moment AGENTMUX_HOME is set - which every test suite
# does, and which is the only way to run a second isolated harness - the CLI and the
# dashboard silently read DIFFERENT directories. The dashboard then shows an empty
# queue, no agents and no runs while the CLI works perfectly, and nothing anywhere says
# the two are looking at different state.
#
# Unset, this is byte-for-byte the previous expression, so nothing about the normal
# deployment changes.
HOME_DIR = Path(os.environ.get("AGENTMUX_HOME", str(Path.home() / ".agentmux")))
RUN_DIR = HOME_DIR / "run"
LOG_DIR = HOME_DIR / "logs"
STREAM_SLOTS = threading.BoundedSemaphore(16)

# ONE STREAM PER AGENT.
#
# The global slot pool alone is not enough. A browser reload opens a fresh EventSource
# per pane while the previous ones are still established — the server cannot tell a
# client has gone until it next tries to write, and with a quiet agent that is up to a
# heartbeat away. Seven panes over a couple of reloads exhausted all sixteen slots, and
# three panes then sat at HTTP 503 showing nothing at all.
#
# So each agent gets a generation number. Opening a stream bumps it; any older thread for
# that agent sees it has been superseded and exits, releasing its slot. Slots held is then
# bounded by the number of AGENTS, not by how many times the page has been loaded.
_stream_gen = {}
_stream_gen_lock = threading.Lock()


def claim_stream(name):
    """Register as the current stream for `name` and return this claim's generation."""
    with _stream_gen_lock:
        generation = _stream_gen.get(name, 0) + 1
        _stream_gen[name] = generation
        return generation


def stream_superseded(name, generation):
    with _stream_gen_lock:
        return _stream_gen.get(name, 0) != generation

# An MQTT exchange blocks its handler thread for up to CONNECT_TIMEOUT +
# SUBSCRIBE_WINDOW. Without a cap, parallel requests against a black-holed broker
# accumulate threads and starve /api/agents and the SSE streams. Same pattern as
# STREAM_SLOTS, deliberately small: this is an operator poking one broker.
MQTT_SLOTS = threading.BoundedSemaphore(4)

# ccstore's validators allow 8192-byte notes, journal bodies and device meta, so the
# request cap has to leave room for that plus JSON overhead. It must stay <= 9999
# because read_cc_body bounds Content-Length to four digits.
CC_BODY_MAX = 9600
HEARTBEAT_SECONDS = 15
NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# Every entry here is read through read_field(), which is the hardened reader
# (regular files only, st_nlink > 1 rejected, O_NOFOLLOW, 512-byte cap, control
# characters rejected). Adding a field inherits all of that; "auth" holds a method
# id from auth.json and never a credential.
FIELDS = ("cli", "perms", "cwd", "launch", "started", "task", "auth",
          "agentdef", "posture", "team", "role")
EXTENSIONS = set(FIELDS) | {"pane"}

# --- Jira reaper -------------------------------------------------------------
#
# agentmux is a pure CLI with no daemon, so nothing runs when a pane exits on its
# own - `agentmux kill` closes its own issues, but a crash or a stray
# `tmux kill-session` leaves the ticket open forever. This server is the only
# long-running piece, and it already computes state == "stale", so the reaper
# belongs here.
#
# Semantics are AT MOST ONCE: the marker is written before the call. A missed
# transition is a nuisance; a Jira comment posted twice on every restart is worse.
TASK_CLI = ROOT.parent / "taskmgmt" / "task.py"
ATLASSIAN_CFG = HOME_DIR / "atlassian.json"
_reaping = set()
_reap_lock = threading.Lock()


def task_management_ready():
    return TASK_CLI.is_file() and ATLASSIAN_CFG.is_file()


def _reap_worker(name, key):
    """Close out one dead agent's issue. Runs off the request thread."""
    try:
        for args in (["done", key, "--from-log", name],
                     ["report", name, "--title", f"agentmux run - {name} - {key}"]):
            subprocess.run(["python3", str(TASK_CLI), *args],
                           # stdout and stderr were already silenced here; stdin was
                           # not, which is the half of the problem that eats scripts.
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=90, check=False)
    except Exception:
        pass            # best effort: never let this surface into an HTTP response
    finally:
        with _reap_lock:
            _reaping.discard(name)


def maybe_reap(name, key):
    """Fire the reaper once for an agent seen stale with a bound issue."""
    if not key or not NAME_PATTERN.fullmatch(name or "") or not task_management_ready():
        return
    # #16. THE MARKER IS SHARED WITH THE CLI, SO IT MUST BE CLAIMED, NOT CHECKED.
    #
    # `_reap_lock` serialises this server's own threads, and only those. `agentmux kill`
    # and `agentmux reap` close the same agent out from separate PROCESSES, where
    # exists()-then-write() is plain check-then-write: both can see "absent" and both
    # post, so a real Jira issue gets two close-out comments and two Confluence reports.
    #
    # It was worse than a narrow race. The marker used to live at run/<name>.reported,
    # and both CLI paths run `rm -f run/<name>.*` immediately after the close-out - so
    # the marker was deleted microseconds after it was written and this check was very
    # nearly guaranteed to miss. run/reported/<name> is a sibling directory that the
    # sidecar glob does not match, so it survives the sweep and is still here when we
    # look. O_CREAT|O_EXCL makes the create itself the claim: one winner, cross-process.
    legacy = RUN_DIR / f"{name}.reported"        # pre-2026-09-22 location
    marker = RUN_DIR / "reported" / name
    with _reap_lock:
        if name in _reaping or marker.exists() or legacy.exists():
            return
        _reaping.add(name)
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        # Claimed first, so a crash mid-call cannot cause a duplicate on restart.
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        # The CLI got here first. Not an error - exactly one close-out is the point.
        with _reap_lock:
            _reaping.discard(name)
        return
    except OSError:
        with _reap_lock:
            _reaping.discard(name)
        return
    try:
        os.write(fd, b"reaped-by-dashboard\n")
    finally:
        os.close(fd)
    threading.Thread(target=_reap_worker, args=(name, key), daemon=True).start()


# --- resource manifest -------------------------------------------------------
#
# The Resources tab is manifest-driven: resources.json declares what to probe and
# what commands to SHOW the operator. The security model is simply that argv comes
# from that file and never from a request. A client may name a resource id; it can
# never supply a command. Actions are shown, never executed.
#
# Results are cached because a full sweep spawns a dozen subprocesses and the tab
# polls. Checks run in a bounded pool so a slow CLI cannot stall the server.
MANIFEST = ROOT / "resources.json"
_res_cache = {"at": 0.0, "data": None}
_res_lock = threading.Lock()
_res_refresh_lock = threading.Lock()
RESOURCE_REFRESH_MIN = 2
RESOURCE_TTL = 12
RESOURCE_WORKERS = 4
CTRL = re.compile("[" + "".join(chr(c) for c in list(range(0, 9)) + list(range(11, 32)) + [127]) + "]")


def framed_snapshot(text):
    """Turn `capture-pane -p -e` output into bytes a terminal renders correctly.

    THE BUG THIS FIXES. capture-pane separates pane rows with a bare LF. A terminal
    treats LF as "down one row", NOT "down one row and back to column 1" — that second
    part is what CR does. The dashboard's terminals are built with convertEol: false,
    deliberately, because the live log stream carries real CRLF from the agent and
    converting it would corrupt that. So each snapshot row was starting at whatever
    column the previous row ended on, producing a staircase of fragments: a line would
    run off the right edge, wrap, and leave orphaned tails like "ng to read" and
    "ine 08" down the left. That is the "lines are gapped, not streaming properly"
    symptom, and it was in the snapshot only — appended log bytes always rendered fine.

    Normalise to CRLF so every row starts at column 1. Existing CRLF is collapsed first
    so nothing is doubled.

    Autowrap is also disabled around the payload: capture-pane emits exactly one line
    per pane row, and if any row reaches the last column the terminal would wrap it and
    push every subsequent row down by one, so the last rows would fall off the bottom.
    With DECAWM off, a full-width row stays on its own row. It is restored afterwards
    because the live agent output that follows genuinely needs wrapping.
    """
    body = text.replace("\r\n", "\n").replace("\r", "").replace("\n", "\r\n")
    return b"\x1b[?7l" + body.encode("utf-8") + b"\x1b[?7h"


def load_manifest():
    try:
        with open(MANIFEST, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or not isinstance(data.get("resources"), list):
            return None
        resources = data["resources"]
        if len(resources) > 16:
            return None
        resource_ids = set()
        count = 0
        for resource in resources:
            if not isinstance(resource, dict) or not isinstance(resource.get("id"), str):
                return None
            if resource["id"] in resource_ids:
                return None
            resource_ids.add(resource["id"])
            checks = resource.get("checks", [])
            if not isinstance(checks, list) or len(checks) > 16:
                return None
            check_ids = set()
            for check in checks:
                if not isinstance(check, dict) or not isinstance(check.get("id"), str):
                    return None
                if check["id"] in check_ids:
                    return None
                check_ids.add(check["id"])
            count += len(checks)
        if count > 64:
            return None
        return data
    except (OSError, ValueError):
        return None


def _clean(text, limit=160):
    """One safe line: no control bytes, length-capped."""
    line = CTRL.sub("", (text or "").strip().splitlines()[0] if (text or "").strip() else "")
    return line[:limit]


def _run_check(check):
    """Resolve only reviewed resource probes; requests never supply definitions."""
    from resource_probes import run_check
    return run_check(check)


# --- Jira tickets -------------------------------------------------------------
#
# The Ticket Reviewer reads real issues and can comment on or transition them.
#
# TWO DELIBERATE CHOICES:
#
# 1. No dry-run flag on these endpoints. Every other write here either happened or
#    returned an error, and a client-supplied "pretend" mode reintroduces exactly
#    the "did it actually happen?" ambiguity that has already bitten this codebase
#    three times. atlassian.py's dry_run is exercised by tests directly instead.
# 2. Searches are cached with a TTL. Jira is a network call on a site with an
#    hourly rate limit (500/hour on Free), and this view polls.
#
# These are the only endpoints that write to a system outside this machine, so the
# UI confirms before calling them.
ISSUE_KEY = re.compile(r"[A-Z][A-Z0-9_]{1,19}-[0-9]{1,10}")
TICKET_TTL = 30
_atlassian = None
_atlassian_error = None
_ticket_cache = {"at": 0.0, "data": None}
_ticket_lock = threading.Lock()


def atlassian_module():
    """Import taskmgmt/atlassian.py by path - taskmgmt/ is not a package."""
    global _atlassian, _atlassian_error
    if _atlassian is not None or _atlassian_error is not None:
        return _atlassian
    import importlib.util
    path = ROOT.parent / "taskmgmt" / "atlassian.py"
    try:
        spec = importlib.util.spec_from_file_location("agentmux_atlassian", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _atlassian = module
    except (OSError, ImportError, SyntaxError, ValueError) as err:
        _atlassian_error = f"{type(err).__name__}"
    return _atlassian


def atlassian_config():
    """Return (cfg, None) or (None, reason). The reason is safe to display."""
    module = atlassian_module()
    if module is None:
        return None, f"taskmgmt/atlassian.py could not be loaded ({_atlassian_error})"
    try:
        return module.load_config(ATLASSIAN_CFG), None
    except Exception as err:
        # load_config's messages name the file and what is missing, never the token.
        return None, str(err).splitlines()[0]


def ticket_setup_hint():
    return [
        {"label": "Create the REST config",
         "command": "python3 taskmgmt/setup_atlassian.py", "secret": True},
        {"label": "Verify it", "command": "python3 taskmgmt/task.py whoami"},
    ]


def tickets_snapshot(force=False):
    now = time.monotonic()
    with _ticket_lock:
        if not force and _ticket_cache["data"] and now - _ticket_cache["at"] < TICKET_TTL:
            return _ticket_cache["data"]

    cfg, reason = atlassian_config()
    if cfg is None:
        # Not an error state: Atlassian is optional. Say what is missing and how to
        # fix it rather than returning an empty list that looks like "no tickets".
        data = {"configured": False, "reason": reason, "setup": ticket_setup_hint(),
                "issues": []}
        with _ticket_lock:
            _ticket_cache.update(at=now, data=data)
        return data

    module = atlassian_module()
    project = str(cfg.get("jira_project") or "").strip()
    jql = (f"project = {project} ORDER BY updated DESC" if ISSUE_KEY.match(project + "-1")
           else "ORDER BY updated DESC")
    try:
        raw = module.jira_search(cfg, jql, limit=40)
    except Exception as err:
        data = {"configured": True, "error": f"Jira search failed: {type(err).__name__}",
                "detail": _clean(str(err), 300), "issues": []}
        with _ticket_lock:
            _ticket_cache.update(at=now, data=data)
        return data

    issues = []
    for item in (raw.get("issues") or [])[:40]:
        fields = item.get("fields") or {}
        status = ((fields.get("status") or {}).get("name")) or ""
        assignee = ((fields.get("assignee") or {}).get("displayName")) or ""
        issues.append({
            "key": _clean(str(item.get("key", "")), 40),
            "summary": _clean(str(fields.get("summary") or ""), 300),
            "status": _clean(status, 60),
            "assignee": _clean(assignee, 80),
            "labels": [_clean(str(l), 40) for l in (fields.get("labels") or [])[:8]],
        })
    data = {"configured": True, "project": _clean(project, 40),
            "base_url": _clean(str(cfg.get("base_url", "")), 200), "issues": issues}
    with _ticket_lock:
        _ticket_cache.update(at=now, data=data)
    return data


# --- auth methods -------------------------------------------------------------
#
# auth.json declares how each CLI can authenticate; ~/.agentmux/auth.json records
# the non-secret settings and which method is active. Both are safe to display.
#
# ~/.agentmux/env holds the SECRETS and is never read for its values. To answer "is
# the key set?", only variable NAMES are parsed out, and only names are returned.
# That discipline is the whole reason the two files are separate: this function may
# read one and must never surface the other.
AUTH_MANIFEST = ROOT / "auth.json"
AUTH_SETTINGS = HOME_DIR / "auth.json"
AUTH_ENV = HOME_DIR / "env"
ENV_EXPORT = re.compile(r"^\s*export\s+([A-Z][A-Z0-9_]{0,63})=", re.M)


def env_var_names():
    """Names only. Values are never read into a variable, logged or returned."""
    try:
        if AUTH_ENV.is_symlink() or not AUTH_ENV.is_file():
            return set(), None
        info = AUTH_ENV.lstat()
        if info.st_size > 65536:
            return set(), None
        mode = f"{stat.S_IMODE(info.st_mode):o}"
        text = AUTH_ENV.read_text(encoding="utf-8", errors="replace")
        names = set(ENV_EXPORT.findall(text))
        del text                      # keep the secret-bearing text out of scope
        return names, mode
    except OSError:
        return set(), None


def _setup_rows(source):
    return [
        {"id": str(a.get("id", "")), "label": _clean(str(a.get("label", "")), 90),
         "command": _clean(str(a.get("command", "")), 300),
         "secret": bool(a.get("secret")),
         "note": _clean(str(a.get("note", "")), 400)}
        for a in (source or []) if isinstance(a, dict)
    ]


def auth_validators():
    """The validators from setup_auth.py, imported rather than copied.

    auth.json names a validator per setting (`"validate": "model"`). Re-implementing
    those patterns here would give two sources of truth that drift silently — the
    browser accepting a value the CLI rejects, or the reverse.
    """
    global _auth_validators
    if _auth_validators is not None:
        return _auth_validators
    import importlib.util
    path = ROOT.parent / "taskmgmt" / "setup_auth.py"
    try:
        spec = importlib.util.spec_from_file_location("agentmux_setup_auth", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _auth_validators = module.VALIDATORS
    except Exception:
        _auth_validators = {}
    return _auth_validators


_auth_validators = None


def auth_snapshot():
    """Grouped by PROVIDER, because that is where shared attributes live.

    A region or an API key belongs to the provider, not to each CLI using it, so the
    payload reports it once with the methods nested underneath. That is also what
    lets the UI render one collapsible section per provider instead of repeating the
    same three fields under every CLI.
    """
    try:
        with AUTH_MANIFEST.open(encoding="utf-8") as fh:
            manifest = json.load(fh)
        methods = manifest["methods"]
        providers = manifest["providers"]
        if not isinstance(methods, list) or not isinstance(providers, list):
            raise ValueError("malformed")
    except (OSError, ValueError, KeyError) as err:
        return {"error": f"auth.json unreadable: {type(err).__name__}", "providers": []}

    settings, settings_mode = {}, None
    try:
        if AUTH_SETTINGS.is_file() and not AUTH_SETTINGS.is_symlink():
            settings_mode = f"{stat.S_IMODE(AUTH_SETTINGS.lstat().st_mode):o}"
            with AUTH_SETTINGS.open(encoding="utf-8") as fh:
                settings = json.load(fh)
    except (OSError, ValueError):
        settings = {}
    active = settings.get("active") or {}
    shared_all = settings.get("providers") or {}
    method_all = settings.get("methods") or {}
    present_names, env_mode = env_var_names()

    def setting_rows(specs, values, scope):
        """Non-secret settings: values ARE shown. A wrong region or gateway URL is
        exactly what an operator opens this screen to find."""
        rows = []
        for spec in specs or []:
            if not isinstance(spec, dict) or not spec.get("key"):
                continue
            key = str(spec["key"])
            rows.append({
                "key": key,
                "scope": scope,
                "label": _clean(str(spec.get("label", key)), 90),
                "example": _clean(str(spec.get("example", "")), 120),
                "value": _clean(str(values.get(key, "")), 200),
                "set": key in values,
            })
        return rows

    groups = []
    by_provider = {}
    for method in methods:
        if isinstance(method, dict) and method.get("id") and method.get("provider"):
            by_provider.setdefault(str(method["provider"]), []).append(method)

    for provider in providers:
        if not isinstance(provider, dict) or not provider.get("id"):
            continue
        pid = str(provider["id"])
        shared = shared_all.get(pid, {})
        provider_settings = setting_rows(provider.get("settings"), shared, "provider")
        # Secrets report PRESENCE only - never a value, never a length, never a
        # prefix, because a prefix is still a leak.
        provider_secrets = [{"name": s, "set": s in present_names}
                            for s in (provider.get("secrets") or [])
                            if isinstance(s, str)]
        provider_gaps = ([f"{pid}.{r['key']}" for r in provider_settings if not r["set"]]
                         + [s["name"] for s in provider_secrets if not s["set"]])

        rows = []
        for method in sorted(by_provider.get(pid, []), key=lambda m: str(m["id"])):
            mid = str(method["id"])
            cli = str(method.get("cli", ""))
            mine = method_all.get(mid, {})
            method_settings = setting_rows(method.get("settings"), mine, "method")
            method_gaps = [f"{mid}.{r['key']}" for r in method_settings if not r["set"]]
            rows.append({
                "id": mid,
                "cli": cli,
                # Settings the browser may change: non-secret, declared, and validated.
                "editable": [row["key"] for row in method_settings],
                "label": _clean(str(method.get("label", "")), 90),
                "default": bool(method.get("default")),
                "active": active.get(cli) == mid,
                "settings": method_settings,
                "missing": provider_gaps + method_gaps,
                "configured": not (provider_gaps or method_gaps),
                "notes": [_clean(str(n), 400) for n in (method.get("notes") or [])],
                "setup": _setup_rows(method.get("setup")),
            })

        groups.append({
            "id": pid,
            "label": _clean(str(provider.get("label", pid)), 90),
            "kind": _clean(str(provider.get("kind", "")), 40),
            "summary": _clean(str(provider.get("summary", "")), 400),
            "settings": provider_settings,
            "secrets": provider_secrets,
            "missing": provider_gaps,
            "configured": not provider_gaps,
            "notes": [_clean(str(n), 400) for n in (provider.get("notes") or [])],
            "setup": _setup_rows(provider.get("setup")),
            "methods": rows,
            "clis": sorted({r["cli"] for r in rows if r["cli"]}),
        })

    return {
        "providers": groups,
        "active": {str(k): str(v) for k, v in active.items()},
        "files": {
            # Existence and mode only. This is the whole report on the secret file.
            "settings": {"path": "~/.agentmux/auth.json", "mode": settings_mode},
            "env": {"path": "~/.agentmux/env", "mode": env_mode,
                    "count": len(present_names)},
        },
    }


def resources_snapshot(force=False):
    """Coalesce refreshes and rate-limit repeated force requests."""
    with _res_lock:
        cached = _res_cache["data"]
        age = time.monotonic() - _res_cache["at"]
        if cached is not None and age < (RESOURCE_REFRESH_MIN if force else RESOURCE_TTL):
            return cached
    if not _res_refresh_lock.acquire(blocking=False):
        if cached is not None:
            return dict(cached, refreshing=True)
        return {"resources": [], "refreshing": True,
                "error": "Resource checks are running. Refresh shortly."}
    try:
        # Another sweep may have finished between the first read and acquisition.
        with _res_lock:
            cached = _res_cache["data"]
            age = time.monotonic() - _res_cache["at"]
            if cached is not None and age < (RESOURCE_REFRESH_MIN if force else RESOURCE_TTL):
                return cached
        return _resources_snapshot(force=force)
    finally:
        _res_refresh_lock.release()


def _resources_snapshot(force=False):
    now = time.monotonic()
    with _res_lock:
        if not force and _res_cache["data"] and now - _res_cache["at"] < RESOURCE_TTL:
            return _res_cache["data"]

    manifest = load_manifest()
    if manifest is None:
        payload = {"error": "resources.json missing or invalid", "resources": []}
    else:
        jobs = []
        for res in manifest["resources"]:
            for check in res.get("checks") or []:
                jobs.append((res.get("id"), check))

        results = {}
        # Bounded fan-out: a dozen CLI probes should not each get a thread.
        import concurrent.futures as cf
        with cf.ThreadPoolExecutor(max_workers=RESOURCE_WORKERS) as pool:
            futures = {pool.submit(_run_check, chk): (rid, chk)
                       for rid, chk in jobs}
            for fut in cf.as_completed(futures):
                rid, check = futures[fut]
                cid = check.get("id")
                try:
                    results[(rid, cid)] = fut.result()
                except Exception:
                    results[(rid, cid)] = {"id": cid, "label": check.get("label"), "ok": False,
                                           "detail": "Unknown: probe failed",
                                           "optional": bool(check.get("optional")),
                                           "hint": _clean(check.get("hint", ""), 300),
                                           "status": "unknown", "code": "probe_failed"}

        out = []
        for res in manifest["resources"]:
            checks = [results.get((res.get("id"), c.get("id")),
                                  {"id": c.get("id"), "label": c.get("label"),
                                   "ok": False, "detail": "Unknown: check not run", "status": "unknown",
                                   "optional": bool(c.get("optional"))})
                      for c in res.get("checks") or []]
            required = [c for c in checks if not c.get("optional")]
            state = ("ok" if required and all(c["ok"] for c in required)
                     else "partial" if any(c["ok"] for c in checks)
                     else "missing")
            out.append({
                "id": res.get("id"), "name": res.get("name"), "kind": res.get("kind"),
                "summary": res.get("summary", ""), "docs": res.get("docs", ""),
                "state": state, "checks": checks,
                "status": ("unavailable" if any(c.get("status") == "unavailable" for c in required)
                           else "unknown" if not required or any(c.get("status") != "configured" for c in required)
                           else "configured"),
                "health_version": res.get("health_version", 1),
                "scope": res.get("scope", "local-read-only"),
                # Actions are DATA for the UI to display. The server never runs them.
                "actions": [{"id": a.get("id"), "label": a.get("label"),
                             "command": a.get("command", ""),
                             "secret": bool(a.get("secret")), "note": a.get("note", "")}
                            for a in res.get("actions") or []],
                "notes": res.get("notes") or [],
            })
        payload = {"version": manifest.get("version", 1),
                   "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                   "resources": out}

    with _res_lock:
        _res_cache["at"] = time.monotonic()
        _res_cache["data"] = payload
    return payload


def feed_snapshot(limit=200):
    """Everything the harness currently knows, as one chronological stream.

    Merged HERE rather than in the browser for three reasons: the client would
    otherwise poll five endpoints and re-derive severity from each, a new source would
    have to be added twice, and the two heaviest sources are already cached
    server-side - resources_snapshot() spawns a probe per resource and agents_snapshot()
    shells out to tmux, so having the feed re-run them would have quietly tripled the
    cost of every poll.

    Never raises. A feed that goes blank because one source is unavailable is worse
    than a feed missing one source, so each block degrades on its own.
    """
    entries = []

    # 1 + 2. Journal and queue chatter, normalised in ccstore.
    try:
        with ccstore.connection() as db:
            entries.extend(ccstore.feed_rows(db, limit))
    except Exception as err:
        entries.append(ccstore.feed_entry(now_iso(), "fault", "error", "dashboard",
                                          f"feed could not read the database: {err}"))

    # 3. Agents. State the CURRENT condition rather than a change log - there is no
    #    history to diff against, and an operator asking "what is up right now" is
    #    better served by a truthful snapshot than by an invented transition.
    try:
        agents = agents_snapshot()
        if agents.get("tmux_server") is not True:
            entries.append(ccstore.feed_entry(agents.get("generated_at"), "agent", "error",
                                              "tmux", "tmux server is not running - no agent is reachable"))
        for a in agents.get("agents", []):
            name = a.get("name") or "?"
            state = str(a.get("state") or "")
            if state == "stale":
                entries.append(ccstore.feed_entry(agents.get("generated_at"), "agent", "warn",
                                                  name, "stale: sidecars in run/ but no live tmux session"))
            else:
                bits = [f"{state}", f"cli={a.get('cli') or '?'}", f"perms={a.get('perms') or '?'}"]
                if a.get("task"):
                    bits.append(f"task={a['task']}")
                entries.append(ccstore.feed_entry(agents.get("generated_at"), "agent", "info",
                                                  name, ", ".join(bits), a.get("task")))
    except Exception as err:
        entries.append(ccstore.feed_entry(now_iso(), "fault", "error", "dashboard",
                                          f"feed could not read agents: {err}"))

    # 4. Providers and systems, from the cached resource probes. force=False matters:
    #    this must never be the thing that starts a probe sweep.
    try:
        res = resources_snapshot(force=False)
        if res.get("error"):
            entries.append(ccstore.feed_entry(now_iso(), "provider", "error", "resources",
                                              str(res["error"])))
        for r in res.get("resources", []):
            state = str(r.get("state") or "missing")
            severity = {"ok": "info", "partial": "warn"}.get(state, "error")
            failed = [c.get("label") or c.get("id") or "?"
                      for c in (r.get("checks") or [])
                      if not c.get("ok") and not c.get("optional")]
            text = f"{state}"
            if r.get("summary"):
                text += f" - {r['summary']}"
            if failed:
                text += f" (failing: {', '.join(failed[:4])})"
            entries.append(ccstore.feed_entry(res.get("generated_at") or now_iso(),
                                              "provider", severity,
                                              r.get("name") or r.get("id") or "?", text,
                                              r.get("id")))
    except Exception as err:
        entries.append(ccstore.feed_entry(now_iso(), "fault", "error", "dashboard",
                                          f"feed could not read resources: {err}"))

    # 5b. Run notices. ccstore.FEED_SOURCES has carried "run" since the feed was
    #     written and Settings has shown a "runs" checkbox the whole time, with nothing
    #     behind either of them - so the one control an operator had for "tell me about
    #     runs" did nothing. This is what makes it mean something, and it costs no
    #     frontend change at all.
    #
    #     Read from the orchestrator inbox rather than re-folding every ledger: these
    #     are the notices run.py already decided were worth a person's attention, so
    #     the feed and the toast cannot disagree about what is worth saying.
    try:
        entries.extend(run_notice_entries())
    except Exception:
        pass

    # 5. Faults the other sources cannot express: messages the courier gave up on.
    #    These are the ones that matter most and were previously visible only by
    #    running `agentmux courier dead`.
    try:
        entries.extend(dead_letter_entries())
    except Exception:
        pass

    entries.sort(key=lambda e: e.get("at") or "", reverse=True)
    return {"generated_at": now_iso(), "entries": ration(entries, limit),
            "sources": list(ccstore.FEED_SOURCES),
            "severities": list(ccstore.FEED_SEVERITIES)}


def ration(entries, limit):
    """Take the newest `limit`, but never let one source starve the others.

    WHY THIS IS NOT JUST entries[:limit]. The journal and chatter blocks each fetch up
    to `limit` rows of their own, so a busy day produces several hundred entries newer
    than anything else the feed knows about - and a plain truncation then drops every
    other source entirely. Run notices are the sharpest case: there are a handful of
    them, they are the ones a person is actually waiting on, and they were being cut
    before anyone saw them. The Settings checkbox for them stayed decorative for a
    different reason than before, which is not an improvement.

    The client filters by source AFTER this, so anything cut here is invisible no
    matter what the operator ticks. That is what makes the cut the wrong place to be
    democratic about recency.

    Each source is guaranteed its newest few; whatever is left over is filled by
    recency across everything, so a quiet system still reads as one chronological
    stream and nothing is reordered.
    """
    if len(entries) <= limit:
        return entries
    reserve = max(5, limit // (len(ccstore.FEED_SOURCES) * 2))
    picked, seen = [], {}
    for entry in entries:                      # already newest-first
        source = entry.get("source")
        if seen.get(source, 0) < reserve:
            seen[source] = seen.get(source, 0) + 1
            picked.append(id(entry))
    keep = set(picked[:limit])
    out = [e for e in entries if id(e) in keep]
    for entry in entries:                      # fill the rest by pure recency
        if len(out) >= limit:
            break
        if id(entry) not in keep:
            out.append(entry)
    out.sort(key=lambda e: e.get("at") or "", reverse=True)
    return out[:limit]


def run_notice_entries(cap=40):
    """The run notices a person was meant to see, as feed lines.

    Read-only and bounded, like dead_letter_entries beside it. The inbox is run.py's
    file; this never claims, truncates or marks anything read - `agentmux run notices`
    owns that, and a reader that quietly consumed them would mean opening the dashboard
    silently cleared the terminal's copy.
    """
    path = HOME_DIR / "inbox" / "orchestrator.jsonl"
    out = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in raw.splitlines()[-cap:]:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        body = str(row.get("body") or "")
        # "kind" here is the inbox's own vocabulary (error/status), not the journal's.
        # A notice about a run that needs review is a warning, not a failure - see the
        # same distinction in run.record_notice.
        severity = "error" if row.get("kind") == "error" else "info"
        if "waiting on your review" in body:
            severity = "warn"
        out.append(ccstore.feed_entry(row.get("at"), "run", severity,
                                      str(row.get("ref") or "run"), body,
                                      row.get("ref")))
    return out


def dead_letter_entries(cap=40):
    """Undeliverable messages, read straight from the courier's dead-letter file.

    Read-only and bounded. The file is the courier's, so this never claims, truncates
    or rewrites it - `agentmux courier requeue` owns that, and two writers on that file
    is a bug this repo has already fixed once.
    """
    path = HOME_DIR / "courier" / "dead-letter.jsonl"   # courier.py:DEAD_LETTER
    out = []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in raw.splitlines()[-cap:]:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        msg = row.get("message") if isinstance(row.get("message"), dict) else row
        out.append(ccstore.feed_entry(
            row.get("at") or msg.get("at"), "fault", "error",
            msg.get("sender") or "courier",
            f"undeliverable to {msg.get('recipient') or '?'}: "
            f"{row.get('reason') or 'gave up'} - {msg.get('body') or ''}",
            msg.get("ref")))
    return out


def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def open_log(name):
    """Open only a regular, single-link log beneath the log directory."""
    if not NAME_PATTERN.fullmatch(name):
        raise ValueError("invalid name")
    path = LOG_DIR / (name + ".log")
    try:
        path.resolve().relative_to(LOG_DIR.resolve())
    except (ValueError, RuntimeError):
        raise PermissionError("unsafe log path") from None
    if LOG_DIR.is_symlink() or path.is_symlink():
        raise PermissionError("unsafe log path")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise FileNotFoundError("not a regular log")
    if info.st_nlink > 1:
        raise PermissionError("hardlinked log")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(LOG_DIR, flags | os.O_DIRECTORY)
    try:
        fd = os.open(name + ".log", flags | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    stream = os.fdopen(fd, "rb", buffering=0)
    try:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise FileNotFoundError("not a regular log")
        if (opened.st_nlink > 1
                or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
            raise PermissionError("unsafe log file")
    except OSError:
        stream.close()
        raise
    return stream


def tmux(*args):
    """Return successful tmux output, or None if unavailable."""
    try:
        result = subprocess.run(
            ["tmux", "-L", "agentmux", *args],
            stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=3, check=False,
        )
        return result.stdout if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


def read_field(path):
    # Validate both the pathname and opened file; never follow metadata links.
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink > 1
                or info.st_size > 512):
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb", buffering=0) as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink > 1
                    or opened.st_size > 512
                    or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
                return None
            raw = stream.read(512)
            after = os.fstat(stream.fileno())
            if after.st_nlink > 1 or after.st_size > 512:
                return None
        first_line = re.split(br"[\r\n]", raw, maxsplit=1)[0].decode("utf-8")
        if any(unicodedata.category(char) in ("Cc", "Cf") for char in first_line):
            return None
        return first_line.strip()
    except (OSError, ValueError, UnicodeError):
        return None


def agents_snapshot():
    now = dt.datetime.now().astimezone()
    sessions = tmux("list-sessions", "-F", "#{session_name}")
    live = set(sessions.splitlines()) if sessions is not None else set()
    metadata = {}
    try:
        # A redirected state directory must not expose unrelated files.
        if not RUN_DIR.is_symlink():
            for path in RUN_DIR.iterdir():
                name, separator, extension = path.name.rpartition(".")
                if name and separator and extension in EXTENSIONS:
                    metadata.setdefault(name, {})[extension] = path
    except OSError:
        pass

    agents = []
    for name in sorted(live | metadata.keys()):
        if not NAME_PATTERN.fullmatch(name):
            continue
        paths = metadata.get(name, {})
        agent = {"name": name}
        agent.update({field: read_field(paths[field]) if field in paths else None
                      for field in FIELDS})
        agent.update(cols=None, rows=None)
        if name in live:
            for field, pane_format in (("cols", "#{pane_width}"),
                                       ("rows", "#{pane_height}")):
                dimension = tmux("list-panes", "-t", "=" + name, "-F", pane_format)
                try:
                    agent[field] = int(dimension.strip()) if dimension else None
                except ValueError:
                    pass
            clients = tmux("list-clients", "-t", "=" + name)
            agent["state"] = "attached" if clients and clients.strip() else "detached"
        else:
            agent["state"] = "stale"
            # Dead pane with a bound issue: close it out exactly once.
            maybe_reap(agent.get("name"), agent.get("task"))
        agent["uptime_seconds"] = None
        if agent["started"]:
            try:
                started = dt.datetime.fromisoformat(
                    agent["started"].replace("Z", "+00:00"))
                if started.tzinfo is None:
                    started = started.astimezone()
                agent["uptime_seconds"] = int((now - started).total_seconds())
            except (ValueError, OverflowError, OSError):
                pass
        agents.append(agent)
    return {"generated_at": now.isoformat(timespec="seconds"),
            "tmux_server": sessions is not None, "agents": agents}


_modbus_service = None
_modbus_lock = threading.Lock()


def modbus_service():
    global _modbus_service
    with _modbus_lock:
        if _modbus_service is None:
            def journal(event):
                with ccstore.connection() as db:
                    ccstore.write(db, 'journal', {
                        'kind': 'note', 'agent': event['actor'],
                        'subject': 'Modbus write ' + event['outcome'],
                        'body': json.dumps(event, allow_nan=False)})
            _modbus_service = modbus_poll.Poller(HOME_DIR / 'modbus-tags.json', journal)
        return _modbus_service


def journal_event(subject, event):
    """Append one operational event to the Control Center journal.

    Shared by the field services (MQTT, the network scanner, PROFINET imports and
    GitHub writes) so every side effect this dashboard causes lands in the same
    append-only log the Status view reads. Failures here are swallowed by the
    caller: a journal that is briefly unavailable must not abort an action the
    operator is watching succeed.
    """
    with ccstore.connection() as db:
        ccstore.write(db, 'journal', {
            'kind': 'note', 'agent': str(event.get('actor') or 'dashboard')[:64],
            'subject': subject,
            'body': json.dumps(event, allow_nan=False, default=str)})


_field_lock = threading.Lock()
_mqtt_monitor = None
_scanner = None
_profinet_schema = None
_github_login = None


def mqtt_service():
    global _mqtt_monitor
    with _field_lock:
        if _mqtt_monitor is None:
            _mqtt_monitor = mqtt_monitor.Monitor(HOME_DIR / 'mqtt-monitor.json')
        return _mqtt_monitor


def scan_service():
    global _scanner
    with _field_lock:
        if _scanner is None:
            _scanner = netscan.Scanner(
                lambda event: journal_event('Network scan ' + event['outcome'], event))
        return _scanner


def profinet_service():
    global _profinet_schema
    with _field_lock:
        if _profinet_schema is None:
            _profinet_schema = profinet.Schema(HOME_DIR / 'profinet-stations.json')
        return _profinet_schema


def github_login_service():
    global _github_login
    with _field_lock:
        if _github_login is None:
            _github_login = github_auth.Login(
                lambda event: journal_event('GitHub ' + event['outcome'], event))
        return _github_login


class Handler(BaseHTTPRequestHandler):
    def send_body(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status, data):
        self.send_body(status, json.dumps(data).encode("utf-8"), "application/json")

    def send_local_auth(self, status, headers, data):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def local_auth_endpoint(self, path, query):
        owner = getattr(self.server, 'application_host', None)
        if owner is None:
            self.send_json(404, {'error': 'not found'})
            return
        if self.command != 'POST' or query:
            self.send_json(405, {'error': 'POST required'})
            return
        body = self.read_cc_body(1024)
        if body is None:
            return
        hosts, origins = self.headers.get_all('Host', []), self.headers.get_all('Origin', [])
        if len(hosts) != 1 or len(origins) != 1:
            self.send_json(403, {'error': 'local sign-in unavailable'})
            return
        try:
            if path == '/api/local-auth/oidc/start':
                if body:
                    raise ValueError()
                headers, response = owner.browser_oidc_start(method=self.command,
                    target=path, host=hosts[0].strip().lower(), origin=origins[0])
                self.send_local_auth(200, headers, response)
                return
            if path == '/api/local-auth/pair':
                if set(body) != {'challenge'}:
                    raise ValueError()
                login = owner.browser_pair(body['challenge'], method=self.command,
                    target=path, host=hosts[0].strip().lower(), origin=origins[0])
                headers, response = login.take_response()
                self.send_local_auth(200, headers, response)
                return
            if path == '/api/local-auth/logout':
                if body:
                    raise ValueError()
                cookies, csrf = self.headers.get_all('Cookie', []), self.headers.get_all('X-Agentmux-CSRF', [])
                if len(cookies) != 1 or len(csrf) != 1:
                    raise ValueError()
                headers = owner.browser_logout(cookies[0], csrf[0], method=self.command,
                    target=path, host=hosts[0].strip().lower(), origin=origins[0])
                self.send_local_auth(200, headers, {'ok': True})
                return
            self.send_json(404, {'error': 'not found'})
        except ContractError as error:
            if str(error) == 'oidc_browser_not_configured':
                self.send_local_auth(404, {'Cache-Control': 'no-store',
                    'Referrer-Policy': 'no-referrer'}, {'error': 'hosted sign-in unavailable'})
                return
            self.send_local_auth(401, {'Cache-Control': 'no-store',
                'Referrer-Policy': 'no-referrer'}, {'error': 'local sign-in unavailable'})
        except Exception:
            self.send_local_auth(401, {'Cache-Control': 'no-store',
                'Referrer-Policy': 'no-referrer'}, {'error': 'local sign-in unavailable'})

    def local_oidc_callback(self, target):
        owner = getattr(self.server, 'application_host', None)
        hosts = self.headers.get_all('Host', [])
        cookies = self.headers.get_all('Cookie', [])
        if (owner is None or self.command != 'GET' or len(hosts) != 1
                or len(cookies) != 1):
            self.send_body(404, b'Sign-in unavailable.', 'text/plain; charset=utf-8')
            return
        try:
            login = owner.browser_oidc_callback(target, cookies[0],
                method=self.command, host=hosts[0].strip().lower())
            headers, response = login.take_response()
            csrf = response.get('csrfToken')
            if not isinstance(csrf, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', csrf):
                raise ValueError()
            nonce = secrets.token_urlsafe(24)
            message = json.dumps({'kind': 'agentmux-oidc-login', 'csrfToken': csrf},
                                 separators=(',', ':'))
            origin = json.dumps('http://' + hosts[0].strip().lower())
            body = ("<!doctype html><meta charset=utf-8><title>Agentmux sign-in</title>"
                "<p>Sign-in complete. You can return to Agentmux.</p>"
                f"<script nonce={json.dumps(nonce)}>"
                f"const message={message};"
                "const channel=new BroadcastChannel('agentmux-local-auth');"
                "channel.postMessage(message);channel.close();"
                f"if(window.opener)window.opener.postMessage(message,{origin});"
                "setTimeout(()=>window.close(),50);</script>").encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy',
                             "default-src 'none'; script-src 'nonce-" + nonce
                             + "'; base-uri 'none'; frame-ancestors 'none'")
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header('Set-Cookie', oidc_browser_cookie('', 0))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            body = b'Sign-in could not be completed.'
            self.send_response(401)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Set-Cookie', oidc_browser_cookie('', 0))
            self.end_headers()
            self.wfile.write(body)

    # How much of a REFUSED body is worth reading. Comfortably above every request
    # this server accepts - the largest cap is MQTT publish at 4096 - and small
    # enough that the drain itself cannot be turned into the denial of service.
    DRAIN_LIMIT = 16384
    # Class-level default so no path can reach the drain before do_GET has set it.
    body_consumed = False

    def drain_request_body(self):
        """Consume a refused request's body so the close is a FIN and not an RST.

        CLOSING A SOCKET THAT STILL HAS UNREAD DATA MAKES THE KERNEL SEND RST RATHER
        THAN FIN, and an RST can discard a response that already reached the client's
        receive buffer but has not been read out of it yet. Every refusal here -
        403 forbidden origin, 415, 405 read-only, 400 - answers and returns without
        touching the body, so a perfectly correct refusal arrives at the caller as
        ConnectionResetError instead of as the status it was sent.

        Measured against this server, POST /api/netscan/start with a foreign Origin:

            2-byte body, 500 serial              500 x 403
            2-byte body, 500 over 20 threads     497 x 403,  3 x ConnectionResetError
            64 KiB body, 200 serial              198 x 403,  2 x ConnectionResetError
            1 MiB body, 100 over 10 threads      100 x BrokenPipeError

        The more unread body, the likelier the reset - which is why this read as a
        rare flake rather than a bug: the bodies this server refuses are usually two
        bytes, and two bytes almost always fit in the receive queue quietly. It cost
        a gate run as `test_field_panels.py ConnectionResetError` with no failing
        assertion anywhere in the suite.

        Nothing is drained for a body too large to be worth reading or a request too
        malformed to have a length: those are refused precisely so they are not read,
        and a caller sending one has already left the protocol.
        """
        if self.headers.get("Transfer-Encoding") is not None:
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,5}", lengths[0]):
            return
        remaining = int(lengths[0])
        if remaining > self.DRAIN_LIMIT:
            return
        previous_timeout = self.connection.gettimeout()
        try:
            self.connection.settimeout(5)
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 4096))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass
        finally:
            try:
                self.connection.settimeout(previous_timeout)
            except OSError:
                pass

    def do_GET(self):
        # Per REQUEST, not per connection: one Handler instance serves every request
        # on a kept-alive connection.
        self.body_consumed = False
        try:
            if not self.host_allowed():
                self.send_json(421, {"error": "misdirected request: unknown Host"})
                return
            self.route()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.send_json(500, {"error": "internal server error"})
        finally:
            # HERE, and only here, because every refusal in this file is a `send_json`
            # followed by a bare return - and there are a dozen of them, in two guard
            # chains and every read-only endpoint. Draining at each site would mean
            # getting all twelve right and every future one as well.
            if not self.body_consumed:
                self.drain_request_body()

    do_HEAD = do_GET
    do_POST = do_GET

    def allowed_origins(self):
        """The origins this server may be reached from: its OWN bound port.

        This used to be the literal string "http://127.0.0.1:8787" in two places.
        That is the same check - the server only ever binds loopback, so its own
        origin is the only same-origin one there is - but writing the port as a
        constant meant the guard was really asserting "we are on 8787", and any
        instance on another port refused every write with `forbidden origin`. That
        made the write paths untestable anywhere except the one port the operator's
        own dashboard already owns, which is exactly the port a test must not take.

        Both host spellings are accepted because both address this same server and
        the browser sends whichever one is in the address bar.
        """
        port = self.server.server_address[1]
        return (f"http://127.0.0.1:{port}", f"http://localhost:{port}")

    def host_allowed(self):
        """Refuse any request whose Host is not this server's own loopback name.

        The Origin check only guards writes. Reads such as /api/stream/<agent> return
        live terminal content, and binding 127.0.0.1 does not stop DNS rebinding: a
        page on evil.example re-points its own name at 127.0.0.1, and the browser then
        treats this server as same-origin with that page and lets it read the
        response. The browser still sends `Host: evil.example:8787`, so allowing only
        our own names closes that path. A missing Host (HTTP/1.0 tooling) is allowed,
        because a browser always sends one.
        """
        hosts = self.headers.get_all("Host", [])
        if not hosts:
            return True
        return len(hosts) == 1 and f"http://{hosts[0].strip().lower()}" in self.allowed_origins()

    def read_cc_body(self, max_bytes=1024):
        """Apply the same JSON, origin, length and timeout guards as resize.

        max_bytes is raised only for MQTT publish, whose payload cap (4096 bytes)
        does not fit a 1024-byte body. The 4-digit Content-Length check below still
        bounds it at 9999 regardless of what a caller asks for.
        """
        content_types = self.headers.get_all("Content-Type", [])
        if (len(content_types) != 1
                or content_types[0].split(";", 1)[0].strip().lower() != "application/json"):
            self.send_json(415, {"error": "application/json required"})
            return None
        origins = self.headers.get_all("Origin", [])
        if origins and (len(origins) != 1 or origins[0] not in self.allowed_origins()):
            self.send_json(403, {"error": "forbidden origin"})
            return None
        lengths = self.headers.get_all("Content-Length", [])
        if (self.headers.get("Transfer-Encoding") is not None
                or len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0])):
            self.send_json(400, {"error": "invalid content length"})
            return None
        if len(lengths[0]) > 4 or int(lengths[0]) > max_bytes:
            self.send_json(413, {"error": "request body too large"})
            return None
        length = int(lengths[0])
        previous_timeout = self.connection.gettimeout()
        try:
            self.connection.settimeout(5)
            raw = self.rfile.read(length)
            self.body_consumed = True
        except OSError:
            # Consumed as far as this request is concerned: we have already waited
            # the five seconds this body was worth, and do_GET must not spend another
            # five draining what never arrived.
            self.body_consumed = True
            self.send_json(408, {"error": "request body timeout"})
            return None
        finally:
            self.connection.settimeout(previous_timeout)
        try:
            if len(raw) != length:
                raise ValueError
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, UnicodeError, RecursionError):
            self.send_json(400, {"error": "invalid JSON object"})
            return None
        return body

    def cc_endpoint(self, resource, query):
        try:
            if self.command == "POST":
                if resource == "messages":
                    self.send_json(405, {"error": "read-only endpoint"})
                    return
                body = self.read_cc_body(CC_BODY_MAX)
                if body is None:
                    return
                values = ccstore.validate_write(resource, body)
                with ccstore.connection() as db:
                    result = ccstore.write(db, resource, values)
                self.send_json(200, result)
                return
            if resource in ("tasks", "status", "delete"):
                self.send_json(405, {"error": "POST required"})
                return
            params = parse_qs(query, keep_blank_values=True, max_num_fields=16)
            allowed = {"limit", "since"} if resource == "messages" else (
                {"limit"} if resource == "journal" else set())
            if params.keys() - allowed or any(len(values) != 1 for values in params.values()):
                raise ccstore.Invalid("invalid query parameters")
            raw_limit = params.get("limit", ["100"])[0]
            if not re.fullmatch(r"[0-9]{1,4}", raw_limit) or not 1 <= int(raw_limit) <= 1000:
                raise ccstore.Invalid("limit must be between 1 and 1000")
            since = ccstore.parse_timestamp(params["since"][0]) if "since" in params else None
            with ccstore.connection() as db:
                result = ccstore.read(db, resource, int(raw_limit), since)
            self.send_json(200, {resource: result})
        except ccboard.Refused as err:
            # /api/status runs the board's gates now, so this surface can be told
            # no. Refused subclasses Exception, not ValueError, so without this arm
            # a gated refusal falls past the whole ladder below and answers 500 -
            # "the server broke" instead of "that card has no evidence yet". The
            # 409 and the `missing` list match board_endpoint exactly, so one
            # client-side handler prints the remedy for either surface.
            self.send_json(409, {"error": str(err), "missing": err.missing})
        except ccstore.Invalid as err:
            # Invalid subclasses ValueError, so it MUST be caught first or the
            # generic handler below swallows the reason and every rejection reads
            # "invalid fields" - which tells the operator nothing. These messages
            # name a field or a bound and never echo submitted content, so they
            # are safe to return.
            self.send_json(400, {"error": str(err)})
        except (ValueError, RecursionError):
            self.send_json(400, {"error": "invalid fields or query parameters"})
        except (ccboard.NotFound, ccstore.NotFound):
            # BOTH, as the board endpoint does at board_endpoint's ladder. These
            # verbs now delegate into ccboard, so a refusal raised down there -
            # deleting something already deleted, say - arrives as ccboard's
            # NotFound. Catching only ccstore's turned that into a 500, which
            # reads as "the server broke" rather than "that is already gone".
            self.send_json(404, {"error": "id not found"})
        except ccstore.sqlite3.IntegrityError:
            self.send_json(409, {"error": "record conflicts with existing data"})
        except (ccstore.sqlite3.Error, OSError, RuntimeError):
            self.send_json(503, {"error": "Control Center storage unavailable"})

    # ── the task-management surface ──────────────────────────────────────────
    #
    # /api/epics and /api/tasks stay exactly as they were - see ccstore.write for
    # why they are treated as mirrors. Everything below is the explicit, gated
    # board: it is addressed by minted key (TM-014), it refuses a task that is not
    # specified well enough to start or close, and it is what the board UI and the
    # CLI drive.
    #
    # Every mutation repeats the /api/resize guards, because read_cc_body applies
    # them: POST only, application/json required, cross-origin Origin rejected,
    # bounded body. The op is picked from a table in code, never interpolated.

    BOARD_READS = ("board", "meta", "entity", "history", "why", "graph", "doctor",
                   "find", "next", "sprint", "dispatchable", "agents", "roster",
                   "targets", "chatter", "profiles")
    BOARD_WRITES = ("create", "update", "status", "move", "delete", "acceptance",
                    "label", "dep", "evidence", "commit", "touch", "comment",
                    "link", "triage", "state", "config", "override",
                    "agentdef", "agentdrop", "recruit", "approve", "retire", "hire",
                    "plcstate", "bootapp", "chatsend")

    def runs_endpoint(self, rest, query):
        """Runs, read-only, plus the one write: the operator's review decision.

        `rest` is what followed /api/runs - "" for the list, "<id>" for one run,
        "<id>/diff" for what it changed, "<id>/review" for the decision. Every id is
        validated by run.valid_run() before it reaches a path join; the six-hex shape
        is the only thing that ever indexes into ~/.agentmux/runs.
        """
        parts = [p for p in rest.split("/") if p] if rest else []
        try:
            if not parts:
                if self.command != "GET":
                    self.send_json(405, {"error": "read-only endpoint"})
                    return
                raw = parse_qs(query).get("limit", ["20"])[0]
                limit = int(raw) if re.fullmatch(r"[0-9]{1,3}", raw) else 20
                self.send_json(200, runsview.list_runs(limit))
                return
            run_id, tail = parts[0], (parts[1] if len(parts) > 1 else "")
            if len(parts) > 2 or not runsview.runmod.valid_run(run_id):
                self.send_json(404, {"error": "not found"})
                return
            if tail == "review":
                # The ONE write here, and it is the human gate in front of
                # completion - see runsview's approval comment for why an agent
                # verifying every job is not the same as the work being wanted.
                if self.command != "POST":
                    self.send_json(405, {"error": "POST required"})
                    return
                body = self.read_cc_body(4096)
                if body is None:
                    return
                decision = body.get("decision")
                if decision not in ("approved", "changes"):
                    self.send_json(400, {"error": "decision must be approved or changes"})
                    return
                note = body.get("note")
                if note is not None and not isinstance(note, str):
                    self.send_json(400, {"error": "note must be a string"})
                    return
                application = getattr(self.server, 'application_host', None)
                if application is not None:
                    cookies = self.headers.get_all('Cookie', [])
                    csrf = self.headers.get_all('X-Agentmux-CSRF', [])
                    hosts = self.headers.get_all('Host', [])
                    origins = self.headers.get_all('Origin', [])
                    if not all(len(values) == 1 for values in
                               (cookies, csrf, hosts, origins)):
                        self.send_local_auth(401, {'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer'},
                            {'error': 'local sign-in required'})
                        return
                    try:
                        result = application.browser_dashboard_command(cookies[0], csrf[0],
                            method=self.command, target=f'/api/runs/{run_id}/review',
                            host=hosts[0].strip().lower(), origin=origins[0], body=body)
                    except DashboardOutcomeUnconfirmed as error:
                        self.send_local_auth(503, {'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer'}, {'error': 'dashboard outcome unconfirmed',
                            'outcome': 'uncertain', 'operationId': error.operation_id})
                        return
                    except ContractError:
                        self.send_local_auth(401, {'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer'},
                            {'error': 'local sign-in required'})
                        return
                    self.send_json(200, result)
                    return
                # The reviewer is the person at this browser. There is no identity to
                # check on loopback and pretending otherwise would be theatre; what
                # matters is that the decision is recorded and attributable to a
                # surface, which "operator (dashboard)" says honestly.
                record = runsview.write_approval(run_id, "operator (dashboard)",
                                                 note, decision)
                self.send_json(200, {"ok": True, "review": record})
                return
            if self.command != "GET":
                self.send_json(405, {"error": "read-only endpoint"})
                return
            if tail == "diff":
                self.send_json(200, runsview.review_diff(run_id))
                return
            if tail:
                self.send_json(404, {"error": "not found"})
                return
            self.send_json(200, runsview.detail(run_id))
        except runsview.ReviewError as err:
            # 409, matching the board: the request was well formed and the run said no.
            self.send_json(409, {"error": str(err)})
        except (OSError, ValueError) as err:
            self.send_json(500, {"error": f"runs unavailable ({type(err).__name__})"})

    def board_endpoint(self, op, query):
        try:
            if self.command == "POST":
                if op not in self.BOARD_WRITES:
                    self.send_json(405, {"error": "read-only endpoint"})
                    return
                body = self.read_cc_body(CC_BODY_MAX)
                if body is None:
                    return
                if not isinstance(body, dict):
                    raise ccboard.Invalid("body must be a JSON object")
                application = getattr(self.server, 'application_host', None)
                if application is not None and op in ('agentdef', 'agentdrop'):
                    cookies = self.headers.get_all('Cookie', [])
                    csrf = self.headers.get_all('X-Agentmux-CSRF', [])
                    hosts, origins = self.headers.get_all('Host', []), self.headers.get_all('Origin', [])
                    if not all(len(values) == 1 for values in (cookies, csrf, hosts, origins)):
                        self.send_local_auth(401, {'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer'}, {'error': 'local sign-in required'})
                        return
                    try:
                        result = application.browser_definition(cookies[0], csrf[0],
                            method=self.command, target='/api/board/' + op,
                            host=hosts[0].strip().lower(), origin=origins[0], body=body)
                    except (ccboard.Refused, ccboard.Invalid, ccboard.NotFound):
                        # Preserve the shared edit/conflict responses below.
                        raise
                    except Exception as error:
                        if isinstance(error, LocalDefinitionOutcomeUnconfirmed):
                            denied = error.code == 'definition_not_authorized'
                            response = {'error': ('definition completion denied' if denied
                                                  else 'definition outcome unconfirmed'),
                                'outcome': 'completion-denied' if denied else 'uncertain'}
                            operation_id = getattr(error, 'operation_id', None)
                            if isinstance(operation_id, str):
                                response['operationId'] = operation_id
                            self.send_local_auth(409 if denied else 503, {'Cache-Control': 'no-store',
                                'Referrer-Policy': 'no-referrer'}, response)
                            return
                        self.send_local_auth(401, {'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer'}, {'error': 'local sign-in required'})
                        return
                    self.send_json(200, result)
                    return
                if application is not None:
                    if 'actor' in body:
                        raise ccboard.Invalid('actor is supplied by the signed-in identity')
                    cookies = self.headers.get_all('Cookie', [])
                    csrf = self.headers.get_all('X-Agentmux-CSRF', [])
                    hosts = self.headers.get_all('Host', [])
                    origins = self.headers.get_all('Origin', [])
                    if not all(len(values) == 1 for values in
                               (cookies, csrf, hosts, origins)):
                        self.send_local_auth(401, {'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer'},
                            {'error': 'local sign-in required'})
                        return
                    try:
                        result = application.browser_dashboard_command(cookies[0], csrf[0],
                            method=self.command, target='/api/board/' + op,
                            host=hosts[0].strip().lower(), origin=origins[0], body=body)
                    except DashboardOutcomeUnconfirmed as error:
                        self.send_local_auth(503, {'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer'}, {'error': 'dashboard outcome unconfirmed',
                            'outcome': 'uncertain', 'operationId': error.operation_id})
                        return
                    except ContractError:
                        self.send_local_auth(401, {'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer'},
                            {'error': 'local sign-in required'})
                        return
                    self.send_json(200, result)
                    return
                with ccstore.connection() as db:
                    self.send_json(200, self.board_write(db, op, body))
                return
            if op not in self.BOARD_READS:
                self.send_json(405, {"error": "POST required"})
                return
            params = parse_qs(query, keep_blank_values=True, max_num_fields=8)
            if any(len(values) != 1 for values in params.values()):
                raise ccboard.Invalid("invalid query parameters")
            with ccstore.connection() as db:
                self.send_json(200, self.board_read(db, op, params))
        except boardteams.HireForbidden as err:
            self.send_json(403, {"error": str(err)})
        except boardteams.HireUnavailable as err:
            self.send_json(503, {"error": str(err)})
        except boardteams.dispatch.coordination.TmuxUnavailable as err:
            # 503, alongside the other "cannot answer right now" cases. retire() asks
            # whether a hired member's pane is still up, and tmux being unreachable is
            # not the same answer as "it stopped" - without this it fell through to the
            # bare ValueError handler and came back 400 "invalid fields", which blames
            # the caller for the machine's problem.
            self.send_json(503, {"error": str(err)})
        except ccboard.Refused as err:
            # 409, not 400: the request was well formed and the board said no. The
            # missing list names the verb that fills each gap, so a client can
            # print a remedy rather than just a rejection.
            self.send_json(409, {"error": str(err), "missing": err.missing})
        except (ccboard.Invalid, ccstore.Invalid) as err:
            self.send_json(400, {"error": str(err)})
        except (ccboard.NotFound, ccstore.NotFound) as err:
            self.send_json(404, {"error": str(err)})
        except (ValueError, RecursionError):
            self.send_json(400, {"error": "invalid fields or query parameters"})
        except ccstore.sqlite3.IntegrityError:
            self.send_json(409, {"error": "record conflicts with existing data"})
        except (ccstore.sqlite3.Error, OSError, RuntimeError):
            self.send_json(503, {"error": "Control Center storage unavailable"})

    def board_read(self, db, op, params):
        if op == "targets":
            return codesys_panel.targets(db, params)
        if op == "chatter":
            return chatter_feed.chatter(db, params)
        if op == "agents":
            return boardagents.agents(db, params)
        if op == "profiles":
            return boardagents.profiles(db, params)
        if op == "roster":
            return boardteams.roster(db, params)

        def one(name, default=None):
            return params.get(name, [default])[0]

        def bounded(name, default, low, high):
            raw = one(name, str(default))
            if not re.fullmatch(r"[0-9]{1,4}", raw or "") or not low <= int(raw) <= high:
                raise ccboard.Invalid(name + " must be between " + str(low)
                                      + " and " + str(high))
            return int(raw)

        if op == "board":
            return ccboard.board(db, include_deleted=one("deleted") == "1")
        if op == "meta":
            return ccboard.meta(db)
        if op == "entity":
            return ccboard.entity(db, ccboard.key_field(one("id"), "id", required=True))
        if op == "history":
            key = one("id")
            return {"events": ccboard.history(
                db, ccboard.key_field(key, "id") if key else None,
                bounded("limit", 200, 1, 1000))}
        if op == "why":
            return ccboard.why(db, ccboard.key_field(one("id"), "id", "task", required=True))
        if op == "graph":
            return ccboard.graph(db)
        if op == "doctor":
            return ccboard.doctor(db)
        if op == "next":
            return {"tasks": ccboard.next_tasks(db, bounded("limit", 10, 1, 200))}
        if op == "dispatchable":
            # Dispatchability is read-only. POST hire deliberately starts a
            # process under boardteams' five bounds: defence in depth, not
            # authentication. Port 8787 is unauthenticated; Origin only stops
            # cross-origin browsers, and non-browser clients can omit it.
            return ccboard.dispatch_view(db, bounded("limit", 10, 1, 200))
        if op == "sprint":
            return ccboard.sprint_report(
                db, ccboard.key_field(one("id"), "id", "sprint", required=True))
        return {"hits": ccboard.find(db, one("q"), bounded("limit", 50, 1, 200))}

    def board_write(self, db, op, body):
        # `mirror` IS NOT A WIRE FLAG, and must not become one again. It used to be
        # read straight off the request body into ccboard.create and
        # ccboard.set_status, which made it an unlimited, reason-free, unlogged
        # gate bypass available to anything that could reach this port: the same
        # power as `override` with none of its four properties - a required
        # reason, a stamped actor, an audit row, and a single use. The board's
        # designed bypass is POST /api/board/override, and a thin card is still
        # creatable through /api/tasks. It is refused by name rather than ignored,
        # so a caller that still sends it is told what to use instead of silently
        # getting the gates it was trying to skip.
        if "mirror" in body:
            raise ccboard.Invalid(
                "mirror is not accepted over HTTP: arm an audited bypass with"
                " /api/board/override, or use /api/tasks for a thin card")
        if op == "plcstate":
            return codesys_panel.plcstate(db, body)
        if op == "bootapp":
            return codesys_panel.bootapp(db, body)
        if op == "chatsend":
            return chatter_feed.chatsend(db, body)
        if op == "agentdef":
            return boardagents.agentdef(db, body)
        if op == "agentdrop":
            return boardagents.agentdrop(db, body)
        if op == "recruit":
            return boardteams.recruit(db, body)
        if op == "approve":
            return boardteams.approve(db, body)
        if op == "retire":
            return boardteams.retire(db, body)
        if op == "hire":
            return boardteams.hire(db, body, bind_host=self.server.server_address[0])

        actor = ccboard.text(body.get("actor"), "actor", 64, pattern=ccboard.NAME_RE)
        session = ccboard.text(body.get("session"), "session", 128)

        def target(kind=None):
            return ccboard.key_field(body.get("id"), "id", kind, required=True)

        def flag(name, default=True):
            value = body.get(name, default)
            if not isinstance(value, bool):
                raise ccboard.Invalid(name + " must be true or false")
            return value

        if op == "create":
            kind = ccboard.text(body.get("kind"), "kind", 16, required=True,
                                choices=tuple(ccboard.KINDS))
            fields = {k: v for k, v in body.items()
                      if k not in ("kind", "actor", "session")}
            return ccboard.create(db, kind, fields, actor, session)
        if op == "update":
            patch = body.get("patch")
            if not isinstance(patch, dict):
                raise ccboard.Invalid("patch must be a JSON object")
            return ccboard.update(db, target(), patch, actor, session)
        if op == "status":
            return ccboard.set_status(db, target(), body.get("status"), actor, session,
                                      body.get("reason"))
        if op == "move":
            return ccboard.move_task(db, target("task"), body.get("epic"), actor, session)
        if op == "delete":
            return ccboard.delete(db, target(), actor, session)
        if op == "acceptance":
            key = target()
            if body.get("text") is not None:
                return ccboard.add_acceptance(db, key, body["text"], actor)
            if flag("remove", False):
                return ccboard.drop_acceptance(db, key, body.get("index"), actor)
            return ccboard.tick_acceptance(db, key, body.get("index"), flag("done"), actor)
        if op == "label":
            return ccboard.set_label(db, target(), body.get("label"), flag("present"), actor)
        if op == "dep":
            return ccboard.set_dep(db, target("task"), body.get("blockedBy"),
                                   flag("present"), actor)
        if op == "evidence":
            return ccboard.add_evidence(db, target(), body.get("ref"), actor)
        if op == "commit":
            return ccboard.add_commit(db, target(), body.get("ref"), actor)
        if op == "touch":
            return ccboard.add_touch(db, target(), body.get("path"), actor)
        if op == "comment":
            return ccboard.add_comment(db, target(), body.get("text"), actor)
        if op == "link":
            return ccboard.set_link(db, target(), body.get("type"), body.get("target"),
                                    flag("present"), actor)
        if op == "triage":
            return ccboard.triage(db, flag("all", False), flag("dryRun", False), actor)
        if op == "state":
            name = ccboard.text(body.get("name"), "name", 32, required=True,
                                choices=ccboard.STATE_NAMES)
            value = body.get("value")
            if name in ("activeEpic", "activeSprint"):
                value = ccboard.key_field(
                    value, name, "epic" if name == "activeEpic" else "sprint")
            elif value is not None:
                raise ccboard.Invalid("override is set through /api/board/override")
            return ccboard.set_state(db, name, value, actor)
        if op == "config":
            return ccboard.set_config(db, ccboard.text(body.get("name"), "name", 32,
                                                       required=True),
                                      body.get("value"), actor)
        return {"override": ccboard.set_override(db, body.get("reason"), actor)}

    def set_auth_setting(self):
        """POST /api/auth/setting  {"method": "<id>", "key": "<key>", "value": "<value>"}

        Changes ONE non-secret setting of one method — the model, a gateway URL. Safe from
        the browser for the same reason /api/auth/select is: it carries no credential, and
        entering one remains a terminal action.

        The key must be DECLARED for that method in auth.json, and the value must pass the
        same validator the CLI uses (imported, not re-implemented). So a request can name a
        setting but never invent one, and never store a value `agentmux spawn` would then
        choke on.
        """
        body = self.read_cc_body()
        if body is None:
            return
        if not isinstance(body, dict) or body.keys() - {"method", "key", "value"}:
            self.send_json(400, {"error": "unknown fields"})
            return
        method_id, key, value = body.get("method"), body.get("key"), body.get("value")
        if not isinstance(method_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", method_id):
            self.send_json(400, {"error": "invalid method id"})
            return
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,40}", key):
            self.send_json(400, {"error": "invalid setting key"})
            return
        if not isinstance(value, str) or not value.strip() or len(value) > 300:
            self.send_json(400, {"error": "value must be a non-empty string under 300 chars"})
            return
        value = value.strip()

        try:
            with AUTH_MANIFEST.open(encoding="utf-8") as handle:
                manifest = json.load(handle)
        except (OSError, ValueError):
            self.send_json(503, {"error": "auth.json unreadable"})
            return
        method = next((m for m in manifest.get("methods") or []
                       if isinstance(m, dict) and m.get("id") == method_id), None)
        if method is None:
            self.send_json(404, {"error": "unknown method"})
            return
        spec = next((s for s in method.get("settings") or []
                     if isinstance(s, dict) and s.get("key") == key), None)
        if spec is None:
            self.send_json(400, {"error": f"{method_id} declares no setting '{key}'"})
            return

        validators = auth_validators()
        pattern_hint = validators.get(spec.get("validate", "text"))
        if pattern_hint is not None:
            pattern, hint = pattern_hint
            if not pattern.match(value):
                self.send_json(400, {"error": f"invalid {key}: {hint}"})
                return

        try:
            settings = {"version": 2, "active": {}, "providers": {}, "methods": {}}
            if AUTH_SETTINGS.is_file() and not AUTH_SETTINGS.is_symlink():
                with AUTH_SETTINGS.open(encoding="utf-8") as handle:
                    settings = json.load(handle)
            for required in ("active", "providers", "methods"):
                settings.setdefault(required, {})
            settings["version"] = 2
            settings.pop("settings", None)     # never leave the v1 key behind
            settings["methods"].setdefault(method_id, {})[key] = value
            previous_umask = os.umask(0o077)
            try:
                temporary = AUTH_SETTINGS.with_suffix(".tmp")
                with open(temporary, "w", encoding="utf-8") as handle:
                    json.dump(settings, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                os.chmod(temporary, 0o600)
                os.replace(temporary, AUTH_SETTINGS)
            finally:
                os.umask(previous_umask)
        except (OSError, ValueError) as err:
            self.send_json(503, {"error": f"could not write the auth settings: "
                                          f"{type(err).__name__}"})
            return
        self.send_json(200, {"ok": True, "method": method_id, "key": key, "value": value,
                             "note": "applies to agents spawned from now on"})

    def select_auth(self):
        """POST /api/auth/select  {"id": "<method-id>"} — set a CLI's active method.

        The ONLY auth write the browser may make, and it carries no secret: it picks
        which already-configured method new agents use. Entering a credential stays a
        terminal action via taskmgmt/setup_auth.py, so a key never crosses HTTP.

        A method that is not fully configured is refused rather than selected, so the
        active method can never be one that would fail at spawn time.
        """
        body = self.read_cc_body()
        if body is None:
            return
        if not isinstance(body, dict) or body.keys() - {"id"}:
            self.send_json(400, {"error": "unknown fields"})
            return
        wanted = body.get("id")
        if not isinstance(wanted, str) or not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", wanted):
            self.send_json(400, {"error": "invalid method id"})
            return

        snapshot = auth_snapshot()
        chosen = next((m for group in snapshot.get("providers", []) for m in group["methods"]
                       if m["id"] == wanted), None)
        if chosen is None:
            self.send_json(404, {"error": "unknown method id"})
            return
        if not chosen["configured"]:
            self.send_json(409, {
                "error": f"{wanted} is not configured (missing "
                         f"{', '.join(chosen['missing'])}). Run: "
                         f"python3 taskmgmt/setup_auth.py {wanted}"})
            return
        cli = chosen["cli"]

        try:
            settings = {"version": 1, "active": {}, "settings": {}}
            if AUTH_SETTINGS.is_file() and not AUTH_SETTINGS.is_symlink():
                with AUTH_SETTINGS.open(encoding="utf-8") as fh:
                    settings = json.load(fh)
            settings.setdefault("active", {})[cli] = wanted
            # 0600 from creation, via a temp file in the same directory, so the file
            # is never momentarily readable by anyone else.
            previous_umask = os.umask(0o077)
            try:
                temporary = AUTH_SETTINGS.with_suffix(".tmp")
                with open(temporary, "w", encoding="utf-8") as fh:
                    json.dump(settings, fh, indent=2, sort_keys=True)
                    fh.write("\n")
                os.chmod(temporary, 0o600)
                os.replace(temporary, AUTH_SETTINGS)
            finally:
                os.umask(previous_umask)
        except (OSError, ValueError) as err:
            self.send_json(503, {"error": f"could not write the auth settings: "
                                          f"{type(err).__name__}"})
            return
        self.send_json(200, {"ok": True, "cli": cli, "active": wanted})

    def ticket_action(self, action):
        """POST /api/tickets/comment | /api/tickets/transition

        These write to Jira, which is outside this machine and not undoable from
        here, so the UI confirms first. There is no dry-run mode on purpose: a
        success response means the call was made and Jira accepted it.
        """
        body = self.read_cc_body(CC_BODY_MAX)
        if body is None:
            return
        allowed = {"key", "text"} if action == "comment" else {"key", "transition_id"}
        if not isinstance(body, dict) or body.keys() - allowed:
            self.send_json(400, {"error": "unknown fields"})
            return
        key = body.get("key")
        if not isinstance(key, str) or not ISSUE_KEY.fullmatch(key):
            self.send_json(400, {"error": "invalid issue key"})
            return
        if action == "comment":
            text = body.get("text")
            if not isinstance(text, str) or not text.strip():
                self.send_json(400, {"error": "comment text is required"})
                return
            if len(text) > 8000:
                self.send_json(400, {"error": "comment exceeds 8000 characters"})
                return
        else:
            transition_id = body.get("transition_id")
            if not isinstance(transition_id, str) or not re.fullmatch(r"[0-9]{1,10}", transition_id):
                self.send_json(400, {"error": "invalid transition id"})
                return

        cfg, reason = atlassian_config()
        if cfg is None:
            self.send_json(409, {"error": reason, "setup": ticket_setup_hint()})
            return
        module = atlassian_module()
        try:
            if action == "comment":
                module.jira_comment(cfg, key, body["text"])
                detail = f"commented on {key}"
            else:
                module.jira_transition(cfg, key, body["transition_id"])
                detail = f"transitioned {key}"
        except Exception as err:
            # atlassian.py raises with messages that never contain the token.
            self.send_json(502, {"error": f"Jira refused: {_clean(str(err), 250)}"})
            return
        with _ticket_lock:
            _ticket_cache.update(at=0.0, data=None)   # the list is now stale
        self.send_json(200, {"ok": True, "detail": detail})

    def modbus_endpoint(self, action):
        if self.command == 'GET' and action == 'tags':
            self.send_json(200, modbus_service().snapshot())
            return
        if self.command != 'POST' or action not in ('tags', 'write'):
            self.send_json(405, {'error': 'POST required'})
            return
        body = self.read_cc_body(9999)
        if body is None:
            return
        try:
            if not isinstance(body, dict):
                raise ValueError('JSON object required')
            service = modbus_service()
            result = service.save(body) if action == 'tags' else service.write(body)
            self.send_json(200, result)
        except (ValueError, TypeError, KeyError) as err:
            self.send_json(400, {'error': str(err)})
        except (OSError, modbus_poll.ModbusError) as err:
            self.send_json(502, {'error': str(err)})

    # -- the field services -------------------------------------------------
    #
    # Four endpoints with the same shape: GET returns a snapshot, POST takes a
    # validated document. Each service owns its own thread and its own bounds, so
    # the handler's whole job is to translate the module's Invalid into a 400 and
    # anything operational into a 502/503. None of them accepts a command, a path
    # or a flag from the request.

    def monitor_endpoint(self, action):
        service = mqtt_service()
        try:
            if self.command == "GET":
                if action != "monitor":
                    self.send_json(405, {"error": "POST required"})
                    return
                params = parse_qs(self.requestline.split()[1].partition("?")[2],
                                  keep_blank_values=True, max_num_fields=8)
                raw_limit = (params.get("limit") or ["200"])[0]
                raw_since = (params.get("since") or ["0"])[0]
                if not re.fullmatch(r"[0-9]{1,5}", raw_limit) or not re.fullmatch(r"[0-9]{1,12}", raw_since):
                    self.send_json(400, {"error": "invalid limit or since"})
                    return
                needle = (params.get("q") or [""])[0]
                self.send_json(200, service.snapshot(int(raw_limit), int(raw_since), needle))
                return
            if action == "stop":
                self.send_json(200, service.stop())
                return
            if action == "clear":
                self.send_json(200, service.clear())
                return
            body = self.read_cc_body(CC_BODY_MAX)
            if body is None:
                return
            if action == "publish":
                # Through the SESSION THAT IS ALREADY OPEN, not a fresh anonymous
                # connection: the live session is the one carrying the operator's
                # credentials and TLS, so a broker that requires either would refuse
                # a second connection made just for this write.
                unknown = body.keys() - {"topic", "payload", "qos", "retain"}
                if unknown:
                    raise mqtt_monitor.Invalid(
                        f"unknown fields: {', '.join(sorted(unknown))}")
                self.send_json(200, service.publish(
                    body.get("topic"), body.get("payload", ""),
                    body.get("qos", 0), bool(body.get("retain"))))
                return
            self.send_json(200, service.start(body))
        except mqtt_monitor.Invalid as err:
            self.send_json(400, {"error": str(err)})
        except mqtt_monitor.Unavailable as err:
            self.send_json(503, {"error": str(err)})
        except (OSError, mqtt.MqttError) as err:
            self.send_json(502, {"error": str(err)})

    def netscan_endpoint(self, action):
        service = scan_service()
        try:
            if self.command == "GET":
                self.send_json(200, service.snapshot())
                return
            if action == "stop":
                self.send_json(200, service.stop())
                return
            body = self.read_cc_body(1024)
            if body is None:
                return
            self.send_json(200, service.start(body))
        except netscan.Invalid as err:
            self.send_json(400, {"error": str(err)})
        except OSError as err:
            self.send_json(503, {"error": f"scan could not start: {err.strerror or err}"})

    def profinet_endpoint(self, action):
        service = profinet_service()
        try:
            if self.command == "GET":
                self.send_json(200, service.state())
                return
            body = self.read_cc_body(CC_BODY_MAX)
            if body is None:
                return
            if action == "schema":
                self.send_json(200, service.save_schema(body))
                return
            result = service.save_snapshot(body.get("records"), body.get("actor"))
            journal_event("PROFINET DCP snapshot imported", {
                "actor": body.get("actor") or "dashboard",
                "stations": len(result["snapshot"]),
                "mismatched": result["reconciliation"]["counts"]["mismatch"],
                "missing": result["reconciliation"]["counts"]["missing"],
                "unexpected": result["reconciliation"]["counts"]["unexpected"]})
            self.send_json(200, result)
        except profinet.Invalid as err:
            self.send_json(400, {"error": str(err)})
        except OSError as err:
            self.send_json(503, {"error": f"schema storage unavailable: {err.strerror or err}"})

    def github_endpoint(self, action):
        try:
            if self.command == "GET":
                self.send_json(200, {"account": github_auth.account(),
                                     "login": github_login_service().snapshot()})
                return
            body = self.read_cc_body(CC_BODY_MAX)
            if body is None:
                return
            if action == "login":
                self.send_json(200, github_login_service().start(body.get("actor")))
                return
            if action == "cancel":
                self.send_json(200, github_login_service().cancel())
                return
            if action == "logout":
                self.send_json(200, {"account": github_auth.logout(
                    body.get("actor"),
                    lambda event: journal_event("GitHub " + event["outcome"], event))})
                return
            maker = github_auth.create_repo if action == "repo" else github_auth.create_issue
            self.send_json(200, maker(
                body, lambda event: journal_event("GitHub " + event["outcome"], event)))
        except github_auth.Invalid as err:
            self.send_json(400, {"error": str(err)})
        except github_auth.Unavailable as err:
            self.send_json(503, {"error": str(err)})

    def mqtt_endpoint(self, action):
        """POST /api/mqtt/publish | /api/mqtt/subscribe

        The operator names the broker, so this makes an outbound connection to a
        host from the request. That is the point of the tool, and it is acceptable
        here because the server binds 127.0.0.1 only, every mutating request needs
        a same-origin JSON preflight, and mqtt.py speaks only MQTT - it cannot be
        steered into emitting an attacker-chosen protocol. It is still the one
        endpoint that talks to the outside world, so host/port/topic are validated
        before a socket is opened, never after.

        No credentials are accepted. If a broker needs auth, CONNACK code 4 or 5
        comes back and is reported as such.
        """
        body = self.read_cc_body(CC_BODY_MAX if action == "publish" else 1024)
        if body is None:
            return
        allowed = {"host", "port", "topic", "payload"} if action == "publish" else {
            "host", "port", "topic"}
        try:
            if not isinstance(body, dict) or body.keys() - allowed:
                raise ValueError("unknown fields")
            host = mqtt.check_host(body.get("host"))
            port = mqtt.check_port(body.get("port"))
            topic = mqtt.check_topic(body.get("topic"), allow_wildcards=action == "subscribe")
            payload = mqtt.check_payload(body.get("payload")) if action == "publish" else None
        except ValueError as err:
            self.send_json(400, {"error": str(err)})
            return

        # grok finding 3: cap concurrent broker exchanges, so parallel requests against
        # a black-holed broker cannot pile up handler threads. Refusing beats queueing -
        # the caller finds out now rather than after a 5s connect timeout.
        #
        # Acquired AFTER validation and released in a finally that covers every exit
        # from here on. Acquiring earlier leaked a slot on each 400, which exhausted
        # the pool after four bad requests and 503'd everything afterwards.
        if not MQTT_SLOTS.acquire(blocking=False):
            self.send_json(503, {"error": "too many MQTT exchanges in flight"})
            return
        try:
            # Do the broker exchange, close the socket, and only then answer. Replying
            # from inside the `with` would tell the caller "ok" while DISCONNECT and the
            # close were still pending, so a client that immediately inspected the
            # broker could see a session we had already reported as finished.
            with mqtt.Connection(host, port) as link:
                if action == "publish":
                    written = link.publish(topic, payload)
                    result = {"ok": True,
                              "detail": f"wrote {written} bytes to {topic} at QoS 0 "
                                        f"(unacknowledged)"}
                else:
                    messages = link.subscribe(topic)
                    for message in messages:
                        message["payload"] = CTRL.sub("", message["payload"])
                        message["topic"] = CTRL.sub("", message["topic"])
                    result = {
                        "ok": True,
                        "detail": (f"{len(messages)} message(s) in "
                                   f"{mqtt.SUBSCRIBE_WINDOW:g}s on {topic}"),
                        "messages": messages,
                    }
            self.send_json(200, result)
        except mqtt.MqttError as err:
            # A broker-level failure is not our fault and not the client's: 502.
            self.send_json(502, {"error": str(err)})
        except (OSError, struct.error) as err:
            self.send_json(502, {"error": f"broker exchange failed: {err}"})
        finally:
            MQTT_SLOTS.release()

    def resize_agent(self, name):
        if not NAME_PATTERN.fullmatch(name):
            self.send_json(400, {"error": "invalid name"})
            return
        content_types = self.headers.get_all("Content-Type", [])
        if (len(content_types) != 1
                or content_types[0].split(";", 1)[0].strip().lower() != "application/json"):
            self.send_json(415, {"error": "application/json required"})
            return
        origins = self.headers.get_all("Origin", [])
        if origins and (len(origins) != 1 or origins[0] not in self.allowed_origins()):
            self.send_json(403, {"error": "forbidden origin"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (self.headers.get("Transfer-Encoding") is not None
                or len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0])):
            self.send_json(400, {"error": "invalid content length"})
            return
        # Bound both the bytes read and the wait for an incomplete body.
        if len(lengths[0]) > 4 or int(lengths[0]) > 1024:
            self.send_json(413, {"error": "request body too large"})
            return
        length = int(lengths[0])
        previous_timeout = self.connection.gettimeout()
        try:
            self.connection.settimeout(5)
            raw = self.rfile.read(length)
            self.body_consumed = True
        except OSError:
            self.body_consumed = True      # see read_cc_body: already waited for it
            self.send_json(408, {"error": "request body timeout"})
            return
        finally:
            self.connection.settimeout(previous_timeout)
        try:
            if len(raw) != length:
                raise ValueError
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError
            cols, rows = body.get("cols"), body.get("rows")
            # Reject rather than silently clamp values outside the permitted bounds.
            if (type(cols) is not int or type(rows) is not int
                    or not 20 <= cols <= 400 or not 5 <= rows <= 200):
                raise ValueError
        except (ValueError, UnicodeError, RecursionError):
            self.send_json(400, {"error": "invalid dimensions or JSON"})
            return
        pane = (read_field(RUN_DIR / (name + ".pane"))
                if not RUN_DIR.is_symlink() else None)
        if not pane or not re.fullmatch(r"%[0-9]+", pane):
            self.send_json(404, {"error": "pane not found"})
            return
        # Use an exact session target, not a pane target or a session prefix match.
        target = "=" + name

        def read_size():
            output = tmux("list-panes", "-t", target, "-F",
                          "#{pane_width}x#{pane_height}")
            match = re.fullmatch(r"([0-9]+)x([0-9]+)", output.strip()) if output else None
            return tuple(map(int, match.groups())) if match else None

        current = read_size()
        if current is None:
            self.send_json(404, {"error": "pane not found"})
            return
        if current != (cols, rows):
            window_id = tmux("list-panes", "-t", target, "-F", "#{window_id}")
            window_id = window_id.strip() if window_id else None
            if not window_id or not re.fullmatch(r"@[0-9]+", window_id):
                self.send_json(500, {"error": "window id lookup failed"})
                return
            if tmux("set-option", "-t", window_id, "window-size", "manual") is None:
                self.send_json(500, {"error": "setting manual window size failed"})
                return
            if tmux("resize-window", "-t", window_id, "-x", str(cols), "-y", str(rows)) is None:
                self.send_json(500, {"error": "resize failed"})
                return
            current = read_size()
            if current is None:
                self.send_json(500, {"error": "size readback failed"})
                return
        actual_cols, actual_rows = current
        # A status line can consume one row; report measured dimensions either way.
        ok = abs(actual_cols - cols) <= 1 and abs(actual_rows - rows) <= 1
        self.send_json(200 if ok else 409,
                       {"ok": ok, "cols": actual_cols, "rows": actual_rows})

    def stream_all(self, query):
        """GET /api/stream-all — every agent's output over ONE SSE connection.

        WHY THIS EXISTS. A browser allows only ~6 concurrent HTTP/1.1 connections per
        host (6 in Firefox by default), and an SSE stream holds one open indefinitely. With
        seven panes the seventh could never connect, so two panes traded places about once
        a second, each showing "disconnected — retrying" half the time. Measured: the two
        alternated perfectly complementarily, and closing one pane's stream simply moved
        the problem to whichever pane reconnected last.

        No amount of server-side tuning fixes that — the limit is in the browser. So all
        agents share one connection and every frame names its agent:

            event: snapshot   data: {"agent": "build", "b64": "..."}
            event: chunk      data: {"agent": "build", "b64": "..."}
            event: gone       data: {"agent": "build"}

        The per-agent endpoint is kept: it is what the tests exercise, and it is still the
        right thing for a single pane.
        """
        params = parse_qs(query or "")
        try:
            tail = min(262144, max(0, int((params.get("tail") or ["16384"])[0])))
        except ValueError:
            tail = 16384

        if not STREAM_SLOTS.acquire(blocking=False):
            self.send_json(503, {"error": "too many streams"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.connection.settimeout(5)

        # name -> {"offset": int, "identity": (dev, ino)}
        tracked = {}
        heartbeat = time.monotonic() + HEARTBEAT_SECONDS
        try:
            while True:
                live = {}
                for agent in agents_snapshot().get("agents", []):
                    name = agent.get("name")
                    if NAME_PATTERN.fullmatch(name or "") and agent.get("state") != "stale":
                        live[name] = agent

                for name in [n for n in tracked if n not in live]:
                    tracked.pop(name, None)
                    self.send_event("gone", {"agent": name})

                for name, agent in live.items():
                    if name not in tracked:
                        # New to this stream: send the pane's rendered screen first, for
                        # the same reason the single-agent endpoint does — a byte tail
                        # cannot reconstruct alternate-screen state.
                        try:
                            with open_log(name) as stream:
                                info = os.fstat(stream.fileno())
                                tracked[name] = {"offset": info.st_size,
                                                 "identity": (info.st_dev, info.st_ino)}
                        except OSError:
                            continue
                        pane = (read_field(RUN_DIR / (name + ".pane"))
                                if not RUN_DIR.is_symlink() else None)
                        snapshot = None
                        if pane and re.fullmatch(r"%[0-9]+", pane):
                            snapshot = tmux("capture-pane", "-p", "-e", "-t", pane)
                        if snapshot is not None:
                            self.send_event("snapshot", {
                                "agent": name,
                                "b64": base64.b64encode(
                                    b"\x1b[2J\x1b[H" + framed_snapshot(snapshot)).decode()})
                        continue

                    state = tracked[name]
                    try:
                        with open_log(name) as stream:
                            info = os.fstat(stream.fileno())
                            identity = (info.st_dev, info.st_ino)
                            if identity != state["identity"] or info.st_size < state["offset"]:
                                state["offset"] = 0          # rotated or truncated
                            state["identity"] = identity
                            stream.seek(state["offset"])
                            chunk = stream.read(65536)
                            state["offset"] += len(chunk)
                    except FileNotFoundError:
                        continue                              # rotation gap
                    except OSError:
                        continue
                    if chunk:
                        self.send_event("chunk", {
                            "agent": name, "b64": base64.b64encode(chunk).decode()})

                now = time.monotonic()
                if now >= heartbeat:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    heartbeat = now + HEARTBEAT_SECONDS
                time.sleep(0.15)
        except OSError:
            return          # client gone; headers are already out, so never send an error
        finally:
            STREAM_SLOTS.release()

    def send_event(self, event, payload):
        body = json.dumps(payload).encode("utf-8")
        self.wfile.write(b"event: " + event.encode() + b"\ndata: " + body + b"\n\n")
        self.wfile.flush()

    def stream_agent(self, name, query):
        if not NAME_PATTERN.fullmatch(name):
            self.send_json(400, {"error": "invalid name"})
            return
        try:
            tail = int(parse_qs(query).get("tail", ["16384"])[0])
            if tail < 0:
                raise ValueError
            tail = min(tail, 262144)
        except ValueError:
            self.send_json(400, {"error": "invalid tail"})
            return
        sessions = tmux("list-sessions", "-F", "#{session_name}")
        if sessions is None or name not in sessions.splitlines():
            self.send_json(404, {"error": "not found"})
            return
        try:
            stream = open_log(name)
        except PermissionError:
            self.send_json(403, {"error": "forbidden"})
            return
        except OSError:
            self.send_json(404, {"error": "not found"})
            return
        # Claim this agent BEFORE taking a slot, so the previous holder starts exiting
        # and its slot comes back even if this request has to be refused.
        generation = claim_stream(name)
        if not STREAM_SLOTS.acquire(blocking=False):
            stream.close()
            self.send_json(503, {"error": "too many streams"})
            return
        try:
            with stream:
                info = os.fstat(stream.fileno())
                identity = (info.st_dev, info.st_ino)
                # Save EOF before capture so appends during capture are not lost.
                offset = info.st_size
                pane = (read_field(RUN_DIR / (name + ".pane"))
                        if not RUN_DIR.is_symlink() else None)
                snapshot = None
                if pane and re.fullmatch(r"%[0-9]+", pane):
                    snapshot = tmux("capture-pane", "-p", "-e", "-t", pane)
                initial = b""
                # Accept tail for compatibility, but ignore it when capture succeeds.
                # A failed capture retains the historical tail fallback.
                if snapshot is None:
                    offset = max(0, info.st_size - tail)
                    stream.seek(offset)
                    if offset > 0:
                        # Resynchronize a clipped tail with a bounded scan.
                        probe = stream.read(min(4096, info.st_size - offset))
                        boundary = re.search(br"[\x1b\n]", probe)
                        if boundary is not None:
                            offset += boundary.start()
                        stream.seek(offset)
                    initial = stream.read(info.st_size - offset)
                    offset += len(initial)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if self.command == "HEAD":
                return
            # Bound blocked writes so disconnected or slow clients free their slot.
            self.connection.settimeout(5)
            try:
                if snapshot is not None:
                    self.wfile.write(b"event: snapshot\n")
                    self.write_chunk(b"\x1b[2J\x1b[H" + framed_snapshot(snapshot))
                if initial:
                    self.write_chunk(initial)
                heartbeat = time.monotonic() + HEARTBEAT_SECONDS
                session_check = time.monotonic() + 1
                while True:
                    try:
                        with open_log(name) as stream:
                            info = os.fstat(stream.fileno())
                            current_identity = (info.st_dev, info.st_ino)
                            if current_identity != identity or info.st_size < offset:
                                offset = 0
                            identity = current_identity
                            stream.seek(offset)
                            chunk = stream.read(65536)
                            offset += len(chunk)
                        if chunk:
                            self.write_chunk(chunk)
                    except FileNotFoundError:
                        # Rotation may briefly leave the pathname absent.
                        pass
                    now = time.monotonic()
                    if now >= heartbeat:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        heartbeat = now + HEARTBEAT_SECONDS
                    # A newer stream for this agent has taken over: stand down and give
                    # the slot back rather than both of us tailing the same log.
                    if stream_superseded(name, generation):
                        return
                    if now >= session_check:
                        sessions = tmux("list-sessions", "-F", "#{session_name}")
                        if sessions is not None and name not in sessions.splitlines():
                            self.wfile.write(b"event: eof\ndata: \n\n")
                            self.wfile.flush()
                            return
                        session_check = time.monotonic() + 1
                    time.sleep(0.1)
            except OSError:
                # Headers already went out; never inject an HTTP error into SSE.
                return
        finally:
            STREAM_SLOTS.release()

    def write_chunk(self, chunk):
        self.wfile.write(b"data: " + base64.b64encode(chunk) + b"\n\n")
        self.wfile.flush()

    def route(self):
        # requestline preserves leading // that BaseHTTPRequestHandler normalizes.
        target = self.requestline.split()[1]
        if not target.startswith("/") or target.startswith("//"):
            self.send_json(403, {"error": "forbidden"})
            return
        try:
            parsed = urlsplit(target)
            path = unquote(parsed.path, errors="strict")
            parts = path.split("/")
            if (".." in parts or "\\" in path or "\x00" in path
                    or path.startswith("//")):
                raise ValueError("unsafe path")
            # A HOME THAT HAS BEEN DELETED IS NOT AN EMPTY HOME.
            #
            # Every store under here opens with mkdir(parents=True, exist_ok=True),
            # which is right on a first run and wrong afterwards: point a running
            # server at a home and delete it, and the next GET /api/board REBUILDS the
            # tree and creates a brand new cc.db. Measured - the board comes back 200
            # with zero epics and zero tasks, and the page renders a clean empty board
            # over the top of a database that is not there any more. Nothing says the
            # board was lost; it looks like a board nobody has used yet.
            #
            # It is also where the deleted /tmp homes that keep reappearing come from:
            # a suite removes its throwaway home, one late request lands on the server
            # still pointed at it, and the directory is back.
            #
            # Refused rather than recreated, and only for /api: static assets come out
            # of the repo, so the page still loads and can show the error instead of
            # failing blank. 503 is the shape the storage-unavailable path already
            # uses. Creating the home at startup is still fine - that is a first run,
            # and main() is where it belongs.
            if path.startswith("/api/") and not HOME_DIR.is_dir():
                self.send_json(503, {"error": f"Control Center storage unavailable: "
                                              f"{HOME_DIR} does not exist"})
                return
            if path == '/api/local-auth/oidc/callback':
                self.local_oidc_callback(target)
                return
            if path in ('/api/local-auth/pair', '/api/local-auth/logout',
                        '/api/local-auth/oidc/start'):
                self.local_auth_endpoint(path, parsed.query)
                return
            if path in ("/api/epics", "/api/tasks", "/api/journal", "/api/messages",
                        "/api/devices", "/api/status", "/api/delete"):
                self.cc_endpoint(path.rsplit("/", 1)[1], parsed.query)
                return
            if path == "/api/feed":
                # Read-only, and deliberately cheap: it reuses the same cached
                # resource and agent snapshots the other views already poll rather
                # than probing again. Routed HERE, in the shared block, so a POST
                # gets 405 like every other read-only endpoint - from the GET-only
                # section it fell through to 404, which tells the caller the endpoint
                # does not exist when it plainly does.
                if self.command != "GET":
                    self.send_json(405, {"error": "read-only endpoint"})
                    return
                raw = parse_qs(parsed.query).get("limit", ["200"])[0]
                limit = (int(raw) if re.fullmatch(r"[0-9]{1,4}", raw)
                         and 1 <= int(raw) <= 2000 else 200)
                self.send_json(200, feed_snapshot(limit))
                return
            if path.startswith("/api/fed/"):
                # The Federation view (EP-032). A hub-socket client like /api/hub/,
                # plus five allowlisted operator actions (fed_panel.WRITE_VERBS) behind
                # the same POST guards as every other write: JSON content type, own
                # origin only, bounded body (read_cc_body).
                op = path[len("/api/fed/"):]
                if op == "panel":
                    if self.command not in ("GET", "HEAD"):
                        self.send_json(405, {"error": "read-only endpoint"})
                        return
                    status, body = fed_panel.panel(HOME_DIR)
                elif op == "action":
                    if self.command != "POST":
                        self.send_json(405, {"error": "POST only"})
                        return
                    req = self.read_cc_body(2048)
                    if req is None:
                        return
                    status, body = fed_panel.action(req, HOME_DIR)
                else:
                    status, body = 404, {"error": "not found"}
                self.send_json(status, body)
                return
            if path.startswith("/api/hub/"):
                # The Hub view (TM-216). Read-only, and a CLIENT of agentmux-hub over
                # its unix socket - never a reader of hub.db. That database is WAL
                # with one writer connection owned by the hub process, and the hub/
                # directory is "owned by agentmux-hub. Nothing else opens these
                # files" (docs/PROTOCOL.md sections 3 and 8). A second sqlite reader
                # here would pin the WAL against checkpoints, couple this page to the
                # hub's private schema, and step around its identity rules. See
                # hub_panel.py. Routed in the shared block so a POST gets 405.
                if self.command not in ("GET", "HEAD"):
                    self.send_json(405, {"error": "read-only endpoint"})
                    return
                status, body = hub_panel.endpoint(path[len("/api/hub/"):],
                                                  parse_qs(parsed.query), HOME_DIR)
                self.send_json(status, body)
                return
            if path == "/api/runs" or path.startswith("/api/runs/"):
                # Deliberately NOT under /api/board/, whose op regex is [a-z]{1,16}
                # with no slash - a run id and a sub-resource would not survive it.
                # Routed here in the shared block for the same reason /api/feed is:
                # from the GET-only section a POST falls through to 404, which tells
                # the caller the endpoint does not exist when it plainly does.
                self.runs_endpoint(path[len("/api/runs"):].strip("/"), parsed.query)
                return
            if path == "/api/board" or path.startswith("/api/board/"):
                op = path[len("/api/board/"):] if len(path) > len("/api/board") else "board"
                if not re.fullmatch(r"[a-z]{1,16}", op):
                    self.send_json(404, {"error": "not found"})
                else:
                    self.board_endpoint(op, parsed.query)
                return
            if path == "/api/auth/setting":
                if self.command != "POST":
                    self.send_json(405, {"error": "POST required"})
                else:
                    self.set_auth_setting()
                return
            if path == "/api/auth/select":
                if self.command != "POST":
                    self.send_json(405, {"error": "POST required"})
                else:
                    self.select_auth()
                return
            if path in ("/api/tickets/comment", "/api/tickets/transition"):
                if self.command != "POST":
                    self.send_json(405, {"error": "POST required"})
                else:
                    self.ticket_action(path.rsplit("/", 1)[1])
                return
            if path in ('/api/modbus/tags', '/api/modbus/write'):
                self.modbus_endpoint(path.rsplit('/', 1)[1])
                return
            if path in ("/api/mqtt/publish", "/api/mqtt/subscribe"):
                if self.command != "POST":
                    self.send_json(405, {"error": "POST required"})
                else:
                    self.mqtt_endpoint(path.rsplit("/", 1)[1])
                return
            if path in ("/api/mqtt/monitor", "/api/mqtt/monitor/stop",
                        "/api/mqtt/monitor/clear", "/api/mqtt/monitor/publish"):
                if self.command == "GET" and path != "/api/mqtt/monitor":
                    self.send_json(405, {"error": "POST required"})
                else:
                    self.monitor_endpoint(path.rsplit("/", 1)[1])
                return
            if path in ("/api/netscan", "/api/netscan/start", "/api/netscan/stop"):
                if self.command == "GET" and path != "/api/netscan":
                    self.send_json(405, {"error": "POST required"})
                else:
                    self.netscan_endpoint(path.rsplit("/", 1)[1])
                return
            if path in ("/api/profinet", "/api/profinet/schema", "/api/profinet/snapshot"):
                if self.command == "GET" and path != "/api/profinet":
                    self.send_json(405, {"error": "POST required"})
                else:
                    self.profinet_endpoint(path.rsplit("/", 1)[1])
                return
            if path in ("/api/github/auth", "/api/github/login", "/api/github/cancel",
                        "/api/github/logout", "/api/github/repo", "/api/github/issue"):
                if self.command == "GET" and path != "/api/github/auth":
                    self.send_json(405, {"error": "POST required"})
                else:
                    self.github_endpoint(path.rsplit("/", 1)[1])
                return
            if path.startswith("/api/resize/"):
                if self.command != "POST":
                    self.send_json(405, {"error": "POST required"})
                else:
                    self.resize_agent(path[len("/api/resize/"):])
                return
            if self.command == "POST":
                self.send_json(404, {"error": "not found"})
                return
            if path == "/api/stream-all":
                self.stream_all(parsed.query)
                return
            if path.startswith("/api/stream/"):
                self.stream_agent(path[len("/api/stream/"):], parsed.query)
                return
            if any(":" in part for part in parts):
                raise ValueError("unsafe path")
            file_path = (ROOT / path.lstrip("/")).resolve()
            file_path.relative_to(ROOT)
        except (ValueError, OSError, RuntimeError, UnicodeError):
            self.send_json(403, {"error": "forbidden"})
            return

        if path == "/api/github":
            self.send_json(200, github_panel.snapshot(HOME_DIR))
            return
        if path == "/api/tickets":
            force = parse_qs(parsed.query).get("refresh", ["0"])[0] == "1"
            self.send_json(200, tickets_snapshot(force=force))
            return
        if path == "/api/tickets/transitions":
            params = parse_qs(parsed.query)
            key = (params.get("key") or [""])[0]
            if not ISSUE_KEY.fullmatch(key):
                self.send_json(400, {"error": "invalid issue key"})
                return
            cfg, reason = atlassian_config()
            if cfg is None:
                self.send_json(409, {"error": reason})
                return
            try:
                raw = atlassian_module().jira_transitions(cfg, key)
            except Exception as err:
                self.send_json(502, {"error": f"Jira refused: {_clean(str(err), 200)}"})
                return
            self.send_json(200, {"key": key, "transitions": [
                {"id": _clean(str(t.get("id", "")), 20),
                 "name": _clean(str(t.get("name", "")), 60)}
                for t in (raw.get("transitions") or [])[:30]
            ]})
            return
        if path == "/api/auth":
            # Read-only. Reports declared methods, their non-secret settings, and
            # whether each required secret is PRESENT - never a secret's value.
            self.send_json(200, auth_snapshot())
            return
        if path == "/api/resources":
            # Read-only. Runs only the probes declared in resources.json; a request
            # can never supply a command. Refreshes share a bounded, rate-limited sweep.
            force = parse_qs(parsed.query).get("refresh", ["0"])[0] == "1"
            self.send_json(200, resources_snapshot(force=force))
            return
        if path == "/api/agents":
            self.send_json(200, agents_snapshot())
            return
        if path == "/":
            file_path = (ROOT / "index.html").resolve()
            content_type = "text/html; charset=utf-8"
        elif path in ("/app.js", "/fitmatrix.js", "/agents.js", "/teams.js", "/iiot.js",
                      "/github.js", "/codesys.js", "/chatter.js", "/mqtt.js",
                      "/netscan.js", "/runs.js", "/kanban.js", "/hub.js",
                      "/fed.js",
                      "/src/components/molecules/index.js",
                      "/src/components/molecules/LabeledField/LabeledField.js",
                      "/src/components/molecules/LabeledField/index.js",
                      "/src/components/molecules/LeadSelector/LeadSelector.js",
                      "/src/components/molecules/LeadSelector/index.js",
                      "/src/components/molecules/RevisionNotice/RevisionNotice.js",
                      "/src/components/molecules/RevisionNotice/index.js",
                      "/src/components/organisms/index.js",
                      "/src/components/organisms/DefinitionEditor/DefinitionEditor.js",
                      "/src/components/organisms/DefinitionEditor/index.js",
                      "/src/components/organisms/ProfilePackagePreview/ProfilePackagePreview.js",
                      "/src/components/organisms/ProfilePackagePreview/index.js",
                      "/src/features/agentDefinitions.js",
                      "/src/features/teams.js"):
            # fitmatrix.js is the readability test harness. index.html loads it only
            # when the URL carries ?fit=1, so it is inert on the normal page but can
            # be run against the REAL page rather than a mock.
            content_type = "text/javascript; charset=utf-8"
        elif path in ("/style.css", "/agents.css", "/teams.css",
                      "/codesys.css", "/chatter.css", "/kanban.css"):
            content_type = "text/css; charset=utf-8"
        elif path == "/themes.json":
            content_type = "application/json"
        elif path in ("/vendor/xterm.js", "/vendor/addon-fit.js", "/vendor/xterm.css"):
            content_type = ("text/css; charset=utf-8" if path.endswith(".css")
                            else "text/javascript; charset=utf-8")
        elif (len(parts) == 3 and parts[1] == "assets"
              and parts[2].endswith(".svg")):
            content_type = "image/svg+xml"
        else:
            self.send_json(404, {"error": "not found"})
            return
        try:
            file_path.relative_to(ROOT)
        except ValueError:
            self.send_json(403, {"error": "forbidden"})
            return
        requested_extension = ".html" if path == "/" else Path(path).suffix
        if file_path.suffix != requested_extension:
            self.send_json(403, {"error": "forbidden"})
            return
        try:
            if not file_path.is_file():
                raise FileNotFoundError
            body = file_path.read_bytes()
        except OSError:
            self.send_json(404, {"error": "not found"})
            return
        self.send_body(200, body, content_type)

    def send_error(self, code, message=None, explain=None):
        self.send_json(code, {"error": "not found" if code == 404 else "request rejected"})

    def log_message(self, format, *args):
        # Avoid logging request paths or other potentially sensitive input.
        pass


class BacklogServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a listen queue that fits this page.

    socketserver.TCPServer sets request_queue_size = 5 and http.server inherits it,
    so five connections may wait to be accepted. This dashboard opens far more than
    five at once by design - an SSE stream per pane, plus the polls behind Status,
    Board, Runs and the field panels - and a browser reload asks for all of them
    again before the previous ones have been reaped.

    WHEN THE ACCEPT QUEUE OVERFLOWS IT DOES NOT LOOK LIKE A FULL QUEUE. The client's
    connect() succeeds and its send() succeeds, because the handshake completed in
    the kernel; the reset arrives later, while it is reading the response. So it
    surfaces as ConnectionResetError against an endpoint that was working perfectly,
    which is how it was read for a long time as a flake in whatever suite happened to
    catch it.

    Measured, POST refused with a foreign Origin, 1000 requests, by phase:

        backlog 5     20 threads  1000 x 403
                      40 threads   985 x 403, 15 x response:ConnectionResetError
                      serial      1000 x 403
        backlog 128   20 threads  1000 x 403
                      40 threads  1000 x 403
                      serial      1000 x 403

    128 rather than socket.SOMAXCONN: on this kernel the constant Python reports is
    INT_MAX, the real ceiling is /proc/sys/net/core/somaxconn (4096 here), and the
    number that matters is "comfortably more than one browser's worth", not "as many
    as the kernel will take".
    """
    request_queue_size = 128

    def __init__(self, server_address, handler, bind_and_activate=True, *, application_host=None):
        self.application_host = application_host
        super().__init__(server_address, handler, bind_and_activate)


def main():
    # --port exists so a test can bring up a REAL server without taking 8787 from
    # the operator's running dashboard. It changes nothing else: the bind stays on
    # loopback, and the write guard derives its allowed origin from whatever port
    # was bound (see Handler.allowed_origins), so a server on another port is as
    # locked down as the default one.
    port = 8787
    if "--port" in sys.argv:
        raw = sys.argv[sys.argv.index("--port") + 1]
        if not re.fullmatch(r"[0-9]{1,5}", raw) or not 1 <= int(raw) <= 65535:
            raise SystemExit("--port takes a number between 1 and 65535")
        port = int(raw)
    # A first run legitimately has no home yet, and this is the one place allowed to
    # make one: route() refuses every /api call once the server is up and the home has
    # gone, rather than quietly rebuilding it around an empty database.
    HOME_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with BacklogServer(("127.0.0.1", port), Handler) as server:
            # Resume the persisted field services without waiting for a browser
            # tab. An operator who left a line watched expects it still to be
            # watched after a restart, and a monitor that only runs while someone
            # is looking at it cannot tell you what happened while nobody was.
            modbus_service()
            mqtt_service()
            # Tells suite_server.py which home this pid serves on hosts without /proc.
            suite_server.declare_home(HOME_DIR)
            print(f"agentmux dashboard: http://127.0.0.1:{server.server_address[1]}",
                  flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except OSError:
        raise SystemExit(f"Unable to start dashboard on 127.0.0.1:{port}")
    finally:
        if _modbus_service is not None:
            _modbus_service.close()
        if _mqtt_monitor is not None:
            _mqtt_monitor.close()


if __name__ == "__main__":
    main()
