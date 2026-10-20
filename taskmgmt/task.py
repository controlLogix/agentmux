#!/usr/bin/env python3
"""agentmux task CLI - the scripted half of the Atlassian integration.

MCP serves the agents (they call Jira from inside a conversation). This serves
the SCRIPTS: agentmux.sh and the dashboard reaper cannot reach an MCP server, so
create-on-spawn, transition-on-exit and Confluence publishing go through here.

    task.py whoami
    task.py create  --summary "Fix the thing" [--desc TEXT] [--label a --label b]
    task.py comment ABC-123 --text "..."         | --from-log <agent>
    task.py done    ABC-123 [--from-log <agent>] [--transition "Done"]
    task.py report  <agent> [--title "..."]      -> Confluence page
    task.py transitions ABC-123                  -> what this issue can move to

Global: --dry-run prints the request instead of sending it. Exit 0 on success,
1 on a handled error, 2 on bad usage. Stdout carries the issue key or page URL so
a shell caller can capture it; diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import html
import os
import pathlib
import re
import stat
import sys

try:
    from taskmgmt import atlassian as atl
except ModuleNotFoundError:
    import atlassian as atl

# AGENTMUX_HOME, like every sibling module. This file resolved the home directly
# from $HOME, so an isolated run still read and wrote the operator's real one.
LOG_DIR = pathlib.Path(
    os.environ.get("AGENTMUX_HOME") or pathlib.Path.home() / ".agentmux"
) / "logs"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*-[0-9]+\Z")

# Matches ANSI CSI/OSC escapes. Agent logs are raw terminal output; Jira and
# Confluence must never receive escape bytes.
ANSI_RE = re.compile(
    r"(?:\x1b\]|\x9d)[\s\S]*?(?:\x07|\x1b\\|\x9c|$)"
    r"|(?:\x1b[P^_]|\x90|\x9e|\x9f)[\s\S]*?(?:\x1b\\|\x9c|$)"
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|\x1b[ -/]*[@-~]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def err(msg: str) -> None:
    print(f"task.py: {msg}", file=sys.stderr)


def display(value, cfg, limit=300):
    """Bound external text and remove controls and the known credential forms."""
    if not isinstance(value, str):
        return "unavailable"
    text = CONTROL_RE.sub("", ANSI_RE.sub("", value))
    header = atl._auth_header(cfg)
    secrets = (cfg.get("api_token"), header, header.partition(" ")[2])
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text[:limit]


def transition_entries(data):
    entries = data.get("transitions")
    if not isinstance(entries, list) or len(entries) > 1000:
        raise atl.AtlassianError("Jira returned no usable transition list")
    for entry in entries:
        if (not isinstance(entry, dict) or type(entry.get("id")) not in (str, int)
                or not re.fullmatch(r"[0-9]{1,30}", str(entry["id"]))
                or not isinstance(entry.get("name"), str) or not 1 <= len(entry["name"]) <= 300):
            raise atl.AtlassianError("Jira returned an invalid transition")
    return entries


def read_agent_log(agent: str, max_bytes: int = 8000) -> str:
    """Tail of an agent's pane log, ANSI-stripped and CR-normalised."""
    if not isinstance(agent, str) or not NAME_RE.fullmatch(agent):
        raise atl.AtlassianError("invalid agent name")
    if type(max_bytes) is not int or not 1 <= max_bytes <= 60000:
        raise atl.AtlassianError("log export limit must be between 1 and 60000 bytes")
    directory = None
    try:
        # Hold the directory and exact file handles across validation and read.
        # Do not follow a replaced name, symlink, FIFO or hardlinked secret file.
        directory = os.open(LOG_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fd = os.open(f"{agent}.log", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise atl.AtlassianError("log export requires a regular file without links")
            handle.seek(max(0, info.st_size - max_bytes))
            raw = handle.read(max_bytes)
    except OSError:
        raise atl.AtlassianError("log could not be safely read from the selected log directory") from None
    finally:
        if directory is not None:
            os.close(directory)
    text = CONTROL_RE.sub("", ANSI_RE.sub("", raw.decode("utf-8", "replace")))
    return "\n".join(line.rstrip() for line in text.splitlines()).strip()


def pick_transition(cfg, key, wanted: str | None):
    """Resolve a transition id. Jira transitions are per-project and per-workflow,
    so a hardcoded id would break on any other project."""
    data = atl.jira_transitions(cfg, key)
    options = transition_entries(data)
    if not options:
        raise atl.AtlassianError(f"{key} has no available transitions")
    pattern = wanted or cfg.get("done_transition") or r"done|closed|complete|resolve"
    try:
        matcher = re.compile(pattern, re.I)
    except (TypeError, re.error):
        raise atl.AtlassianError("the selected transition pattern is invalid") from None
    for t in options:
        if matcher.search(t["name"]):
            return t["id"], t["name"]
    names = ", ".join(display(t["name"], cfg, 80) for t in options[:10])
    raise atl.AtlassianError(
        f"no transition on {key} matched the selected pattern. Available: {names}. "
        'Review "done_transition" in the selected Atlassian configuration.'
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="task.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="print the request instead of sending it")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("whoami")

    c = sub.add_parser("create")
    c.add_argument("--summary", required=True)
    c.add_argument("--desc", default="")
    c.add_argument("--label", action="append", default=[])
    c.add_argument("--type", default="Task")

    cm = sub.add_parser("comment")
    cm.add_argument("key")
    g = cm.add_mutually_exclusive_group(required=True)
    g.add_argument("--text")
    g.add_argument("--from-log", metavar="AGENT")

    d = sub.add_parser("done")
    d.add_argument("key")
    d.add_argument("--from-log", metavar="AGENT")
    d.add_argument("--transition", help="regex or exact name; overrides config")

    r = sub.add_parser("report")
    r.add_argument("agent")
    r.add_argument("--title")
    r.add_argument("--parent")

    t = sub.add_parser("transitions")
    t.add_argument("key")

    args = ap.parse_args(argv)
    dry = args.dry_run

    try:
        cfg = atl.load_config()
    except atl.AtlassianError as exc:
        err(str(exc))
        return 1

    def need_key(k):
        if not KEY_RE.fullmatch(k):
            raise atl.AtlassianError("invalid Jira issue key")
        return k

    try:
        if args.cmd == "whoami":
            me = atl.whoami(cfg, dry_run=dry)
            if dry:
                print(me)
            else:
                name = me.get("displayName") or me.get("emailAddress")
                if not isinstance(name, str) or not name.strip():
                    raise atl.AtlassianError("Atlassian returned no usable account name")
                print(display(name, cfg, 200))

        elif args.cmd == "create":
            out = atl.jira_create(cfg, args.summary, args.desc, args.type,
                                  args.label, dry_run=dry)
            if dry:
                print(out)
            else:
                key = out.get("key")
                if not isinstance(key, str) or not KEY_RE.fullmatch(key):
                    raise atl.OutcomeUnknown("create returned no valid issue key; reconcile the issue before retrying")
                print(key)            # stdout = the key, for shell capture

        elif args.cmd == "comment":
            key = need_key(args.key)
            text = args.text if args.text is not None else \
                f"agentmux log tail for `{args.from_log}`:\n\n{read_agent_log(args.from_log)}"
            atl.jira_comment(cfg, key, text, dry_run=dry)
            print(f"commented on {key}")

        elif args.cmd == "done":
            key = need_key(args.key)
            if args.from_log:
                atl.jira_comment(
                    cfg, key,
                    f"agentmux agent `{args.from_log}` finished. Log tail:\n\n"
                    f"{read_agent_log(args.from_log)}",
                    dry_run=dry)
            if dry:
                print(f"[dry-run] would resolve a transition for {key} and apply it")
            else:
                tid, tname = pick_transition(cfg, key, args.transition)
                atl.jira_transition(cfg, key, tid)
                print(f"{key} -> {display(tname, cfg)}")

        elif args.cmd == "report":
            body = read_agent_log(args.agent, max_bytes=60000)
            title = args.title or f"agentmux run - {args.agent}"
            # Escape first, then wrap: the log is arbitrary text and Confluence
            # storage format is XML.
            page = ("<p>Captured from <code>~/.agentmux/logs/"
                    f"{html.escape(args.agent)}.log</code>.</p>"
                    f"<ac:structured-macro ac:name=\"code\">"
                    f"<ac:plain-text-body><![CDATA[{body.replace(']]>', ']] >')}]]>"
                    f"</ac:plain-text-body></ac:structured-macro>")
            out = atl.confluence_upsert(cfg, title, page,
                                        parent_id=args.parent, dry_run=dry)
            if dry:
                print(out)
            else:
                # Build the link from the configured site and validated receipt,
                # never from an arbitrary URL returned in an external response.
                page_id = atl._content_id(out.get("id"))
                prefix = "/wiki" if cfg["deployment"] == "cloud" else ""
                print(f"{cfg['base_url']}{prefix}/pages/viewpage.action?pageId={page_id}")

        elif args.cmd == "transitions":
            key = need_key(args.key)
            data = atl.jira_transitions(cfg, key, dry_run=dry)
            if dry:
                print(data)
            else:
                for tr in transition_entries(data):
                    print(f"{str(tr['id']):>6}  {display(tr['name'], cfg)}")

    except atl.AtlassianError as exc:
        err(display(str(exc), cfg, 500))
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
