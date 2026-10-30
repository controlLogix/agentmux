"""agentmux hub <verb> - the client side of the protocol. See docs/PROTOCOL.md 7.

Talks newline-delimited JSON to hub/hub.sock. The hub, not this client, decides who
the caller is (process ancestry); this client never sends an identity of its own
except the operator-only --as.

Output is written for two readers: an agent CLI that must act on it (the default
text form, which ends with the exact next command), and scripts (--json).
"""
from __future__ import annotations

from contextvars import ContextVar
selected_connection = ContextVar("selected_core_connection", default=None)

import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from agentmux_windows import validate_callback
ROOT = os.environ.get("AGENTMUX_HOME") or os.path.expanduser("~/.agentmux")
SOCK = os.path.join(ROOT, "hub", "hub.sock")
ENROLLED_STARTUP_SECONDS = 30
# hub.server._work_request_refusal: the authenticated request expired or its
# caller changed before the reply. Its effect may already have applied.
WORK_REQUEST_REFUSAL = 'authenticated work request changed or expired'

USAGE = """usage: agentmux hub <verb> [args]
  daemon     start [--selection ABSOLUTE_PATH]... | stop | status | ping | token (where your TCP token file is)
  stream     subscribe [--events [--since SEQ]]   one JSON line per new message / claimable change / event
  agent      whoami | inbox [--ack] | ack <id>... | claim [<work_id>] | heartbeat
             done|fail|return|block <work_id> [--result TEXT]
             post --to ADDR [--kind K] [--ref R] [--idem KEY] TEXT|-
             work add --to ADDR --title T [--body B | --body-file F] [--parent ID] [--priority N]
                      [--require CAP]... [--repo R] [--task-key K] [--federate (offer it to every hub on NATS)]
             work show <id> | work list [--state S] [--repo R] | work cancel <id> [--reason R] (operator)
  operator   repo add <repo> <path>... [--title T] [--group G]... [--accept-normalized]
             team add <repo> <team> [--member SESSION]...
             spawn <repo> <role> <agent> [--cli codex|claude|grok|shell] [--model M] [--team T] [--cwd P]
             kill <session> | agents [--live] | events [--since N] [--entity E] | resolve ADDR
             adopt <legacy-session> <repo> <role> <agent> [--cli C]    bring a pre-hub agent under the hub
             retire-courier [--dry-run]   import the courier's backlog, stop it; post goes via the hub
  federation fed help | fed setup | fed status | fed peers | fed share|unshare|trust | fed kill [--revoke] | fed resume
             fed quarantine | fed approve|deny <id> | fed audit | fed <plugin> <verb> ...   (docs/FEDERATION.md)
             mcp          stdio MCP server exposing the agent and federation verbs (for claude/codex)
  startup    [--selection ABSOLUTE_PATH] [--managed-worker] [--output human|json]
  dashboard  --selection ABSOLUTE_PATH
  enrolled   mcp --enrolled --selection ABSOLUTE_PATH [--managed-worker]
  global     --json   --as SESSION (operator only; testing)
  recovery   work mutations accept --operation-id ID; retry with the same ID and arguments
             qualified calls generate an ID before sending and retain it on transport retry
addresses: agent:<repo>-<role>-<agent>  role:<repo>/<role>  role:*/<role>  role:group:<g>/<role>
           role:team:<repo>/<team>/<role>  team:<repo>/<team>  virtual:operator
           peer:<peer>[/<repo>/<role>[/<agent>]]   (another person's hub, via federation)"""


class Fail(SystemExit):
    pass


def connect(timeout):
    """Unix socket by default. AGENTMUX_HUB_URL=tcp://127.0.0.1:PORT selects the
    token-authenticated TCP listener - the only way in from Windows, where there is no
    unix socket and no process ancestry for the hub to read."""
    try:
        if validate_callback(os.environ):
            tcp_token()  # Reject an unreadable token file before opening a socket.
    except ValueError as exc:
        raise Fail(str(exc))
    url = os.environ.get("AGENTMUX_HUB_URL", "")
    if url.startswith("tcp://"):
        host, _, port = url[6:].rpartition(":")
        s = socket.create_connection((host or "127.0.0.1", int(port)), timeout=timeout)
        return s, True
    s = socket.socket(socket.AF_UNIX)
    try:
        s.settimeout(timeout)
        s.connect(SOCK)
    except BaseException as error:
        try:
            s.close()
        except BaseException as cleanup_error:
            # Preserve the original failure and the consumed close failure.
            raise error from cleanup_error
        raise
    return s, False


def tcp_token():
    tok = os.environ.get("AGENTMUX_HUB_TOKEN")
    path = os.environ.get("AGENTMUX_HUB_TOKEN_FILE")
    if not tok and path:
        try:
            with open(path) as f:
                tok = f.read().strip()
        except OSError:
            raise Fail("agentmux hub: cannot read the TCP token file")
    if not tok:
        raise Fail("agentmux hub: TCP needs AGENTMUX_HUB_TOKEN or AGENTMUX_HUB_TOKEN_FILE")
    return tok


def call(verb, args=None, as_=None, timeout=30):
    try:
        validate_callback(os.environ, verb)
    except ValueError as exc:
        raise Fail(str(exc))
    deadline = time.monotonic() + timeout
    arguments = dict(args or {})
    operation_id = None
    qualified = False
    work_mutation = verb in ('work_add', 'claim', 'heartbeat', 'release', 'work_cancel', 'claim_path', 'fed_work_add')
    lifecycle_mutation = verb in ('spawn', 'adopt', 'kill')
    if verb in ('fed_code_share', 'fed_code_fetch') or work_mutation or lifecycle_mutation:
        family = 'lifecycle' if lifecycle_mutation else ('work' if work_mutation else 'code')
        operation_id = arguments.pop('operation_id', None)
        if operation_id is not None and (type(operation_id) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', operation_id) is None):
            raise Fail(f'invalid {family} operation ID')
        discovery = 'ping' if lifecycle_mutation or work_mutation and verb != 'fed_work_add' else 'fed_verbs'
        registry = call(discovery, as_=as_, timeout=min(10, max(.001, deadline - time.monotonic())))
        qualified = (type(registry.get('result')) is dict and registry['result'].get('lifecycleOperationIds' if lifecycle_mutation else 'workOperationIds') is True
            if discovery == 'ping' else
            any(row.get('verb') == verb and row.get('operationIds') is True
                for row in registry.get('result', []) if isinstance(row, dict)))
        if operation_id is not None and not qualified:
            raise Fail(f'this Hub does not support {family} operation recovery IDs')
        if qualified and operation_id is None:
            operation_id = family + '_' + secrets.token_hex(24)
    req = {'verb': verb, 'args': arguments}
    if as_:
        req['as'] = as_
    if operation_id is not None:
        req['operationId'] = operation_id
    # Freeze one intent before any mutation exchange. Only the transport token
    # may be refreshed; it is excluded from the Hub's authenticated intent.
    packet = json.dumps(req)
    for attempt in range(2 if qualified else 1):
        s = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            selected = selected_connection.get()
            if selected is not None:
                resp = selected.exchange(json.loads(packet), remaining)
            else:
                s, tcp = connect(remaining)
                outgoing = json.loads(packet)
                if tcp:
                    outgoing['token'] = tcp_token()
                s.sendall((json.dumps(outgoing) + '\n').encode())
                buf = b''
                while not buf.endswith(b'\n'):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    s.settimeout(remaining)
                    chunk = s.recv(65536)
                    if not chunk:
                        raise EOFError()
                    buf += chunk
                resp = json.loads(buf)
            if not isinstance(resp, dict):
                raise ValueError('invalid Hub response')
        except ValueError:
            recovery = f'; recover with --operation-id {operation_id}' if operation_id else ''
            raise Fail(f'agentmux hub: invalid response{recovery}') from None
        except (OSError, EOFError) as exc:
            if qualified and attempt == 0 and time.monotonic() < deadline:
                continue
            recovery = f'; recover with --operation-id {operation_id}' if operation_id else ''
            raise Fail(f'agentmux hub: response unavailable ({type(exc).__name__}){recovery}') from None
        finally:
            if s is not None:
                s.close()
        if not resp.get('ok'):
            refused = resp.get('error') == WORK_REQUEST_REFUSAL
            # The same frozen intent and operation ID return the Hub's recorded
            # outcome; the Hub never applies a second effect for one ID.
            if (refused and verb in ('spawn', 'kill') and qualified and attempt == 0
                    and time.monotonic() < deadline):
                continue
            recovery = (f'; recover with --operation-id {operation_id}' if refused and operation_id
                else f'; operation ID {operation_id}' if operation_id else '')
            raise Fail(f"agentmux hub {verb}: {resp.get('error', 'no response')}{recovery}")
        return resp


def opt(argv, name, default=None, multi=False, flag=False):
    vals, out, i = [], [], 0
    while i < len(argv):
        if argv[i] == name:
            if flag:
                vals.append(True); i += 1; continue
            if i + 1 >= len(argv):
                raise Fail(f"{name} needs a value")
            vals.append(argv[i + 1]); i += 2; continue
        out.append(argv[i]); i += 1
    argv[:] = out
    if flag:
        return bool(vals)
    if multi:
        return vals
    return vals[-1] if vals else default


def show_msgs(r):
    sess = r["session"]
    lines = []
    msgs = r["messages"]
    if not msgs:
        lines.append(f"No new messages for {sess}.")
    else:
        lines.append(f"{len(msgs)} message(s) for {sess}:")
    for m in msgs:
        lines.append(f"--- {m['id']}  from {m['sender']}  kind={m['kind']}" + (f"  ref={m['ref']}" if m['ref'] else ""))
        if m.get("body_ref"):
            lines.append(f"(body is in {m['body_ref']} - read that file; sha256 {m['body_sha'][:16]})")
        if m.get("body"):
            lines.append(m["body"])
    lines.append("---")
    if r.get("acked"):
        lines.append(f"Acknowledged {len(r['acked'])} message(s).")
    elif msgs:
        lines.append("Acknowledge with: agentmux hub ack " + " ".join(m["id"] for m in msgs))
    act = r.get("active") or []
    for a in act:
        lines.append(f"Your active work: {a['id']} \"{a['title']}\" (lease until {a['lease_until']})")
    cl = r.get("claimable") or []
    if cl:
        lines.append(f"Claimable work ({len(cl)}): " + "; ".join(f"{c['id']} \"{c['title']}\" [{c['target']}]" for c in cl[:5]))
        lines.append("Take the next one with: agentmux hub claim")
    elif not act and not msgs:
        lines.append("Nothing to do right now. Stop and wait for the next [hub] line.")
    return "\n".join(lines)


def show_work(w):
    if not w:
        return "no such work item"
    out = [f"{w['id']}  [{w['state']}]  {w['title']}",
           f"  target {w['target']}  repo {w['repo']}  priority {w['priority']}  by {w['created_by']}"
           + (f"  parent {w['parent_id']}" if w.get("parent_id") else "") + (f"  task {w['task_key']}" if w.get("task_key") else "")]
    if w.get("claimed_by"):
        out.append(f"  claimed by {w['claimed_by']} until {w['lease_until']}")
    if w.get("body"):
        out.append("  ---\n" + "\n".join("  " + l for l in w["body"].splitlines()))
    if w.get("result"):
        out.append(f"  result: {w['result']}")
    for c in w.get("children") or []:
        out.append(f"  child {c['id']} [{c['state']}] {c['title']} -> {c['target']}" + (f" ({c['claimed_by']})" if c['claimed_by'] else ""))
    return "\n".join(out)


def python():
    """The interpreter for the hub: the repo's .venv when it exists (federation needs
    nats-py, hub/requirements.txt), else this one. AGENTMUX_PYTHON overrides."""
    env = os.environ.get("AGENTMUX_PYTHON")
    if env:
        return env
    venv = os.path.join(REPO, ".venv", "bin", "python")
    return venv if os.path.exists(venv) else sys.executable


def _stop_enrolled_child(process):
    """Stop and reap the exact enrolled child before reporting startup failure."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    else:
        process.wait()


def start(selections=()):
    try:
        validate_callback(os.environ, "start")
    except ValueError as exc:
        raise Fail(str(exc))
    running = False
    try:
        call("ping", timeout=3)
        running = True
    except Fail:
        pass
    if running:
        if selections:
            raise Fail("an existing hub must be stopped before enrolled startup")
        print("hub already running")
        return
    os.makedirs(os.path.join(ROOT, "hub"), exist_ok=True)
    startup_deadline = time.monotonic() + ENROLLED_STARTUP_SECONDS if selections else None
    command = ([python(), os.path.join(REPO, "hub", "server.py")] if not selections else
               [python(), os.path.join(REPO, "hub", "enrolled_hub_bootstrap.py"),
                '--startup-deadline', repr(startup_deadline),
                *(value for path in selections for value in ('--selection', path))])
    with open(os.path.join(ROOT, "hub", "hub.log"), "a") as logf:
        process = subprocess.Popen(command, stdout=logf, stderr=logf,
                                   stdin=subprocess.DEVNULL, start_new_session=True, cwd=ROOT)
    if selections:
        try:
            while time.monotonic() < startup_deadline:
                if process.poll() is not None:
                    raise Fail("hub did not come up; see " + os.path.join(ROOT, "hub", "hub.log"))
                remaining = startup_deadline - time.monotonic()
                try:
                    call("ping", timeout=min(2, max(0.001, remaining)))
                    if process.poll() is not None:
                        raise Fail("hub did not come up; see " + os.path.join(ROOT, "hub", "hub.log"))
                    print(f"hub started ({SOCK})")
                    return
                except Fail:
                    time.sleep(min(0.2, max(0, startup_deadline - time.monotonic())))
        except BaseException:
            _stop_enrolled_child(process)
            raise
        _stop_enrolled_child(process)
        raise Fail("hub did not come up; see " + os.path.join(ROOT, "hub", "hub.log"))
    for _ in range(50):
        time.sleep(0.2)
        if process.poll() is not None:
            process.wait()
            raise Fail("hub did not come up; see " + os.path.join(ROOT, "hub", "hub.log"))
        try:
            call("ping", timeout=2)
            print(f"hub started ({SOCK})")
            return
        except Fail:
            continue
    raise Fail("hub did not come up; see " + os.path.join(ROOT, "hub", "hub.log"))


def main(argv, *, registered_context=None):
    if argv and argv[0] == 'selected':
        arguments = list(argv[1:])
        repository = opt(arguments, '--repository-root')
        profile = opt(arguments, '--profile-id')
        if not repository or not arguments or arguments[0] != '--' or len(arguments) < 2:
            raise Fail('Use selected --repository-root PATH [--profile-id ID] -- COMMAND.')
        from hub.client_launch_repository import core_handoff
        try:
            return core_handoff(repository, arguments[1:], profile_id=profile)
        except Exception:
            raise Fail('Selected core Hub setup is required.') from None
    if registered_context is not None:
        from hub.profile_context import RegisteredProfileContext
        if (type(registered_context) is not RegisteredProfileContext or not argv
                or argv[0] not in ('startup', 'mcp', 'dashboard') or '--selection' not in argv):
            raise Fail('Registered profile context requires an explicit installed startup selection.')
    as_ = opt(argv, "--as")
    js = opt(argv, "--json", flag=True)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE); return
    verb, rest = argv[0], argv[1:]
    work_operation_id = (opt(rest, '--operation-id') if verb in
        ('claim', 'done', 'fail', 'return', 'block', 'heartbeat', 'spawn', 'adopt', 'kill') or
        verb == 'work' and rest[:1] in (['add'], ['cancel']) else None)

    def work_args(arguments=None):
        result = dict(arguments or {})
        if work_operation_id is not None:
            result['operation_id'] = work_operation_id
        return result
    try:
        validate_callback(os.environ, verb)
    except ValueError as exc:
        raise Fail(str(exc))

    def out(resp, text=None):
        if js:
            print(json.dumps(resp["result"], indent=2, default=str))
        else:
            print(text if text is not None else json.dumps(resp["result"], indent=2, default=str))

    if verb == "fed":
        return fed_main(rest, as_, js)
    if verb == "mcp":
        sys.path.insert(0, REPO)
        if rest:
            from hub.client_launch_entrypoint import EnrolledSession, OptionsError, parse_options
            try:
                options = parse_options(rest, mcp=True)
                if as_ is not None or js:
                    raise OptionsError("Enrolled MCP does not accept legacy output or identity overrides.")
            except OptionsError as exc:
                raise Fail(str(exc)) from None
            return EnrolledSession(options, registered_context=registered_context).serve_mcp()
        from hub.fed import mcp
        return mcp.main()
    if verb == "startup":
        from hub.client_launch_entrypoint import EnrolledSession, OptionsError, parse_options
        try:
            options = parse_options(rest)
            if as_ is not None or js:
                raise OptionsError("Use explicit startup output options without identity overrides.")
        except OptionsError as exc:
            raise Fail(str(exc)) from None
        return EnrolledSession(options, registered_context=registered_context).report()
    if verb == "dashboard":
        from hub.client_launch_entrypoint import EnrolledSession, OptionsError, parse_options
        try:
            options = parse_options(rest)
            if (options.managed_worker or options.output != 'human' or as_ is not None or js):
                raise OptionsError('Dashboard sign-in accepts only an explicit enrolled selection.')
        except OptionsError as exc:
            raise Fail(str(exc)) from None
        return EnrolledSession(options, registered_context=registered_context).open_dashboard()
    if verb == "start":
        selections = tuple(opt(rest, "--selection", multi=True))
        if rest:
            raise Fail("hub start accepts only repeated --selection paths")
        return start(selections)
    if verb == "stop":
        call("shutdown"); print("hub stopping"); return
    if verb == "status" and opt(rest, "--bridge", flag=True):
        r = call("status", {"bridge": True}, as_=as_)
        b = r["result"]
        return out(r, f"node {b['node']}  nats {b['nats_url'] or 'off'}  connected={b['connected']}\n"
                      f"stats {json.dumps(b['stats'])}\nrole subjects: {', '.join(b['role_subjects']) or '-'}")
    if verb in ("ping", "status", "whoami"):
        r = call(verb, as_=as_)
        if verb == "whoami" and not js:
            a = r["result"].get("agent")
            print(f"{r['caller']}" + (f"  repo={a['repo']} role={a['role']} cli={a['cli']} state={a['state']}\n"
                                      f"eligible: {', '.join(r['result']['eligible'])}" if a else ""))
            return
        if verb == "status" and not js:
            st = r["result"]
            print(f"repos: {', '.join(st['repos']) or '-'}")
            print("deliveries: " + ", ".join(f"{k}={v}" for k, v in sorted(st["deliveries"].items())) or "-")
            print("work: " + ", ".join(f"{k}={v}" for k, v in sorted(st["work"].items())))
            for a in st["agents"]:
                print(f"  {a['session']:<40} {a['cli']:<7} {a['state']:<8} {a['state_note'] or ''}")
            for d in st["dead"]:
                print(f"  DEAD {d['message_id']} -> {d['recipient']}: {d['last_error']}")
            return
        return out(r)
    if verb == "token":
        r = call("token", as_=as_)
        return out(r, f"your token is in {r['result']['path']} (mode 0600). Use it with "
                      "AGENTMUX_HUB_URL=tcp://127.0.0.1:<tcp_port> AGENTMUX_HUB_TOKEN_FILE=<that path>")
    if verb == "subscribe":
        stream = "events" if opt(rest, "--events", flag=True) else "mail"
        req = {"verb": "subscribe", "args": {"stream": stream, "since": int(opt(rest, "--since", 0))}}
        if as_:
            req["as"] = as_
        s, tcp = connect(None)
        if tcp:
            req["token"] = tcp_token()
        s.sendall((json.dumps(req) + "\n").encode())
        f = s.makefile("r")
        try:
            for line in f:
                print(line.rstrip("\n"), flush=True)
        except KeyboardInterrupt:
            pass
        return
    if verb == "inbox":
        ack = opt(rest, "--ack", flag=True)
        sess = opt(rest, "--session")
        r = call("inbox", {"ack": ack, "session": sess, "limit": int(opt(rest, "--limit", 20))}, as_=as_)
        return out(r, show_msgs(r["result"]))
    if verb == "ack":
        r = call("ack", {"ids": rest}, as_=as_)
        return out(r, f"acked {len(r['result']['acked'])}")
    if verb == "claim":
        r = call("claim", work_args({"work_id": rest[0] if rest else None}), as_=as_)
        c = r["result"].get("claimed")
        if not c:
            return out(r, "Nothing claimable for you right now" + (f" ({r['result']['reason']})" if r['result'].get('reason') else "")
                       + ". Stop and wait for the next [hub] line.")
        return out(r, "You claimed:\n" + show_work(c) +
                   f"\nWhen finished: agentmux hub done {c['id']} --result \"<summary>\"   (or fail/return/block)")
    if verb in ("done", "fail", "return", "block"):
        if not rest:
            raise Fail(f"{verb} needs a work id")
        result = opt(rest, "--result")
        outcome = {"fail": "failed", "return": "returned", "block": "blocked"}.get(verb, "done")
        r = call("release", work_args({"work_id": rest[0], "outcome": outcome, "result": result}), as_=as_)
        return out(r, f"{rest[0]} -> {r['result']['state']}")
    if verb == "heartbeat":
        return out(call("heartbeat", work_args(), as_=as_))
    if verb == "post":
        to = opt(rest, "--to"); kind = opt(rest, "--kind", "note"); ref = opt(rest, "--ref")
        idem = opt(rest, "--idem")
        if not to:
            raise Fail("post needs --to ADDRESS")
        if rest[:1] == ["--"]:
            rest = rest[1:]
        body = " ".join(rest)
        if body == "-":
            body = sys.stdin.read()
        r = call("post", {"to": to, "kind": kind, "ref": ref, "idem_key": idem, "body": body}, as_=as_)
        res = r["result"]
        return out(r, f"posted {res['id']} to {', '.join(res['recipients'])}" + (" (duplicate idem key)" if res["duplicate"] else ""))
    if verb == "work":
        sub = rest[0] if rest else "list"
        rest = rest[1:]
        if sub == "add":
            body_file = opt(rest, "--body-file")
            body = open(body_file).read() if body_file else opt(rest, "--body")
            req = opt(rest, "--require", multi=True)
            a = {"to": opt(rest, "--to"), "title": opt(rest, "--title"), "body": body, "parent": opt(rest, "--parent"),
                 "priority": int(opt(rest, "--priority", 100)), "repo": opt(rest, "--repo"),
                 "task_key": opt(rest, "--task-key"), "requirements": {"capabilities": req} if req else None,
                 "federate": opt(rest, "--federate", flag=True)}
            if not a["to"] or not a["title"]:
                raise Fail("work add needs --to and --title")
            r = call("work_add", work_args(a), as_=as_)
            return out(r, f"created {r['result']['id']} -> {r['result']['target']}")
        if sub == "cancel":
            reason = opt(rest, '--reason')
            if len(rest) != 1:
                raise Fail('work cancel needs a work id')
            r = call("work_cancel", work_args({"work_id": rest[0], "reason": reason}), as_=as_)
            return out(r, f"cancelled: {', '.join(r['result']['cancelled']) or 'nothing open'}")
        if sub == "show":
            r = call("work_show", {"work_id": rest[0]}, as_=as_)
            return out(r, show_work(r["result"]))
        if sub == "list":
            r = call("work_list", {"state": opt(rest, "--state"), "repo": opt(rest, "--repo")}, as_=as_)
            return out(r, "\n".join(f"{w['id']} [{w['state']:<16}] {w['title'][:50]:<50} {w['target']} {w['claimed_by'] or ''}"
                                    for w in r["result"]) or "no work items")
        raise Fail(f"unknown work subcommand {sub}")
    if verb == "repo":
        if not rest or rest[0] != "add" or len(rest) < 3:
            raise Fail("usage: agentmux hub repo add <repo> <path>...")
        rest = rest[1:]
        title = opt(rest, "--title"); groups = opt(rest, "--group", multi=True)
        acc = opt(rest, "--accept-normalized", flag=True)
        r = call("repo_add", {"repo": rest[0], "paths": rest[1:], "title": title, "groups": groups,
                              "accept_normalized": acc}, as_=as_)
        return out(r, f"repo {r['result']['repo']} registered")
    if verb == "team":
        if not rest or rest[0] != "add" or len(rest) < 3:
            raise Fail("usage: agentmux hub team add <repo> <team> [--member S]...")
        rest = rest[1:]
        mem = opt(rest, "--member", multi=True)
        r = call("team_add", {"repo": rest[0], "team": rest[1], "members": mem}, as_=as_)
        return out(r, f"team {rest[0]}/{rest[1]}: {', '.join(r['result']['members'])}")
    if verb == "spawn":
        cli = opt(rest, "--cli", "codex"); model = opt(rest, "--model"); teams = opt(rest, "--team", multi=True)
        cwd = opt(rest, "--cwd"); acc = opt(rest, "--accept-normalized", flag=True)
        if len(rest) != 3:
            raise Fail("usage: agentmux hub spawn <repo> <role> <agent> [--cli C]")
        r = call("spawn", work_args({"repo": rest[0], "role": rest[1], "agent": rest[2], "cli": cli, "model": model,
                           "teams": teams, "cwd": cwd, "accept_normalized": acc}), as_=as_, timeout=180)
        if r['result'].get('outcome') == 'not-started':
            return out(r, f"{r['result']['session']} did not start: the original caller deadline expired. "
                f"Operation {r['result']['operationId']} remains not started.")
        return out(r, f"spawned {r['result']['session']} ({r['result']['handle']}) in {r['result']['cwd']}")
    if verb == "kill":
        return out(call("kill", work_args({"session": rest[0]}), as_=as_))
    if verb == "adopt":
        cli = opt(rest, "--cli"); acc = opt(rest, "--accept-normalized", flag=True)
        if len(rest) != 4:
            raise Fail("usage: agentmux hub adopt <legacy-session> <repo> <role> <agent> [--cli C]")
        r = call("adopt", work_args({"legacy": rest[0], "repo": rest[1], "role": rest[2], "agent": rest[3], "cli": cli,
                           "accept_normalized": acc}), as_=as_)
        return out(r, f"adopted {r['result']['legacy']} as {r['result']['session']} ({r['result']['cli']}, "
                      f"{r['result']['handle']}); both names now reach it")
    if verb == "retire-courier":
        dry = opt(rest, "--dry-run", flag=True)
        r = call("retire_courier", {"dry_run": dry}, as_=as_, timeout=180)
        res = r["result"]
        text = (f"{'would import' if dry else 'imported'} {res['imported']} undelivered message(s) from "
                f"{res['outboxes']} outbox(es); {res['duplicate']} already imported")
        if res["unresolved"]:
            text += f"\n  left in the queue (recipient unknown to the hub - adopt it first): {', '.join(res['unresolved'][:10])}"
        if not dry:
            text += f"\n  courier stopped: {res.get('courier_stopped')}; `agentmux post` now goes through the hub"
        return out(r, text)
    if verb == "agents":
        r = call("agents", {"live": opt(rest, "--live", flag=True)}, as_=as_)
        return out(r, "\n".join(f"{a['session']:<40} {a['cli']:<7} {a['state']:<8} {a['handle'] or '-':<5} "
                                f"out={a['last_output'] or '-'}" for a in r["result"]) or "no agents")
    if verb == "events":
        # Without --since, show the newest events: the oldest 200 are never what
        # `hub events | tail` is asked for once the table outgrows one page.
        since = opt(rest, "--since")
        r = call("events", {"since": int(since or 0), "entity": opt(rest, "--entity"), "tail": since is None,
                            "limit": int(opt(rest, "--limit", 200))}, as_=as_)
        return out(r, "\n".join(f"{e['seq']:>5} {e['at']} {e['entity']:<8} {e['entity_id'][:48]:<48} {e['event']:<12} "
                                f"{e['actor'] or ''} {(e['detail'] or '')[:120]}" for e in r["result"]))
    if verb == "resolve":
        return out(call("resolve", {"address": rest[0]}, as_=as_))
    raise Fail(f"unknown verb {verb!r}\n{USAGE}")


# -- federation (docs/FEDERATION.md 10): verbs come from the hub's registry ---------------
FED_HELP = """usage: agentmux hub fed <verb> [args]      (docs/FEDERATION.md)
  setup                          create .venv with nats-py (hub/requirements.txt), then restart the hub
  status | peers                 connection and identity | who is online in the circle
  share <repo> [--peers a,b]     opt a repo in (default: the whole circle)    unshare <repo>
  trust <peer|*> --level auto|flag|approve|deny
  kill [--revoke] | resume       KILL SWITCH: disconnect and stay disconnected (--revoke: withdraw + tell peers)
  quarantine | approve <id> [--privileged] | deny <id>
  audit [--peer P] [--limit N]
  <plugin> <verb> ...            e.g. board add --repo R --title T, know search "q", code share --to peer:alice
Run `agentmux hub fed verbs` for every verb and its parameters."""


def fed_parse(argv, params):
    args, words, i = {}, [], 0
    while i < len(argv):
        t = argv[i]
        if t.startswith("--") and len(t) > 2:
            name = t[2:].replace("-", "_")
            p = params.get(name, {})
            if p.get("type") == "boolean":
                args[name] = True
                i += 1
                continue
            if i + 1 >= len(argv):
                raise Fail(f"{t} needs a value")
            v = argv[i + 1]
            if p.get("type") == "array":
                args.setdefault(name, []).extend(x for x in v.split(",") if x)
            elif p.get("type") == "integer":
                args[name] = int(v)
            else:
                args[name] = v
            i += 2
            continue
        words.append(t)
        i += 1
    pos = [n for n, p in params.items() if p.get("positional")]
    if words:
        if not pos:
            raise Fail(f"unexpected words: {' '.join(words)}")
        text = " ".join(words)
        if text == "-":
            text = sys.stdin.read()
        if params[pos[0]].get("type") == "array":
            args.setdefault(pos[0], []).extend(words)
        else:
            args.setdefault(pos[0], text)
    return args


def fed_text(verb, res):
    if isinstance(res, list):
        if not res:
            return "(none)"
        keys = [k for k in ("key", "id", "seq", "at", "peer", "node", "repo", "dir", "plane", "from_peer", "status",
                            "state", "decision", "title", "summary", "reason", "assignee", "snippet") if k in res[0]]
        return "\n".join("  ".join(str(r.get(k) if r.get(k) is not None else "-")[:70] for k in keys) for r in res)
    if isinstance(res, dict):
        return "\n".join(f"{k}: {json.dumps(v, default=str) if isinstance(v, (dict, list)) else v}"
                         for k, v in res.items())
    return str(res)


def fed_setup():
    venv = os.path.join(REPO, ".venv")
    if not os.path.exists(os.path.join(venv, "bin", "python")):
        subprocess.run([sys.executable, "-m", "venv", venv], check=True)
    subprocess.run([os.path.join(venv, "bin", "pip"), "install", "-q",
                    "-r", os.path.join(REPO, "hub", "requirements.txt"),
                    "-c", os.path.join(REPO, "hub", "requirements.lock")], check=True)
    print(f"federation dependencies installed in {venv}; restart the hub (agentmux hub stop; agentmux hub start)")


def fed_main(rest, as_, js):
    if not rest or rest[0] in ("help", "-h", "--help"):
        print(FED_HELP)
        return
    if rest[0] == "setup":
        return fed_setup()
    reg = {v["verb"]: v for v in call("fed_verbs", as_=as_)["result"]}
    if rest[0] == "verbs":
        for name, v in reg.items():
            ps = " ".join((f"<{k}>" if p["positional"] else f"--{k.replace('_', '-')}" +
                           ("" if p["type"] == "boolean" else f" {p['type'][:3].upper()}")) +
                          ("" if p["required"] else "?") for k, p in v["params"].items())
            print(f"{name.removeprefix('fed_').replace('_', ' ', 1):<22} {ps}\n    {v['help']}"
                  f"{'  (operator)' if v['operator_only'] else ''}")
        return
    if len(rest) >= 2 and f"fed_{rest[0]}_{rest[1]}" in reg:
        verb, argv = f"fed_{rest[0]}_{rest[1]}", rest[2:]
    elif f"fed_{rest[0]}" in reg:
        verb, argv = f"fed_{rest[0]}", rest[1:]
    elif rest[0] == "know" and len(rest) >= 2 and f"fed_knowledge_{rest[1]}" in reg:
        verb, argv = f"fed_knowledge_{rest[1]}", rest[2:]
    else:
        raise Fail(f"unknown federation verb: {' '.join(rest[:2])}\n{FED_HELP}")
    args = fed_parse(argv, reg[verb]["params"])
    args["cwd"] = os.getcwd()
    r = call(verb, args, as_=as_, timeout=90)
    if js:
        print(json.dumps(r["result"], indent=2, default=str))
    else:
        print(fed_text(verb, r["result"]))


if __name__ == "__main__":
    try:
        completed = main(sys.argv[1:])
        if completed is not None:
            from hub.client_launch_entrypoint import EnrolledSession
            if isinstance(completed, EnrolledSession):
                sys.exit(completed.exit_code())
    except Fail as e:
        print(e, file=sys.stderr)
        sys.exit(1)
