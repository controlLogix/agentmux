#!/usr/bin/env python3
"""Verify the Ticket Reviewer: HTTP guards, the not-configured path, and the
request shaping in taskmgmt/atlassian.py.

    python3 dashboard/test_tickets.py --offline
    AGENTMUX_BASE_URL=<isolated dashboard URL> python3 dashboard/test_tickets.py

Use an isolated dashboard with no Atlassian configuration for the HTTP checks.
The test never chooses the operator's dashboard by default. With --offline only
the payload and private-file checks run:

  - over HTTP, the guards and the not-configured (409) path are asserted;
  - the actual request shaping is asserted through atlassian.py's dry_run, which
    returns the request it WOULD send instead of sending it.

Live Jira account qualification is separate from this fixture.
"""

import importlib.util
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
import os  # noqa: E402
OFFLINE = sys.argv[1:] == ["--offline"]
BASE = os.environ.get("AGENTMUX_BASE_URL")
if sys.argv[1:] and not OFFLINE:
    raise SystemExit("Use --offline or select an isolated dashboard with AGENTMUX_BASE_URL.")
if not OFFLINE:
    from urllib.parse import urlsplit
    target = urlsplit(BASE or "")
    home = os.environ.get("AGENTMUX_HOME")
    if (target.scheme != "http" or target.hostname != "127.0.0.1"
            or not target.port or target.port == 8787 or target.username is not None
            or target.path not in ("", "/") or target.query or target.fragment
            or not home or os.path.lexists(Path(home) / "atlassian.json")):
        raise SystemExit("HTTP checks require a selected loopback fixture port and AGENTMUX_HOME without Atlassian configuration.")
passed = failed = 0


def check(label, expected, actual):
    global passed, failed
    if expected == actual:
        print(f"  ok    {label:<50} {actual!r}")
        passed += 1
    else:
        print(f"  FAIL  {label:<50} got {actual!r} want {expected!r}")
        failed += 1


def post(path, body, ctype="application/json", origin=None):
    request = urllib.request.Request(f"{BASE}/{path}", data=json.dumps(body).encode(),
                                    method="POST")
    if ctype:
        request.add_header("Content-Type", ctype)
    if origin:
        request.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as err:
        raw = err.read()
        try:
            return err.code, json.loads(raw)
        except ValueError:
            return err.code, None


def get(path):
    try:
        with urllib.request.urlopen(f"{BASE}/{path}", timeout=20) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as err:
        raw = err.read()
        try:
            return err.code, json.loads(raw)
        except ValueError:
            return err.code, None


def http_status(path):
    try:
        with urllib.request.urlopen(f"{BASE}/{path}", timeout=20) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code


# ───────────────────────── atlassian.py request shaping ─────────────────────────

print("--- atlassian.py imports ---")
spec = importlib.util.spec_from_file_location(
    "atl", REPO / "taskmgmt" / "atlassian.py")
atl = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(atl)
    check("module imports", True, True)
except Exception as err:                      # noqa: BLE001 - this IS the assertion
    check("module imports", True, f"{type(err).__name__}: {err}")
    print("\npassed 0, failed 1")
    sys.exit(1)

CLOUD = {"deployment": "cloud", "base_url": "https://example.atlassian.net",
         "email": "someone@example.com", "api_token": "NOT-A-REAL-TOKEN",
         "jira_project": "CCC", "confluence_space": "OPS"}
SERVER = dict(CLOUD, deployment="server", base_url="https://jira.example.com")

print("--- dry_run returns the request instead of sending it ---")
out = atl.jira_search(CLOUD, "project = CCC ORDER BY updated DESC", limit=5, dry_run=True)
check("dry_run is flagged", True, out.get("dry_run"))
check("no Authorization header is returned", True, "Authorization" not in json.dumps(out))
check("no token anywhere in the result", False, "NOT-A-REAL-TOKEN" in json.dumps(out))
check("cloud search is a POST", "POST", out.get("method"))
check("cloud uses /search/jql", True, out.get("url", "").endswith("/search/jql"))
check("cloud uses the v3 API", True, "/rest/api/3/" in out.get("url", ""))
check("jql is passed through", "project = CCC ORDER BY updated DESC",
      (out.get("body") or {}).get("jql"))

out = atl.jira_search(SERVER, "project = CCC", limit=5, dry_run=True)
check("server search is a GET", "GET", out.get("method"))
check("server uses the v2 API", True, "/rest/api/2/" in out.get("url", ""))

print("--- comment bodies use ADF on cloud ---")
out = atl.jira_comment(CLOUD, "CCC-1", "hello from a test", dry_run=True)
check("comment is a POST", "POST", out.get("method"))
check("targets the issue's comment collection", True,
      out.get("url", "").endswith("/issue/CCC-1/comment"))
body = out.get("body") or {}
check("body is ADF, not a bare string", "doc",
      ((body.get("body") or {}).get("type")))
check("the text survives", "hello from a test",
      body["body"]["content"][0]["content"][0]["text"])

out = atl.jira_comment(SERVER, "CCC-1", "hello from a test", dry_run=True)
check("server comment is a plain string", "hello from a test",
      (out.get("body") or {}).get("body"))

print("--- transitions ---")
out = atl.jira_transitions(CLOUD, "CCC-1", dry_run=True)
check("listing transitions is a GET", "GET", out.get("method"))
check("targets the transitions collection", True,
      out.get("url", "").endswith("/issue/CCC-1/transitions"))
out = atl.jira_transition(CLOUD, "CCC-1", 31, dry_run=True)
check("applying one is a POST", "POST", out.get("method"))
check("id is sent as a string", "31",
      ((out.get("body") or {}).get("transition") or {}).get("id"))

print("--- load_config refuses a loose credential file ---")
import os                                                        # noqa: E402
import stat                                                      # noqa: E402
import tempfile                                                  # noqa: E402
tmp = Path(tempfile.mkdtemp(prefix="atl-cfg-"))
loose = tmp / "atlassian.json"
loose.write_text(json.dumps(CLOUD), encoding="utf-8")
os.chmod(loose, 0o644)
try:
    atl.load_config(loose)
    check("0644 config rejected", True, False)
except Exception as err:
    check("0644 config rejected", True, "must be 600" in str(err))
os.chmod(loose, 0o600)
try:
    cfg = atl.load_config(loose)
    check("0600 config accepted", "cloud", cfg["deployment"])
except Exception as err:
    check("0600 config accepted", "cloud", f"{type(err).__name__}: {err}")
# A missing required key must be named, and the message must not leak the token.
(tmp / "bad.json").write_text(json.dumps({"deployment": "cloud"}), encoding="utf-8")
os.chmod(tmp / "bad.json", 0o600)
try:
    atl.load_config(tmp / "bad.json")
    check("incomplete config rejected", True, False)
except Exception as err:
    check("incomplete config rejected", True,
          "missing" in str(err) and "api_token" in str(err))
import shutil                                                    # noqa: E402
shutil.rmtree(tmp, ignore_errors=True)

if OFFLINE:
    print(f"Offline payload/configuration checks: passed {passed}, failed {failed}. HTTP checks not run.")
    sys.exit(1 if failed else 0)

# ────────────────────────────── the HTTP surface ──────────────────────────────

print("--- /api/tickets is honest when Jira is not configured ---")
code, data = get("api/tickets")
check("GET /api/tickets", 200, code)
configured = bool(data.get("configured"))
if configured:
    raise SystemExit("Refusing ticket mutation tests: the selected dashboard has Atlassian configuration.")
else:
    check("configured is false, not an empty list", False, configured)
    check("it says why", True, bool(data.get("reason")))
    check("it shows how to fix it", True,
          any("setup_atlassian" in a.get("command", "") for a in data.get("setup", [])))
    check("no invented issues", [], data.get("issues"))
    print(f"        reason: {data.get('reason')}")

print("--- guards on the write endpoints ---")
for path in ("api/tickets/comment", "api/tickets/transition"):
    check(f"GET {path} -> 405", 405, http_status(path))
    check(f"{path} no JSON ctype -> 415", 415,
          post(path, {"key": "CCC-1"}, ctype=None)[0])
    check(f"{path} cross-origin -> 403", 403,
          post(path, {"key": "CCC-1"}, origin="https://evil.example")[0])
    check(f"{path} unknown field -> 400", 400, post(path, {"wat": 1})[0])

print("--- input validation happens before any Jira call ---")
for label, path, body in [
    ("lowercase key", "api/tickets/comment", {"key": "ccc-1", "text": "x"}),
    ("no number", "api/tickets/comment", {"key": "CCC-", "text": "x"}),
    ("path traversal in key", "api/tickets/comment", {"key": "../../x-1", "text": "x"}),
    ("empty comment", "api/tickets/comment", {"key": "CCC-1", "text": "   "}),
    ("oversize comment", "api/tickets/comment", {"key": "CCC-1", "text": "x" * 8500}),
    ("non-numeric transition", "api/tickets/transition",
     {"key": "CCC-1", "transition_id": "31; DROP"}),
    ("transition id as int", "api/tickets/transition",
     {"key": "CCC-1", "transition_id": 31}),
]:
    code, payload = post(path, body)
    check(label, 400, code)

print("--- and only then reports Jira is unavailable ---")
code, payload = post("api/tickets/comment", {"key": "CCC-1", "text": "valid"})
check("valid input, no config -> 409", 409, code)
check("409 names the missing config", True, bool((payload or {}).get("error")))
check("409 carries the setup commands", True, bool((payload or {}).get("setup")))

check("transitions needs a valid key -> 400", 400, http_status("api/tickets/transitions?key=x"))
check("transitions with no key -> 400", 400, http_status("api/tickets/transitions"))
if not configured:
    check("transitions with no config -> 409", 409,
          http_status("api/tickets/transitions?key=CCC-1"))

print()
print(f"passed {passed}, failed {failed}")
sys.exit(1 if failed else 0)
