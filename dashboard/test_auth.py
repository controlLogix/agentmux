#!/usr/bin/env python3
"""Verify the auth provider/method plumbing end to end.

    Run through dashboard/run_tests.sh against its disposable dashboard.

Runs setup_auth.py against an ISOLATED HOME under /tmp with an obviously fake
token, so the operator's real ~/.agentmux/env and ~/.codex are never touched.

The /api/* section uses the dashboard home selected by run_tests.sh. Its fixture
is restored within that disposable home. Run through run_tests.sh to isolate HTTP
writes from the operator's server as well as the setup_auth subprocesses.

What this is actually proving:
  - a provider's SHARED attributes are stored ONCE on the provider, not copied
    onto each method that uses them;
  - an unconfigured provider blocks every method that depends on it;
  - the profile has valid TOML while native client acceptance stays unverified;
  - agentmux resolves a method into the right flags and exports;
  - no secret VALUE reaches the generated config, the HTTP API, or any output;
  - /api/auth/select keeps the same guards as every other mutating endpoint.

The subprocess test replaces getpass with a synthetic input reader. Production
setup requires a terminal with hidden input and does not permit echoed fallback.
"""

import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# Refuse missing fixture context before any configuration read or HTTP request.
BASE = os.environ.get("AGENTMUX_BASE_URL", "")
_fixture_home = os.environ.get("AGENTMUX_HOME", "")
if (not re.fullmatch(r"http://127[.]0[.]0[.]1:[0-9]+", BASE)
        or BASE.endswith(":8787") or not _fixture_home
        or os.environ.get("AGENTMUX_NO_COURIER") != "1"):
    raise SystemExit("Use the disposable dashboard runner; no test request was sent.")
try:
    Path(_fixture_home).resolve().relative_to(Path(tempfile.gettempdir()).resolve())
except ValueError:
    raise SystemExit("The auth integration test requires a temporary fixture home.")
FAKE_TOKEN = "FAKE-NOT-A-REAL-KEY-do-not-use-0000"
GATEWAY = "http://127.0.0.1:4000/v1"
CODEX_MODEL = "example-model-v1"
GCP_PROJECT = "example-project"
GCP_REGION = "us-central1"

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
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as err:
        raw = err.read()
        try:
            return err.code, json.loads(raw)
        except ValueError:
            return err.code, None


def get(path):
    with urllib.request.urlopen(f"{BASE}/{path}", timeout=15) as response:
        return response.status, json.loads(response.read())


def http_status(path):
    try:
        with urllib.request.urlopen(f"{BASE}/{path}", timeout=15) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code


sandbox = Path(tempfile.mkdtemp(prefix="agentmux-auth-test-"))
env = dict(os.environ)
env["HOME"] = str(sandbox)
env["CODEX_HOME"] = str(sandbox / ".codex")
env["AGENTMUX_REPO"] = str(REPO)
env["AGENTMUX_HOME"] = str(sandbox / ".agentmux")

def setup_auth(args, answers="", timeout=180):
    """Exercise the command with synthetic input and no terminal fallback."""
    harness = ("import getpass, runpy, sys; "
               "getpass.getpass = lambda prompt: sys.stdin.readline().rstrip('\\n'); "
               "sys.argv = ['taskmgmt/setup_auth.py', *sys.argv[1:]]; "
               "runpy.run_path('taskmgmt/setup_auth.py', run_name='__main__')")
    return subprocess.run([sys.executable, "-c", harness, *args], cwd=REPO, env=env,
                          input=answers, capture_output=True, text=True, timeout=timeout)


def split_resolution(stdout):
    """Split auth_resolve's tab-separated "<flags>\t<exports>" output.

    Deliberately does NOT strip the whole line first: with no flags the line begins
    with the tab, and stripping that makes partition find no separator, so `flags`
    silently swallows the exports and every export assertion fails misleadingly.
    """
    flags, _, exports = stdout.rstrip("\n").partition("\t")
    return flags.strip(), exports.strip()


def resolve(method_id, cli):
    """Call auth_resolve with its production ROOT initialization, without dispatch."""
    script = ('eval "$(sed -n "/^ROOT=/p; /^auth_resolve()/,/^}/p" agentmux.sh | tr -d "\\r")"; '
              f'auth_resolve {method_id} {cli}')
    return subprocess.run(["bash", "-c", script], cwd=REPO, env=env,
                          capture_output=True, text=True, timeout=60)


# ORDER MATTERS HERE. The "nothing configured yet" refusals have to run BEFORE the
# providers are filled in, because configuring one is what makes its methods resolve.
print(f"--- nothing configured: a method is refused, and says what is missing ({sandbox}) ---")
out = resolve("claude-vertex", "claude")
check("unconfigured PROVIDER blocks its method", True,
      out.returncode != 0 and "vertex.gcp_project" in (out.stdout + out.stderr))
out = resolve("codex-custom", "codex")
check("unconfigured METHOD is refused", True,
      out.returncode != 0 and "not configured" in (out.stdout + out.stderr))

# An api-key method declares NO settings - its only requirement is the provider
# secret. The gate used to check settings[] alone, so these two resolved cleanly
# with no key stored and failed inside the pane instead. Both CLIs, because each
# sits on its own provider and they regressed independently.
for method_id, cli, secret in [("codex-api-key", "codex", "OPENAI_API_KEY"),
                               ("claude-api-key", "claude", "ANTHROPIC_API_KEY")]:
    out = resolve(method_id, cli)
    combined = out.stdout + out.stderr
    check(f"{method_id} without a key is refused", True, out.returncode != 0)
    check(f"{method_id} names the missing secret", True, secret in combined)
    check(f"{method_id} points at --provider, not the method", True,
          "--provider" in combined)

print("--- provider: shared attributes are stored once, on the provider ---")
result = setup_auth(["--provider", "vertex"], f"{GCP_PROJECT}\n{GCP_REGION}\n")
combined = result.stdout + result.stderr
check("configure provider exits 0", 0, result.returncode)
check("it lists the methods that use it", True, "claude-vertex" in combined)

settings_path = sandbox / ".agentmux" / "auth.json"
check("settings written", True, settings_path.is_file())
check("settings mode 0600", "600", f"{settings_path.stat().st_mode & 0o777:o}")
settings = json.loads(settings_path.read_text())
check("project stored under the provider", GCP_PROJECT,
      settings["providers"]["vertex"]["gcp_project"])
check("region stored under the provider", GCP_REGION,
      settings["providers"]["vertex"]["gcp_region"])
check("and nowhere else", ["gcp_project", "gcp_region"],
      sorted(settings["providers"]["vertex"]))

print("--- a provider secret never lands in the settings file ---")
result = setup_auth(["--provider", "custom"], f"{FAKE_TOKEN}\n{FAKE_TOKEN}\n")
combined = result.stdout + result.stderr
check("configure provider exits 0", 0, result.returncode)
check("token is never echoed", False, FAKE_TOKEN in combined)
env_path = sandbox / ".agentmux" / "env"
check("env mode 0600", "600", f"{env_path.stat().st_mode & 0o777:o}")
check("no secret in the settings file", False, FAKE_TOKEN in settings_path.read_text())
check("the secret is in env, not settings", True, FAKE_TOKEN in env_path.read_text())

# The positive half of the gate check above: with a key stored, a method whose ONLY
# requirement is that secret resolves cleanly. Its provider is configured here rather
# than earlier so the refusal above is tested against a genuinely empty store.
setup_auth(["--provider", "openai"], f"{FAKE_TOKEN}\n{FAKE_TOKEN}\n")
out = resolve("codex-api-key", "codex")
check("codex-api-key resolves once its key is stored", 0, out.returncode)
check("and the key itself never appears in the resolution", False,
      FAKE_TOKEN in (out.stdout + out.stderr))

print("--- method-specific attributes are namespaced by method id ---")
setup_auth(["codex-custom"], f"{GATEWAY}\n{CODEX_MODEL}\n")
settings = json.loads(settings_path.read_text())
check("model stored per method", CODEX_MODEL,
      settings["methods"]["codex-custom"]["model"])
check("gateway stored per method", GATEWAY,
      settings["methods"]["codex-custom"]["gateway_base_url"])
check("provider settings not duplicated onto it", ["gateway_base_url", "model"],
      sorted(settings["methods"]["codex-custom"]))

print("--- the generated codex profile ---")
profile_path = sandbox / ".codex" / "codex-custom.config.toml"
check("profile written", True, profile_path.is_file())
profile = profile_path.read_text()
for line in profile.splitlines():
    if line.strip() and not line.startswith("#"):
        print(f"        {line}")
check("no secret in the profile", False, FAKE_TOKEN in profile)
check("names the env var instead", True, 'env_key = "CODEX_CUSTOM_API_KEY"' in profile)
check("wire_api is responses", True, 'wire_api = "responses"' in profile)
check("base_url is the gateway", True, f'base_url = "{GATEWAY}"' in profile)
check("model is the configured one", True, f'model = "{CODEX_MODEL}"' in profile)

print("--- local profile syntax does not establish native client acceptance ---")
result = setup_auth(["--verify", "codex-custom"])
combined = result.stdout + result.stderr
check("verify reports unqualified live access", 2, result.returncode)
check("TOML syntax checked without starting Codex", True, "profile TOML syntax is valid" in combined)
check("native client acceptance remains unknown", True, "UNKNOWN" in combined)
check("verify reports presence only", True, "present (value not shown)" in combined)
check("verify never prints the secret", False, FAKE_TOKEN in combined)

print("--- agentmux resolves each method ---")
out = resolve("codex-custom", "codex")
check("codex-custom resolves", 0, out.returncode)
flags, exports = split_resolution(out.stdout)
check("emits its own codex profile flag", True, "--profile codex-custom" in flags)
# The model is passed EXPLICITLY as well as living in the profile, so a model switched
# in Settings takes effect on the next spawn without the TOML being regenerated.
check("passes the configured model as a flag", True, f"-m {CODEX_MODEL}" in flags)
check("no secret in the resolution", False, FAKE_TOKEN in out.stdout)

out = resolve("claude-vertex", "claude")
check("claude-vertex resolves once its provider is set", 0, out.returncode)
flags, exports = split_resolution(out.stdout)
print(f"        exports: {exports}")
check("CLAUDE_CODE_USE_VERTEX exported", True, "export CLAUDE_CODE_USE_VERTEX=1" in exports)
# Both of these come from the PROVIDER, which is the whole point of the two-level split.
check("project id from the PROVIDER", True,
      f"export ANTHROPIC_VERTEX_PROJECT_ID={GCP_PROJECT}" in exports)
check("region from the PROVIDER", True, f"export CLOUD_ML_REGION={GCP_REGION}" in exports)
check("claude gets no --profile flag", "", flags)
check("no secret in the exports", False, FAKE_TOKEN in exports)

print("--- and rejects what it should ---")
for label, method_id, cli, expect in [
    ("unknown method", "nope-nope", "codex", "unknown --auth method"),
    ("cli mismatch", "codex-custom", "claude", "is for --cli codex"),
]:
    out = resolve(method_id, cli)
    combined = out.stdout + out.stderr
    check(label, True, out.returncode != 0 and expect in combined)

shutil.rmtree(sandbox, ignore_errors=True)
check("sandbox removed", False, sandbox.exists())

# ──────────────────────────── the HTTP surface ────────────────────────────

print("--- /api/auth groups by provider and leaks nothing ---")
code, data = get("api/auth")
check("GET /api/auth", 200, code)
providers = {p["id"]: p for p in data["providers"]}
check("methods nest under their provider", ["claude-vertex"],
      sorted(m["id"] for m in providers["vertex"]["methods"]))
check("provider settings are declared on the provider",
      ["gcp_project", "gcp_region"],
      [s["key"] for s in providers["vertex"]["settings"]])
check("and not repeated on its methods", [[]],
      [sorted(s["key"] for s in m["settings"])
       for m in providers["vertex"]["methods"]])
check("a method declares only its own settings",
      [["gateway_base_url", "model"]],
      [sorted(s["key"] for s in m["settings"])
       for m in providers["custom"]["methods"]])
blob = json.dumps(data)
check("no secret-shaped value anywhere in the payload", False,
      bool(re.search(r"(sk-[A-Za-z0-9]{8}|ABSK[A-Za-z0-9+/=]{8}|xai-[A-Za-z0-9]{8})", blob)))
secret_keys = set()
for p in data["providers"]:
    for s in p["secrets"]:
        secret_keys |= set(s)
check("secrets carry only name + set", {"name", "set"}, secret_keys)
check("env file reported by mode only", {"path", "mode", "count"},
      set(data["files"]["env"]))

print("--- /api/auth/select keeps the standard guards ---")
# HTTP writes belong to the selected server home, not the setup_auth subprocess
# sandbox. Restore that fixture only; never restore an unrelated default-home file.
LIVE_AUTH = Path(_fixture_home) / "auth.json"
_live_before = LIVE_AUTH.read_bytes() if LIVE_AUTH.exists() else None

def _restore_live_auth(announce=True):
    if _live_before is None:
        LIVE_AUTH.unlink(missing_ok=True)
    elif not LIVE_AUTH.exists() or LIVE_AUTH.read_bytes() != _live_before:
        previous = os.umask(0o077)
        try:
            handle, temporary = tempfile.mkstemp(dir=str(LIVE_AUTH.parent),
                                                 prefix="." + LIVE_AUTH.name)
            with os.fdopen(handle, "wb") as fh:
                fh.write(_live_before)
            os.chmod(temporary, 0o600)
            os.replace(temporary, LIVE_AUTH)
        finally:
            os.umask(previous)
        if announce:
            print("        selected auth.json restored to its pre-test bytes")

# Called explicitly before the summary, because run_tests.sh parses the LAST line for
# "passed N, failed M" - anything printed after it makes the suite read as a failure.
# atexit keeps it correct on the exception path, silently and idempotently.
atexit.register(_restore_live_auth, announce=False)

check("GET is 405", 405, http_status("api/auth/select"))
check("no JSON content type -> 415", 415, post("api/auth/select", {"id": "x"}, ctype=None)[0])
check("cross-origin -> 403", 403,
      post("api/auth/select", {"id": "x"}, origin="https://evil.example")[0])
check("unknown field -> 400", 400, post("api/auth/select", {"wat": 1})[0])
check("bad id shape -> 400", 400, post("api/auth/select", {"id": "../../etc/passwd"})[0])
check("unknown id -> 404", 404, post("api/auth/select", {"id": "no-such-method"})[0])
# Find an unconfigured method at RUNTIME rather than naming one.
#
# This used to hardcode a method id, which was unconfigured on this machine until it
# was configured — and then the test failed for the right reason about the wrong thing.
# A test that encodes today's environment as a fact expires silently.
unconfigured = next((m["id"] for group in data["providers"] for m in group["methods"]
                     if not m["configured"]), None)
if unconfigured is None:
    print("        every method is configured; skipping the 409 checks")
else:
    code, payload = post("api/auth/select", {"id": unconfigured})
    check(f"unconfigured ({unconfigured}) -> 409", 409, code)
    check("409 says how to fix it", True,
          "setup_auth.py" in (payload or {}).get("error", ""))

configured = next((m["id"] for group in data["providers"] for m in group["methods"]
                   if m["configured"]), None)
if configured is None:
    print("        no configured method; skipping the 200 check")
else:
    expected_cli = next(m["cli"] for group in data["providers"] for m in group["methods"]
                        if m["id"] == configured)
    code, payload = post("api/auth/select", {"id": configured})
    check(f"configured ({configured}) -> 200", 200, code)
    check("and reports which CLI changed", expected_cli, (payload or {}).get("cli"))

print("--- /api/auth/setting: the model is switchable, safely ---")
check("GET is 405", 405, http_status("api/auth/setting"))
check("no JSON content type -> 415", 415,
      post("api/auth/setting", {"method": "codex-custom", "key": "model",
                                "value": "x"}, ctype=None)[0])
check("cross-origin -> 403", 403,
      post("api/auth/setting", {"method": "codex-custom", "key": "model", "value": "x"},
           origin="https://evil.example")[0])

for label, body, want in [
    ("unknown method -> 404", {"method": "no-such-method", "key": "model", "value": "x"}, 404),
    ("undeclared key -> 400", {"method": "codex-custom", "key": "nope", "value": "x"}, 400),
    ("a provider key is not a method key",
     {"method": "claude-vertex", "key": "gcp_region", "value": "us-central1"}, 400),
    ("shell metacharacters rejected",
     {"method": "codex-custom", "key": "model", "value": "a b; rm -rf /"}, 400),
    ("empty value -> 400", {"method": "codex-custom", "key": "model", "value": "   "}, 400),
    ("extra field -> 400",
     {"method": "codex-custom", "key": "model", "value": "x", "wat": 1}, 400),
    ("bad method id shape -> 400",
     {"method": "../../etc", "key": "model", "value": "x"}, 400),
    ("non-string value -> 400", {"method": "codex-custom", "key": "model", "value": 7}, 400),
    ("gateway URL must be a URL",
     {"method": "codex-custom", "key": "gateway_base_url", "value": "not a url"}, 400),
]:
    code, payload = post("api/auth/setting", body)
    check(label, want, code)

# Round-trip a real switch through the API, then put it back. The value is arbitrary
# now that there is no verified-id list to choose from - what is under test is that a
# write reaches the store and reads back, not that any particular model exists.


def stored_model(payload):
    return next((s["value"] for group in payload["providers"] for m in group["methods"]
                 if m["id"] == "codex-custom" for s in m["settings"]
                 if s["key"] == "model"), None)


before = stored_model(data)
target = "switched-model-v2" if before != "switched-model-v2" else "switched-model-v3"
code, payload = post("api/auth/setting",
                     {"method": "codex-custom", "key": "model", "value": target})
check("switching the model -> 200", 200, code)
check("it says when it applies", True, "spawned" in (payload or {}).get("note", ""))
check("the new model is persisted", target, stored_model(get("api/auth")[1]))
if before:
    post("api/auth/setting", {"method": "codex-custom", "key": "model", "value": before})
    check("and restored", before, stored_model(get("api/auth")[1]))
else:
    # Nothing was configured for this method before the run, so there is no prior value
    # to put back - _restore_live_auth below removes the entry wholesale. Announced
    # rather than silently absent: a check that vanishes from the count looks identical
    # to one that passed.
    print("        no prior model value to restore; skipping the restore check")

_restore_live_auth()

print()
print(f"passed {passed}, failed {failed}")
sys.exit(1 if failed else 0)
