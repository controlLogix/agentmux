"""GitHub device sign-in and constrained creation through the local `gh` CLI.

`gh` owns credentials. This module exposes only the device code and selected
account fields, never raw command output or authentication diagnostics. A login
keeps its original process until it has been waited for; cancellation cannot
release the credential store while that process can still write it.

The legacy actor and confirmation fields describe user intent. They are not
authenticated platform authority. The calling owner must provide current scoped
authorization and durable reconciliation before using these external writes.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time

try:
    import pty
    import select
    HAVE_PTY = True
except ImportError:                       # Windows, or a Python built without it
    HAVE_PTY = False

LOGIN_TIMEOUT = 300.0
LOGIN_STOP_TIMEOUT = 5.0
LOGIN_JOIN_TIMEOUT = 6.0
DEVICE_URL = "https://github.com/login/device"
CODE_RE = re.compile(r"\b([A-Z0-9]{4}-[A-Z0-9]{4})\b")
# Repository creation takes a positional name. Keep its first character distinct
# from a command option; free text values below use the --option=value form.
REPO_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}\Z")
OWNER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\Z")
NWO_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}\Z")

# Asked for at login. `repo` covers private repositories, `workflow` lets a run be
# re-dispatched, `read:org` makes an org's repositories visible in the picker.
SCOPES = "repo,workflow,read:org,gist"
_CREDENTIAL_LOCK = threading.Lock()


class Invalid(ValueError):
    """Operator input the panel refuses. Maps to HTTP 400."""


class Unavailable(RuntimeError):
    """gh is missing, unauthenticated, or the host cannot run the flow. HTTP 503."""


class OutcomeUnknown(Unavailable):
    """A write may have reached GitHub; the owner must reconcile before retrying."""

    outcome_unknown = True


def install_command():
    return "brew install gh" if sys.platform == "darwin" else "sudo apt install gh"


def gh_path():
    return shutil.which("gh") or shutil.which("gh.exe")


def is_windows_gh(binary):
    return bool(binary) and os.path.basename(binary).lower() == "gh.exe"


WINDOWS_LOGIN = ("Sign in on the Windows side in PowerShell or Command Prompt: "
                 f"gh auth login --web --scopes {SCOPES}")


def _run(args, timeout=20, stdin_text=None, *, changes_remote=False):
    """Run gh and return stdout. stderr is DISCARDED, deliberately.

    gh writes authentication diagnostics to stderr, and those can name a token's
    host, its source file and occasionally a prefix. None of that should reach a
    browser, so failures are reported as the exit status and the verb that failed.
    """
    binary = gh_path()
    if not binary:
        raise Unavailable("gh is not installed or not on PATH.")
    try:
        done = subprocess.run(
            [binary, *args], capture_output=True, text=True, timeout=timeout,
            # Explicit, because the default is the system codepage: a commit
            # subject or an issue title with a non-ASCII character then raises
            # UnicodeDecodeError out of a reader thread, which surfaces as a
            # server error with no connection to what was actually read.
            encoding="utf-8", errors="replace",
            **({"input": stdin_text} if stdin_text is not None
               else {"stdin": subprocess.DEVNULL}),
            env={**os.environ, "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1",
                 "GH_HOST": "github.com", "CLICOLOR": "0", "NO_COLOR": "1"})
    except subprocess.SubprocessError:
        if changes_remote:
            raise OutcomeUnknown(
                "GitHub did not confirm the write outcome. Reconcile the target before retrying.") from None
        raise Unavailable(f"gh {args[0]} did not complete.") from None
    except OSError:
        raise Unavailable(f"gh {args[0]} did not complete.") from None
    if done.returncode:
        if changes_remote:
            raise OutcomeUnknown(
                "GitHub did not confirm the write outcome. Reconcile the target before retrying.")
        raise Unavailable(f"gh {' '.join(args[:2])} failed (exit {done.returncode}).")
    return done.stdout


def _result_url(output, repo, *, issue=False):
    """Accept only a GitHub URL for the requested repository and action."""
    suffix = r"/issues/[1-9][0-9]*" if issue else ""
    for line in output.splitlines():
        value = line.strip()
        if len(value) > 200:
            continue
        match = re.fullmatch(r"https://github\.com/([^/]+/[^/]+)" + suffix, value)
        if not match or not NWO_RE.fullmatch(match.group(1)):
            continue
        found = match.group(1)
        if found.rsplit("/", 1)[1] in (".", ".."):
            continue
        if (found.casefold() == repo.casefold() if "/" in repo
                else found.rsplit("/", 1)[1].casefold() == repo.casefold()):
            return value
    raise OutcomeUnknown(
        "GitHub did not return the expected target. Reconcile the target before retrying.")


def account():
    """Who gh is signed in as, and with what. Never returns or logs a token."""
    binary = gh_path()
    windows = is_windows_gh(binary)
    state = {"cli": bool(binary), "authenticated": False, "login": None,
             "name": None, "url": None, "scopes": [], "rate": None,
             "can_login": HAVE_PTY and bool(binary) and not windows, "hostname": "github.com",
             "scopes_requested": SCOPES.split(",")}
    if not state["cli"]:
        state["message"] = "gh is not installed. Install it, then sign in from here."
        state["command"] = install_command()
        return state
    if windows:
        state["message"] = WINDOWS_LOGIN
        state["command"] = f"gh auth login --web --scopes {SCOPES}"
    try:
        # --include prints the response headers, and X-Oauth-Scopes is the only
        # honest source for what this token may actually do. Asking `gh auth status`
        # instead would mean parsing human-facing output off stderr.
        raw = _run(["api", "--hostname", "github.com", "--include", "user"], timeout=15)
    except Unavailable as err:
        state["message"] = ("gh is installed but not signed in. " + str(err)
                            if "failed" in str(err) else str(err))
        if windows:
            state["message"] += " " + WINDOWS_LOGIN
        state["command"] = f"gh auth login --web --scopes {SCOPES}"
        return state
    head, _, body = raw.partition("\n\n") if "\n\n" in raw else raw.partition("\r\n\r\n")
    for line in head.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "x-oauth-scopes":
            state["scopes"] = [s.strip() for s in value.split(",")
                               if re.fullmatch(r"[A-Za-z][A-Za-z0-9:_-]{0,79}", s.strip())][:50]
    try:
        user = json.loads(body)
        if (not isinstance(user, dict) or not isinstance(user.get("login"), str)
                or not OWNER_RE.fullmatch(user["login"])):
            raise ValueError("invalid user")
    except (ValueError, TypeError):
        state["message"] = "gh returned an unreadable user record."
        return state
    login = user["login"]
    state.update(authenticated=True,
                 login=login,
                 name=str(user.get("name") or "")[:120] or None,
                 url=f"https://github.com/{login}")
    try:
        rate = json.loads(_run(["api", "--hostname", "github.com", "rate_limit"], timeout=10))["resources"]["core"]
        state["rate"] = {"remaining": int(rate["remaining"]), "limit": int(rate["limit"]),
                         "reset": int(rate["reset"])}
    except (Unavailable, ValueError, KeyError, TypeError):
        pass
    missing = [s for s in ("repo",) if s not in state["scopes"]]
    if missing and state["scopes"]:
        state["message"] = (f"Signed in, but the token is missing the {', '.join(missing)} "
                            f"scope, so creating repositories will be refused. "
                            f"Sign in again to widen it.")
        if windows:
            state["message"] += " " + WINDOWS_LOGIN
    return state


class Login:
    """One device-flow sign-in, driven over a PTY, readable while it runs.

    At most one at a time per server: two concurrent flows would both be writing
    gh's credential file, and the operator would have no way to tell which code on
    screen belongs to which.
    """

    def __init__(self, journal=None):
        self.journal = journal
        self.lock = threading.Lock()
        self.thread = None
        self._process = None
        self._owns_credentials = False
        self.state = "idle"        # idle | starting | waiting | finishing | done | error
        self.code = None
        self.url = DEVICE_URL
        self.error = None
        self.started_at = None
        self.actor = None
        self._cancel = threading.Event()

    def available(self):
        binary = gh_path()
        return HAVE_PTY and bool(binary) and not is_windows_gh(binary)

    def start(self, actor):
        actor = str(actor or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", actor):
            raise Invalid("an operator name is required before signing in")
        binary = gh_path()
        if not binary:
            raise Unavailable("gh is not installed or not on PATH.")
        if is_windows_gh(binary):
            raise Unavailable(WINDOWS_LOGIN)
        if not HAVE_PTY:
            raise Unavailable(
                "This host cannot run the interactive flow. Run it in a terminal: "
                f"gh auth login --web --scopes {SCOPES}")
        with self.lock:
            if self._process is not None or (self.thread and self.thread.is_alive()):
                raise Invalid("a sign-in is already in progress")
            if self.thread:
                self.thread.join()
            if not _CREDENTIAL_LOCK.acquire(blocking=False):
                raise Invalid("a GitHub sign-in or sign-out is already in progress")
            self._owns_credentials = True
            self._cancel = threading.Event()
            self.state = "starting"
            self.code = None
            self.error = None
            self.actor = actor
            self.started_at = time.time()
            self.thread = threading.Thread(target=self._run, args=(self._cancel, binary, actor),
                                           name="gh-login", daemon=True)
            try:
                self.thread.start()
            except RuntimeError:
                self.thread = None
                self.state = "error"
                self.error = "The sign-in worker could not start."
                self._release_credentials()
                raise Unavailable(self.error) from None
        return self.snapshot()

    def cancel(self):
        with self.lock:
            thread = self.thread
            process = self._process
            if self._process is not None or (thread and thread.is_alive()):
                self._cancel.set()
                self.state = "finishing"
                self.code = None
                self.error = "Stopping sign-in."
        if thread and thread is not threading.current_thread():
            # Keep the original worker and process if cleanup takes longer.
            thread.join(timeout=LOGIN_JOIN_TIMEOUT)
        if process is not None and (thread is None or not thread.is_alive()):
            # A previous wait can fail after the child has stopped. Recheck only
            # that retained handle; a zero timeout cannot wait on a live child.
            try:
                process.wait(timeout=0)
            except (OSError, subprocess.SubprocessError):
                with self.lock:
                    if self._process is process:
                        self.error = "Sign-in cleanup is incomplete. Cancel again after the original process stops."
            else:
                with self.lock:
                    if self._process is process and self.thread is thread:
                        self._process = None
                        self._release_credentials()
                        self.state = "idle"
                        self.error = "Sign-in stopped. Check the current GitHub account before trying again."
        return self.snapshot()

    def _release_credentials(self):
        if self._owns_credentials:
            self._owns_credentials = False
            _CREDENTIAL_LOCK.release()

    def _run(self, cancel, binary, actor):
        primary = secondary = process = None
        code = None
        failure = None
        joined = True
        try:
            if cancel.is_set():
                return
            primary, secondary = pty.openpty()
            if cancel.is_set():
                return
            process = subprocess.Popen(
                [binary, "auth", "login", "--hostname", "github.com", "--web",
                 "--git-protocol", "https", "--scopes", SCOPES],
                stdin=secondary, stdout=secondary, stderr=secondary,
                close_fds=True, start_new_session=True,
                env={**os.environ, "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1",
                     "GH_HOST": "github.com", "CLICOLOR": "0", "BROWSER": "true"})
            with self.lock:
                self._process = process
            os.close(secondary)
            secondary = None
            buffer = ""
            pressed = False
            deadline = time.monotonic() + LOGIN_TIMEOUT
            while not cancel.is_set() and time.monotonic() < deadline:
                ready, _, _ = select.select([primary], [], [], 0.5)
                if ready:
                    try:
                        chunk = os.read(primary, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    buffer = (buffer + chunk.decode("utf-8", "replace"))[-8192:]
                    found = CODE_RE.search(buffer)
                    with self.lock:
                        if found and not self.code and not cancel.is_set():
                            self.code = found.group(1)
                            self.state = "waiting"
                    if found and not pressed and not cancel.is_set():
                        # gh waits on Enter before it opens a browser. BROWSER=true
                        # above makes that a no-op, so the operator opens the URL
                        # themselves from the page - on the machine they are sitting
                        # at, which is not necessarily this one.
                        pressed = True
                        try:
                            os.write(primary, b"\n")
                        except OSError:
                            pass
                if process.poll() is not None:
                    break
            if process.poll() is None:
                with self.lock:
                    self.state = "finishing"
                if not cancel.is_set():
                    failure = "Sign-in timed out before GitHub confirmed the code."
        except (OSError, ValueError, subprocess.SubprocessError):
            failure = "GitHub sign-in could not complete."
        finally:
            if process is not None:
                try:
                    if process.poll() is None:
                        try:
                            process.terminate()
                        except ProcessLookupError:
                            pass
                    try:
                        code = process.wait(timeout=LOGIN_STOP_TIMEOUT)
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                        # Do not abandon the original wait after sending kill.
                        # cancel() returns a bounded response while this worker
                        # still owns any process whose exit has not arrived.
                        code = process.wait()
                except (OSError, subprocess.SubprocessError):
                    joined = False
                    failure = "Sign-in cleanup is incomplete. Another sign-in is blocked."
            for descriptor in (secondary, primary):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            with self.lock:
                self.code = None
                if not joined:
                    self.state = "finishing"
                    self.error = failure
                else:
                    self._process = None
                    self._release_credentials()
                    if cancel.is_set():
                        self.state = "idle"
                        self.error = "Sign-in stopped. Check the current GitHub account before trying again."
                    elif code == 0:
                        self.state = "done"
                        self.error = None
                    else:
                        self.state = "error"
                        self.error = failure or ("GitHub did not complete the sign-in. "
                                                 "Check the code and try again.")
            outcome = ("sign-in outcome unknown" if not joined or (cancel.is_set() and code == 0)
                       else "sign-in cancelled" if cancel.is_set()
                       else "signed in" if code == 0 else "sign-in failed")
            self._record(outcome, actor)

    def _record(self, outcome, actor):
        if not self.journal:
            return
        try:
            self.journal({"kind": "github", "outcome": outcome, "actor": actor,
                          "at": time.time()})
        except Exception:
            pass

    def snapshot(self):
        with self.lock:
            return {"state": self.state, "code": self.code, "url": self.url,
                    "error": self.error, "started_at": self.started_at,
                    "available": self.available(),
                    "command": f"gh auth login --web --scopes {SCOPES}"}


def logout(actor, journal=None):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(actor or "")):
        raise Invalid("an operator name is required")
    if not _CREDENTIAL_LOCK.acquire(blocking=False):
        raise Invalid("a GitHub sign-in or sign-out is already in progress")
    try:
        # --hostname is required or gh prompts, and a prompt on a pipe hangs.
        _run(["auth", "logout", "--hostname", "github.com"], timeout=20)
    finally:
        _CREDENTIAL_LOCK.release()
    if journal:
        try:
            journal({"kind": "github", "outcome": "signed out", "actor": actor,
                     "at": time.time()})
        except Exception:
            pass
    return account()


# -- write actions ----------------------------------------------------------

def create_repo(body, journal=None):
    """`gh repo create`. The argument vector is built here, never supplied."""
    if not isinstance(body, dict):
        raise Invalid("body must be a JSON object")
    unknown = body.keys() - {"name", "owner", "visibility", "description", "actor",
                             "confirm", "gitignore", "license"}
    if unknown:
        raise Invalid(f"unknown fields: {', '.join(sorted(unknown))}")
    actor = str(body.get("actor") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", actor):
        raise Invalid("an operator name is required")
    if body.get("confirm") is not True:
        raise Invalid("creating a repository requires an explicit confirmation")
    name = str(body.get("name") or "").strip()
    if not REPO_NAME_RE.match(name):
        raise Invalid("repository name may use letters, digits, dot, dash and underscore")
    owner = str(body.get("owner") or "").strip()
    if owner and not OWNER_RE.match(owner):
        raise Invalid("owner must be a GitHub user or organisation name")
    visibility = str(body.get("visibility") or "private")
    if visibility not in ("private", "public", "internal"):
        raise Invalid("visibility must be private, public or internal")
    description = str(body.get("description") or "").strip()[:350]
    if any(ord(c) < 0x20 for c in description):
        raise Invalid("description contains control characters")

    target = f"{owner}/{name}" if owner else name
    args = ["repo", "create", target, f"--{visibility}"]
    if description:
        args += [f"--description={description}"]
    gitignore = str(body.get("gitignore") or "").strip()
    if gitignore:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+#.-]{0,39}", gitignore):
            raise Invalid("invalid .gitignore template name")
        args += ["--gitignore", gitignore]
    licence = str(body.get("license") or "").strip()
    if licence:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,39}", licence):
            raise Invalid("invalid licence template name")
        args += ["--license", licence]
    out = _run(args, timeout=45, changes_remote=True).strip()
    url = _result_url(out, target)
    if journal:
        try:
            journal({"kind": "github", "outcome": "repository created", "actor": actor,
                     "repo": target, "visibility": visibility, "at": time.time()})
        except Exception:
            pass
    return {"ok": True, "repo": target, "url": url[:200],
            "detail": f"Created {target} ({visibility})."}


def create_issue(body, journal=None):
    """`gh issue create` against an existing repository."""
    if not isinstance(body, dict):
        raise Invalid("body must be a JSON object")
    unknown = body.keys() - {"repo", "title", "body", "labels", "actor", "confirm"}
    if unknown:
        raise Invalid(f"unknown fields: {', '.join(sorted(unknown))}")
    actor = str(body.get("actor") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", actor):
        raise Invalid("an operator name is required")
    if body.get("confirm") is not True:
        raise Invalid("opening an issue requires an explicit confirmation")
    repo = str(body.get("repo") or "").strip()
    if not NWO_RE.match(repo) or repo.rsplit("/", 1)[1] in (".", ".."):
        raise Invalid("repository must be given as owner/name")
    title = str(body.get("title") or "").strip()
    if not 1 <= len(title) <= 250 or any(ord(c) < 0x20 for c in title):
        raise Invalid("a title of 1 to 250 printable characters is required")
    text = str(body.get("body") or "")[:8000]
    labels = body.get("labels") or []
    if not isinstance(labels, list) or len(labels) > 10:
        raise Invalid("at most 10 labels")
    args = ["issue", "create", "--repo", f"github.com/{repo}", f"--title={title}",
            "--body-file", "-"]
    # Keep bodies out of argv, including an explicit empty body. Omitting it
    # would let gh start an editor or prompt instead of using the requested data.
    for label in labels:
        if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9 :._-]{1,50}", label):
            raise Invalid("a label may use letters, digits, space, colon, dot, dash, underscore")
        args += [f"--label={label}"]
    out = _run(args, timeout=45, stdin_text=text, changes_remote=True).strip()
    url = _result_url(out, repo, issue=True)
    if journal:
        try:
            journal({"kind": "github", "outcome": "issue opened", "actor": actor,
                     "repo": repo, "title": title, "at": time.time()})
        except Exception:
            pass
    return {"ok": True, "repo": repo, "url": url[:200],
            "detail": f"Opened an issue on {repo}."}
