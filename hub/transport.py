"""Terminal transports. See docs/TRANSPORT.md.

A Transport moves bytes to and from a terminal and reports what state the terminal
itself is in (normal, copy-mode, dead). It knows nothing about any agent CLI - that is
profiles.py - and nothing about messages - that is deliver.py.

Only TmuxTransport exists. The interface is what another backend (Orca, ConPTY, a
headless SDK agent) would implement.
"""
from __future__ import annotations

import os
import re
import subprocess
import uuid
from abc import ABC, abstractmethod

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][A-Za-z0-9]|\x1b[=>]")

# Abstract key vocabulary (TRANSPORT.md 4). A transport maps each to its own name;
# anything outside this set is refused rather than typed as literal text, which is
# what tmux does with an unknown key name (it typed "Dowm" once).
KEYS = {"Enter", "Escape", "Tab", "BTab", "Space", "BSpace", "Up", "Down", "Left", "Right",
        "Home", "End", "PageUp", "PageDown", "C-c", "C-u", "C-d"}


def strip_ansi(s: str) -> str:
    return ANSI.sub("", s)


class Transport(ABC):
    name = "abstract"

    @abstractmethod
    def list(self) -> list[str]: ...
    @abstractmethod
    def alive(self, session: str) -> bool: ...
    @abstractmethod
    def handle(self, session: str) -> tuple[str, int] | None: ...     # (pane id, pane pid)
    @abstractmethod
    def mode(self, handle: str) -> str: ...                            # normal | copy | dead
    @abstractmethod
    def capture(self, handle: str) -> str: ...                         # visible screen, ANSI stripped
    @abstractmethod
    def send_text(self, handle: str, text: str) -> None: ...          # literal, no submit
    @abstractmethod
    def send_buffer(self, handle: str, text: str, *, before_paste=None) -> None: ...
    @abstractmethod
    def send_key(self, handle: str, key: str) -> None: ...
    @abstractmethod
    def leave_mode(self, handle: str) -> None: ...
    @abstractmethod
    def output_mark(self, session: str) -> int | None: ...             # monotonic output counter
    @abstractmethod
    def kill(self, session: str, *, expected=None) -> bool: ...

    def termination_target(self, session: str) -> str:
        raise TmuxError("termination identity unavailable")

    def require_buffer_cleanup(self) -> None:
        """Refuse final cleanup if this transport retains an input buffer."""


class TmuxError(RuntimeError):
    pass


class TmuxBufferCleanupFailure(TmuxError):
    """Retain the original allocation without exposing its text in diagnostics."""
    def __init__(self, transport, socket, name):
        super().__init__("tmux buffer cleanup incomplete")
        self.transport, self.socket, self.name = transport, socket, name
        self.state = "active"
        self.operation_failure = self.cleanup_failure = self.retry_failure = None

    def retry_cleanup(self):
        if self.state == "closed":
            return
        if self.state != "cleanup_uncertain":
            raise TmuxError("tmux buffer operation remains active")
        try:
            self.transport._remove_buffer(self)
        except BaseException as failure:
            self.retry_failure = failure
            raise self from failure


class TmuxTransport(Transport):
    name = "tmux"

    def __init__(self, socket: str | None = None, logdir: str | None = None, *, native_core=None):
        if native_core is not None:
            from hub.native_core_context import NativeCoreContext
            if type(native_core) is not NativeCoreContext:
                raise TmuxError('native core context required')
        self.native_core = native_core
        self.socket = socket or os.environ.get("AGENTMUX_SOCKET", "agentmux")
        self.logdir = logdir
        self._buffers: dict[str, TmuxBufferCleanupFailure] = {}

    def _tm(self, *args, input_=None, check=True) -> str:
        if self.native_core is not None:
            r = self.native_core.tmux(self.socket, args, input_=input_)
        else:
            r = subprocess.run(["tmux", "-L", self.socket, *args], input=input_, capture_output=True,
                               stdin=None if input_ is not None else subprocess.DEVNULL, timeout=10)
        if check and r.returncode != 0:
            raise TmuxError(r.stderr.decode(errors="replace").strip() or f"tmux {args[0]} failed")
        return r.stdout.decode(errors="replace")

    def list(self):
        try:
            out = self._tm("list-sessions", "-F", "#{session_name}")
        except TmuxError:
            return []
        return [l for l in out.splitlines() if l]

    def alive(self, session):
        if self.native_core is not None:
            r = self.native_core.tmux(self.socket, ('has-session', '-t', f'={session}'))
        else:
            r = subprocess.run(["tmux", "-L", self.socket, "has-session", "-t", f"={session}"],
                               capture_output=True, stdin=subprocess.DEVNULL, timeout=10)
        if r.returncode != 0:
            return False
        h = self.handle(session)
        return bool(h) and self.mode(h[0]) != "dead"

    def handle(self, session):
        try:
            out = self._tm("list-panes", "-t", f"={session}", "-F", "#{pane_id} #{pane_pid}")
        except TmuxError:
            return None
        first = out.split("\n", 1)[0].split()
        return (first[0], int(first[1])) if len(first) == 2 else None

    def mode(self, handle):
        try:
            out = self._tm("display-message", "-p", "-t", handle, "#{pane_dead} #{pane_in_mode}").split()
        except TmuxError:
            return "dead"
        if not out or out[0] == "1":
            return "dead"
        return "copy" if len(out) > 1 and out[1] == "1" else "normal"

    def capture(self, handle):
        return strip_ansi(self._tm("capture-pane", "-p", "-J", "-t", handle))

    def send_text(self, handle, text):
        if "\n" in text or "\r" in text:
            raise ValueError("send_text is single-line; use send_buffer for multi-line text")
        self._tm("send-keys", "-t", handle, "-l", "--", text)

    def send_buffer(self, handle, text, *, before_paste=None):
        # load-buffer from stdin: no argv size limit (D04: >16 KB became a bare Enter),
        # no shell parsing of ; or \ . paste-buffer -p wraps it in bracketed paste
        # only if the application asked for it. Reclaim only this allocation.
        name = f"hub-{os.getpid()}-{uuid.uuid4().hex}"
        allocation = TmuxBufferCleanupFailure(self, self.socket, name)
        self._buffers[name] = allocation
        try:
            self._tm("load-buffer", "-b", name, "-", input_=text.encode())
            if before_paste is not None:
                before_paste()
            self._tm("paste-buffer", "-p", "-b", name, "-t", handle)
        except BaseException as failure:
            try:
                self._remove_buffer(allocation)
            except BaseException as cleanup:
                allocation.state = "cleanup_uncertain"
                allocation.operation_failure, allocation.cleanup_failure = failure, cleanup
                raise allocation from BaseExceptionGroup("tmux buffer operation and cleanup failed", [failure, cleanup])
            raise
        try:
            self._remove_buffer(allocation)
        except BaseException as cleanup:
            allocation.state, allocation.cleanup_failure = "cleanup_uncertain", cleanup
            raise allocation from cleanup

    def _remove_buffer(self, allocation):
        # Reconcile an uncertain load reply as well as a confirmed allocation.
        if self._buffers.get(allocation.name) is not allocation or self.socket != allocation.socket:
            raise TmuxError("tmux buffer allocation owner changed")
        names = self._tm("list-buffers", "-F", "#{buffer_name}").splitlines()
        if self.socket != allocation.socket:
            raise TmuxError("tmux buffer allocation socket changed")
        if allocation.name in names:
            if self.socket != allocation.socket:
                raise TmuxError("tmux buffer allocation socket changed")
            self._tm("delete-buffer", "-b", allocation.name)
        allocation.state = "closed"
        del self._buffers[allocation.name]

    def require_buffer_cleanup(self):
        if self._buffers:
            raise next(iter(self._buffers.values()))

    def send_key(self, handle, key):
        if key not in KEYS and not re.fullmatch(r"[!-~]", key):
            raise ValueError(f"not an abstract key: {key!r}")
        self._tm("send-keys", "-t", handle, key)

    def leave_mode(self, handle):
        self._tm("send-keys", "-t", handle, "-X", "cancel", check=False)

    def output_mark(self, session):
        # The pipe-pane log grows exactly when the pane prints. This is the liveness
        # signal R-LIVE-1 requires - NOT #{session_activity}, which went hours stale
        # on panes that were demonstrably working and got them killed (C4).
        if not self.logdir:
            return None
        try:
            return os.stat(os.path.join(self.logdir, f"{session}.log")).st_size
        except OSError:
            return None

    def termination_target(self, session):
        raw = self._tm("list-panes", "-s", "-t", f"={session}", "-F",
                       "#{pid}|#{start_time}|#{session_id}|#{session_created}|#{pane_id}|#{pane_pid}")
        rows = raw.splitlines()
        pattern = r"[1-9][0-9]*\|[0-9]+\|\$[0-9]+\|[0-9]+\|%[0-9]+\|[1-9][0-9]*"
        if not rows or any(not re.fullmatch(pattern, row) for row in rows):
            raise TmuxError("termination identity unavailable")
        parts = [row.split("|") for row in rows]
        if len({tuple(row[:4]) for row in parts}) != 1 or len({row[4] for row in parts}) != len(rows):
            raise TmuxError("termination identity unavailable")
        return "\n".join(sorted(rows))

    def kill(self, session, *, expected=None):
        if expected is None or self.termination_target(session) != expected:
            raise TmuxError("termination target changed")
        server_pid, started, session_id, created, _, _ = expected.splitlines()[0].split("|")
        guard = (f"#{{&&:#{{==:#{{pid}},{server_pid}}},"
                 f"#{{&&:#{{==:#{{start_time}},{started}}},#{{==:#{{session_created}},{created}}}}}}}")
        pairs = [row.split("|")[4:] for row in expected.splitlines()]
        pattern = "^(" + "|".join(f"{pane}[|]{pid}" for pane, pid in pairs) + ")$"
        # Check every pane and the total count inside the same tmux command.
        # A sampled roster alone leaves a gap before termination.
        roster = "#{W:#{P:#{m/r:" + pattern + ",#{pane_id}|#{pane_pid}}}}"
        guard = "#{&&:" + guard + ",#{==:" + roster + "," + "1" * len(pairs) + "}}"
        result = self._tm("if-shell", "-F", "-t", session_id, guard,
                          f"kill-session -t {session_id} ; display-message -p agentmux-kill-confirmed",
                          "display-message -p agentmux-kill-refused")
        if result.strip() != "agentmux-kill-confirmed":
            raise TmuxError("termination unconfirmed")
        return True


class FakeTransport(Transport):
    """In-memory transport for offline tests. Screens are scripted per session."""
    name = "fake"

    def __init__(self):
        self.sessions: dict[str, dict] = {}
        self.sent: list[tuple[str, str, str]] = []   # (session, kind, payload)

    def add(self, session, screen="› ", mode="normal", pid=1000):
        self.sessions[session] = {"screen": screen, "mode": mode, "pid": pid, "out": 0, "on_submit": None}

    def _s(self, handle):
        return self.sessions[handle]

    def list(self):
        return sorted(self.sessions)

    def alive(self, session):
        return session in self.sessions and self.sessions[session]["mode"] != "dead"

    def handle(self, session):
        s = self.sessions.get(session)
        return (session, s["pid"]) if s else None

    def mode(self, handle):
        return self.sessions.get(handle, {"mode": "dead"})["mode"]

    def capture(self, handle):
        return self._s(handle)["screen"]

    def send_text(self, handle, text):
        self.sent.append((handle, "text", text))
        s = self._s(handle)
        if s["mode"] == "copy":
            return                                     # copy-mode swallows keys (D02)
        s["screen"] = s["screen"].rstrip("\n") + text

    def send_buffer(self, handle, text, *, before_paste=None):
        if before_paste is not None:
            before_paste()
        self.sent.append((handle, "buffer", text))
        self._s(handle)["screen"] += f"[Pasted Content {len(text)} chars]"

    def send_key(self, handle, key):
        self.sent.append((handle, "key", key))
        s = self._s(handle)
        if key == "Enter" and s["mode"] == "normal":
            cb = s.get("on_submit")
            s["screen"] = cb(s["screen"]) if cb else "working… (esc to interrupt)\n› "
            s["out"] += 1

    def leave_mode(self, handle):
        self.sent.append((handle, "key", "cancel-mode"))
        if self._s(handle)["mode"] == "copy":
            self._s(handle)["mode"] = "normal"

    def output_mark(self, session):
        s = self.sessions.get(session)
        return s["out"] if s else None

    def termination_target(self, session):
        if session not in self.sessions:
            raise TmuxError("termination identity unavailable")
        return f"{session}|{self.sessions[session]['pid']}|{id(self.sessions[session])}"

    def kill(self, session, *, expected=None):
        if expected is None or self.termination_target(session) != expected:
            raise TmuxError("termination target changed")
        del self.sessions[session]
        return True
