"""Explicit installed-hook routing; legacy transports never supply defaults."""
from dataclasses import dataclass
import json
import os
import subprocess
import sys
import termios
import time

from hub.profile_context import RegisteredProfileContext
from hub.client_launch_coordinator import StartupResult, human_summary, startup, result as startup_result


class OptionsError(ValueError):
    pass


@dataclass(frozen=True)
class Options:
    selection: str | None
    managed_worker: bool
    output: str
    repository_root: str | None = None


def parse_options(arguments, *, mcp=False):
    selection, worker, output, repository_root = None, False, "human", None
    seen = set()
    index = 0
    while index < len(arguments):
        key = arguments[index]
        if key in seen or key not in ("--enrolled", "--selection", "--repository-root", "--managed-worker", "--output"):
            raise OptionsError("Invalid client startup options.")
        seen.add(key)
        if key in ("--selection", "--repository-root", "--output"):
            index += 1
            if index >= len(arguments) or not arguments[index] or arguments[index].startswith("--"):
                raise OptionsError("Client startup option requires a value.")
            if key == "--selection":
                selection = arguments[index]
            elif key == '--repository-root':
                repository_root = arguments[index]

            else:
                output = arguments[index]
        elif key == "--managed-worker":
            worker = True
        index += 1
    if output not in ("human", "json") or (mcp and "--output" in seen):
        raise OptionsError("Invalid client startup output mode.")
    if selection is None and repository_root is not None:
        if (not os.path.isabs(repository_root) or os.path.normpath(repository_root) != repository_root
                or repository_root.startswith('//') or repository_root == '/'
                or len(repository_root.encode('utf-8', errors='surrogatepass')) > 4096
                or len(repository_root.split('/')) > 128
                or any(ord(char) < 32 or 127 <= ord(char) <= 159 or '\ud800' <= char <= '\udfff'
                       for char in repository_root)):
            raise OptionsError('Repository root must be an explicit canonical absolute path.')
    return Options(selection, worker, output, repository_root)


class EnrolledSession:
    """The actual caller retains startup ownership until its session closes."""
    def __init__(self, options: Options, *, registered_context=None):
        if registered_context is not None and (type(registered_context) is not RegisteredProfileContext
                or options.selection is None):
            raise OptionsError('Registered profile context requires an explicit installed selection.')
        self.options = options
        self._registered_context = registered_context
        self._profile_context = None
        self._bound_startup_interrupted = False
        self.result: StartupResult | None = None
        self.application = None
        self._application_failed = False
        self._startup_deadline = None

    @property
    def profile_context(self):
        """Display values from the selection bytes validated for this session."""
        return self._profile_context

    def start(self, *, mcp=False):
        if self._bound_startup_interrupted:
            raise OptionsError('Registered client startup did not complete. Close this session before another attempt.')
        if self.result is None:
            entered = time.monotonic()
            self._startup_deadline = entered + (6 if self.options.managed_worker else 11)
            if self.options.selection is None and self.options.repository_root is not None:
                try:
                    from hub.client_launch_repository import repository_startup
                    self.result = repository_startup(self.options, mcp=mcp, deadline=entered + 1)
                except Exception:
                    self.result = startup_result('status' if self.options.managed_worker else 'ensure',
                                                 'setup_required', 'setup_required')
            else:
                binding = self._registered_context
                try:
                    if binding is None:
                        self.result = startup(self.options.selection, managed_worker=self.options.managed_worker)
                    else:
                        self.result = startup(self.options.selection, managed_worker=self.options.managed_worker,
                                              registered_context=binding)
                except BaseException:
                    if binding is not None:
                        self._bound_startup_interrupted = True
                    raise
                else:
                    self._registered_context = None
            selected = self.result.selection
            if selected is not None:
                self._profile_context = getattr(selected, 'profile_context', None)
            if (selected is not None and selected.application_client is not None
                    and self.result.public['outcome'] == 'observed'
                    and self.result.public['infrastructureReadiness'] in ('ready', 'degraded')):
                self.result.public['applicationBinding'] = {'state': 'unavailable', 'hubId': None}
                try:
                    from hub.client_launch_session import ApplicationClientSession
                    self.application = ApplicationClientSession(selected)
                    deadline = min(time.monotonic() + 5, self._startup_deadline)
                    self.application.start(deadline=deadline)
                    self.result.public['applicationBinding'] = self.application.status(deadline=self._startup_deadline)
                    self._application_failed = self.result.public['applicationBinding']['state'] != 'verified'
                except Exception:
                    self._application_failed = True
                except BaseException:
                    self.exit_code()
                    raise
        return self.result

    def serve_mcp(self, *, stdin=None, stdout=None):
        from hub.fed import mcp
        selected = self.start(mcp=True)
        try:
            mcp.main(stdin=sys.stdin if stdin is None else stdin,
                     stdout=sys.stdout if stdout is None else stdout, startup_result=selected,
                     application_session=self.application)
        except BaseException:
            self.exit_code()
            raise
        return self

    def report(self, *, stdout=None, stderr=None):
        selected = self.start()
        try:
            if self.application is not None:
                selected.public['applicationBinding'] = self.application.status(deadline=self._startup_deadline)
            if self.options.output == "json":
                target = sys.stdout if stdout is None else stdout
                target.write(json.dumps(selected.public) + "\n")
            else:
                target = sys.stderr if stderr is None else stderr
                target.write(human_summary(selected) + "\n")
            target.flush()
        except BaseException:
            self.exit_code()
            raise
        return self

    @staticmethod
    def _hidden_pairing_code(path='/dev/tty'):
        """Read one pairing code without echo or fallback to process streams."""
        descriptor = None
        try:
            flags = os.O_RDWR | getattr(os, 'O_NOCTTY', 0) | getattr(os, 'O_CLOEXEC', 0)
            descriptor = os.open(path, flags)
            if not os.isatty(descriptor):
                raise OSError()
            previous = termios.tcgetattr(descriptor)
            changed = list(previous)
            changed[3] &= ~termios.ECHO

            def write_all(data):
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError()
                    view = view[written:]

            write_all(b'Pairing code: ')
            value = bytearray()
            try:
                termios.tcsetattr(descriptor, termios.TCSAFLUSH, changed)
                while len(value) < 25:
                    item = os.read(descriptor, 1)
                    if not item or item in (b'\n', b'\r'):
                        break
                    value.extend(item)
            finally:
                termios.tcsetattr(descriptor, termios.TCSAFLUSH, previous)
                write_all(b'\n')
        except (OSError, termios.error, UnicodeError):
            raise OptionsError('A local interactive terminal is required for dashboard sign-in.') from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
        try:
            value = bytes(value).decode('ascii').strip().upper()
        except UnicodeError:
            raise OptionsError('The dashboard pairing code is invalid.') from None
        import re
        if re.fullmatch(r'[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){4}', value) is None:
            raise OptionsError('The dashboard pairing code is invalid.')
        return value

    def open_dashboard(self):
        """Open a clean loopback URL, then approve its hidden entered challenge."""
        selected = self.start()
        origin = 'http://127.0.0.1:8787'
        try:
            if (self.application is None or self._application_failed
                    or not self.application.local_browser_enabled()):
                raise OptionsError('This installed client is not enrolled for dashboard sign-in.')
            subprocess.run(['/usr/bin/open', origin + '/'], check=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5)
            challenge = self._hidden_pairing_code()
            try:
                self.application.local_browser_session_open(challenge, origin,
                    deadline=time.monotonic() + 5)
            finally:
                challenge = None
        except BaseException:
            self._application_failed = True
            self.exit_code()
            raise
        return self

    def finish_cleanup(self):
        runtime_done = self.result is None or self.result.finish_cleanup()
        application_done = self.application is None or self.application.close(deadline=time.monotonic() + 1)
        return runtime_done and application_done

    def exit_code(self):
        """Finish the exact child on CLI exit, after the bounded status response.

        If the OS has not reaped a killed child, exit must wait for that original
        handle. It cannot safely detach or replace the owner. This exit-only
        wait does not start a retry or change the startup response deadline.
        """
        complete = self.finish_cleanup()
        capture = self.result.capture if self.result is not None else None
        if not complete and capture is not None and capture.pending is not None:
            capture.returncode = capture.pending.wait()
            capture.pending = None
            complete = self.finish_cleanup()
        if self.application is not None:
            complete = self.application.join_final() and (self.result is None or self.result.finish_cleanup())
        if not complete or self.result is None or self._application_failed:
            return 1
        return 0 if self.result.public["outcome"] in ("observed", "progress") else 1
