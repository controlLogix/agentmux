"""Start the selected runtime before opening the fixed Claude Desktop app.

The installed native dispatcher admits the client package before entering this
module. Startup separately admits its explicit private selection. The desktop
bundle check identifies a client; it grants no application or broker authority.
"""
import os
import platform
import plistlib
import signal
import stat
import sys

from hub.client_launch_entrypoint import EnrolledSession, Options


DESKTOP_APP = '/Applications/Claude.app'
DESKTOP_BUNDLE_ID = 'com.anthropic.claudefordesktop'
OPEN_EXECUTABLE = '/usr/bin/open'


class DesktopLaunchError(ValueError):
    """Only fixed diagnostics may leave the launcher."""


class DesktopTerminated(BaseException):
    def __init__(self, signum):
        self.signum = signum
        super().__init__('Desktop launch was interrupted.')


class _TerminationGuard:
    """Fence launch without interrupting process allocation or owned cleanup."""
    def __init__(self):
        self.signum = None
        self.phase = 'startup'
        self._previous = {}

    def requested(self, signum, _frame=None):
        if self.signum is None:
            self.signum = signum
        # Before transfer, startup already has its own bounded response budget.
        # Raising inside Popen could lose a child before it returns its handle.
        # Cleanup must also keep joining that handle despite repeated signals.
        if self.phase == 'transfer':
            raise DesktopTerminated(self.signum)

    def check(self):
        if self.signum is not None:
            raise DesktopTerminated(self.signum)

    def __enter__(self):
        try:
            for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                previous = signal.getsignal(signum)
                self._previous[signum] = previous
                signal.signal(signum, self.requested)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_):
        for signum, previous in reversed(tuple(self._previous.items())):
            signal.signal(signum, previous)
        self._previous.clear()


def _directory_allowed(info, *, applications):
    mode = stat.S_IMODE(info.st_mode)
    if applications:
        # macOS permits its administrator group to install applications. This
        # fixed system ancestor is not a private enrollment directory.
        return info.st_uid == 0 and ((mode == 0o755 and info.st_gid in (0, 80))
                                     or (mode == 0o775 and info.st_gid == 80))
    return info.st_uid in (0, os.geteuid()) and not mode & 0o022


def _selection(arguments):
    if (len(arguments) != 2 or arguments[0] != '--selection'
            or type(arguments[1]) is not str or not os.path.isabs(arguments[1])
            or os.path.normpath(arguments[1]) != arguments[1]
            or len(arguments[1]) > 4096
            or any(char in arguments[1] for char in '\x00\r\n')):
        raise DesktopLaunchError('Desktop launcher selection is invalid.')
    return arguments[1]


def _desktop_present():
    """Read bounded bundle metadata through fixed, held no-follow directories.

    User-installed native clients remain under the user's control. No plist
    value selects a program, arguments, enrollment, or an import path here.
    """
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in ('Applications', 'Claude.app', 'Contents'):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            previous, parent = parent, child
            os.close(previous)
            info = os.fstat(parent)
            if not _directory_allowed(info, applications=part == 'Applications'):
                raise DesktopLaunchError('Claude Desktop installation is unavailable.')
        fd = os.open('Info.plist', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.geteuid())
                    or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022
                    or not 0 < before.st_size <= 65536):
                raise DesktopLaunchError('Claude Desktop installation is unavailable.')
            raw = os.read(fd, 65537)
            after = os.fstat(fd)
            if (len(raw) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise DesktopLaunchError('Claude Desktop installation is unavailable.')
            metadata = plistlib.loads(raw)
            if (type(metadata) is not dict or metadata.get('CFBundleIdentifier') != DESKTOP_BUNDLE_ID
                    or metadata.get('CFBundlePackageType') != 'APPL'):
                raise DesktopLaunchError('Claude Desktop installation is unavailable.')
        finally:
            os.close(fd)
    finally:
        os.close(parent)


class DesktopLaunchSession:
    """Retain the original startup session until cleanup permits process replacement."""
    def __init__(self, selection):
        self.startup = EnrolledSession(Options(selection, False, 'human'))
        self._attempted = False

    def launch(self, *, stderr=None):
        with _TerminationGuard() as termination:
            return self._launch(stderr=sys.stderr if stderr is None else stderr,
                                desktop_check=_desktop_present, replace=os.execve, termination=termination)

    def _finish_startup(self, termination):
        termination.phase = 'cleanup'
        while True:
            try:
                return self.startup.exit_code()
            except (KeyboardInterrupt, InterruptedError):
                # An interrupted waiter retains the same startup result and
                # process handles. Retry only its join, never startup or launch.
                termination.requested(signal.SIGINT)

    def _launch(self, *, stderr, desktop_check, replace, termination=None):
        """Internal offline seams cannot be selected by a command or settings."""
        if self._attempted:
            raise DesktopLaunchError('Desktop launch was already attempted.')
        self._attempted = True
        termination = _TerminationGuard() if termination is None else termination
        try:
            termination.check()
            desktop_check()
            termination.check()
            result = self.startup.report(stderr=stderr).result
            termination.check()
            complete = self._finish_startup(termination)
            termination.phase = 'checking'
            termination.check()
            if (complete != 0 or result is None or result.public['outcome'] != 'observed'
                    or result.public['infrastructureReadiness'] not in ('ready', 'degraded')):
                raise DesktopLaunchError('Desktop launch requires confirmed runtime startup. Run startup diagnostics.')
            # Recheck after startup without accepting an alternate path. Native
            # authentication and client configuration remain the app's own.
            desktop_check()
            # Cleanup is complete here. A signal delivered before successful
            # process replacement can now raise safely and prevent app opening.
            termination.phase = 'transfer'
            termination.check()
            replace(OPEN_EXECUTABLE, [OPEN_EXECUTABLE, '-a', DESKTOP_APP],
                    {'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8', 'LC_CTYPE': 'UTF-8'})
            raise DesktopLaunchError('Claude Desktop could not be opened.')
        except BaseException:
            # Cleanup joins the original startup child. Cancellation never
            # means it stopped, nor permits replacing this session or process.
            self._finish_startup(termination)
            termination.check()
            raise


def main(arguments, *, stderr=None):
    """Installed route: launch-claude-desktop --selection ABSOLUTE_PRIVATE_PATH."""
    error_output = sys.stderr if stderr is None else stderr
    try:
        selection = _selection(arguments)
        if sys.platform != 'darwin' or platform.machine() != 'arm64' or os.geteuid() == 0:
            raise DesktopLaunchError('Desktop launcher requires native macOS ARM64 and an ordinary user.')
        DesktopLaunchSession(selection).launch(stderr=error_output)
    except DesktopTerminated as error:
        error_output.write('Desktop launch was interrupted.\n')
        error_output.flush()
        return 128 + error.signum
    except KeyboardInterrupt:
        error_output.write('Desktop launch was interrupted.\n')
        error_output.flush()
        return 130
    except Exception as error:
        message = str(error) if isinstance(error, DesktopLaunchError) else 'Claude Desktop could not be opened.'
        error_output.write(message + '\n')
        error_output.flush()
        return 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
