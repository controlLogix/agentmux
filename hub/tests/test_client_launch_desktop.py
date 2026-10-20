"""Offline launcher checks; no app, installed runtime or broker is started."""
import io
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from hub import client_launch_desktop as desktop
from hub import client_launch_entrypoint as entry
from hub.client_launch_coordinator import Capture, result


class Replaced(BaseException):
    """Model successful exec without starting a process."""


class DesktopLauncher(unittest.TestCase):
    def selected(self):
        observed = result('ensure', 'observed')
        observed.public['infrastructureReadiness'] = 'ready'
        startup = Mock(result=observed)
        startup.report.return_value = startup
        startup.exit_code.return_value = 0
        with patch.object(desktop, 'EnrolledSession', return_value=startup) as create:
            session = desktop.DesktopLaunchSession('/private/profile with "quotes"/selection.json')
        self.assertEqual(create.call_args.args[0], entry.Options(
            '/private/profile with "quotes"/selection.json', False, 'human'))
        return session, startup

    def test_selection_is_literal_and_closed(self):
        path = '/private/space and "quote"/selection.json'
        self.assertEqual(desktop._selection(['--selection', path]), path)
        for args in ([], ['--selection'], ['--selection', 'relative'],
                     ['--selection', '/private/../selection'], ['--selection', '/bad\npath'],
                     ['--selection', path, '--client', '/bad'], ['--selection', path, '--managed-worker']):
            with self.subTest(args=args), self.assertRaises(desktop.DesktopLaunchError):
                desktop._selection(args)

    def test_summary_and_cleanup_precede_fixed_process_replacement(self):
        session, startup = self.selected()
        order = []
        startup.report.side_effect = lambda **kwargs: order.append('summary') or startup
        startup.exit_code.side_effect = lambda: order.append('cleanup') or 0
        check = Mock(side_effect=lambda: order.append('bundle'))
        def replace(path, argv, env):
            order.append('replace')
            self.assertEqual(path, '/usr/bin/open')
            self.assertEqual(argv, ['/usr/bin/open', '-a', '/Applications/Claude.app'])
            self.assertEqual(env, {'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8', 'LC_CTYPE': 'UTF-8'})
            raise Replaced()
        with self.assertRaises(Replaced):
            session._launch(stderr=io.StringIO(), desktop_check=check, replace=replace)
        self.assertEqual(order[:5], ['bundle', 'summary', 'cleanup', 'bundle', 'replace'])
        with self.assertRaisesRegex(desktop.DesktopLaunchError, 'already attempted'):
            session._launch(stderr=io.StringIO(), desktop_check=check, replace=replace)

    def test_setup_progress_failure_and_unknown_readiness_never_launch(self):
        for outcome, readiness, code in (('setup_required', 'unknown', 0),
                ('starting', 'unknown', 0), ('failed', 'ready', 0),
                ('observed', 'unknown', 0), ('observed', 'ready', 1)):
            session, startup = self.selected()
            startup.result.public.update(outcome=outcome, infrastructureReadiness=readiness)
            startup.exit_code.return_value = code
            replace = Mock()
            with self.subTest(outcome=outcome, readiness=readiness, code=code), \
                    self.assertRaises(desktop.DesktopLaunchError):
                session._launch(stderr=io.StringIO(), desktop_check=Mock(), replace=replace)
            replace.assert_not_called()
            startup.exit_code.assert_called()

    def test_bundle_refusal_and_replacement_after_startup_prevent_open(self):
        for failures in ([OSError('private metadata')], [None, OSError('private metadata')]):
            session, startup = self.selected()
            replace = Mock()
            with self.assertRaises(OSError):
                session._launch(stderr=io.StringIO(), desktop_check=Mock(side_effect=failures), replace=replace)
            replace.assert_not_called()
            startup.exit_code.assert_called()

    def test_cancellation_and_summary_failure_join_original_startup(self):
        for error in (KeyboardInterrupt(), BrokenPipeError('private output')):
            session, startup = self.selected()
            startup.report.side_effect = error
            replace = Mock()
            with self.subTest(error=type(error)), self.assertRaises(type(error)):
                session._launch(stderr=io.StringIO(), desktop_check=Mock(), replace=replace)
            startup.exit_code.assert_called_once_with()
            replace.assert_not_called()

    def test_original_pending_child_is_joined_before_launch(self):
        observed = result('ensure', 'observed')
        observed.public['infrastructureReadiness'] = 'ready'
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('private-command', 1), 0]
        observed.capture = Capture(pending=child)
        output = io.StringIO()
        session = desktop.DesktopLaunchSession('/private/selection with spaces.json')
        def replace(*args):
            self.assertIsNone(observed.capture.pending)
            self.assertEqual(child.wait.call_args_list[0].kwargs, {'timeout': 1})
            self.assertEqual(child.wait.call_args_list[1].kwargs, {})
            self.assertTrue(output.getvalue())
            raise Replaced()
        with patch.object(entry, 'startup', return_value=observed), self.assertRaises(Replaced):
            session._launch(stderr=output, desktop_check=Mock(), replace=replace)
        self.assertIs(session.startup.result, observed)
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.call_count, 2)

    def test_main_refuses_unsupported_platform_and_hides_private_errors(self):
        for supported in (False, True):
            output = io.StringIO()
            with patch.object(desktop.sys, 'platform', 'darwin' if supported else 'linux'), \
                    patch.object(desktop.platform, 'machine', return_value='arm64'), \
                    patch.object(desktop.os, 'geteuid', return_value=501), \
                    patch.object(desktop.DesktopLaunchSession, 'launch', side_effect=OSError('/secret/path')) as launch:
                self.assertEqual(desktop.main(['--selection', '/private/selection'], stderr=output), 1)
            self.assertNotIn('/secret/path', output.getvalue())
            self.assertEqual(launch.call_count, int(supported))


class DesktopBundle(unittest.TestCase):
    def check(self, *, metadata=None, symlink=False):
        with tempfile.TemporaryDirectory() as directory:
            contents = Path(directory, 'Applications', 'Claude.app', 'Contents')
            contents.mkdir(parents=True)
            path = contents / 'Info.plist'
            path.write_bytes(plistlib.dumps(metadata if metadata is not None else {
                'CFBundleIdentifier': desktop.DESKTOP_BUNDLE_ID, 'CFBundlePackageType': 'APPL'}))
            if symlink:
                path.rename(contents / 'other.plist')
                path.symlink_to('other.plist')
            real_open, real_stat = os.open, os.fstat
            roles = {}
            def opened(path, flags, **kwargs):
                fd = real_open(directory if path == '/' else path, flags, **kwargs)
                roles[fd] = path
                return fd
            def metadata(fd):
                info = real_stat(fd)
                if roles.get(fd) == 'Applications':
                    return SimpleNamespace(st_uid=0, st_gid=80, st_mode=0o40775)
                return info
            with patch.object(desktop.os, 'open', side_effect=opened), \
                    patch.object(desktop.os, 'fstat', side_effect=metadata):
                desktop._desktop_present()

    def test_exact_bundle_metadata(self):
        self.check()

    def test_system_applications_allows_only_root_and_administrator_layout(self):
        for uid, gid, mode, allowed in ((0, 80, 0o775, True), (0, 80, 0o755, True),
                (0, 0, 0o755, True), (0, 20, 0o775, False), (501, 80, 0o775, False),
                (0, 80, 0o777, False), (0, 80, 0o2775, False)):
            with self.subTest(uid=uid, gid=gid, mode=mode):
                self.assertEqual(desktop._directory_allowed(
                    SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode), applications=True), allowed)

    def test_administrator_write_exception_does_not_apply_to_bundle(self):
        self.assertFalse(desktop._directory_allowed(
            SimpleNamespace(st_uid=0, st_gid=80, st_mode=0o775), applications=False))

    def test_wrong_bundle_and_package_kind_refused(self):
        for metadata in ({'CFBundleIdentifier': 'other', 'CFBundlePackageType': 'APPL'},
                         {'CFBundleIdentifier': desktop.DESKTOP_BUNDLE_ID, 'CFBundlePackageType': 'BNDL'}, {}):
            with self.subTest(metadata=metadata), self.assertRaises(desktop.DesktopLaunchError):
                self.check(metadata=metadata)

    def test_linked_metadata_refused(self):
        with self.assertRaises(OSError):
            self.check(symlink=True)
