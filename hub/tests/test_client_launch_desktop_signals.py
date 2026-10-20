"""Catchable termination with offline Python helpers; no runtime or app starts."""
import io
import json
import os
import select
import signal
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from hub import client_launch_desktop as desktop
from hub import client_launch_entrypoint as entry
from hub.client_launch_coordinator import Capture, result


SCRIPT = r'''
import json, os, signal, subprocess, sys
from hub import client_launch_desktop as desktop
from hub.client_launch_entrypoint import EnrolledSession
from hub.client_launch_coordinator import Capture, result

original_handlers = {number: signal.getsignal(number)
                     for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
requested = desktop._TerminationGuard.requested
def acknowledged(self, number, frame=None):
    requested(self, number, frame)
    print(json.dumps({'stage': 'signal', 'number': number}), flush=True)
desktop._TerminationGuard.requested = acknowledged
owned = {}
class OfflineStartup(EnrolledSession):
    def report(self, **kwargs):
        self.result = result('ensure', 'observed')
        self.result.public['infrastructureReadiness'] = 'ready'
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        owned['child'] = child
        self.result.capture = Capture(pending=child)
        print(json.dumps({'stage': 'startup', 'pid': child.pid}), flush=True)
        sys.stdin.readline()
        if sys.argv[1:] == ['fail-startup']:
            raise ValueError('PRIVATE_STARTUP_FAILURE')
        return self
    def exit_code(self):
        if not owned.get('cleanup_entered'):
            owned['cleanup_entered'] = True
            print(json.dumps({'stage': 'cleanup'}), flush=True)
            sys.stdin.readline()
        return super().exit_code()

desktop.EnrolledSession = OfflineStartup
desktop._desktop_present = lambda: None
desktop.sys.platform = 'darwin'
desktop.platform.machine = lambda: 'arm64'
desktop.os.geteuid = lambda: 501
def refused_open(*args):
    print('UNEXPECTED_OPEN', flush=True)
    raise AssertionError('App opening was not fenced')
desktop.os.execve = refused_open
code = desktop.main(['--selection', '/private/offline-selection'])
restored = all(signal.getsignal(number) == previous for number, previous in original_handlers.items())
print(json.dumps({'stage': 'done', 'restored': restored,
                  'joined': owned['child'].returncode is not None}), flush=True)
raise SystemExit(code)
'''


class DesktopTermination(unittest.TestCase):
    def line(self, process):
        ready, _, _ = select.select([process.stdout], [], [], 4)
        self.assertTrue(ready, 'Offline launcher stage timed out')
        line = process.stdout.readline()
        self.assertTrue(line, 'Offline launcher exited before its expected stage')
        return json.loads(line)

    def test_term_hup_and_repeated_termination_join_original_child_and_restore_handlers(self):
        for first_signal, during_cleanup, startup_fails in (
                (signal.SIGTERM, False, False), (signal.SIGHUP, True, False), (signal.SIGTERM, True, True)):
            with self.subTest(signal=first_signal, during_cleanup=during_cleanup, startup_fails=startup_fails):
                arguments = [sys.executable, '-c', SCRIPT] + (['fail-startup'] if startup_fails else [])
                process = subprocess.Popen(arguments, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                child_pid = None
                try:
                    starting = self.line(process)
                    self.assertEqual(starting['stage'], 'startup')
                    child_pid = starting['pid']
                    if not during_cleanup:
                        process.send_signal(first_signal)
                        self.assertEqual(self.line(process), {'stage': 'signal', 'number': first_signal})
                    process.stdin.write('continue\n')
                    process.stdin.flush()
                    self.assertEqual(self.line(process)['stage'], 'cleanup')
                    if during_cleanup:
                        process.send_signal(first_signal)
                        self.assertEqual(self.line(process), {'stage': 'signal', 'number': first_signal})
                    # Acknowledgement separates each delivery. Without this,
                    # POSIX may coalesce signals or Python may process a lower
                    # signal number first even when it was sent later.
                    for repeated in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                        process.send_signal(repeated)
                        self.assertEqual(self.line(process), {'stage': 'signal', 'number': repeated})
                    output, error = process.communicate('finish cleanup\n', timeout=4)
                    self.assertEqual(process.returncode, 128 + first_signal)
                    self.assertNotIn('UNEXPECTED_OPEN', output)
                    self.assertEqual(json.loads(output), {'stage': 'done', 'restored': True, 'joined': True})
                    self.assertEqual(error, 'Desktop launch was interrupted.\n')
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)
                finally:
                    if process.poll() is None:
                        # Release both offline handshakes so the same launcher
                        # can finish its owned child even after an assertion.
                        try:
                            process.communicate('continue\nfinish cleanup\n', timeout=4)
                        except subprocess.TimeoutExpired:
                            if child_pid is not None:
                                try:
                                    os.kill(child_pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                            process.kill()
                            process.communicate(timeout=4)
                    for stream in (process.stdin, process.stdout, process.stderr):
                        stream.close()

    def test_interrupted_cleanup_rejoins_same_retained_startup_child(self):
        observed = result('ensure', 'observed')
        observed.public['infrastructureReadiness'] = 'ready'
        child = Mock()
        child.poll.return_value = None
        child.wait.side_effect = [KeyboardInterrupt(), subprocess.TimeoutExpired('offline', 1),
                                  InterruptedError(), 0]
        observed.capture = Capture(pending=child)
        session = desktop.DesktopLaunchSession('/private/offline-selection')
        replace = Mock()
        with patch.object(entry, 'startup', return_value=observed), \
                self.assertRaises(desktop.DesktopTerminated) as termination:
            session._launch(stderr=io.StringIO(), desktop_check=Mock(), replace=replace)
        self.assertEqual(termination.exception.signum, signal.SIGINT)
        self.assertIs(session.startup.result, observed)
        self.assertIsNone(observed.capture.pending)
        self.assertEqual(child.wait.call_count, 4)
        replace.assert_not_called()

    def test_termination_at_final_transfer_fences_open_and_restores_handlers(self):
        previous = {number: signal.getsignal(number)
                    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
        observed = result('ensure', 'observed')
        observed.public['infrastructureReadiness'] = 'ready'
        startup = Mock(result=observed)
        startup.report.return_value = startup
        startup.exit_code.return_value = 0
        def replace(*args):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            self.fail('Transfer continued after termination')
        with patch.object(desktop, 'EnrolledSession', return_value=startup), \
                patch.object(desktop, '_desktop_present'), patch.object(desktop.os, 'execve', side_effect=replace):
            session = desktop.DesktopLaunchSession('/private/offline-selection')
            with self.assertRaises(desktop.DesktopTerminated):
                session.launch(stderr=io.StringIO())
        self.assertEqual({number: signal.getsignal(number) for number in previous}, previous)
        startup.exit_code.assert_called()
