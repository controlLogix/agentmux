from pathlib import Path
p=Path('/home/ryan/.cache/agentmux-governance/p02-native-collector-cleanup-repair-v3/native_go.py')
s=p.read_text();a=s.index('    def test_hidden_preparation_refuses_populated_workspace')
new=r'''    def test_owned_builtin_timeout_reaps_actual_child(self):
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'],
                                   start_new_session=True)
        try:
            start = time.monotonic()
            code, timed_out = wait_owned(process, .01, deadline=start + .5)
            self.assertTrue(timed_out)
            self.assertEqual(code, -signal.SIGKILL)
            self.assertEqual(process.returncode, code)
            self.assertLess(time.monotonic() - start, .5)
        finally:
            if process.returncode is None:
                stop_owned(process, time.monotonic() + 2)

    def test_owned_cleanup_timeout_retains_owner_and_retry_resolves(self):
        first = subprocess.TimeoutExpired('fixed', 1)
        cleanup = subprocess.TimeoutExpired('fixed', .05)
        process = mock.Mock(pid=12345, returncode=None)
        process.wait.side_effect = [first, cleanup, -9]
        deadline = time.monotonic() + .05
        with mock.patch.object(os, 'killpg', create=True) as kill:
            with self.assertRaises(OwnedCleanupError) as result:
                wait_owned(process, .01, deadline=deadline)
            owner = result.exception.owner
            self.assertIs(owner.process, process)
            self.assertIn(owner, _RETAINED_REAPS)
            self.assertIsNone(owner.code)
            self.assertIs(result.exception._cleanup_cause, cleanup)
            self.assertIs(result.exception._cause, first)
            for call in process.wait.call_args_list:
                self.assertIn('timeout', call.kwargs)
                self.assertLessEqual(call.kwargs['timeout'], .05)
            self.assertEqual(owner.stop_until(time.monotonic() + 1), -9)
            self.assertNotIn(owner, _RETAINED_REAPS)
            self.assertIs(result.exception._cleanup_cause, cleanup)
            kill.assert_called_once_with(12345, signal.SIGKILL)

    def test_owned_cleanup_interruption_retains_owner(self):
        process = mock.Mock(pid=12345, returncode=None)
        interruption = KeyboardInterrupt()
        process.wait.side_effect = [subprocess.TimeoutExpired('fixed', 1), interruption, -9]
        with mock.patch.object(os, 'killpg', create=True):
            with self.assertRaises(OwnedCleanupError) as result:
                wait_owned(process, .01, deadline=time.monotonic() + .05)
            owner = result.exception.owner
            self.assertIs(owner.process, process)
            self.assertIs(result.exception._cleanup_cause, interruption)
            self.assertEqual(owner.stop_until(time.monotonic() + 1), -9)
            self.assertNotIn(owner, _RETAINED_REAPS)

    def test_owned_cleanup_stop_failure_never_disappears_after_reap(self):
        process = mock.Mock(pid=12345, returncode=None)
        process.wait.return_value = 0
        private = PermissionError('private synthetic cause')
        with mock.patch.object(os, 'killpg', side_effect=private, create=True):
            with self.assertRaises(OwnedCleanupError) as result:
                stop_owned(process, time.monotonic() + .05)
            owner = result.exception.owner
            self.assertEqual(owner.code, 0)
            self.assertIs(result.exception._cleanup_cause, private)
            with self.assertRaises(OwnedCleanupError) as repeated:
                owner.stop_until(time.monotonic() + .05)
            self.assertIs(repeated.exception.owner, owner)
            self.assertEqual(process.wait.call_count, 1)
            self.assertNotIn('private', str(result.exception))
            self.assertNotIn('private', repr(result.exception))

    def test_owned_cleanup_shutdown_reaps_exact_retained_child(self):
        # The controlled timeout obeys the wait contract. Its exact builtin
        # process.wait performs the real reap during interpreter shutdown.
        program = r"""
import atexit, json, os, runpy, subprocess, sys, time
child = None
@atexit.register
def verify():
    joined = child is not None and child.returncode == -9
    print(json.dumps({'exactChildReaped': joined}), flush=True)
    if not joined: os._exit(3)
collector = runpy.run_path(sys.argv[1])
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'], start_new_session=True)
actual_wait = child.wait
def controlled_wait(timeout=None):
    if timeout is not None: raise subprocess.TimeoutExpired('fixed', timeout)
    return actual_wait()
child.wait = controlled_wait
try:
    collector['stop_owned'](child, time.monotonic() + .01)
except collector['OwnedCleanupError'] as failure:
    assert failure.owner.process is child and failure.owner.code is None
else:
    raise AssertionError('missing retained exact owner')
"""
        process = subprocess.Popen([sys.executable, '-c', program, str(Path(__file__).resolve())],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(json.loads(out), {'exactChildReaped': True})
            self.assertEqual(err, b'')
        finally:
            if process.returncode is None:
                stop_owned(process, time.monotonic() + 2)

'''
s=s[:a]+new+s[a:];p.write_text(s)
