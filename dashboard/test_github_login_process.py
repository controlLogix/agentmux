"""Serialized local PTY checks using a disposable executable, never real gh.

Run only in the coordinator's process-test slot. These tests do not qualify a
GitHub account or device authorization; they check process ownership and cleanup.
"""
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import github_auth as auth


@unittest.skipUnless(auth.HAVE_PTY and sys.platform == 'darwin', 'native macOS PTY check')
class GitHubLoginProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.binary = self.home / 'gh-fixture'
        self.logins = []
        self.change(patch.dict(os.environ, {'HOME': str(self.home),
                                          'GH_CONFIG_DIR': str(self.home / 'gh')}, clear=True))
        self.change(patch.object(auth, 'gh_path', return_value=str(self.binary)))
        self.change(patch.object(auth, 'LOGIN_STOP_TIMEOUT', 0.2))
        self.change(patch.object(auth, 'LOGIN_JOIN_TIMEOUT', 3.0))
        self.addCleanup(self.stop_original_processes)

    def change(self, patcher):
        patcher.start()
        self.addCleanup(patcher.stop)

    def executable(self, body):
        self.binary.write_text(f'#!{sys.executable}\n' + body)
        self.binary.chmod(0o700)

    def start(self):
        login = auth.Login()
        self.logins.append(login)
        login.start('fixture-operator')
        return login

    def wait_for(self, login, states):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            state = login.snapshot()
            if state['state'] in states:
                return state
            time.sleep(0.01)
        self.fail(f'Login did not reach {states}: {login.snapshot()["state"]}')

    def stop_original_processes(self):
        for login in self.logins:
            with login.lock:
                process, thread = login._process, login.thread
            login.cancel()
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if thread is not None:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive(), 'original login worker is still running')
        self.assertFalse(auth._CREDENTIAL_LOCK.locked(), 'credential owner was not released')

    def test_cancel_joins_original_process_before_another_login(self):
        self.executable('import time\nprint("ABCD-1234", flush=True)\ntime.sleep(60)\n')
        login = self.start()
        self.wait_for(login, {'waiting'})
        with login.lock:
            original_process, original_thread = login._process, login.thread
        self.assertEqual(login.cancel()['state'], 'idle')
        self.assertIs(login.thread, original_thread)
        self.assertFalse(original_thread.is_alive())
        self.assertEqual(original_process.returncode, -signal.SIGTERM)
        self.assertEqual(original_process.wait(timeout=0), -signal.SIGTERM)

        self.executable('print("EFGH-5678", flush=True)\n')
        login.start('next-operator')
        self.wait_for(login, {'done'})
        login.thread.join(timeout=3)
        self.assertIsNot(login.thread, original_thread)
        self.assertFalse(login.thread.is_alive())

    def test_ignored_termination_is_killed_and_waited(self):
        self.executable('import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                        'print("ABCD-1234", flush=True)\ntime.sleep(60)\n')
        login = self.start()
        self.wait_for(login, {'waiting'})
        with login.lock:
            process = login._process
        self.assertEqual(login.cancel()['state'], 'idle')
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual(process.wait(timeout=0), -signal.SIGKILL)
        self.assertFalse(login.thread.is_alive())

    def test_timeout_retains_fixed_destination_and_reaps_child(self):
        self.change(patch.object(auth, 'LOGIN_TIMEOUT', 0.2))
        self.executable('import time\nprint("ABCD-1234 https://evilgithub.com/login/device", flush=True)\n'
                        'time.sleep(60)\n')
        login = self.start()
        self.wait_for(login, {'waiting'})
        with login.lock:
            process = login._process
        state = self.wait_for(login, {'error'})
        login.thread.join(timeout=3)
        self.assertEqual(state['url'], auth.DEVICE_URL)
        self.assertIn('timed out', state['error'])
        self.assertIsNone(state['code'])
        self.assertEqual(process.wait(timeout=0), -signal.SIGTERM)
        self.assertFalse(login.thread.is_alive())


if __name__ == '__main__':
    unittest.main()
