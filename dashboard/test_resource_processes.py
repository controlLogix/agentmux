"""Opt-in native process checks; run only in the coordinator's live test slot.

Run from the repository root:
    AGENTMUX_RESOURCE_PROCESS_TEST=1 <prepared-python> -m dashboard.test_resource_processes

These tests start only Python fixture processes. They do not start installed
clients, inspect user settings, access credentials, or use the network. Importing
this module without the explicit opt-in and supported host exits with status 2.
"""
import os
import platform
import subprocess
import sys
import unittest
from unittest.mock import patch

if os.environ.get('AGENTMUX_RESOURCE_PROCESS_TEST') != '1':
    print('Resource process checks require AGENTMUX_RESOURCE_PROCESS_TEST=1 and a reserved live test slot.',
          file=sys.stderr)
    raise SystemExit(2)
if platform.system() != 'Darwin' or platform.machine().lower() != 'arm64':
    print('Resource process checks require native macOS ARM64 Python.', file=sys.stderr)
    raise SystemExit(2)

from dashboard import resource_probes as probes


class ResourceProcesses(unittest.TestCase):
    def capture_fixture(self, script, timeout=5):
        """Keep the actual Popen object to check the runner completed cleanup."""
        owned = []
        real_popen = subprocess.Popen

        def start(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            owned.append(process)
            return process

        try:
            with patch.object(probes.subprocess, 'Popen', side_effect=start):
                result = probes._capture([sys.executable, '-I', '-c', script], timeout)
            self.assertEqual(len(owned), 1)
            process = owned[0]
            self.assertIsNotNone(process.returncode, 'Runner did not reap its original process.')
            self.assertTrue(process.stdout.closed, 'Runner left its original pipe open.')
            return result, process.returncode
        finally:
            # Keep the same handles if a regression fails before the assertions.
            # No process is found or selected by name, historical PID, or port.
            for process in owned:
                try:
                    if process.returncode is None:
                        process.kill()
                    process.wait()
                finally:
                    if process.stdout is not None:
                        process.stdout.close()

    def test_normal_capture_reaps_and_closes(self):
        result, returncode = self.capture_fixture(
            "import sys; print('fixture stdout', flush=True); print('fixture stderr', file=sys.stderr, flush=True)"
        )
        code, output, failure = result
        self.assertEqual((code, returncode, failure), (0, 0, None))
        self.assertEqual(output.splitlines(), ['fixture stdout', 'fixture stderr'])

    def test_stdin_is_eof(self):
        result, returncode = self.capture_fixture(
            "import sys; print('stdin EOF' if sys.stdin.read() == '' else 'unexpected input', flush=True)"
        )
        self.assertEqual(result, (0, 'stdin EOF\n', None))
        self.assertEqual(returncode, 0)

    def test_nonzero_exit_is_preserved(self):
        result, returncode = self.capture_fixture(
            "import sys; print('fixture failure', flush=True); sys.exit(7)"
        )
        self.assertEqual(result, (7, 'fixture failure\n', None))
        self.assertEqual(returncode, 7)

    def test_timeout_kills_reaps_and_closes(self):
        result, returncode = self.capture_fixture(
            "import time; print('waiting fixture', flush=True); time.sleep(60)", timeout=0.5
        )
        self.assertEqual(result, (None, '', 'timeout'))
        self.assertLess(returncode, 0)

    def test_output_limit_kills_reaps_and_closes(self):
        result, returncode = self.capture_fixture(
            f"import sys, time; sys.stdout.write('x' * {probes.MAX_OUTPUT + 1}); sys.stdout.flush(); time.sleep(60)"
        )
        self.assertEqual(result, (None, '', 'output_limit'))
        self.assertLess(returncode, 0)


if __name__ == '__main__':
    unittest.main()
