"""Focused checks for macOS compatibility wrapper ownership and deadlines."""
import fcntl
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, call, patch


WRAPPER = Path(__file__).resolve().parents[2] / "compat/bin/timeout"


@unittest.skipUnless(sys.platform == "darwin" and platform.machine() == "arm64",
                     "requires native macOS ARM64")
class CompatSessionAndLines(unittest.TestCase):
    def invoke(self, tool, *args, input_=None, environment=None):
        child = subprocess.Popen([str(WRAPPER.with_name(tool)), *args],
                                 stdin=subprocess.PIPE if input_ is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 env=environment)
        try:
            stdout, stderr = child.communicate(input_, timeout=5)
        except subprocess.TimeoutExpired:
            child.terminate()
            child.communicate(timeout=5)
            self.fail("compatibility command exceeded its deadline")
        return child.returncode, stdout, stderr

    def test_setsid_preserves_arguments_and_creates_session(self):
        arguments = ["one argument", "'quoted'", "$(literal)", "--flag"]
        probe = "import json,os,sys; print(json.dumps([os.getpid(),os.getsid(0),os.getpgrp(),sys.argv[1:]]))"
        for flags in (("--",), ("-fw", "--"), ("--fork", "--wait", "--")):
            with self.subTest(flags=flags):
                code, stdout, stderr = self.invoke("setsid", *flags, sys.executable, "-c", probe, *arguments)
                self.assertEqual((code, stderr), (0, ""))
                pid, session, group, received = json.loads(stdout)
                self.assertEqual(pid, session)
                self.assertEqual(pid, group)
                self.assertNotEqual(session, os.getsid(0))
                self.assertEqual(received, arguments)

    def test_setsid_wait_preserves_child_exit_and_signal(self):
        for program, expected in (("import sys; sys.exit(7)", 7),
                                  ("import os,signal; os.kill(os.getpid(),signal.SIGTERM)", 143)):
            with self.subTest(expected=expected):
                code, stdout, stderr = self.invoke("setsid", "-fw", sys.executable, "-c", program)
                self.assertEqual((code, stdout, stderr), (expected, "", ""))

    def test_setsid_refuses_missing_command_and_unknown_options(self):
        for args, expected in (((), 1), (("--unknown",), 1),
                               (("/nonexistent/agentmux-fixture-command",), 127)):
            with self.subTest(args=args):
                code, stdout, stderr = self.invoke("setsid", *args)
                self.assertEqual(code, expected)
                self.assertEqual(stdout, "")
                self.assertTrue(stderr.startswith(("setsid:", "usage: setsid")))

    def test_setsid_ignores_path_python_stub(self):
        with tempfile.TemporaryDirectory() as directory:
            stub = Path(directory) / "python3"
            stub.write_text("#!/bin/sh\nexit 89\n")
            stub.chmod(0o700)
            code, stdout, stderr = self.invoke("setsid", "-fw", "/usr/bin/true",
                                               environment=dict(os.environ, PATH=directory + ":/usr/bin:/bin"))
            self.assertEqual((code, stdout, stderr), (0, "", ""))

    def test_tac_reverses_stdin_and_named_file_with_spaces(self):
        content = "first\nsecond\nthird\n"
        expected = "third\nsecond\nfirst\n"
        self.assertEqual(self.invoke("tac", input_=content), (0, expected, ""))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lines with spaces.txt"
            path.write_text(content)
            self.assertEqual(self.invoke("tac", str(path)), (0, expected, ""))


class CompatTimeout(unittest.TestCase):
    def run_wrapper(self, waits, args=None):
        args = args or ["/selected/command", "one argument", "'quoted'", "$(literal)"]
        child = Mock()
        child.wait.side_effect = waits
        with patch("sys.argv", [str(WRAPPER), "2s", *args]), \
                patch("subprocess.Popen", return_value=child) as spawn:
            with self.assertRaises(SystemExit) as exited:
                runpy.run_path(str(WRAPPER), run_name="__main__")
        spawn.assert_called_once_with(args)
        return exited.exception.code, child

    def test_normal_exit_preserves_status_and_exact_arguments(self):
        code, child = self.run_wrapper([7])
        self.assertEqual(code, 7)
        self.assertEqual(child.mock_calls, [call.wait(timeout=2.0)])

    def test_child_signal_status_is_unchanged(self):
        code, child = self.run_wrapper([-signal.SIGTERM])
        self.assertEqual(code, -signal.SIGTERM)
        self.assertEqual(child.mock_calls, [call.wait(timeout=2.0)])

    def test_expiry_joins_after_term(self):
        code, child = self.run_wrapper([
            subprocess.TimeoutExpired("command", 2), -signal.SIGTERM,
        ])
        self.assertEqual(code, 124)
        self.assertEqual(child.mock_calls, [
            call.wait(timeout=2.0), call.send_signal(signal.SIGTERM),
            call.wait(timeout=5),
        ])

    def test_expiry_joins_original_child_after_kill(self):
        code, child = self.run_wrapper([
            subprocess.TimeoutExpired("command", 2),
            subprocess.TimeoutExpired("command", 5), -signal.SIGKILL,
        ])
        self.assertEqual(code, 124)
        self.assertEqual(child.mock_calls, [
            call.wait(timeout=2.0), call.send_signal(signal.SIGTERM),
            call.wait(timeout=5), call.kill(), call.wait(),
        ])

    def test_interrupt_forwards_sigint_and_joins_original_child(self):
        code, child = self.run_wrapper([KeyboardInterrupt(), 130])
        self.assertEqual(code, 130)
        self.assertEqual(child.mock_calls, [
            call.wait(timeout=2.0), call.send_signal(signal.SIGINT), call.wait(),
        ])


@unittest.skipUnless(sys.platform == "darwin" and platform.machine() == "arm64",
                     "requires native macOS ARM64")
class CompatFlock(unittest.TestCase):
    FLOCK = WRAPPER.with_name("flock")

    def command(self, descriptor, *options):
        return [str(self.FLOCK), *options, str(descriptor)]

    def invoke(self, descriptor, *options):
        child = subprocess.Popen(
            self.command(descriptor, *options), pass_fds=(descriptor,),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=getattr(self, "environment", None),
        )
        try:
            stdout, stderr = child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.terminate()
            child.communicate()
            self.fail("flock did not finish within the test deadline")
        return child.returncode, stdout, stderr

    def test_nonfinite_timeouts_are_refused(self):
        with tempfile.TemporaryFile() as free_lock:
            for value in ("nan", "NaN", "inf", "+inf", "-inf", "Infinity", "1e309"):
                with self.subTest(timeout=value):
                    code, stdout, stderr = self.invoke(free_lock.fileno(), "-w", value)
                    self.assertEqual(code, 1)
                    self.assertEqual(stdout, "")
                    self.assertEqual(stderr, "flock shim: timeout must be finite\n")

    def test_finite_timeouts_acquire_an_available_lock(self):
        with tempfile.TemporaryFile() as free_lock:
            for value in ("-1", "0", "0.1"):
                with self.subTest(timeout=value):
                    self.assertEqual(self.invoke(free_lock.fileno(), "-w", value),
                                     (0, "", ""))
                    fcntl.flock(free_lock.fileno(), fcntl.LOCK_UN)

    def test_contended_nonpositive_timeouts_and_nonblock_keep_exit_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            with path.open("w") as owner, path.open("w") as contender:
                fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                for options in (("-w", "-1"), ("-w", "0"), ("-n",)):
                    with self.subTest(options=options):
                        self.assertEqual(self.invoke(contender.fileno(), *options),
                                         (1, "", ""))

    def test_contended_finite_timeout_expires(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            with path.open("w") as owner, path.open("w") as contender:
                fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                started = time.monotonic()
                self.assertEqual(self.invoke(contender.fileno(), "-w", "0.1"),
                                 (1, "", ""))
                self.assertGreaterEqual(time.monotonic() - started, 0.1)


class InlineFlock(CompatFlock):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        harness = WRAPPER.parents[2] / "agentmux.sh"
        source = harness.read_text()
        dispatch = '\ncase "${1:-}" in\n'
        self.assertEqual(source.count(dispatch), 1)
        self.harness = root / "agentmux.sh"
        self.harness.write_text(source.replace(dispatch, "\nreturn 0 # stop test dispatch\n"))
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash)
        self.environment = dict(
            os.environ, PATH="/usr/bin:/bin:/usr/sbin:/sbin",
            AGENTMUX_HOME=str(root / "home"), AGENTMUX_REPO=str(harness.parent),
            AGENTMUX_NO_COURIER="1", AGENTMUX_IDLE_MINUTES="0",
            CLAUDE_CONFIG_DIR=str(root / "claude"),
        )

    def command(self, descriptor, *options):
        return [self.bash, "-c", '''
command -v flock >/dev/null 2>&1 && exit 2
source "$1" || exit 2
declare -F flock >/dev/null || exit 2
# Keep the original subprocess as the Python wait owner.
python3() { exec "$interpreter" "$@"; }
interpreter="$2"
shift 2
flock "$@"
''', "inline-flock-test", str(self.harness), sys.executable,
                *options, str(descriptor)]


if __name__ == "__main__":
    unittest.main()
