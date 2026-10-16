"""Unprivileged fake-child controls. Never invokes hdiutil, sudo or root entrypoints."""
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import threading
import time
import unittest
from unittest import mock

REAL_WRITE = os.write


def load_program(name):
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("fixture_control_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # __main__ guard prevents root actions.
    module.deadline = time.monotonic() + 2
    module.CAPTURE_LIMIT = 32
    module.TERM_GRACE_SECONDS = 0.02
    module.KILL_JOIN_SECONDS = 0.1
    module.PIPE_DRAIN_SECONDS = 0.05
    return module


class FakeChild:
    def __init__(self, module, scenario):
        self.waits = self.terms = self.kills = 0
        self.released = threading.Event()
        self.writers = []
        readers = []
        for _ in range(2):
            reader, writer = os.pipe()
            readers.append(os.fdopen(reader, "rb", buffering=0))
            self.writers.append(writer)
        self.stdout, self.stderr = readers
        self.ignore_term = scenario == "timeout-kill"
        if scenario in ("stdout-overflow", "stderr-overflow"):
            REAL_WRITE(self.writers[scenario == "stderr-overflow"], b"x" * 64)
        elif scenario == "short-write":
            REAL_WRITE(self.writers[0], b"data")
        if scenario != "inherited-pipe":
            self.close_writers()
        if scenario in ("normal", "short-write", "inherited-pipe", "late-zero"):
            self.released.set()
        if scenario == "late-zero":
            module.deadline = time.monotonic() - 1
        if scenario == "cancel-int":
            module.cancel(signal.SIGINT, None)
        if scenario == "cancel-term":
            module.cancel(signal.SIGTERM, None)

    def close_writers(self):
        while self.writers:
            os.close(self.writers.pop())

    def wait(self):
        self.waits += 1
        if not self.released.wait(1):
            raise RuntimeError("fake sole wait failed to receive shutdown")
        return 0  # Deliberately late zero cannot erase a sticky failure.

    def terminate(self):
        self.terms += 1
        if not self.ignore_term:
            self.released.set()

    def kill(self):
        self.kills += 1
        self.released.set()


class LifecycleControls(unittest.TestCase):
    def test_wait_state_constructors_precede_creation(self):
        for program in ("setup", "teardown"):
            for constructor in ("Event", "Thread"):
                module = load_program(program)
                with tempfile.TemporaryDirectory() as directory:
                    rootfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with mock.patch.object(module.threading, constructor, side_effect=RuntimeError("pure-constructor")), \
                                mock.patch.object(module.subprocess, "Popen") as factory:
                            with self.assertRaises(RuntimeError):
                                module.command(rootfd, "constructor", ["info", "-plist"])
                            factory.assert_not_called()
                        self.assertEqual(len(module.owned), 2)
                    finally:
                        module.close_all()
                        os.close(rootfd)
                    self.assertEqual(module.owned, [])

    def test_evidenced_apfs_alias_requires_exact_canonical_uuid(self):
        uuid = "7C3457EF-0000-11AA-AA11-00306543ECAC"
        for program in ("setup", "teardown"):
            module = load_program(program)
            alias = {"dev-entry": "/dev/disk99s1", "content-hint": "Apple_APFS",
                     "unmapped-content-hint": uuid}
            canonical = {"dev-entry": "/dev/disk99s1", "content-hint": uuid}
            self.assertEqual(module.entities([alias]), module.entities([canonical]))
            for unmapped in (None, "", "wrong"):
                changed = dict(alias)
                if unmapped is None:
                    del changed["unmapped-content-hint"]
                else:
                    changed["unmapped-content-hint"] = unmapped
                with self.assertRaises(module.FixtureFailure):
                    module.entities([changed])
            with self.assertRaises(module.FixtureFailure):
                module.entities([dict(canonical, **{"unmapped-content-hint": "wrong"})])
            with self.assertRaises(module.FixtureFailure):
                module.entities([alias, alias])

    def test_blank_image_create_uses_documented_udif_type(self):
        # Inspect the literal command only. No root entrypoint or hdiutil call.
        source = Path(__file__).with_name("setup.py").read_text()
        tree = ast.parse(source)
        setup = next(node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and node.name == "setup")
        commands = [node for node in ast.walk(setup)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "command" and len(node.args) == 3
                    and isinstance(node.args[2], ast.List) and node.args[2].elts
                    and isinstance(node.args[2].elts[0], ast.Constant)
                    and node.args[2].elts[0].value == "create"]
        self.assertEqual(len(commands), 1)
        root = "/private/tmp/agentmux-c05-apfs-20261015-7c4e92b1"
        for label in ("owners", "noowners"):
            image = root + "/" + label + ".dmg"
            argv = []
            for node in commands[0].args[2].elts:
                if isinstance(node, ast.Constant) and type(node.value) is str:
                    argv.append(node.value)
                else:
                    self.assertIsInstance(node, ast.Name)
                    self.assertEqual(node.id, "image")
                    argv.append(image)
            self.assertEqual(argv, ["create", "-size", "128m", "-fs", "APFS",
                                    "-layout", "GPTSPUD", "-type", "UDIF",
                                    "-volname", "AgentmuxC05", image])
            for forbidden in ("-format", "-srcfolder", "-srcdevice"):
                self.assertNotIn(forbidden, argv)

    def test_blocked_inherited_mask_refuses_before_creation(self):
        for program in ("setup", "teardown"):
            for blocked in (signal.SIGINT, signal.SIGTERM):
                module = load_program(program)
                previous = signal.pthread_sigmask(signal.SIG_BLOCK, {blocked})
                try:
                    with self.assertRaises(module.FixtureFailure):
                        module.require_unmasked()
                    with tempfile.TemporaryDirectory() as directory:
                        rootfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            with mock.patch.object(module.subprocess, "Popen") as factory:
                                with self.assertRaises(module.FixtureFailure):
                                    module.command(rootfd, "blocked", ["info", "-plist"])
                                factory.assert_not_called()
                            self.assertIn(blocked, signal.pthread_sigmask(signal.SIG_BLOCK, set()))
                        finally:
                            module.close_all()
                            os.close(rootfd)
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def test_actual_literal_child_unmasked_term_after_ready(self):
        # No hdiutil invocation: only this fixed unprivileged Python child.
        literal = (
            "import json,signal\n"
            "mask=signal.pthread_sigmask(signal.SIG_BLOCK,set())\n"
            "print(json.dumps({'ready':True,'mask':sorted(int(s) for s in mask),"
            "'termDefault':signal.getsignal(signal.SIGTERM)==signal.SIG_DFL}),flush=True)\n"
            "while True: signal.pause()\n"
        )
        original_popen = __import__("subprocess").Popen
        for program in ("setup", "teardown"):
            with self.subTest(program=program):
                module = load_program(program)
                module.require_unmasked()
                module.deadline = time.monotonic() + 5
                module.CAPTURE_LIMIT = 1024
                module.TERM_GRACE_SECONDS = 2
                module.KILL_JOIN_SECONDS = 2
                child = None
                observed = bytearray()
                receipt = None
                term_at = []
                wait_at = []
                previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
                for number in previous:
                    signal.signal(number, module.cancel)  # Installed before actual creation.
                def factory(argv, **kwargs):
                    nonlocal child
                    self.assertEqual(argv, ["/usr/bin/hdiutil", "info", "-plist"])
                    self.assertFalse(signal.pthread_sigmask(signal.SIG_BLOCK, set()).intersection(
                        {signal.SIGINT, signal.SIGTERM}))
                    child = original_popen(["/usr/bin/python3", "-I", "-S", "-c", literal], **kwargs)
                    original_wait, original_term = child.wait, child.terminate
                    def wait():
                        result = original_wait()
                        wait_at.append(time.monotonic())
                        return result
                    def terminate():
                        term_at.append(time.monotonic())
                        return original_term()
                    child.wait = mock.Mock(side_effect=wait)
                    child.terminate = mock.Mock(side_effect=terminate)
                    child.kill = mock.Mock(wraps=child.kill)
                    return child
                def capture(fd, data):
                    nonlocal receipt
                    written = REAL_WRITE(fd, data)
                    observed.extend(data)
                    if receipt is None and b"\n" in observed:
                        receipt = json.loads(bytes(observed).split(b"\n", 1)[0])
                        # Actual signal to this test process only, after child readiness.
                        signal.raise_signal(signal.SIGTERM)
                    return written
                with tempfile.TemporaryDirectory() as directory:
                    rootfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with mock.patch.object(module.subprocess, "Popen", side_effect=factory):
                            with mock.patch.object(module.os, "write", side_effect=capture):
                                with self.assertRaises(module.FixtureFailure):
                                    module.command(rootfd, "actual", ["info", "-plist"])
                        self.assertEqual(receipt["ready"], True)
                        self.assertTrue(receipt["termDefault"])
                        self.assertFalse(set(receipt["mask"]).intersection(
                            {int(signal.SIGINT), int(signal.SIGTERM)}))
                        self.assertTrue(module.cancelled)
                        self.assertEqual(child.returncode, -signal.SIGTERM)
                        self.assertEqual(child.wait.call_count, 1)
                        self.assertEqual(child.terminate.call_count, 1)
                        self.assertEqual(child.kill.call_count, 0)
                        self.assertLess(wait_at[0] - term_at[0], 2)
                        self.assertTrue(child.stdout.closed and child.stderr.closed)
                        print(json.dumps({"actualControl": program, "mask": receipt["mask"],
                            "termDefault": receipt["termDefault"], "exitCode": child.returncode,
                            "waits": 1, "terms": 1, "kills": 0,
                            "termJoinSeconds": wait_at[0]-term_at[0],
                            "pipesClosed": True}), flush=True)
                    finally:
                        # The lifecycle keeper retains genuinely unconfirmed waits;
                        # reaching this block must never create another waiter.
                        module.close_all()
                        os.close(rootfd)
                        for number, handler in previous.items():
                            signal.signal(number, handler)

    def test_keeper_observes_late_original_wait_and_closes_pipes(self):
        for program in ("setup", "teardown"):
            module = load_program(program)
            child = None
            release = None
            fault = OSError("actual_selector_creation_failure")
            def factory(argv, **kwargs):
                nonlocal child, release
                child = FakeChild(module, "selector-fail-late")
                release = threading.Timer(0.03, child.released.set)
                release.start()
                return child
            with tempfile.TemporaryDirectory() as directory:
                rootfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with mock.patch.object(module.subprocess, "Popen", side_effect=factory):
                        with mock.patch.object(module.selectors, "DefaultSelector", side_effect=fault):
                            with self.assertRaises(module.FixtureFailure) as failure:
                                module.command(rootfd, "late", ["info", "-plist"])
                    self.assertIs(failure.exception.causes[0], fault)
                    self.assertTrue(any(isinstance(cause, module.FixtureFailure) and
                        "historically_unconfirmed" in str(cause) for cause in failure.exception.causes))
                    self.assertEqual(child.waits, 1)
                    self.assertEqual(child.terms, 0)
                    self.assertEqual(child.kills, 0)
                    self.assertTrue(child.stdout.closed and child.stderr.closed)
                    self.assertEqual(len(module.owned), 2)
                finally:
                    if release:
                        release.join()
                    if child:
                        child.close_writers()
                    module.close_all()
                    os.close(rootfd)
                self.assertEqual(module.owned, [])

    def test_failed_wait_is_not_terminal_authority(self):
        for program in ("setup", "teardown"):
            module = load_program(program)
            terminal = threading.Event()
            self.assertFalse(module.wait_confirmed(terminal, {}))
            terminal.set()
            failure = OSError("actual_wait_failure")
            self.assertFalse(module.wait_confirmed(terminal, {"error": failure}))
            self.assertFalse(module.wait_confirmed(terminal, {"status": 0, "error": failure}))
            self.assertTrue(module.wait_confirmed(terminal, {"status": 0}))

    def test_owned_command_controls(self):
        for program in ("setup", "teardown"):
            for scenario in ("normal", "stdout-overflow", "stderr-overflow",
                             "cancel-int", "cancel-term", "timeout-kill",
                             "late-zero", "inherited-pipe", "short-write"):
                with self.subTest(program=program, scenario=scenario):
                    module = load_program(program)
                    if scenario == "timeout-kill":
                        module.deadline = time.monotonic() + 0.03
                    child = None
                    def factory(argv, **kwargs):
                        nonlocal child
                        self.assertFalse(signal.pthread_sigmask(signal.SIG_BLOCK, set()).intersection(
                            {signal.SIGINT, signal.SIGTERM}))
                        self.assertEqual(argv, ["/usr/bin/hdiutil", "info", "-plist"])
                        self.assertEqual(kwargs["stdout"], module.subprocess.PIPE)
                        self.assertEqual(kwargs["stderr"], module.subprocess.PIPE)
                        child = FakeChild(module, scenario)
                        return child
                    with tempfile.TemporaryDirectory() as directory:
                        rootfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            with mock.patch.object(module.subprocess, "Popen", side_effect=factory):
                                write_patch = mock.patch.object(module.os, "write", return_value=0) if scenario == "short-write" else contextlib.nullcontext()
                                with write_patch:
                                    if scenario == "normal":
                                        module.command(rootfd, "control", ["info", "-plist"])
                                    else:
                                        with self.assertRaises(module.FixtureFailure):
                                            module.command(rootfd, "control", ["info", "-plist"])
                            self.assertEqual(child.waits, 1)
                            self.assertTrue(child.stdout.closed and child.stderr.closed)
                            if scenario in ("stdout-overflow", "stderr-overflow", "cancel-int", "cancel-term", "timeout-kill"):
                                self.assertEqual(child.terms, 1)
                            if scenario == "timeout-kill":
                                self.assertEqual(child.kills, 1)
                            self.assertLessEqual(os.stat(directory + "/control.stdout").st_size, 32)
                            self.assertLessEqual(os.stat(directory + "/control.stderr").st_size, 32)
                        finally:
                            if child:
                                child.close_writers()
                            module.close_all()
                            os.close(rootfd)

    def test_precreation_cancel_and_expiry(self):
        for program in ("setup", "teardown"):
            for expired in (False, True):
                module = load_program(program)
                if expired:
                    module.deadline = time.monotonic() - 1
                else:
                    module.cancel(signal.SIGTERM, None)
                with mock.patch.object(module.subprocess, "Popen") as factory:
                    with self.assertRaises(module.FixtureFailure):
                        module.command(-1, "unused", ["info", "-plist"])
                    factory.assert_not_called()
                    self.assertEqual(module.owned, [])

    def test_primary_and_all_close_causes_retained(self):
        for program in ("setup", "teardown"):
            module = load_program(program)
            primary = RuntimeError("actual_primary")
            first, second = OSError("first_close"), OSError("second_close")
            module.owned[:] = [101, 102]  # Pure close-fault simulation; no OS FD authority.
            def action():
                raise primary
            with mock.patch.object(module.os, "close", side_effect=[first, second]) as close:
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    with self.assertRaises(module.FixtureFailure) as failure:
                        module.finalize(action)
            self.assertIs(failure.exception.causes[0], primary)
            self.assertEqual(failure.exception.causes[1].causes, (first, second))
            self.assertEqual(close.call_count, 2)
            self.assertEqual(module.owned, [])
            self.assertEqual(output.getvalue(), "")

    def test_private_record_short_write(self):
        for program in ("setup", "teardown"):
            module = load_program(program)
            with tempfile.TemporaryDirectory() as directory:
                rootfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with mock.patch.object(module.os, "write", return_value=0):
                        with self.assertRaises(module.FixtureFailure):
                            module.private_bytes(rootfd, "receipt", b"private")
                    self.assertEqual(os.stat(directory + "/receipt").st_size, 0)
                finally:
                    module.close_all()
                    os.close(rootfd)

    def test_finalization_close_then_success_and_cancel(self):
        for program in ("setup", "teardown"):
            for cancellation in (False, True):
                module = load_program(program)
                module.owned[:] = [101, 102]
                closed = []
                def close(fd):
                    closed.append(fd)
                    if cancellation:
                        module.cancel(signal.SIGINT, None)
                with mock.patch.object(module.os, "close", side_effect=close):
                    with contextlib.redirect_stdout(io.StringIO()) as output:
                        if cancellation:
                            with self.assertRaises(module.FixtureFailure):
                                module.finalize(lambda: {"complete": True})
                        else:
                            module.finalize(lambda: {"complete": True})
                self.assertEqual(closed, [102, 101])
                self.assertEqual(module.owned, [])
                self.assertEqual(bool(output.getvalue()), not cancellation)


if __name__ == "__main__":
    unittest.main()
