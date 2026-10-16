"""Draft pure controls. No watchdog, Bash, tmux, native API or child is launched."""
import ast
import ctypes as C
import hashlib
import os
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name('idle_watchdog_fixture.py')
PIN = '6fae75d474456a0ec2682e5316ee73589c77d06f7fff787402661bdba23e8f57'


def definitions():
    fd = os.open(str(SOURCE), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        raw = os.read(fd, 262145)
        after = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
        assert before.st_nlink == 1 and not before.st_mode & 0o022
        assert len(raw) == before.st_size and len(raw) <= 262144
        assert hashlib.sha256(raw).hexdigest() == PIN
        assert all(getattr(before, k) == getattr(after, k) for k in
                   ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
                    'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    finally:
        os.close(fd)
    module = types.ModuleType('held_idle_fixture_definitions')
    exec(compile(raw, '<held-idle-fixture>', 'exec'), module.__dict__)
    return module.__dict__, raw


class IdleFixtureControls(unittest.TestCase):
    def setUp(self):
        self.m, self.raw = definitions()

    def owner(self):
        value = self.m['Owned'].__new__(self.m['Owned'])
        value.child = types.SimpleNamespace(pid=777, returncode=None)
        value.joined = False
        return value

    def library(self, rows=None, short=False, change=False, zero_list=False, zombie=False):
        m = self.m
        rows = [(2, 1), (3, 1), (200, 1), (9, 6)] if rows is None else rows
        seen, list_calls = [], []
        def pidinfo(pid, flavor, argument, pointer, size):
            self.assertEqual(pid, 777)
            value = pointer._obj
            if flavor == 3:
                value.pid, value.ppid, value.uid = 777, os.getpid(), os.geteuid()
                value.status, value.flags = (5 if zombie else 3), 0
                value.start_sec, value.start_usec = 123, 456
                return C.sizeof(m['ProcBSDInfo'])
            self.assertEqual(flavor, 1)
            list_calls.append(True)
            if zero_list:
                return 0
            actual = list(rows)
            if change and len(list_calls) > 1:
                actual = actual[:-1]
            for index, (fd, kind) in enumerate(actual):
                value[index].fd, value[index].kind = fd, kind
            return len(actual) * C.sizeof(m['ProcFDInfo'])
        def pidfdinfo(pid, fd, flavor, pointer, size):
            self.assertEqual((pid, flavor), (777, 1))
            seen.append(fd)
            pointer._obj.vnode.metadata.dev = 12
            pointer._obj.vnode.metadata.ino = 34 if fd in (3, 200) else 99
            return size - 1 if short else size
        return types.SimpleNamespace(proc_pidinfo=pidinfo, proc_pidfdinfo=pidfdinfo), seen

    def test_sdk_layout_expectations(self):
        # Source-level layout check, not native qualification.
        self.assertEqual(tuple(C.sizeof(self.m[n]) for n in ('ProcBSDInfo', 'ProcFDInfo',
            'ProcFileInfo', 'VInfoStat', 'VNodeInfo', 'VNodeFDInfo')), (136, 8, 24, 136, 152, 176))

    def test_all_vnodes_are_inspected_not_only_fd200(self):
        lib, seen = self.library()
        result = self.m['darwin_probe'](self.owner(), (12, 34), lib)
        self.assertEqual(result['matchingFDs'], [3, 200])
        self.assertEqual(seen, [2, 3, 200])
        self.assertTrue(result['completeStableEnumeration'])

    def test_negative_is_complete_enumeration_not_missing_proc_waiver(self):
        lib, seen = self.library(rows=[(2, 1), (9, 6)])
        result = self.m['darwin_probe'](self.owner(), (12, 34), lib)
        self.assertEqual(result['matchingFDs'], [])
        self.assertEqual(seen, [2])
        for changes in ({'short': True}, {'change': True}, {'zero_list': True}, {'zombie': True}):
            lib, _ = self.library(**changes)
            with self.assertRaises(ValueError):
                self.m['darwin_probe'](self.owner(), (12, 34), lib)

    def test_reaped_owner_cannot_supply_query_authority(self):
        owner = self.owner()
        owner.joined = True
        lib, _ = self.library()
        with self.assertRaises(ValueError):
            self.m['darwin_probe'](owner, (12, 34), lib)

    def test_linux_retains_file_identity_assertion_and_fails_on_io_error(self):
        m = self.m
        def metadata(path):
            return types.SimpleNamespace(st_dev=12, st_ino=34 if path.endswith('/200') else 99)
        with mock.patch.dict(m, linux_stamp=lambda owner: 'birth'), \
                mock.patch.object(m['os'], 'listdir', return_value=['0', '2', '200']), \
                mock.patch.object(m['os'], 'stat', side_effect=metadata):
            self.assertEqual(m['linux_probe'](self.owner(), (12, 34))['matchingFDs'], [200])
        with mock.patch.dict(m, linux_stamp=lambda owner: 'birth'), \
                mock.patch.object(m['os'], 'listdir', side_effect=FileNotFoundError(2, 'pure')):
            with self.assertRaises(FileNotFoundError):
                m['linux_probe'](self.owner(), (12, 34))

    def test_capture_acquisition_failure_before_popen_closes_consumed_handles(self):
        m = self.m
        m['owners'][:] = []
        with mock.patch.object(m['os'], 'open', side_effect=[10, OSError(5, 'pure')]), \
                mock.patch.object(m['os'], 'fsync', side_effect=OSError(5, 'pure')), \
                mock.patch.object(m['os'], 'close') as close, \
                mock.patch.object(m['subprocess'], 'Popen') as factory:
            with self.assertRaises(OSError):
                m['Owned']([], {}, Path('/private/tmp/pure'), 'pure')
            factory.assert_not_called()
            close.assert_called_once_with(10)
            self.assertIsNone(m['owners'][0].outfd)

    def test_original_child_and_captures_are_registered_before_return(self):
        m = self.m
        m['owners'][:] = []
        child = types.SimpleNamespace(pid=777, returncode=None)
        with mock.patch.object(m['os'], 'open', side_effect=[10, 11]), \
                mock.patch.object(m['os'], 'close') as close, \
                mock.patch.object(m['subprocess'], 'Popen', return_value=child):
            owner = m['Owned'](['closed'], {}, Path('/private/tmp/pure'), 'pure')
            self.assertIs(m['owners'][0], owner)
            self.assertIs(owner.child, child)
            self.assertFalse(owner.joined)
            close.assert_not_called()

    def test_eof_cleanup_or_expiry_never_qualifies_home_exit(self):
        m = self.m
        owner = types.SimpleNamespace(joined=True, timeout=False, cleanup_eof=False,
                                     capture_errors=[], stdout_bytes=bytearray(b'READY\nTICK\n'))
        self.assertTrue(m['successful_behavior'](owner, 0, b''))
        for output in (b'READY\nEOF_CLEANUP\n', b'READY\nLIFETIME_EXPIRED\n'):
            owner.stdout_bytes = bytearray(output)
            self.assertFalse(m['successful_behavior'](owner, 0, b''))
        owner.stdout_bytes = bytearray(b'READY\nTICK\n')
        owner.cleanup_eof = True
        self.assertFalse(m['successful_behavior'](owner, 0, b''))
        owner.cleanup_eof = False
        self.assertFalse(m['successful_behavior'](owner, 0, b'UNEXPECTED_TMUX\n'))

    def join_fake(self, events, broken_progress=False):
        m = self.m
        owner = self.owner()
        owner.timeout = owner.cleanup_eof = owner.output_joined = False
        owner.capture_errors = []
        owner.stdout_bytes = bytearray(b'READY\nTICK\n')
        owner.close_captures = mock.Mock()
        clock, waits = [0], []
        stdin = types.SimpleNamespace(closed=False)
        def close_input():
            stdin.closed = True
        stdin.close = close_input
        owner.child.stdin = stdin
        owner.child.stdout = mock.Mock()
        remaining = iter(events)
        def wait(timeout):
            waits.append(timeout)
            at, expired = next(remaining)
            clock[0] = at
            if expired:
                raise m['subprocess'].TimeoutExpired('pure', timeout)
            owner.child.returncode = 0
        owner.child.wait = wait
        with mock.patch.object(m['time'], 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(m['select'], 'select', return_value=([owner.child.stdout], [], [])), \
                mock.patch.object(m['os'], 'read', return_value=b''), \
                mock.patch.dict(m, print=mock.Mock(side_effect=BrokenPipeError() if broken_progress else None)):
            self.assertEqual(owner.join(8), 0)
        self.assertTrue(owner.joined and owner.output_joined)
        owner.close_captures.assert_called_once_with()
        return owner, waits

    def test_intermediate_poll_preserves_eight_second_budget(self):
        owner, waits = self.join_fake([(5, True), (7, False)])
        self.assertEqual(waits, [5, 3])
        self.assertFalse(owner.timeout or owner.cleanup_eof)
        self.assertTrue(self.m['successful_behavior'](owner, 0, b''))

    def test_actual_expiry_and_repeated_broken_progress_retain_owner(self):
        owner, waits = self.join_fake([(5, True), (8, True), (13, True), (14, False)], True)
        self.assertEqual(waits, [5, 3, 5, 5])
        self.assertTrue(owner.timeout and owner.cleanup_eof)
        self.assertIn('progress_output_failed', owner.capture_errors)
        self.assertFalse(self.m['successful_behavior'](owner, 0, b''))

    def test_zero_exit_after_original_deadline_cannot_pass(self):
        owner, waits = self.join_fake([(9, False)])
        self.assertEqual(waits, [5])
        self.assertTrue(owner.timeout)
        self.assertFalse(self.m['successful_behavior'](owner, 0, b''))

    def test_missing_home_guard_mutation_is_caught_despite_redirected_stderr(self):
        owner = types.SimpleNamespace(joined=True, timeout=False, cleanup_eof=False,
                                     capture_errors=[], stdout_bytes=bytearray(b'READY\nTICK\n'))
        # Model deletion of the home guard: tmux is invoked, returns failure,
        # then the watchdog exits zero with its stderr suppressed by production.
        self.assertTrue(self.m['successful_home_behavior'](owner, 0, b'', b''))
        self.assertFalse(self.m['successful_home_behavior'](owner, 0, b'', b'TMUX\n'))
        self.assertIn(b'capture_bytes(sentinel)', self.raw)
        self.assertIn(b'printf "TMUX', self.raw)

    def test_sentinel_append_failure_continues_exact_loop_not_break(self):
        program = self.m['tmux_sentinel_program'](Path('/private/tmp/pure-sentinel'))
        self.assertEqual(program,
            b'#!/bin/sh\nif printf "TMUX\\n" >> /private/tmp/pure-sentinel; then\n'
            b'  exit 125\nelse\n  exit 0\nfi\n')
        self.assertNotIn(b'exec ', program)
        self.assertNotIn(b'read ', program)
        source = self.m['held'](Path('/Users/ryan/GitHub/agentmux/agentmux.sh'),
                                self.m['SOURCE_SHA256'])
        body = self.m['heredoc'](source)
        lines = body.splitlines()
        tmux = next(i for i, line in enumerate(lines) if line.startswith('  tmux -L '))
        self.assertTrue(lines[tmux].endswith('list-sessions >/dev/null 2>&1 || break'))
        self.assertTrue(lines[tmux + 1].endswith('idle >> "$RUNDIR/.idle.log" 2>&1'))
        self.assertEqual(lines[tmux + 2], 'done')
        self.assertTrue(any(line.startswith('while sleep ') for line in lines[:tmux]))
        self.assertLess(self.raw.index(b'os.rmdir(run)'), self.raw.index(b'actual.tick()'))
        self.assertIn(b'not os.path.lexists(run) and not os.path.lexists(home)', self.raw)
        # Pure model only: missing-run redirection prevents idle execution;
        # tmux status zero enters another sleep, not the zero-exit break.
        owner, _ = self.join_fake([(5, True), (8, True), (9, False)])
        owner.stdout_bytes.extend(b'READY\nEOF_CLEANUP\n')
        self.assertFalse(self.m['successful_home_behavior'](owner, 0, b'', b''))
        owner.timeout = owner.cleanup_eof = False
        self.assertFalse(self.m['successful_home_behavior'](owner, 0, b'', b''))

    def test_mutation_requires_normal_behavior_not_merely_home_refusal(self):
        self.assertIn(b'require(successful_behavior(actual, code, stderr) and', self.raw)
        owner = types.SimpleNamespace(joined=True, timeout=False, cleanup_eof=False,
                                     capture_errors=[], stdout_bytes=bytearray(b'READY\nTICK\n'))
        for code, stderr, output in ((1, b'', b'READY\nTICK\n'),
                                     (0, b'error', b'READY\nTICK\n'),
                                     (0, b'', b'READY\n')):
            owner.stdout_bytes = bytearray(output)
            home = self.m['successful_home_behavior'](owner, code, stderr, b'TMUX\n')
            admitted = self.m['successful_behavior'](owner, code, stderr) and not home
            self.assertFalse(admitted)

    def test_exact_heredoc_and_source_scope(self):
        body = b'#!/usr/bin/env bash\n# CLOSE EVERY DESCRIPTOR\n[ -d "$RUNDIR" ] || break\n'
        source = b'prefix\n  cat > "$self" <<WATCHDOG\n' + body + b'WATCHDOG\nrest\n'
        self.assertEqual(self.m['heredoc'](source), body.decode())
        for changed in (source.replace(b'<<WATCHDOG', b'<<OTHER'), source + source):
            with self.assertRaises(ValueError):
                self.m['heredoc'](changed)

    def test_no_signal_group_adoption_or_detached_launcher_api(self):
        tree = ast.parse(self.raw)
        forbidden = {'kill', 'killpg', 'terminate', 'poll', 'setsid', 'getpgid', 'fork', 'waitpid'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden)
        self.assertNotIn(b'start_idle_watchdog(', self.raw)
        self.assertIn(b'actual.join(removed_at + 8)', self.raw)


if __name__ == '__main__':
    unittest.main()
