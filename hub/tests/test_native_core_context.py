"""Native file custody controls, not installed workflow qualification."""
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from hub.native_core_context import _PreparedFile, NativeCoreError
from hub.installed_client_admission import InstalledClientError
from hub.native_core_context import NativeCoreContext


class NativeHarnessCommands(unittest.TestCase):
    def test_harness_uses_only_selected_paths_and_literal_arguments(self):
        context = object.__new__(NativeCoreContext)
        context.root = '/selected/installed'; context.home = '/Users/selected'
        context.codex_package_root = '/selected/codex'; context.workspaces = ('/approved/repo',)
        context.tools = {role: SimpleNamespace(path='/selected/' + role)
                         for role in ('bash', 'tmux', 'codexBinary')}
        with patch.object(context, 'recheck'), patch.dict(os.environ, {'PATH': '/untrusted', 'AGENTMUX_BIN': '/untrusted/bin',
                'AGENTMUX_NO_BYPASS': '1'}):
            command = context.harness_command('spawn', ['repo-worker-one', '--cli', 'codex', '--cwd', '/approved/repo'],
                hub_home='/owned/home', socket_name='owned-socket')
        self.assertEqual(command.arguments, ('/selected/bash', '/selected/installed/app/agentmux.sh',
            'spawn', 'repo-worker-one', '--cli', 'codex', '--cwd', '/approved/repo'))
        self.assertEqual(command.environment['PATH'], '/selected/installed/app/native-bin:/usr/bin:/bin')
        self.assertEqual(command.environment['CODEX_MANAGED_PACKAGE_ROOT'], '/selected/codex')
        self.assertNotIn('AGENTMUX_BIN', command.environment)
        self.assertEqual(command.environment['HOME'], '/Users/selected')
        self.assertEqual(command.environment['AGENTMUX_NO_BYPASS'], '1')

    def test_other_provider_cannot_use_native_core_harness(self):
        context = object.__new__(NativeCoreContext); context.workspaces = ()
        with self.assertRaises(NativeCoreError):
            context.harness_command('spawn', ['worker', '--cli', 'other'], hub_home='/owned/home', socket_name='owned')


@unittest.skipUnless(os.uname().sysname == 'Darwin', 'requires native macOS admission')
class PreparedCoreCustody(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='a703-', dir=str(Path.home()/'.cache'))
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name).resolve()/'tool'
        self.path.write_bytes(b'original prepared bytes')
        self.path.chmod(0o755)
        self.entry = {'path': str(self.path), 'sha256': 'sha256:' + hashlib.sha256(self.path.read_bytes()).hexdigest()}

    def admit(self):
        return _PreparedFile(self.entry, time.monotonic()+5)

    def test_original_file_stays_held(self):
        held = self.admit()
        try:
            held.check(time.monotonic()+5)
            self.assertEqual(os.pread(held.held.fd, 64, 0), b'original prepared bytes')
        finally:
            held.close()
        self.assertTrue(held.held.closed)

    def test_replacement_with_identical_bytes_refuses(self):
        held = self.admit()
        try:
            replacement = self.path.with_suffix('.new')
            replacement.write_bytes(self.path.read_bytes()); replacement.chmod(0o755)
            replacement.replace(self.path)
            with self.assertRaises(InstalledClientError):
                held.check(time.monotonic()+5)
        finally:
            held.close()

    def test_changed_bytes_refuse(self):
        held = self.admit()
        try:
            self.path.write_bytes(b'substituted bytes')
            with self.assertRaises((InstalledClientError, NativeCoreError)):
                held.check(time.monotonic()+5)
        finally:
            held.close()

    def test_missing_tool_refuses(self):
        self.path.unlink()
        with self.assertRaises(InstalledClientError):
            self.admit()

    def test_writable_by_others_refuses(self):
        self.path.chmod(0o777)
        with self.assertRaises(InstalledClientError):
            self.admit()

    def test_symlink_selection_refuses(self):
        target = self.path.with_suffix('.actual')
        self.path.rename(target); self.path.symlink_to(target)
        with self.assertRaises(NativeCoreError):
            self.admit()

    def test_wrong_digest_refuses(self):
        self.entry['sha256'] = 'sha256:' + '0'*64
        with self.assertRaises(NativeCoreError):
            self.admit()


@unittest.skipUnless(os.uname().sysname == 'Darwin', 'native Unix sockets')
class NativeTransportObservation(unittest.TestCase):
    def setUp(self):
        import secrets
        self.context = object.__new__(NativeCoreContext)
        self.name = 'amux703-control-' + secrets.token_hex(8)
        self.directory = Path('/private/tmp') / ('tmux-' + str(os.getuid()))
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.path = self.directory / self.name
        self.addCleanup(self.path.unlink, missing_ok=True)

    def observe(self):
        return self.context.transport_not_connectable(self.name)

    def socket(self, listening=False):
        import socket
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(stream.close)
        stream.bind(str(self.path))
        self.path.chmod(0o660)
        if listening:
            stream.listen(4)
        return stream

    def test_missing_and_stale_endpoint_are_not_connectable_without_unlink(self):
        self.assertTrue(self.observe())
        stream = self.socket()
        stream.close()
        original = self.path.lstat().st_ino
        self.assertTrue(self.observe())
        self.assertEqual(self.path.lstat().st_ino, original)

    def test_live_listener_is_present(self):
        self.socket(listening=True)
        self.assertFalse(self.observe())

    def test_file_and_symlink_refuse(self):
        self.path.write_text('not socket')
        with self.assertRaises(NativeCoreError): self.observe()
        self.path.unlink()
        self.path.symlink_to('/private/tmp')
        with self.assertRaises(NativeCoreError): self.observe()

    def test_socket_replacement_during_probe_refuses(self):
        import errno
        self.socket().close()
        def replace(path):
            self.path.unlink()
            self.path.write_text('changed')
            return errno.ECONNREFUSED
        with patch('hub.native_core_context.socket.socket') as factory:
            factory.return_value.__enter__.return_value.connect_ex.side_effect = replace
            with self.assertRaises(NativeCoreError): self.observe()

    def test_other_error_and_timeout_refuse(self):
        import errno
        self.socket().close()
        for outcome in (errno.EACCES, errno.ENOENT, errno.ETIMEDOUT):
            with self.subTest(outcome=outcome), patch('hub.native_core_context.socket.socket') as factory:
                factory.return_value.__enter__.return_value.connect_ex.return_value = outcome
                with self.assertRaises(NativeCoreError): self.observe()
        with patch('hub.native_core_context.socket.socket') as factory:
            factory.return_value.__enter__.return_value.connect_ex.side_effect = TimeoutError()
            with self.assertRaises(TimeoutError): self.observe()

    def test_foreign_leaf_owner_refuses(self):
        self.socket().close()
        original = os.stat
        def foreign(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if path == self.name:
                return SimpleNamespace(st_mode=value.st_mode, st_uid=os.getuid()+1)
            return value
        with patch('hub.native_core_context.os.stat', side_effect=foreign):
            with self.assertRaises(NativeCoreError): self.observe()
