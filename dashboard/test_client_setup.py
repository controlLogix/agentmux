"""Disposable terminal setup and durable-receipt checks; no native client runs."""
import contextlib
import fcntl
import io
import json
import os
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dashboard import client_setup as setup
from dashboard.resource_registration import RegistrationConflict
from dashboard.resource_settings import SettingsPublicationError
from hub.tests import test_installed_client_admission as package_fixture


class ClientSetup(unittest.TestCase):
    native_image = staticmethod(package_fixture.InstalledClientPackage.native_image)
    digest = package_fixture.InstalledClientPackage.digest

    def setUp(self):
        # Reuse the existing small installed-package fixture. Its native checker
        # is substituted; this suite does not qualify the installed Python payload.
        package_fixture.InstalledClientPackage.setUp(self)
        self.desktop = self.base / 'desktop-settings'
        self.desktop.mkdir(mode=0o700)
        self.configuration = self.desktop / 'config.json'
        self.before = {'theme': 'dark', 'mcpServers': {'unrelated': {'env': {'TOKEN': 'PRIVATE_SENTINEL'}}}}
        self.configuration.write_text(json.dumps(self.before))
        self.configuration.chmod(0o600)
        self.records = self.base / 'private-records'
        self.records.mkdir(mode=0o700)
        self.receipt = self.records / 'desktop.json'
        boundary = patch('dashboard.client_setup._configuration', return_value=str(self.configuration))
        boundary.start()
        self.addCleanup(boundary.stop)

    def run_setup(self, operation, *, apply=True):
        return setup.run_setup(installation_id=self.installation_id, selection=str(self.selection),
            receipt=str(self.receipt), operation=operation, apply=apply, deadline=time.monotonic() + 2)

    def test_preview_is_read_only_and_apply_remove_restore_persist_full_ownership(self):
        original = self.configuration.read_bytes()
        self.assertEqual(self.run_setup('install', apply=False)['outcome'], 'ready')
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.configuration.read_bytes(), original)
        self.assertEqual(self.run_setup('install')['outcome'], 'applied')
        receipt = json.loads(self.receipt.read_bytes())
        self.assertIsNone(receipt['pending'])
        self.assertEqual(receipt['state']['current']['installationId'], self.installation_id)
        self.assertEqual(receipt['state']['current']['configurationPath'], str(self.configuration))
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b'PRIVATE_SENTINEL', self.receipt.read_bytes())
        added = json.loads(self.configuration.read_bytes())
        self.assertEqual(added['mcpServers']['unrelated'], self.before['mcpServers']['unrelated'])
        self.run_setup('remove')
        self.assertEqual(json.loads(self.configuration.read_bytes()), self.before)
        removed = json.loads(self.receipt.read_bytes())
        self.assertIsNone(removed['state']['current'])
        self.assertIsNotNone(removed['state']['saved'])
        self.run_setup('restore')
        self.assertEqual(json.loads(self.configuration.read_bytes()), added)
        self.assertIsNone(json.loads(self.receipt.read_bytes())['pending'])

    def test_commit_failure_after_publication_recovers_only_the_receipt(self):
        real_write = setup._ReceiptStore.write
        calls = 0
        def fail_commit(store, value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise setup.ClientSetupError('client_setup_receipt_incomplete')
            return real_write(store, value)
        with patch.object(setup._ReceiptStore, 'write', fail_commit):
            with self.assertRaisesRegex(SettingsPublicationError, '^settings_receipt_pending$'):
                self.run_setup('install')
        receipt = json.loads(self.receipt.read_bytes())
        self.assertIsNotNone(receipt['pending'])
        published = self.configuration.read_bytes()
        with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_recovery_required$'):
            self.run_setup('install')
        self.assertEqual(self.run_setup('recover', apply=False)['outcome'], 'recovery_ready')
        self.assertIsNotNone(json.loads(self.receipt.read_bytes())['pending'])
        self.assertEqual(self.run_setup('recover')['outcome'], 'recovered')
        self.assertEqual(self.configuration.read_bytes(), published)
        self.assertIsNone(json.loads(self.receipt.read_bytes())['pending'])
        self.run_setup('remove')
        self.assertEqual(json.loads(self.configuration.read_bytes()), self.before)

    def replace_configuration(self):
        replacement = self.configuration.with_name('replacement.json')
        replacement.write_bytes(self.configuration.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(self.configuration)

    def test_final_publication_check_keeps_pending_receipt(self):
        real_registration = setup.desktop_registration
        @contextlib.contextmanager
        def replaced_after_yield(*args, **kwargs):
            with real_registration(*args, **kwargs) as publication:
                yield publication
                self.replace_configuration()
        with patch.object(setup, 'desktop_registration', replaced_after_yield):
            with self.assertRaises(SettingsPublicationError):
                self.run_setup('install')
        self.assertIsNotNone(json.loads(self.receipt.read_bytes())['pending'])
        published = self.configuration.read_bytes()
        self.assertEqual(self.run_setup('recover')['outcome'], 'recovered')
        self.assertEqual(self.configuration.read_bytes(), published)

    def test_final_recovery_check_keeps_pending_receipt(self):
        with patch.object(setup, 'desktop_registration', side_effect=RegistrationConflict('configuration_changed')):
            with self.assertRaises(RegistrationConflict):
                self.run_setup('install')
        pending = self.receipt.read_bytes()
        real_snapshot = setup.desktop_settings_snapshot
        @contextlib.contextmanager
        def replaced_after_yield(*args, **kwargs):
            with real_snapshot(*args, **kwargs) as snapshot:
                yield snapshot
                self.replace_configuration()
        with patch.object(setup, 'desktop_settings_snapshot', replaced_after_yield):
            with self.assertRaisesRegex(RegistrationConflict, '^configuration_changed$'):
                self.run_setup('recover')
        self.assertEqual(self.receipt.read_bytes(), pending)
        self.assertEqual(self.run_setup('recover')['outcome'], 'recovered')

    def test_committed_receipt_sync_failure_requires_native_recheck(self):
        real_write, real_sync = setup._ReceiptStore.write, os.fsync
        calls = 0
        def fail_committed_directory_sync(store, value):
            nonlocal calls
            calls += 1
            if calls != 2:
                return real_write(store, value)
            def sync(fd):
                if fd == store.parent.fd:
                    raise OSError('PRIVATE_SENTINEL')
                return real_sync(fd)
            with patch.object(setup.os, 'fsync', sync):
                return real_write(store, value)
        with patch.object(setup._ReceiptStore, 'write', fail_committed_directory_sync):
            with self.assertRaisesRegex(SettingsPublicationError, '^settings_receipt_pending$'):
                self.run_setup('install')
        self.assertIsNone(json.loads(self.receipt.read_bytes())['pending'])
        published = self.configuration.read_bytes()
        with patch.object(setup.os, 'fsync', wraps=real_sync) as sync:
            self.assertEqual(self.run_setup('recover')['outcome'], 'no_pending_change')
            self.assertGreaterEqual(sync.call_count, 2)
        self.assertEqual(self.configuration.read_bytes(), published)
        changed = json.loads(published)
        changed['mcpServers']['agentmux']['args'].append('foreign')
        self.configuration.write_text(json.dumps(changed))
        with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_recovery_conflict$'):
            self.run_setup('recover')

    def test_failure_before_publication_reconciles_to_previous_ownership(self):
        original = self.configuration.read_bytes()
        with patch('dashboard.client_setup.desktop_registration',
                   side_effect=RegistrationConflict('configuration_changed')):
            with self.assertRaisesRegex(RegistrationConflict, '^configuration_changed$'):
                self.run_setup('install')
        self.assertEqual(self.configuration.read_bytes(), original)

        self.assertIsNotNone(json.loads(self.receipt.read_bytes())['pending'])
        self.run_setup('recover')
        recovered = json.loads(self.receipt.read_bytes())
        self.assertIsNone(recovered['pending'])
        self.assertIsNone(recovered['state']['current'])
        self.assertEqual(self.configuration.read_bytes(), original)

    def test_settings_lock_covers_install_and_recovery_receipt_commit(self):
        real_write = setup._ReceiptStore.write
        commits = 0
        def check_locked(store, value):
            nonlocal commits
            if value['pending'] is None:
                commits += 1
                fd = os.open(self.desktop, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(fd)
            return real_write(store, value)
        with patch.object(setup._ReceiptStore, 'write', check_locked):
            self.run_setup('install')
            with patch.object(setup, 'desktop_registration', side_effect=RegistrationConflict('configuration_changed')):
                with self.assertRaises(RegistrationConflict):
                    self.run_setup('remove')
            self.run_setup('recover')
        self.assertEqual(commits, 2)

    def test_receipt_rejects_inconsistent_pending_ownership(self):
        with patch.object(setup, 'desktop_registration', side_effect=RegistrationConflict('configuration_changed')):
            with self.assertRaises(RegistrationConflict):
                self.run_setup('install')
        value = json.loads(self.receipt.read_bytes())
        value['pending']['operation'] = 'remove'
        self.receipt.write_bytes(setup._encode(value))
        original = self.configuration.read_bytes()
        with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_receipt_invalid$'):
            self.run_setup('recover')
        self.assertEqual(self.configuration.read_bytes(), original)

    def test_recovery_refuses_unrelated_edits_and_wrong_enrollment(self):
        with patch('dashboard.client_setup.desktop_registration',
                   side_effect=RegistrationConflict('configuration_changed')):
            with self.assertRaises(RegistrationConflict):
                self.run_setup('install')
        pending = self.receipt.read_bytes()
        changed = json.loads(self.configuration.read_bytes())
        changed['later'] = True
        self.configuration.write_text(json.dumps(changed))
        with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_recovery_conflict$'):
            self.run_setup('recover')
        self.assertEqual(self.receipt.read_bytes(), pending)
        self.assertTrue(json.loads(self.configuration.read_bytes())['later'])
        another = self.selection.with_name('another-enrollment.json')
        another.write_bytes(self.selection.read_bytes())
        another.chmod(0o600)
        with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_owner_mismatch$'):
            setup.run_setup(installation_id=self.installation_id, selection=str(another),
                receipt=str(self.receipt), operation='recover', apply=True, deadline=time.monotonic() + 2)
        self.assertEqual(self.receipt.read_bytes(), pending)

    def test_unowned_entry_and_foreign_receipt_are_not_replaced(self):
        original = self.configuration.read_bytes()
        self.receipt.write_bytes(b'UNRELATED_RECEIPT')
        self.receipt.chmod(0o600)
        with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_receipt_invalid$'):
            self.run_setup('install')
        self.assertEqual(self.receipt.read_bytes(), b'UNRELATED_RECEIPT')
        self.assertEqual(self.configuration.read_bytes(), original)
        self.receipt.unlink()
        data = json.loads(original)
        data['mcpServers']['agentmux'] = {'command': '/unrelated/application', 'args': []}
        self.configuration.write_text(json.dumps(data))
        with self.assertRaisesRegex(RegistrationConflict, '^registration_not_owned$'):
            self.run_setup('install')
        self.assertFalse(self.receipt.exists())
        self.assertEqual(json.loads(self.configuration.read_bytes()), data)

    def test_interrupted_initial_receipt_does_not_change_settings(self):
        original, real_write = self.configuration.read_bytes(), os.write
        calls = 0
        def partial_write(fd, body):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, body[:1])
            raise OSError('PRIVATE_SENTINEL')
        with patch.object(setup.os, 'write', partial_write):
            with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_receipt_incomplete$'):
                self.run_setup('install')
        self.assertEqual(self.configuration.read_bytes(), original)
        self.assertEqual(self.receipt.read_bytes(), b'{')
        with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_receipt_invalid$'):
            self.run_setup('recover')
        self.assertEqual(self.receipt.read_bytes(), b'{')

    def test_receipt_created_during_initial_write_is_preserved(self):
        original, real_open = self.configuration.read_bytes(), os.open
        def competing_create(path, flags, *args, **kwargs):
            if path == self.receipt.name and flags & os.O_EXCL:
                fd = real_open(path, flags, *args, **kwargs)
                try:
                    os.write(fd, b'UNRELATED_RECEIPT')
                finally:
                    os.close(fd)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(setup.os, 'open', competing_create):
            with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_receipt_incomplete$'):
                self.run_setup('install')
        self.assertEqual(self.receipt.read_bytes(), b'UNRELATED_RECEIPT')
        self.assertEqual(self.configuration.read_bytes(), original)

    def test_terminal_requires_apply_and_withholds_private_paths(self):
        args = ['--client-installation', self.installation_id, '--selection', str(self.selection),
                '--receipt', str(self.receipt), '--operation', 'install']
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertEqual(setup.main(args), 0)
        self.assertEqual(json.loads(output.getvalue())['outcome'], 'ready')
        self.assertFalse(self.receipt.exists())
        self.assertNotIn(str(self.base), output.getvalue() + error.getvalue())
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertEqual(setup.main(args + ['--PRIVATE_SENTINEL']), 1)
        self.assertNotIn('PRIVATE_SENTINEL', output.getvalue() + error.getvalue())
        self.assertFalse(self.receipt.exists())


class NativeAccountHome(unittest.TestCase):
    def test_environment_home_cannot_redirect_native_settings(self):
        account = SimpleNamespace(pw_uid=501, pw_dir='/Users/native-account')
        with patch.object(setup.os, 'getuid', return_value=501), patch.object(setup.os, 'geteuid', return_value=501), \
                patch.object(setup.pwd, 'getpwuid', return_value=account) as lookup, \
                patch.dict(os.environ, {'HOME': '/tmp/foreign-home'}):
            self.assertEqual(setup._configuration(),
                '/Users/native-account/Library/Application Support/Claude/claude_desktop_config.json')
            lookup.assert_called_once_with(501)

    def test_missing_invalid_or_mismatched_native_account_is_refused(self):
        for account, effective in ((SimpleNamespace(pw_uid=502, pw_dir='/Users/native'), 501),
                                   (SimpleNamespace(pw_uid=501, pw_dir='relative'), 501),
                                   (SimpleNamespace(pw_uid=501, pw_dir='/Users/native'), 0)):
            with self.subTest(effective=effective), patch.object(setup.os, 'getuid', return_value=501), \
                    patch.object(setup.os, 'geteuid', return_value=effective), \
                    patch.object(setup.pwd, 'getpwuid', return_value=account):
                with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_native_home_unavailable$'):
                    setup._configuration()
        with patch.object(setup.pwd, 'getpwuid', side_effect=KeyError('PRIVATE_SENTINEL')):
            with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_native_home_unavailable$'):
                setup._configuration()


if __name__ == '__main__':
    unittest.main()
