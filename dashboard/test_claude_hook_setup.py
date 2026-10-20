"""Disposable Claude Code hook setup and durable receipt checks."""
import json
import os
import time
import unittest
from unittest.mock import patch

from dashboard import claude_hook_setup as setup
from dashboard.resource_registration import RegistrationConflict
from dashboard.resource_settings import SettingsPublicationError
from hub import installed_client_admission as admission
from hub.tests import test_installed_client_admission as package_fixture


class ClaudeHookSetup(unittest.TestCase):
    native_image = staticmethod(package_fixture.InstalledClientPackage.native_image)
    digest = package_fixture.InstalledClientPackage.digest

    def setUp(self):
        package_fixture.InstalledClientPackage.setUp(self)
        self.configuration_root = self.base / 'claude configuration'
        self.configuration_root.mkdir(mode=0o700)
        self.configuration = self.configuration_root / 'settings.json'
        self.records = self.base / 'private records'
        self.records.mkdir(mode=0o700)
        self.receipt = self.records / 'claude-hook.json'

    def run_setup(self, operation, *, apply=True):
        return setup.run_setup(installation_id=self.installation_id, selection=str(self.selection),
            receipt=str(self.receipt), operation=operation, apply=apply,
            configuration_path=str(self.configuration),
            deadline=time.monotonic() + 2)

    def test_missing_settings_preview_install_remove_restore_and_receipt_privacy(self):
        self.assertEqual(self.run_setup('install', apply=False)['outcome'], 'ready')
        self.assertFalse(self.configuration.exists())
        self.assertFalse(self.receipt.exists())

        self.assertEqual(self.run_setup('install')['outcome'], 'applied')
        value = json.loads(self.configuration.read_bytes())
        group = value['hooks']['SessionStart'][0]
        self.assertEqual(group['matcher'], 'startup|resume|fork')
        self.assertEqual(group['hooks'][0]['args'], ['claude-code-hook', '--client-installation',
            self.installation_id, '--selection', str(self.selection)])
        record = json.loads(self.receipt.read_bytes())
        self.assertIsNone(record['pending'])
        self.assertEqual(record['state']['current']['installationId'], self.installation_id)
        self.assertEqual(self.configuration.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b'PRIVATE_SENTINEL', self.receipt.read_bytes())

        self.assertEqual(self.run_setup('remove')['outcome'], 'applied')
        self.assertEqual(json.loads(self.configuration.read_bytes()), {})
        removed = json.loads(self.receipt.read_bytes())
        self.assertIsNone(removed['state']['current'])
        self.assertIsNotNone(removed['state']['saved'])
        self.assertEqual(self.run_setup('restore')['outcome'], 'applied')
        self.assertEqual(json.loads(self.configuration.read_bytes())['hooks']['SessionStart'][0], group)

    def test_unrelated_hooks_settings_secrets_and_number_tokens_survive(self):
        original = (b'{"large":1e9999,"secret":"PRIVATE_SENTINEL","hooks":{"SessionStart":'
                    b'[{"matcher":"clear","hooks":[{"type":"command","command":"/keep",'
                    b'"args":[]}]}],"Stop":[{"hooks":[]}]}}\n')
        self.configuration.write_bytes(original)
        self.configuration.chmod(0o600)
        self.run_setup('install')
        changed = json.loads(self.configuration.read_bytes(), parse_float=str)
        self.assertEqual(changed['large'], '1e9999')
        self.assertEqual(changed['secret'], 'PRIVATE_SENTINEL')
        self.assertEqual(changed['hooks']['SessionStart'][0]['matcher'], 'clear')
        self.assertEqual(changed['hooks']['Stop'], [{'hooks': []}])
        self.assertIn(b'1e9999', self.configuration.read_bytes())
        self.assertNotIn(b'PRIVATE_SENTINEL', self.receipt.read_bytes())
        self.run_setup('remove')
        after = json.loads(self.configuration.read_bytes(), parse_float=str)
        self.assertEqual(after, json.loads(original, parse_float=str))

    def test_install_updates_only_the_exact_receipt_owned_group(self):
        self.run_setup('install')
        old = 'f' * 64
        settings = json.loads(self.configuration.read_bytes())
        settings['hooks']['SessionStart'][0]['hooks'][0]['args'][2] = old
        self.configuration.write_text(json.dumps(settings) + '\n')
        receipt = json.loads(self.receipt.read_bytes())
        current = receipt['state']['current']
        current['installationId'] = old
        current['group']['hooks'][0]['args'][2] = old
        self.receipt.write_bytes(setup.durable._encode(receipt))

        self.assertEqual(self.run_setup('install')['outcome'], 'applied')
        updated = json.loads(self.configuration.read_bytes())
        self.assertEqual(updated['hooks']['SessionStart'][0]['hooks'][0]['args'][2],
                         self.installation_id)
        committed = json.loads(self.receipt.read_bytes())
        self.assertEqual(committed['state']['current']['installationId'], self.installation_id)

    def test_interrupted_receipt_commit_requires_and_completes_recovery(self):
        real_write = setup.durable._ReceiptStore.write
        calls = 0
        def interrupt_commit(store, value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise setup.ClaudeHookSetupError('claude_hook_receipt_incomplete')
            return real_write(store, value)
        with patch.object(setup.durable._ReceiptStore, 'write', interrupt_commit):
            with self.assertRaisesRegex(SettingsPublicationError, '^settings_receipt_pending$'):
                self.run_setup('install')
        pending = self.receipt.read_bytes()
        self.assertIsNotNone(json.loads(pending)['pending'])
        published = self.configuration.read_bytes()
        with self.assertRaisesRegex(setup.ClaudeHookSetupError, '^claude_hook_recovery_required$'):
            self.run_setup('remove')
        self.assertEqual(self.run_setup('recover', apply=False)['outcome'], 'recovery_ready')
        self.assertEqual(self.receipt.read_bytes(), pending)
        self.assertEqual(self.run_setup('recover')['outcome'], 'recovered')
        self.assertEqual(self.configuration.read_bytes(), published)
        self.assertIsNone(json.loads(self.receipt.read_bytes())['pending'])

    def test_unowned_literal_hook_and_changed_owned_group_refuse(self):
        handler = {'type': 'command', 'command': admission.STABLE_FRONTEND,
                   'args': ['claude-code-hook', '--client-installation', self.installation_id,
                            '--selection', str(self.selection)]}
        self.configuration.write_text(json.dumps({'hooks': {'SessionStart': [
            {'matcher': 'startup', 'hooks': [handler]}]}}) + '\n')
        self.configuration.chmod(0o600)
        with self.assertRaisesRegex(RegistrationConflict, '^registration_not_owned$'):
            self.run_setup('install')
        self.configuration.write_text('{}\n')
        self.run_setup('install')
        changed = json.loads(self.configuration.read_bytes())
        changed['hooks']['SessionStart'][0]['matcher'] = 'startup'
        self.configuration.write_text(json.dumps(changed) + '\n')
        with self.assertRaisesRegex(RegistrationConflict, '^registration_changed$'):
            self.run_setup('remove')

    def test_file_appearing_at_absent_commit_is_preserved_and_requires_review(self):
        foreign = b'{"foreign":"PRIVATE_SENTINEL"}\n'
        real_link = os.link
        def appear_before_link(source, destination, **options):
            self.configuration.write_bytes(foreign)
            self.configuration.chmod(0o600)
            return real_link(source, destination, **options)
        with patch('dashboard.resource_settings.os.link', side_effect=appear_before_link):
            with self.assertRaisesRegex(SettingsPublicationError, '^settings_write_failed$'):
                self.run_setup('install')
        self.assertEqual(self.configuration.read_bytes(), foreign)
        self.assertIsNotNone(json.loads(self.receipt.read_bytes())['pending'])
        with self.assertRaisesRegex(setup.ClaudeHookSetupError, '^claude_hook_recovery_conflict$'):
            self.run_setup('recover')
        self.assertEqual(self.configuration.read_bytes(), foreign)

    def test_no_pending_recovery_refuses_malformed_settings_without_writing(self):
        self.run_setup('install')
        receipt = self.receipt.read_bytes()
        for malformed in (b'[]\n', b'{"hooks":[]}\n'):
            with self.subTest(malformed=malformed):
                self.configuration.write_bytes(malformed)
                with self.assertRaisesRegex(RegistrationConflict, '^configuration_invalid$'):
                    self.run_setup('recover')
                self.assertEqual(self.configuration.read_bytes(), malformed)
                self.assertEqual(self.receipt.read_bytes(), receipt)


if __name__ == '__main__':
    unittest.main()
