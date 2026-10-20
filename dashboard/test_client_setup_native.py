"""Opt-in native settings composition check using only disposable configuration.

Run only in the coordinator's native qualification slot. This exercises the
setup caller with a substituted disposable settings path. It does not invoke
the installed terminal command, start a client, or touch native Desktop settings.
"""
import fcntl
import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

from dashboard import claude_hook_setup as hook_setup
from dashboard import client_setup as setup
from dashboard.resource_registration import RegistrationConflict
from dashboard.resource_settings import (SettingsPublicationError, desktop_registration,
                                         desktop_settings_snapshot)
from hub.installed_client_admission import admit_installed_client


@unittest.skipUnless(os.environ.get('AGENTMUX_NATIVE_SETTINGS_COMPOSITION') == '1',
                     'requires an explicit native qualification slot')
class NativeDesktopComposition(unittest.TestCase):
    def test_installed_admission_claude_hook_lifecycle_and_absent_settings(self):
        self.assertEqual((platform.system(), platform.machine()), ('Darwin', 'arm64'))
        installation = os.environ['AGENTMUX_NATIVE_CLIENT_ID']
        selection = os.environ['AGENTMUX_NATIVE_ENROLLMENT_SELECTION']
        deadline = time.monotonic() + 120
        admission = admit_installed_client(installation, selection, deadline=deadline)
        try:
            temporary = tempfile.mkdtemp(prefix='agentmux-native-claude-hook-')
            fixture_complete = False
            try:
                directory = Path(temporary).resolve()
                directory.chmod(0o700)
                configuration_root = directory / 'claude-configuration'
                configuration_root.mkdir(mode=0o700)
                configuration = configuration_root / 'settings.json'
                records = directory / 'private-records'
                records.mkdir(mode=0o700)
                receipt = records / 'claude-hook.json'

                def document():
                    return json.loads(configuration.read_bytes(), parse_float=str, parse_int=str)

                def run_setup(operation, *, apply=True):
                    return hook_setup.run_setup(installation_id=installation, selection=selection,
                        receipt=str(receipt), operation=operation,
                        configuration_path=str(configuration), apply=apply, deadline=deadline)

                self.assertEqual(run_setup('install', apply=False)['outcome'], 'ready')
                self.assertFalse(configuration.exists())
                self.assertFalse(receipt.exists())

                self.assertEqual(run_setup('install')['outcome'], 'applied')
                group = document()['hooks']['SessionStart'][0]
                self.assertEqual(group['matcher'], 'startup|resume|fork')
                self.assertEqual(group['hooks'], [{
                    'type': 'command',
                    'command': admission.declaration.command,
                    'args': ['claude-code-hook', '--client-installation', installation,
                             '--selection', selection],
                }])
                committed = json.loads(receipt.read_bytes())
                self.assertIsNone(committed['pending'])
                self.assertEqual(committed['state']['current']['installationId'], installation)
                self.assertEqual(configuration.stat().st_mode & 0o777, 0o600)
                self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)

                self.assertEqual(run_setup('remove')['outcome'], 'applied')
                self.assertEqual(document(), {})
                unrelated = (b'{"large":1e9999,"secret":"DISPOSABLE_SENTINEL","hooks":'
                    b'{"SessionStart":[{"matcher":"clear","hooks":[{"type":"command",'
                    b'"command":"/fixture/unrelated","args":[]}]}],"Stop":[{"hooks":[]}]}}\n')
                configuration.write_bytes(unrelated)
                configuration.chmod(0o600)

                def preserved():
                    current = document()
                    groups = current['hooks']['SessionStart']
                    current['hooks']['SessionStart'] = [item for item in groups if item != group]
                    self.assertEqual(current,
                        json.loads(unrelated, parse_float=str, parse_int=str))
                    self.assertIn(b'1e9999', configuration.read_bytes())
                    self.assertNotIn(b'DISPOSABLE_SENTINEL', receipt.read_bytes())
                    self.assertEqual(configuration.stat().st_mode & 0o777, 0o600)

                self.assertEqual(run_setup('restore')['outcome'], 'applied')
                self.assertEqual(document()['hooks']['SessionStart'][0], group)
                preserved()
                self.assertEqual(run_setup('remove')['outcome'], 'applied')
                self.assertEqual(configuration.read_bytes(), unrelated)

                real_write = hook_setup.durable._ReceiptStore.write
                writes = 0
                def interrupt_commit(store, value):
                    nonlocal writes
                    writes += 1
                    if writes == 2:
                        raise hook_setup.ClaudeHookSetupError('claude_hook_receipt_incomplete')
                    return real_write(store, value)
                with patch.object(hook_setup.durable._ReceiptStore, 'write', interrupt_commit):
                    with self.assertRaisesRegex(SettingsPublicationError,
                                                 '^settings_receipt_pending$'):
                        run_setup('restore')
                pending_record = receipt.read_bytes()
                self.assertIsNotNone(json.loads(pending_record)['pending'])
                published = configuration.read_bytes()
                with self.assertRaisesRegex(hook_setup.ClaudeHookSetupError,
                                             '^claude_hook_recovery_required$'):
                    run_setup('remove')
                self.assertEqual(run_setup('recover', apply=False)['outcome'], 'recovery_ready')
                self.assertEqual(receipt.read_bytes(), pending_record)
                self.assertEqual(run_setup('recover')['outcome'], 'recovered')
                self.assertEqual(configuration.read_bytes(), published)
                self.assertIsNone(json.loads(receipt.read_bytes())['pending'])
                self.assertEqual(run_setup('remove')['outcome'], 'applied')
                self.assertEqual(configuration.read_bytes(), unrelated)
                preserved()

                admission.recheck(deadline=deadline)
                self.assertEqual({item.name for item in directory.iterdir()},
                                 {configuration_root.name, records.name})
                self.assertEqual({item.name for item in configuration_root.iterdir()},
                                 {configuration.name})
                self.assertEqual({item.name for item in records.iterdir()}, {receipt.name})
                fixture_complete = True
            finally:
                if fixture_complete:
                    shutil.rmtree(temporary)
                else:
                    self.retained_fixture = temporary
        finally:
            admission.close()
        self.assertTrue(admission.closed)

    def test_installed_admission_setup_lifecycle_and_retained_rechecks(self):
        self.assertEqual((platform.system(), platform.machine()), ('Darwin', 'arm64'))
        installation = os.environ['AGENTMUX_NATIVE_CLIENT_ID']
        selection = os.environ['AGENTMUX_NATIVE_ENROLLMENT_SELECTION']
        deadline = time.monotonic() + 120
        admission = admit_installed_client(installation, selection, deadline=deadline)
        try:
            temporary = tempfile.mkdtemp(prefix='agentmux-native-settings-')
            fixture_complete = False
            try:
                directory = Path(temporary).resolve()
                directory.chmod(0o700)
                configuration = directory / 'disposable-desktop.json'
                original = (b'{"theme":"dark","large":1e9999,"negativeZero":-0,"mcpServers":'
                    b'{"unrelated":{"command":"/fixture/unrelated","args":["keep"],'
                    b'"env":{"TOKEN":"DISPOSABLE_SENTINEL"}}}}\n')
                configuration.write_bytes(original)
                configuration.chmod(0o600)
                records = directory / 'private-records'
                records.mkdir(mode=0o700)
                receipt = records / 'desktop-setup.json'

                def document():
                    return json.loads(configuration.read_bytes(), parse_float=str, parse_int=str)

                unrelated = document()
                def preserved():
                    current = document()
                    current['mcpServers'].pop('agentmux', None)
                    self.assertEqual(current, unrelated)
                    self.assertIn(b'1e9999', configuration.read_bytes())
                    self.assertIn(b'-0', configuration.read_bytes())
                    self.assertEqual(configuration.stat().st_mode & 0o777, 0o600)

                def run_setup(operation, *, apply=True):
                    with patch.object(setup, '_configuration', return_value=str(configuration)):
                        return setup.run_setup(installation_id=installation, selection=selection,
                            receipt=str(receipt), operation=operation, apply=apply, deadline=deadline)

                self.assertEqual(run_setup('install')['outcome'], 'applied')
                caller_entry = document()['mcpServers']['agentmux']
                caller_receipt = json.loads(receipt.read_bytes())
                self.assertIsNone(caller_receipt['pending'])
                self.assertEqual(caller_receipt['state']['current']['installationId'], installation)
                self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(b'DISPOSABLE_SENTINEL', receipt.read_bytes())
                preserved()
                self.assertEqual(run_setup('remove')['outcome'], 'applied')
                self.assertNotIn('agentmux', document()['mcpServers'])
                preserved()
                self.assertEqual(run_setup('restore')['outcome'], 'applied')
                self.assertEqual(document()['mcpServers']['agentmux'], caller_entry)
                preserved()
                self.assertEqual(run_setup('remove')['outcome'], 'applied')
                self.assertNotIn('agentmux', document()['mcpServers'])

                real_write = setup._ReceiptStore.write
                writes = 0
                def interrupt_commit(store, value):
                    nonlocal writes
                    writes += 1
                    if writes == 2:
                        raise setup.ClientSetupError('client_setup_receipt_incomplete')
                    return real_write(store, value)
                with patch.object(setup._ReceiptStore, 'write', interrupt_commit):
                    with self.assertRaisesRegex(SettingsPublicationError, '^settings_receipt_pending$'):
                        run_setup('restore')
                pending_record = receipt.read_bytes()
                pending = json.loads(pending_record)
                self.assertIsNotNone(pending['pending'])
                published = configuration.read_bytes()
                with self.assertRaisesRegex(setup.ClientSetupError, '^client_setup_recovery_required$'):
                    run_setup('remove')
                self.assertEqual(run_setup('recover', apply=False)['outcome'], 'recovery_ready')
                self.assertEqual(receipt.read_bytes(), pending_record)
                self.assertEqual(run_setup('recover')['outcome'], 'recovered')
                self.assertEqual(configuration.read_bytes(), published)
                self.assertIsNone(json.loads(receipt.read_bytes())['pending'])
                self.assertEqual(run_setup('remove')['outcome'], 'applied')
                self.assertNotIn('agentmux', document()['mcpServers'])
                preserved()

                accepted = []
                def accept():
                    # Acceptance must run while the actual settings lock is held.
                    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(fd)
                    accepted.append(True)

                path = str(configuration)
                with desktop_settings_snapshot(path, admission=admission, deadline=deadline) as snapshot:
                    self.assertEqual(snapshot.raw, original)
                self.assertEqual(configuration.read_bytes(), original)
                with desktop_registration(path, admission=admission, deadline=deadline,
                        expected_before=snapshot.raw, expected_identity=snapshot.identity,
                        on_accept=accept) as publication:
                    added = publication.edit.ownership
                    self.assertIsNotNone(added)
                self.assertEqual(len(accepted), 1)
                expected_entry = {'command': admission.declaration.command,
                                  'args': list(admission.declaration.arguments)}
                self.assertEqual(document()['mcpServers']['agentmux'], expected_entry)
                preserved()

                before = configuration.read_bytes(), configuration.stat().st_ino
                with desktop_registration(path, admission=admission, owned=added, deadline=deadline) as publication:
                    self.assertEqual(publication.edit.outcome, 'unchanged')
                self.assertEqual((configuration.read_bytes(), configuration.stat().st_ino), before)

                with desktop_registration(path, admission=admission, owned=added,
                        remove=True, deadline=deadline) as publication:
                    self.assertIsNone(publication.edit.ownership)
                self.assertNotIn('agentmux', document()['mcpServers'])
                preserved()
                # Restore the saved owned entry through the same admitted command.
                with desktop_registration(path, admission=admission, deadline=deadline) as publication:
                    restored = publication.edit.ownership
                self.assertEqual(json.loads(restored.entry_json), json.loads(added.entry_json))
                self.assertEqual(document()['mcpServers']['agentmux'], expected_entry)
                preserved()

                def replace_same_bytes():
                    replacement = directory / 'owned-replacement.json'
                    replacement.write_bytes(configuration.read_bytes())
                    replacement.chmod(0o600)
                    replacement.replace(configuration)

                with desktop_settings_snapshot(path, admission=admission, deadline=deadline) as stale:
                    pass
                replace_same_bytes()
                with self.assertRaisesRegex(RegistrationConflict, '^configuration_changed$'):
                    with desktop_registration(path, admission=admission, owned=restored,
                            deadline=deadline, expected_before=stale.raw, expected_identity=stale.identity):
                        self.fail('stale file identity accepted')
                with self.assertRaisesRegex(RegistrationConflict, '^configuration_changed$'):
                    with desktop_settings_snapshot(path, admission=admission, deadline=deadline):
                        replace_same_bytes()
                try:
                    with desktop_registration(path, admission=admission, owned=restored,
                            remove=True, deadline=deadline):
                        replace_same_bytes()
                except SettingsPublicationError as error:
                    if error.cleanup_owners:
                        raise
                    try:
                        self.assertEqual(str(error), 'settings_publication_uncertain')
                        self.assertIsNotNone(error.recovery)
                    finally:
                        if error.recovery is not None:
                            error.recovery.close()
                else:
                    self.fail('replacement after publication was accepted')
                self.assertNotIn('agentmux', document()['mcpServers'])
                preserved()
                admission.recheck(deadline=deadline)
                self.assertEqual({item.name for item in directory.iterdir()}, {configuration.name, records.name})
                self.assertEqual({item.name for item in records.iterdir()}, {receipt.name})
                fixture_complete = True
            except SettingsPublicationError as error:
                # Every unexpected publication failure retains exact recovery.
                # Keep the disposable files if any cleanup remains uncertain.
                owners = ([error.recovery] if error.recovery is not None else []) + list(error.cleanup_owners)
                for owner in owners:
                    if hasattr(owner, 'close'):
                        try:
                            owner.close()
                        except BaseException:
                            error.add_note('A retained settings owner still needs cleanup inspection.')
                error.add_note('The disposable settings fixture was retained for inspection.')
                self.retained_fixture = temporary
                raise
            finally:
                if fixture_complete:
                    shutil.rmtree(temporary)
                else:
                    self.retained_fixture = temporary
        finally:
            admission.close()
        self.assertTrue(admission.closed)


if __name__ == '__main__':
    unittest.main()
