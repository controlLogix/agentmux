"""Offline manifest, route and cache checks. No client or server is started."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


class Resources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory(prefix='resource-home-')
        with patch.dict(os.environ, {'HOME': cls.home.name, 'AGENTMUX_HOME': cls.home.name}):
            spec = importlib.util.spec_from_file_location('resource_server_test', ROOT / 'server.py')
            cls.server = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.server)

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    def setUp(self):
        self.s = self.server
        self.s._res_cache = {'at': 0, 'data': None}
        self.s._res_refresh_lock = threading.Lock()

    def test_manifest_preserves_ids_and_resolves_every_check(self):
        from resource_probes import ALLOWED_COMMANDS, NATIVE_REFS
        manifest = self.s.load_manifest()
        self.assertIsNotNone(manifest)
        resources = {r['id']: r for r in manifest['resources']}
        expected = {'atlassian': {'mcp-codex', 'mcp-grok', 'mcp-claude', 'rest-config'},
                    'codex': {'installed', 'auth', 'yolo', 'config'},
                    'grok': {'installed', 'auth', 'shared-auth'},
                    'claude': {'installed', 'creds', 'agent-config'},
                    'harness': {'tmux', 'launcher', 'pane-env'},
                    'addons': {'claude-plugins', 'grok-plugins'}}
        for rid, ids in expected.items():
            self.assertTrue(ids <= {c['id'] for c in resources[rid]['checks']})
        actions = {'atlassian': {'login-codex', 'setup-rest', 'verify', 'dry-run'},
                   'codex': {'login', 'install'}, 'grok': {'login', 'install'},
                   'claude': {'login'}, 'harness': {'install', 'share'},
                   'addons': {'grok-market', 'grok-install'}}
        for rid, ids in actions.items():
            self.assertTrue(ids <= {action['id'] for action in resources[rid]['actions']})
        for resource in resources.values():
            self.assertEqual(resource['health_version'], 1)
            self.assertEqual(resource['scope'], 'local-read-only')
            for check in resource['checks']:
                if check['type'] == 'command':
                    self.assertIn(tuple(check['argv']), ALLOWED_COMMANDS)
                elif check['type'] == 'file':
                    self.assertIn(check['native_ref'], NATIVE_REFS)
                else:
                    self.assertEqual(check['type'], 'manual')
                    self.assertTrue(check['hint'])

    def test_invalid_and_oversized_manifest_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / 'resources.json'
            for value in [{'resources': [{}]}, {'resources': [{'id': 'r', 'checks': [{}]}]},
                          {'resources': [{'id': 'r'}, {'id': 'r'}]},
                          {'resources': [{'id': str(i)} for i in range(17)]}]:
                manifest.write_text(json.dumps(value))
                with patch.object(self.s, 'MANIFEST', manifest):
                    self.assertIsNone(self.s.load_manifest())

    def test_snapshot_distinguishes_status_and_retains_optional_hints(self):
        manifest = {'resources': [
            {'id': status, 'checks': [{'id': status}], 'actions': [{'id': 'setup', 'command': 'client login', 'secret': True}]}
            for status in ['configured', 'unavailable', 'unknown']]}
        def check(entry):
            status = entry['id']
            return {'id': status, 'ok': status == 'configured', 'status': status}
        with patch.object(self.s, 'load_manifest', return_value=manifest), patch.object(self.s, '_run_check', side_effect=check):
            data = self.s.resources_snapshot()
        for resource in data['resources']:
            self.assertEqual(resource['status'], resource['id'])
            self.assertEqual(resource['actions'][0]['command'], 'client login')
            self.assertTrue(resource['actions'][0]['secret'])

    def test_optional_failure_keeps_label_hint_and_required_status(self):
        manifest = {'resources': [{'id': 'client', 'checks': [
            {'id': 'required'},
            {'id': 'optional', 'label': 'Optional plugin', 'optional': True, 'hint': 'Use the native client.'}]}]}
        def check(entry):
            if entry['id'] == 'optional':
                raise ValueError('SENTINEL_SECRET')
            return {'id': 'required', 'ok': True, 'status': 'configured'}
        with patch.object(self.s, 'load_manifest', return_value=manifest), patch.object(self.s, '_run_check', side_effect=check):
            data = self.s.resources_snapshot()
        resource = data['resources'][0]
        self.assertEqual(resource['status'], 'configured')
        optional = resource['checks'][1]
        self.assertTrue(optional['optional'])
        self.assertEqual(optional['label'], 'Optional plugin')
        self.assertEqual(optional['hint'], 'Use the native client.')
        self.assertNotIn('SENTINEL_SECRET', json.dumps(data))

    def test_cache_refresh_cooldown_and_coalescing(self):
        cached = {'resources': []}
        self.s._res_cache = {'at': 100, 'data': cached}
        with patch.object(self.s.time, 'monotonic', return_value=101), patch.object(self.s, '_resources_snapshot') as run:
            self.assertIs(self.s.resources_snapshot(force=True), cached)
            run.assert_not_called()
        self.s._res_refresh_lock.acquire()
        try:
            with patch.object(self.s.time, 'monotonic', return_value=200), patch.object(self.s, '_resources_snapshot') as run:
                self.assertTrue(self.s.resources_snapshot(force=True)['refreshing'])
                run.assert_not_called()
        finally:
            self.s._res_refresh_lock.release()
        with patch.object(self.s.time, 'monotonic', return_value=200), patch.object(self.s, '_resources_snapshot', return_value=cached) as run:
            self.s.resources_snapshot(force=True)
            run.assert_called_once_with(force=True)

    def test_refresh_rechecks_after_lock_acquisition(self):
        stale, fresh = {'resources': ['old']}, {'resources': ['new']}
        self.s._res_cache = {'at': 1, 'data': stale}
        def acquire(**_):
            self.s._res_cache = {'at': 100, 'data': fresh}
            return True
        lock = Mock()
        lock.acquire.side_effect = acquire
        with patch.object(self.s, '_res_refresh_lock', lock), patch.object(self.s.time, 'monotonic', return_value=101), patch.object(self.s, '_resources_snapshot') as run:
            self.assertIs(self.s.resources_snapshot(force=True), fresh)
            run.assert_not_called()
        lock.release.assert_called_once()

    def test_request_cannot_supply_probe_command(self):
        handler = self.s.Handler.__new__(self.s.Handler)
        handler.requestline = 'GET /api/resources?refresh=1&argv=sh&command=touch HTTP/1.1'
        handler.command = 'GET'
        handler.send_json = Mock()
        with patch.object(self.s, 'resources_snapshot', return_value={'resources': []}) as snapshot, patch.object(self.s, 'HOME_DIR', Path(self.home.name)):
            handler.route()
        snapshot.assert_called_once_with(force=True)
        handler.send_json.assert_called_once_with(200, {'resources': []})


class DesktopRegistrationPlanning(unittest.TestCase):
    def setUp(self):
        from resource_registration import prepare_desktop_registration, RegistrationConflict
        self.prepare = prepare_desktop_registration
        self.conflict = RegistrationConflict
        self.selection = dict(installation_id='fixture-installation-1',
                              configuration_path='/fixture/Claude/config.json',
                              command='/fixture/owned application',
                              arguments=('--selection', '/fixture/private selection.json'))

    def test_add_update_remove_restore_preserve_unrelated_entries(self):
        before = json.dumps({'theme': 'dark', 'mcpServers': {
            'unrelated': {'command': 'existing-client', 'env': {'TOKEN': 'PRIVATE_SENTINEL'}}}}).encode()
        added = self.prepare(before, **self.selection)
        self.assertEqual(added.outcome, 'added')
        self.assertEqual(json.loads(added.after)['mcpServers']['unrelated'],
                         json.loads(before)['mcpServers']['unrelated'])
        unchanged = self.prepare(added.after, owned=added.ownership, **self.selection)
        self.assertEqual(unchanged.outcome, 'unchanged')
        self.assertEqual(unchanged.after, added.after)
        updated = self.prepare(added.after, owned=added.ownership,
                               **dict(self.selection, arguments=('--selection', '/fixture/changed.json')))
        self.assertEqual(updated.outcome, 'updated')
        removed = self.prepare(updated.after, installation_id=self.selection['installation_id'],
                               configuration_path=self.selection['configuration_path'],
                               owned=updated.ownership, remove=True)
        self.assertEqual(json.loads(removed.after), json.loads(before))
        restored = self.prepare(removed.after, **self.selection)
        self.assertEqual(json.loads(restored.after), json.loads(added.after))
        self.assertNotIn('PRIVATE_SENTINEL', repr(added))
        self.assertNotIn('PRIVATE_SENTINEL', repr(added.ownership))

    def test_unowned_or_changed_registration_and_other_installation_refuse(self):
        added = self.prepare(b'{}', **self.selection)
        with self.assertRaisesRegex(self.conflict, '^registration_not_owned$'):
            self.prepare(added.after, **self.selection)
        with self.assertRaisesRegex(self.conflict, '^registration_owner_mismatch$'):
            self.prepare(added.after, owned=added.ownership,
                         **dict(self.selection, installation_id='other-installation'))
        with self.assertRaisesRegex(self.conflict, '^registration_owner_mismatch$'):
            self.prepare(added.after, owned=added.ownership,
                         **dict(self.selection, configuration_path='/fixture/other/config.json'))
        changed = json.loads(added.after)
        changed['mcpServers']['agentmux']['args'].append('operator-change')
        with self.assertRaisesRegex(self.conflict, '^registration_changed$'):
            self.prepare(json.dumps(changed).encode(), installation_id=self.selection['installation_id'],
                               configuration_path=self.selection['configuration_path'],
                         owned=added.ownership, remove=True)

    def test_stale_plan_refuses_and_removal_keeps_later_unrelated_entry(self):
        added = self.prepare(b'{}', **self.selection)
        with self.assertRaisesRegex(self.conflict, '^configuration_changed$'):
            added.for_snapshot(b'{"later": true}', configuration_path=self.selection['configuration_path'])
        with self.assertRaisesRegex(self.conflict, '^configuration_changed$'):
            added.for_snapshot(b'{}', configuration_path='/fixture/other/config.json')
        self.assertEqual(added.for_snapshot(b'{}', configuration_path=self.selection['configuration_path']), added.after)
        changed = json.loads(added.after)
        changed['mcpServers']['later'] = {'command': 'operator-tool'}
        removed = self.prepare(json.dumps(changed).encode(), installation_id=self.selection['installation_id'],
                               configuration_path=self.selection['configuration_path'],
                               owned=added.ownership, remove=True)
        self.assertEqual(json.loads(removed.after), {'mcpServers': {'later': {'command': 'operator-tool'}}})
        removed_empty = self.prepare(added.after, installation_id=self.selection['installation_id'],
                               configuration_path=self.selection['configuration_path'],
                                     owned=added.ownership, remove=True)
        self.assertEqual(json.loads(removed_empty.after), {})

    def test_invalid_configuration_and_inline_auth_owner_are_rejected(self):
        from resource_registration import OwnedDesktopRegistration
        for raw in (b'[]', b'{"mcpServers": []}', b'{"x": 1, "x": 2}', b'{"x": NaN}'):
            with self.assertRaisesRegex(self.conflict, '^configuration_invalid$'):
                self.prepare(raw, **self.selection)
        owner = OwnedDesktopRegistration('fixture-installation-1', self.selection['configuration_path'],
                    b'{"command":"/fixture/app","args":[],"env":{"TOKEN":"PRIVATE_SENTINEL"}}')
        with self.assertRaisesRegex(self.conflict, '^registration_owner_invalid$'):
            self.prepare(b'{}', owned=owner, **self.selection)

    def test_unrelated_numeric_tokens_and_unicode_are_preserved(self):
        before = b'{"precise":1.0000000000000001,"large":1e999,"negativeZero":-0,"text":"\\ud800"}'
        added = self.prepare(before, **self.selection)
        for token in (b'1.0000000000000001', b'1e999', b'-0', b'\\ud800'):
            self.assertIn(token, added.after)
        with self.assertRaisesRegex(self.conflict, '^application_command_invalid$'):
            self.prepare(b'{}', **dict(self.selection, arguments=('\ud800',)))
        with self.assertRaisesRegex(self.conflict, '^configuration_path_invalid$'):
            self.prepare(b'{}', **dict(self.selection, configuration_path='/fixture/\ud800'))


class DesktopSettingsPublication(unittest.TestCase):
    """Disposable file operations only; no native clients or services are started."""
    def setUp(self):
        from dashboard.resource_registration import prepare_desktop_registration, prepare_desktop_rollback
        from dashboard.resource_settings import _publish_desktop_at, SettingsPublicationError
        self.prepare, self.rollback = prepare_desktop_registration, prepare_desktop_rollback
        self.publish, self.error = _publish_desktop_at, SettingsPublicationError
        from native_security import descriptor_admission as native
        self.native = native
        def offline_metadata(fd, *, purpose, deadline):
            # Exercise shared metadata policy only. ACL and mount qualification
            # still require the real Darwin checker in a separate native slot.
            native._metadata(fd, purpose)
            return True
        self.native_patch = patch('dashboard.resource_settings.native_admission.check_descriptor',
                                  side_effect=offline_metadata)
        self.native_check = self.native_patch.start()
        self.addCleanup(self.native_patch.stop)
        self.directory = tempfile.TemporaryDirectory(prefix='resource-settings-')
        os.chmod(self.directory.name, 0o700)
        self.path = Path(self.directory.name) / 'config.json'
        self.path.write_bytes(b'{"theme":"dark"}')
        self.path.chmod(0o600)
        self.parent = os.open(self.directory.name, os.O_RDONLY | os.O_DIRECTORY)
        self.selection = dict(installation_id='fixture-installation', configuration_path=str(self.path),
                              command='/fixture/admitted-application', arguments=('--selection', '/fixture/selection'))

    def tearDown(self):
        os.close(self.parent)
        self.directory.cleanup()

    def test_publication_retains_receipt_and_rollback_preserves_later_settings(self):
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        owner = self.publish(self.parent, edit, recheck=lambda: None)
        try:
            self.assertEqual(self.path.read_bytes(), edit.after)
            self.assertEqual(os.fstat(owner._fd).st_ino, self.path.stat().st_ino)
            changed = json.loads(self.path.read_bytes())
            changed['later'] = {'keep': True}
            self.path.write_text(json.dumps(changed))
            rollback = self.rollback(self.path.read_bytes(), published=owner.edit)
            restored = self.publish(self.parent, rollback, recheck=lambda: None)
            restored.close()
            self.assertEqual(json.loads(self.path.read_bytes()), {'theme': 'dark', 'later': {'keep': True}})
        finally:
            owner.close()
        self.assertIsNone(owner._fd)

    def test_stale_file_replacement_and_staged_edit_refuse_without_overwrite(self):
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        replacement = self.path.with_name('replacement')
        replacement.write_bytes(edit.before)
        replacement.chmod(0o600)
        calls = 0
        def replace_after_staging():
            nonlocal calls
            calls += 1
            if calls == 2:
                os.replace(replacement, self.path)
        with self.assertRaisesRegex(self.error, '^configuration_changed$') as caught:
            self.publish(self.parent, edit, recheck=replace_after_staging)
        caught.exception.recovery.close()
        self.assertEqual(self.path.read_bytes(), edit.before)
        self.assertTrue(caught.exception.staging_name.startswith('.agentmux-settings-'))
        self.assertTrue((self.path.parent / caught.exception.staging_name).exists())

    def test_post_publish_failure_retains_exact_published_owner(self):
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        calls = 0
        def recheck():
            nonlocal calls
            calls += 1
            if calls == 3:
                from dashboard.resource_registration import RegistrationConflict
                raise RegistrationConflict('application_admission_lost')
        with self.assertRaisesRegex(self.error, '^settings_publication_uncertain$') as caught:
            self.publish(self.parent, edit, recheck=recheck)
        recovery = caught.exception.recovery
        try:
            self.assertEqual(self.path.read_bytes(), edit.after)
            self.assertEqual(os.fstat(recovery._fd).st_ino, self.path.stat().st_ino)
            self.assertIsNone(caught.exception.staging_name)
        finally:
            recovery.close()

    def test_permissions_symlinks_and_missing_settings_refuse(self):
        from dashboard.resource_registration import RegistrationConflict
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        os.chmod(self.directory.name, 0o755)
        with self.assertRaisesRegex(RegistrationConflict, '^settings_native_admission_failed$'):
            self.publish(self.parent, edit, recheck=lambda: None)
        os.chmod(self.directory.name, 0o700)
        self.path.unlink()
        self.path.symlink_to('/private/unrelated-settings')
        with self.assertRaises(self.error):
            self.publish(self.parent, edit, recheck=lambda: None)
        self.assertTrue(self.path.is_symlink())
        self.path.unlink()
        with self.assertRaises(self.error):
            self.publish(self.parent, edit, recheck=lambda: None)
        self.assertFalse(self.path.exists())

    def test_update_and_removal_rollback_restore_only_original_owned_entry(self):
        original = self.prepare(self.path.read_bytes(), **self.selection)
        updated = self.prepare(original.after, owned=original.ownership,
                               **dict(self.selection, arguments=('--changed',)))
        undone = self.rollback(updated.after, published=updated)
        self.assertEqual(json.loads(undone.after), json.loads(original.after))
        removed = self.prepare(updated.after, installation_id=self.selection['installation_id'],
                    configuration_path=str(self.path), owned=updated.ownership, remove=True)
        restored = self.rollback(removed.after, published=removed)
        self.assertEqual(json.loads(restored.after), json.loads(updated.after))
        changed = json.loads(updated.after)
        changed['mcpServers']['agentmux']['args'].append('operator-edit')
        from dashboard.resource_registration import RegistrationConflict
        with self.assertRaisesRegex(RegistrationConflict, '^registration_changed$'):
            self.rollback(json.dumps(changed).encode(), published=updated)

    def test_rollback_uses_absence_in_snapshot_instead_of_stale_receipt(self):
        original = self.prepare(self.path.read_bytes(), **self.selection)
        absent = self.prepare(original.before, installation_id=self.selection['installation_id'],
                    configuration_path=str(self.path), owned=original.ownership, remove=True)
        self.assertEqual(absent.outcome, 'already_absent')
        later = b'{"later":true}'
        self.assertEqual(self.rollback(later, published=absent).after, later)
        added = self.prepare(original.before, owned=original.ownership,
                             **dict(self.selection, arguments=('--new-command',)))
        rolled_back = self.rollback(added.after, published=added)
        self.assertNotIn('agentmux', json.loads(rolled_back.after).get('mcpServers', {}))
        self.assertEqual(json.loads(rolled_back.after), json.loads(original.before))
        unchanged = self.prepare(original.after, owned=original.ownership, **self.selection)
        self.assertEqual(self.rollback(later, published=unchanged).after, later)
        from dashboard.resource_registration import RegistrationConflict
        with self.assertRaisesRegex(RegistrationConflict, '^registration_changed$'):
            self.rollback(later, published=added)

    def test_staging_collision_never_claims_an_unowned_entry(self):
        sentinel = self.path.parent / '.agentmux-settings-fixed'
        sentinel.write_bytes(b'UNRELATED_SENTINEL')
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        with patch('dashboard.resource_settings.secrets.token_hex', return_value='fixed'):
            with self.assertRaises(self.error) as caught:
                self.publish(self.parent, edit, recheck=lambda: None)
        self.assertIsNone(caught.exception.staging_name)
        self.assertIsNone(caught.exception.recovery)
        self.assertEqual(sentinel.read_bytes(), b'UNRELATED_SENTINEL')
        self.assertEqual(self.path.read_bytes(), edit.before)

    def test_reused_directory_handle_does_not_bypass_an_existing_lock(self):
        import fcntl
        from dashboard.resource_registration import RegistrationConflict
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        fcntl.flock(self.parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with self.assertRaisesRegex(RegistrationConflict, '^settings_busy$'):
                self.publish(self.parent, edit, recheck=lambda: None)
        finally:
            fcntl.flock(self.parent, fcntl.LOCK_UN)
        self.assertEqual(self.path.read_bytes(), edit.before)

    def test_interruption_after_rename_transfers_recovery_owner(self):
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        calls = 0
        def recheck():
            nonlocal calls
            calls += 1
            if calls == 3:
                raise KeyboardInterrupt
        with self.assertRaisesRegex(self.error, '^settings_publication_uncertain$') as caught:
            self.publish(self.parent, edit, recheck=recheck)
        try:
            self.assertEqual(self.path.read_bytes(), edit.after)
            self.assertEqual(os.fstat(caught.exception.recovery._fd).st_ino, self.path.stat().st_ino)
        finally:
            caught.exception.recovery.close()

    def test_shared_admission_failure_keeps_settings_unchanged(self):
        from dashboard.resource_registration import RegistrationConflict
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        for failure in ('native_admission_acl', 'native_admission_mount'):
            with self.subTest(failure=failure):
                self.native_check.side_effect = self.native.AdmissionError(failure)
                with self.assertRaisesRegex(RegistrationConflict, '^settings_native_admission_failed$'):
                    self.publish(self.parent, edit, recheck=lambda: None)
                self.assertEqual(self.path.read_bytes(), edit.before)

    def test_staging_admission_runs_before_private_bytes_are_written(self):
        import fcntl
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        def deny_staging(fd, *, purpose, deadline):
            self.native._metadata(fd, purpose)
            if (purpose is self.native.DescriptorPurpose.PRIVATE_FILE
                    and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY):
                raise self.native.AdmissionError('native_admission_acl')
            return True
        self.native_check.side_effect = deny_staging
        with self.assertRaisesRegex(self.error, '^settings_native_admission_failed$') as caught:
            self.publish(self.parent, edit, recheck=lambda: None)
        try:
            self.assertEqual(self.path.read_bytes(), edit.before)
            self.assertEqual((self.path.parent / caught.exception.staging_name).read_bytes(), b'')
        finally:
            caught.exception.recovery.close()

    def test_shared_admission_failure_after_rename_retains_uncertain_owner(self):
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        original_inode = self.path.stat().st_ino
        def deny_published_file(fd, *, purpose, deadline):
            self.native._metadata(fd, purpose)
            inode = os.fstat(fd).st_ino
            if (purpose is self.native.DescriptorPurpose.PRIVATE_FILE
                    and inode != original_inode and inode == self.path.stat().st_ino):
                raise self.native.AdmissionError('native_admission_acl')
            return True
        self.native_check.side_effect = deny_published_file
        with self.assertRaisesRegex(self.error, '^settings_publication_uncertain$') as caught:
            self.publish(self.parent, edit, recheck=lambda: None)
        try:
            self.assertEqual(self.path.read_bytes(), edit.after)
            self.assertEqual(os.fstat(caught.exception.recovery._fd).st_ino, self.path.stat().st_ino)
        finally:
            caught.exception.recovery.close()

    def test_one_deadline_is_passed_to_shared_admission(self):
        import time
        from dashboard.resource_registration import RegistrationConflict
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        with self.assertRaisesRegex(RegistrationConflict, '^settings_deadline$'):
            self.publish(self.parent, edit, recheck=lambda: None, deadline=time.monotonic() - 1)
        self.native_check.assert_not_called()
        deadline = time.monotonic() + 1
        owner = self.publish(self.parent, edit, recheck=lambda: None, deadline=deadline)
        owner.close()
        self.assertTrue(self.native_check.call_args_list)
        for call in self.native_check.call_args_list:
            self.assertEqual(call.kwargs['deadline'], deadline)

    def test_expiry_during_final_recheck_retains_uncertain_publication(self):
        edit = self.prepare(self.path.read_bytes(), **self.selection)
        now, calls = [10], 0
        def recheck():
            nonlocal calls
            calls += 1
            if calls == 3:
                now[0] = 12
        with patch('dashboard.resource_settings.time.monotonic', side_effect=lambda: now[0]):
            with self.assertRaisesRegex(self.error, '^settings_publication_uncertain$') as caught:
                self.publish(self.parent, edit, recheck=recheck, deadline=11)
        try:
            self.assertEqual(self.path.read_bytes(), edit.after)
            self.assertEqual(os.fstat(caught.exception.recovery._fd).st_ino, self.path.stat().st_ino)
        finally:
            caught.exception.recovery.close()


if __name__ == '__main__':
    unittest.main()
