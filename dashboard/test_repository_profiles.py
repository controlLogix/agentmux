"""Disposable repository references; native ACL/mount behavior is not qualified."""
import json
from dataclasses import replace
import fcntl
import os
from pathlib import Path
import tempfile
import stat
import time
import unittest
from unittest.mock import patch

from dashboard import repository_profiles as profiles

ONE = 'profile_' + '1' * 32
TWO = 'profile_' + '2' * 32


class RepositoryProfiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = Path(self.temporary.name).resolve()
        self.repository.chmod(0o700)
        native = patch.object(profiles.filesystem, '_native')
        native.start()
        self.addCleanup(native.stop)
        self.directory = self.repository / '.agentmux'
        self.config = self.directory / 'config.json'

    def existing(self, raw):
        self.directory.mkdir(mode=0o755, exist_ok=True)
        self.config.write_bytes(raw)
        self.config.chmod(0o644)

    def test_preview_is_read_only_and_publication_is_idempotent(self):
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        self.assertEqual(plan.outcome, 'create')
        self.assertFalse(self.directory.exists())
        self.assertIsNone(profiles.read_repository_profile(str(self.repository)))
        self.assertEqual(profiles.publish_repository_profile(plan), 'created')
        self.assertEqual(json.loads(self.config.read_bytes()), {'schemaVersion': '1.0.0', 'profileId': ONE})
        before = self.config.read_bytes(), self.config.stat().st_ino
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        self.assertEqual(profiles.publish_repository_profile(plan), 'unchanged')
        self.assertEqual((self.config.read_bytes(), self.config.stat().st_ino), before)
        self.assertEqual(profiles.read_repository_profile(str(self.repository)).profile_id, ONE)

    def test_existing_matching_reference_and_other_agentmux_files_are_preserved(self):
        raw = ('{ "profileId": "' + ONE + '", "schemaVersion": "1.0.0" }').encode()
        self.existing(raw)
        sentinel = self.directory / 'agents'
        sentinel.mkdir()
        (sentinel / 'keep.md').write_text('UNRELATED')
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        self.assertEqual(profiles.publish_repository_profile(plan), 'unchanged')
        self.assertEqual(self.config.read_bytes(), raw)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o644)
        self.assertEqual((sentinel / 'keep.md').read_text(), 'UNRELATED')
        with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_conflict$'):
            profiles.prepare_repository_profile(str(self.repository), TWO)
        self.assertEqual(self.config.read_bytes(), raw)

    def test_closed_schema_duplicates_bounds_and_profile_id_format(self):
        valid = {'schemaVersion': '1.0.0', 'profileId': ONE}
        invalid = [b'{}', b'[]', b'\xff', b' ' * 4097,
                   ('{"schemaVersion":"1.0.0","profileId":"' + ONE + '","profileId":"' + ONE + '"}').encode()]
        for value in ({**valid, 'path': '/private/path'}, {**valid, 'endpoint': 'tls://host'},
                      {**valid, 'credentials': 'SECRET'}, {**valid, 'schemaVersion': 1},
                      {**valid, 'profileId': '../escape'}, {**valid, 'profileId': 'profile_' + 'A' * 32},
                      {**valid, 'profileId': 1}, {**valid, 'profileId': 'Ryan - Local Development'}):
            invalid.append(json.dumps(value).encode())
        for raw in invalid:
            with self.subTest(length=len(raw)):
                self.existing(raw)
                with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_invalid$'):
                    profiles.read_repository_profile(str(self.repository))
                self.assertEqual(self.config.read_bytes(), raw)

    def test_symlink_config_directory_and_repository_are_refused(self):
        target = self.repository / 'unrelated.json'
        target.write_text('UNRELATED')
        self.directory.mkdir()
        self.config.symlink_to(target)
        with self.assertRaises(profiles.RepositoryProfileError):
            profiles.read_repository_profile(str(self.repository))
        self.config.unlink()
        self.directory.rmdir()
        self.directory.symlink_to(self.repository, target_is_directory=True)
        with self.assertRaises(profiles.RepositoryProfileError):
            profiles.prepare_repository_profile(str(self.repository), ONE)
        alias = self.repository / 'alias'
        alias.symlink_to(self.repository, target_is_directory=True)
        with self.assertRaises(profiles.RepositoryProfileError):
            profiles.prepare_repository_profile(str(alias), ONE)
        self.assertEqual(target.read_text(), 'UNRELATED')

    def test_stale_preview_does_not_replace_a_new_or_same_byte_replacement(self):
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        self.existing(json.dumps({'schemaVersion': '1.0.0', 'profileId': ONE}).encode())
        with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_changed$'):
            profiles.publish_repository_profile(plan)
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        replacement = self.directory / 'replacement'
        replacement.write_bytes(self.config.read_bytes())
        replacement.chmod(0o644)
        replacement.replace(self.config)
        with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_changed$'):
            profiles.publish_repository_profile(plan)

    def test_replacement_during_read_is_refused(self):
        raw = json.dumps({'schemaVersion': '1.0.0', 'profileId': ONE}).encode()
        self.existing(raw)
        read = os.read
        def changed(fd, limit):
            result = read(fd, limit)
            replacement = self.directory / 'replacement'
            replacement.write_bytes(raw)
            replacement.chmod(0o644)
            replacement.replace(self.config)
            return result
        with patch.object(profiles.os, 'read', changed):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_changed$'):
                profiles.read_repository_profile(str(self.repository))

    def test_atomic_publication_never_replaces_competing_config(self):
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        link = os.link
        def competing(*args, **kwargs):
            self.config.write_bytes(b'FOREIGN')
            return link(*args, **kwargs)
        with patch.object(profiles.os, 'link', competing):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_publication_uncertain$') as caught:
                profiles.publish_repository_profile(plan)
        self.assertEqual(self.config.read_bytes(), b'FOREIGN')
        recovery = caught.exception.recovery
        try:
            self.assertFalse(recovery.published)
            self.assertTrue((self.directory / recovery.staging_name).exists())
            self.assertTrue(os.fstat(recovery._directory))
            self.assertTrue(os.fstat(recovery._writer))
        finally:
            recovery.close()

    def test_directory_replacement_during_publication_retains_exact_owner(self):
        self.directory.mkdir()
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        link = os.link
        moved = self.repository / 'moved-agentmux'
        def moved_directory(*args, **kwargs):
            result = link(*args, **kwargs)
            self.directory.rename(moved)
            self.directory.mkdir()
            return result
        with patch.object(profiles.os, 'link', moved_directory):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_publication_uncertain$') as caught:
                profiles.publish_repository_profile(plan)
        recovery = caught.exception.recovery
        try:
            self.assertEqual(os.fstat(recovery._directory).st_ino, moved.stat().st_ino)
            self.assertFalse(self.config.exists())
            self.assertTrue((moved / 'config.json').exists())
        finally:
            recovery.close()

    def test_deadline_and_invalid_plan_are_refused_without_writes(self):
        with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_deadline$'):
            profiles.prepare_repository_profile(str(self.repository), ONE, deadline=time.monotonic() - 1)
        with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_plan_required$'):
            profiles.publish_repository_profile({})
        self.assertFalse(self.directory.exists())

    def test_directory_disappearing_or_replaced_before_stage_never_writes_cwd(self):
        self.directory.mkdir()
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        opened = profiles._open_directory
        for action in ('missing', 'replacement'):
            calls = 0
            def changed(owner):
                nonlocal calls
                calls += 1
                if calls == 2:
                    self.directory.rmdir()
                    if action == 'replacement':
                        self.directory.mkdir()
                    else:
                        return None
                return opened(owner)
            with self.subTest(action=action), patch.object(profiles, '_open_directory', changed):
                with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_changed$'):
                    profiles.publish_repository_profile(plan)
            if not self.directory.exists():
                self.directory.mkdir()
            plan = profiles.prepare_repository_profile(str(self.repository), ONE)
            self.assertEqual(list(self.directory.iterdir()), [])

    def test_exclusive_stage_collision_never_claims_foreign_file(self):
        self.directory.mkdir()
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        name = '.profile-reference-' + 'a' * 32
        (self.directory / name).write_bytes(b'FOREIGN')
        with patch.object(profiles.secrets, 'token_hex', return_value='a' * 32):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_path_invalid$') as caught:
                profiles.publish_repository_profile(plan)
        self.assertIsNone(caught.exception.recovery)
        self.assertEqual((self.directory / name).read_bytes(), b'FOREIGN')
        self.assertFalse(self.config.exists())

    def test_malformed_plan_fields_are_closed_diagnostics(self):
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        for value in (replace(plan, repository=None), replace(plan, _repository_identity=None),
                      replace(plan, _before={}), replace(plan, outcome='foreign')):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_plan_required$'):
                profiles.publish_repository_profile(value)

    def test_ancestor_close_failure_preserves_publication_and_consumes_all_handles(self):
        self.directory.mkdir()
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        closed, original_close = [], os.close
        ancestor = []
        original_owner_close = profiles._RepositoryDirectory.close
        def owner_close(owner):
            if owner.handles:
                ancestor.append(owner.handles[-1])
            return original_owner_close(owner)
        def close(fd):
            original_close(fd)
            closed.append(fd)
            if ancestor and fd == ancestor[0]:
                ancestor.clear()
                raise KeyboardInterrupt()
        with patch.object(profiles._RepositoryDirectory, 'close', owner_close), patch.object(profiles.os, 'close', close):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_publication_uncertain$') as caught:
                profiles.publish_repository_profile(plan)
        recovery = caught.exception.recovery
        try:
            self.assertTrue(recovery.published)
            self.assertTrue(caught.exception.cleanup_owners)
            self.assertTrue(os.fstat(recovery._directory))
            self.assertGreater(len(closed), 3)
        finally:
            recovery.close()

    def test_existing_file_receives_native_acl_checks(self):
        self.existing(json.dumps({'schemaVersion': '1.0.0', 'profileId': ONE}).encode())
        def denied(fd, private):
            if os.fstat(fd).st_ino == self.config.stat().st_ino:
                raise profiles.filesystem.ProfileError('profile_acl_access_denied')
        with patch.object(profiles.filesystem, '_native', denied):
            with self.assertRaises(profiles.RepositoryProfileError):
                profiles.read_repository_profile(str(self.repository))

    def test_nested_read_and_directory_close_uncertainty_keep_both_owners(self):
        self.existing(json.dumps({'schemaVersion': '1.0.0', 'profileId': ONE}).encode())
        inodes = {self.config.stat().st_ino, self.directory.stat().st_ino}
        original_close, failed = os.close, []
        def close(fd):
            fail = os.fstat(fd).st_ino in inodes
            original_close(fd)
            if fail:
                failed.append(fd)
                raise OSError('PRIVATE_SENTINEL')
        with patch.object(profiles.os, 'close', close):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_cleanup_pending$') as caught:
                profiles.read_repository_profile(str(self.repository))
        consumed = {fd for owner in caught.exception.cleanup_owners
                    for fd in getattr(owner, '_uncertain', ())}
        self.assertEqual(consumed, set(failed))
        self.assertEqual(len(consumed), 2)

    def test_post_publication_read_close_failure_keeps_publication_and_source_owner(self):
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        original_close, failed = os.close, []
        def close(fd):
            info = os.fstat(fd)
            fail = (self.config.exists() and stat.S_ISREG(info.st_mode)
                    and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
            original_close(fd)
            if fail:
                failed.append(fd)
                raise OSError('PRIVATE_SENTINEL')
        with patch.object(profiles.os, 'close', close):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_publication_uncertain$') as caught:
                profiles.publish_repository_profile(plan)
        recovery = caught.exception.recovery
        try:
            self.assertTrue(recovery.published)
            consumed = {fd for owner in caught.exception.cleanup_owners
                        for fd in getattr(owner, '_uncertain', ())}
            self.assertEqual(consumed, set(failed))
            self.assertTrue(os.fstat(recovery._writer))
        finally:
            recovery.close()

    def test_native_cleanup_owner_is_not_lost(self):
        native_error = profiles.filesystem.NativeCleanupFailure(123, 456, None)
        with patch.object(profiles.filesystem, '_native', side_effect=native_error):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_cleanup_pending$') as caught:
                profiles.read_repository_profile(str(self.repository))
        self.assertIn(native_error, caught.exception.cleanup_owners)

    def test_first_write_preserves_other_agentmux_files(self):
        self.directory.mkdir(mode=0o755)
        other = self.directory / 'keep.md'
        other.write_bytes(b'UNRELATED')
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        self.assertEqual(profiles.publish_repository_profile(plan), 'created')
        self.assertEqual(other.read_bytes(), b'UNRELATED')
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o755)

    def test_parent_sync_failure_retains_created_directory_before_any_file_write(self):
        plan = profiles.prepare_repository_profile(str(self.repository), ONE)
        with patch.object(profiles.os, 'fsync', side_effect=OSError('PRIVATE_SENTINEL')):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_publication_uncertain$') as caught:
                profiles.publish_repository_profile(plan)
        recovery = caught.exception.recovery
        try:
            self.assertTrue(recovery.directory_created)
            self.assertEqual(os.fstat(recovery._parent).st_ino, self.repository.stat().st_ino)
            self.assertEqual(os.fstat(recovery._directory).st_ino, self.directory.stat().st_ino)
            self.assertIsNone(recovery._writer)
            self.assertIsNone(recovery.staging_name)
            self.assertFalse(recovery.published)
            self.assertEqual(list(self.directory.iterdir()), [])
        finally:
            recovery.close()
        self.assertTrue(self.directory.is_dir())
        self.assertFalse(self.config.exists())

    def test_child_retention_failure_keeps_original_parent_after_repository_replacement(self):
        repository = self.repository / 'original'
        repository.mkdir(mode=0o700)
        moved = self.repository / 'retained-original'
        plan = profiles.prepare_repository_profile(str(repository), ONE)
        opened, calls = profiles._open_directory, 0
        def replaced(owner):
            nonlocal calls
            calls += 1
            if calls == 2:
                repository.rename(moved)
                repository.mkdir(mode=0o700)
                (repository / 'keep').write_bytes(b'UNRELATED')
                raise OSError('PRIVATE_SENTINEL')
            return opened(owner)
        with patch.object(profiles, '_open_directory', replaced):
            with self.assertRaisesRegex(profiles.RepositoryProfileError, '^repository_profile_publication_uncertain$') as caught:
                profiles.publish_repository_profile(plan)
        recovery = caught.exception.recovery
        try:
            self.assertTrue(recovery.directory_created)
            self.assertIsNone(recovery._directory)
            self.assertEqual(os.fstat(recovery._parent).st_ino, moved.stat().st_ino)
            self.assertNotEqual(os.fstat(recovery._parent).st_ino, repository.stat().st_ino)
            self.assertTrue((moved / '.agentmux').is_dir())
        finally:
            recovery.close()
        self.assertEqual((repository / 'keep').read_bytes(), b'UNRELATED')
        self.assertTrue((moved / '.agentmux').is_dir())


if __name__ == '__main__':
    unittest.main()
