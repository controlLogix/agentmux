"""Offline repo-ID handoff checks; central admission and exec are not simulated authority."""
import io
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from dashboard import repository_profiles as references
from hub import client_launch_entrypoint as entry
from hub import client_launch_repository as repository
from hub.client_launch_coordinator import result
from hub.client_launch_selection import SelectionError


class Replaced(BaseException):
    pass


class RepositoryCallbacks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.nested = self.root / 'src' / 'package'
        self.nested.mkdir(parents=True)
        self.profile = 'profile_' + 'a' * 32
        self.write_reference(self.root, self.profile)
        native = patch.object(references.filesystem, '_native')
        native.start(); self.addCleanup(native.stop)
        self.owner = Mock(path='/protected/runtime', closed=True)

    def write_reference(self, root, profile):
        directory = root / '.agentmux'
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / 'config.json'
        path.write_text(json.dumps({'schemaVersion':'1.0.0', 'profileId':profile}))
        path.chmod(0o600)
        return path

    def invoke(self, directory, command=('agents',), *, admission=None):
        with patch.object(repository.os, 'getcwd', return_value=str(directory)), \
                patch.object(repository, 'admit_runtime', side_effect=admission, return_value=self.owner), \
                patch.object(repository.os, 'execv', side_effect=Replaced) as replace:
            try:
                repository.RepositoryCoreCallback().invoke(command)
            finally:
                self.replace = replace

    def test_root_and_nested_cwd_use_same_literal_root_and_actual_exec(self):
        pid = os.getpid()
        for cwd in (self.root, self.nested):
            with self.subTest(cwd=cwd), self.assertRaises(Replaced):
                self.invoke(cwd, ('done','opaque-id','--operation-id','original'))
            self.assertEqual(os.getpid(), pid)
            self.assertEqual(self.replace.call_args.args, (self.owner.path,
                [self.owner.path,'profile-core','--profile-id',self.profile,
                 '--repository-root',str(self.root),'--','done','opaque-id','--operation-id','original']))

    def test_nearest_explicit_nested_reference_is_used_without_parent_fallback(self):
        other = 'profile_' + 'b' * 32
        self.write_reference(self.root / 'src', other)
        with self.assertRaises(Replaced): self.invoke(self.nested)
        args = self.replace.call_args.args[1]
        self.assertEqual(args[3:6], [other,'--repository-root',str(self.root / 'src')])
        with self.assertRaises(references.RepositoryProfileError):
            self.invoke(self.nested, admission=ValueError('central_refused'))
        self.replace.assert_not_called()

    def test_missing_malformed_and_git_boundaries_do_not_escape_to_parent(self):
        boundary = self.root / 'src' / '.agentmux'
        boundary.mkdir()
        for raw in (None, b'{}', b'not-json'):
            if raw is not None: (boundary / 'config.json').write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(references.RepositoryProfileError):
                self.invoke(self.nested)
            self.replace.assert_not_called()
        (boundary / 'config.json').unlink(); boundary.rmdir()
        (self.root / 'src' / '.git').write_text('gitdir: untrusted')
        with self.assertRaises(references.RepositoryProfileError): self.invoke(self.nested)
        self.replace.assert_not_called()

    def test_config_replacement_or_new_nearer_reference_during_admission_refuses(self):
        original = self.root / '.agentmux' / 'config.json'
        def replace_config(**kwargs):
            alternate = original.with_name('replacement')
            alternate.write_bytes(original.read_bytes()); alternate.chmod(0o600)
            alternate.replace(original)
            return self.owner
        with self.assertRaisesRegex(references.RepositoryProfileError, 'changed'):
            self.invoke(self.nested, admission=replace_config)
        self.replace.assert_not_called(); self.owner.close.assert_called_once()
        def nearer(**kwargs):
            self.write_reference(self.root / 'src', self.profile)
            return self.owner
        with self.assertRaisesRegex(references.RepositoryProfileError, 'changed'):
            self.invoke(self.nested, admission=nearer)
        self.replace.assert_not_called()

    def test_unsafe_path_reference_and_start_refuse(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.nested, target_is_directory=True)
        with self.assertRaises(references.RepositoryProfileError): self.invoke(alias)
        self.replace.assert_not_called()

    def test_nearer_symlink_and_cwd_replacement_refuse(self):
        local = self.root / 'src' / '.agentmux'
        local.symlink_to(self.root / '.agentmux', target_is_directory=True)
        with self.assertRaises(references.RepositoryProfileError): self.invoke(self.nested)
        self.replace.assert_not_called()
        local.unlink()
        def moved(**kwargs):
            self.nested.rename(self.nested.with_name('moved'))
            self.nested.mkdir()
            return self.owner
        with self.assertRaisesRegex(references.RepositoryProfileError, 'changed'):
            self.invoke(self.nested, admission=moved)
        self.replace.assert_not_called()
        reference = self.root / '.agentmux' / 'config.json'
        reference.chmod(0o666)
        with self.assertRaises(references.RepositoryProfileError): self.invoke(self.nested)
        self.replace.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'selected_core_setup_required'):
            self.invoke(self.root, ('start',))
        self.replace.assert_not_called()

    def test_missing_reference_expired_deadline_and_root_boundary_refuse(self):
        (self.root / '.agentmux' / 'config.json').unlink()
        with self.assertRaises(references.RepositoryProfileError): self.invoke(self.nested)
        for directory, deadline in ((str(self.nested), time.monotonic()-1), ('/', time.monotonic()+1)):
            with self.assertRaises(references.RepositoryProfileError):
                with references.discover_repository_profile(directory, deadline=deadline): pass


    def test_callback_retains_runtime_owner_and_original_exec_failure(self):
        for raises in (True, False):
            with self.subTest(raises=raises):
                cleanup = OSError('close failed')
                self.owner.reset_mock()
                self.owner.close.side_effect = cleanup if raises else None
                self.owner.closed = False
                with self.assertRaisesRegex(references.RepositoryProfileError, 'cleanup_pending') as caught:
                    self.invoke(self.nested)
                self.assertEqual(caught.exception.cleanup_owners, (self.owner,))
                handoff = caught.exception.__cause__
                self.assertIsInstance(handoff, repository._HandoffFailure)
                self.assertIsInstance(handoff._causes[0], Replaced)
                if raises: self.assertIs(handoff._causes[1], cleanup)
                self.owner.close.assert_called_once_with()

    def test_callback_retains_admission_cleanup_and_recovery_without_retry(self):
        cleanup, recovery, extra = Mock(), Mock(), Mock()
        failure = SelectionError('native_admission_failed', cleanup=cleanup)
        failure.recovery, failure.cleanup_owners = recovery, (extra, cleanup)
        with self.assertRaisesRegex(references.RepositoryProfileError, 'cleanup_pending') as caught:
            self.invoke(self.nested, admission=failure)
        self.assertEqual(caught.exception.cleanup_owners, (extra, cleanup, recovery))
        self.assertIs(caught.exception.recovery, recovery)
        self.assertIs(caught.exception.__cause__, failure)
        self.owner.close.assert_not_called()
        self.replace.assert_not_called()
        for retained in (cleanup, recovery, extra): retained.close.assert_not_called()

    def test_callback_preserves_combined_directory_and_runtime_cleanup(self):
        close = references._RepositoryDirectory.close
        directory_failure = Mock()
        def failed_close(owner):
            close(owner)
            raise references.RepositoryProfileError('repository_profile_cleanup_pending',
                cleanup_owners=(directory_failure,))
        self.owner.closed = False
        with patch.object(references._RepositoryDirectory, 'close', failed_close), \
                self.assertRaisesRegex(references.RepositoryProfileError, 'cleanup_pending') as caught:
            self.invoke(self.nested)
        self.assertEqual(caught.exception.cleanup_owners, (directory_failure, self.owner))
        translated = caught.exception.__cause__
        self.assertEqual(translated.cleanup_owners, (self.owner,))
        self.assertIsInstance(translated.__cause__._causes[0], Replaced)
        self.owner.close.assert_called_once_with()

    def test_recheck_cleanup_and_failed_close_keep_both_original_owners(self):
        nested_cleanup = Mock()
        failure = SelectionError('launcher_unavailable', cleanup=nested_cleanup)
        self.owner.recheck.side_effect = failure
        self.owner.close.side_effect = OSError('close failed')
        with self.assertRaisesRegex(references.RepositoryProfileError, 'cleanup_pending') as caught:
            self.invoke(self.nested)
        self.assertEqual(caught.exception.cleanup_owners, (self.owner, nested_cleanup))
        self.assertIs(caught.exception.__cause__._causes[0], failure)
        self.owner.close.assert_called_once_with()
        self.replace.assert_not_called()


class RepositoryStartup(unittest.TestCase):
    def options(self, worker=False, output='human'):
        return entry.Options(None, worker, output, '/approved/repo with spaces')

    def test_root_option_is_closed_and_does_not_select_from_cwd(self):
        value = entry.parse_options(['--repository-root', '/approved/repo with spaces', '--output', 'json'])
        self.assertEqual(value.repository_root, '/approved/repo with spaces')
        self.assertIsNone(entry.parse_options([]).repository_root)
        for args in (['--repository-root'], ['--repository-root', 'relative'],
                ['--repository-root', '//approved/repo'], ['--repository-root', '/approved/../repo'],
                ['--repository-root', '/approved/repo', '--repository-root', '/other'],
                ['--repository-root', '/approved/\nrepo'],
                ['--repository-root', '/r' * 128],
                ['--repository-root', '/approved/\u0080repo'], ['--repository-root', '/approved/\u009frepo']):
            with self.subTest(args=args), self.assertRaises(entry.OptionsError):
                entry.parse_options(args)

    def test_explicit_selection_bypasses_repository_import_and_reads(self):
        observed = result('ensure', 'observed')
        options = entry.parse_options(['--selection', '/private/explicit.json',
                                       '--repository-root', 'unused-relative-root'])
        with patch.object(entry, 'startup', return_value=observed) as startup, \
                patch.object(repository, 'repository_startup') as handoff, \
                patch.object(references, 'read_repository_profile') as read:
            session = entry.EnrolledSession(options)
            self.assertIs(session.start(), observed)
            self.assertIs(session.start(), observed)
        startup.assert_called_once_with('/private/explicit.json', managed_worker=False)
        handoff.assert_not_called()
        read.assert_not_called()

    def test_all_closed_operations_keep_literal_ids_and_retained_image(self):
        profile = 'profile_' + 'a' * 32
        for mcp, worker, output, operation in ((False, False, 'human', 'startup'),
                (False, False, 'json', 'startup-json'), (False, True, 'human', 'startup-worker'),
                (False, True, 'json', 'startup-worker-json'), (True, False, 'human', 'mcp'),
                (True, True, 'human', 'mcp-worker')):
            options = self.options(worker, output)
            read = Mock(return_value=references.RepositoryProfileReference(profile))
            owner = Mock(path='/protected/runtime with spaces', closed=True)
            order = []
            owner.recheck.side_effect = lambda **kwargs: order.append('recheck')
            owner.close.side_effect = lambda: order.append('close')
            def replace(path, arguments):
                self.assertEqual(order, ['recheck'])
                self.assertEqual(path, owner.path)
                self.assertEqual(arguments, [owner.path, 'profile-client', '--profile-id', profile,
                    '--repository-root', options.repository_root, '--operation', operation])
                raise Replaced()
            with self.subTest(operation=operation), self.assertRaises(Replaced):
                repository._repository_startup(options, mcp=mcp, deadline=time.monotonic() + 1,
                    read=read, admit=Mock(return_value=owner), replace=replace)
            self.assertEqual(order, ['recheck', 'close'])
            read.assert_called_once()

    def test_absent_malformed_reference_and_admission_failure_are_setup_required(self):
        for read in (Mock(return_value=None), Mock(side_effect=references.RepositoryProfileError('PRIVATE')),
                     Mock(side_effect=FileNotFoundError('PRIVATE'))):
            admit, replace = Mock(), Mock()
            observed = repository._repository_startup(self.options(), mcp=False, deadline=time.monotonic() + 1,
                read=read, admit=admit, replace=replace)
            self.assertEqual((observed.public['outcome'], observed.public['code']), ('setup_required', 'setup_required'))
            self.assertNotIn('PRIVATE', json.dumps(observed.public))
            admit.assert_not_called()
            replace.assert_not_called()
        replace = Mock()
        observed = repository._repository_startup(self.options(), mcp=False, deadline=time.monotonic() + 1,
            read=Mock(return_value=references.RepositoryProfileReference('profile_' + 'a' * 32)),
            admit=Mock(side_effect=SelectionError('native_admission_failed')), replace=replace)
        self.assertEqual(observed.public['outcome'], 'setup_required')
        replace.assert_not_called()

    def test_reader_and_exec_cleanup_uncertainty_keep_original_owners(self):
        retained = object()
        read = Mock(side_effect=references.RepositoryProfileError('repository_profile_cleanup_pending',
                    cleanup_owners=(retained,)))
        observed = repository._repository_startup(self.options(), mcp=False, deadline=time.monotonic() + 1,
            read=read, admit=Mock(), replace=Mock())
        self.assertEqual(observed.selection_cleanup.owners, (retained,))
        self.assertFalse(observed.finish_cleanup())
        owner = Mock(path='/protected/runtime', closed=False)
        owner.close.side_effect = OSError('PRIVATE')
        observed = repository._repository_startup(self.options(), mcp=False, deadline=time.monotonic() + 1,
            read=Mock(return_value=references.RepositoryProfileReference('profile_' + 'a' * 32)),
            admit=Mock(return_value=owner), replace=Mock(side_effect=OSError('PRIVATE')))
        self.assertEqual(observed.selection_cleanup.owners, (owner,))
        self.assertFalse(observed.finish_cleanup())
        owner.close.assert_called_once_with()

    def test_actual_closed_repo_reader_feeds_only_id_to_native_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / '.agentmux').mkdir(mode=0o700)
            reference = root / '.agentmux' / 'config.json'
            reference.write_text(json.dumps({'schemaVersion': '1.0.0', 'profileId': 'profile_' + 'b' * 32}))
            reference.chmod(0o600)
            options = entry.Options(None, False, 'human', str(root))
            owner = Mock(path='/protected/runtime', closed=True)
            replace = Mock(side_effect=Replaced)
            with patch.object(references.filesystem, '_native'), self.assertRaises(Replaced):
                repository._repository_startup(options, mcp=False, deadline=time.monotonic() + 1,
                    read=references.read_repository_profile, admit=Mock(return_value=owner), replace=replace)
            self.assertEqual(replace.call_args.args[1][3], 'profile_' + 'b' * 32)
            self.assertEqual(reference.read_text(), json.dumps({'schemaVersion': '1.0.0', 'profileId': 'profile_' + 'b' * 32}))

    def test_enrolled_mcp_setup_state_remains_protocol_clean_and_once_only(self):
        setup = result('status', 'setup_required', 'setup_required')
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'agentmux_startup_status'}}
        output = io.StringIO()
        with patch.object(repository, 'repository_startup', return_value=setup) as handoff:
            session = entry.EnrolledSession(self.options(worker=True))
            session.serve_mcp(stdin=io.StringIO(json.dumps(request) + '\n'), stdout=output)
            session.start()
        self.assertTrue(handoff.call_args.kwargs['mcp'])
        handoff.assert_called_once()
        self.assertEqual(json.loads(output.getvalue())['result']['structuredContent']['outcome'], 'setup_required')
