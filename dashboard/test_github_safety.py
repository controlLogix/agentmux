"""Offline GitHub boundary checks; every command and PTY is replaced in process."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, call, patch

import github_auth as auth
import github_panel as panel


class GitHubSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.patch(auth, '_CREDENTIAL_LOCK', threading.Lock())
        self.patch(auth, 'gh_path', return_value='/fixture/gh')
        self.patch(auth.subprocess, 'run', side_effect=AssertionError('unexpected command'))
        self.patch(auth.subprocess, 'Popen', side_effect=AssertionError('unexpected child'))
        self.patch(auth.pty, 'openpty', side_effect=AssertionError('unexpected PTY'))
        self.patch(auth.threading, 'Thread', side_effect=AssertionError('unexpected worker'))
        self.environ = patch.dict(os.environ, {'HOME': str(self.home)}, clear=True)
        self.environ.start()
        self.addCleanup(self.environ.stop)
        panel._CACHE.clear()

    def patch(self, target, name, *args, **kwargs):
        change = patch.object(target, name, *args, **kwargs)
        value = change.start()
        self.addCleanup(change.stop)
        return value

    def write(self, issue=False, **fields):
        body = {'actor': 'operator', 'confirm': True}
        body.update({'repo': 'owner/repo', 'title': 'Title'} if issue
                    else {'owner': 'owner', 'name': 'repo'})
        body.update(fields)
        return auth.create_issue(body) if issue else auth.create_repo(body)

    def claim_login(self, journal=None):
        login = auth.Login(journal)
        self.assertTrue(auth._CREDENTIAL_LOCK.acquire(blocking=False))
        login._owns_credentials = True
        login.state = 'starting'
        return login

    def test_description_cannot_add_an_option(self):
        with patch.object(auth, '_run', return_value='https://github.com/owner/repo') as run:
            self.write(description='--public')
        self.assertEqual(run.call_args.args[0],
                         ['repo', 'create', 'owner/repo', '--private', '--description=--public'])
        self.assertTrue(run.call_args.kwargs['changes_remote'])

    def test_title_and_labels_keep_option_values(self):
        with patch.object(auth, '_run', return_value='https://github.com/owner/repo/issues/7') as run:
            self.write(issue=True, title='--web', labels=['--assignee', '-x'], body='private body')
        self.assertEqual(run.call_args.args[0],
                         ['issue', 'create', '--repo', 'github.com/owner/repo', '--title=--web',
                          '--body-file', '-', '--label=--assignee', '--label=-x'])
        self.assertEqual(run.call_args.kwargs['stdin_text'], 'private body')
        self.assertTrue(run.call_args.kwargs['changes_remote'])

    def test_empty_issue_body_is_explicit(self):
        with patch.object(auth, '_run', return_value='https://github.com/owner/repo/issues/7') as run:
            self.write(issue=True)
        self.assertEqual(run.call_args.args[0][-2:], ['--body-file', '-'])
        self.assertEqual(run.call_args.kwargs['stdin_text'], '')

    def test_invalid_targets_never_execute(self):
        with patch.object(auth, '_run') as run:
            for fields in ({'name': '--public'}, {'owner': 'other/repo'},
                           {'confirm': False}, {'actor': ''}, {'unknown': 'value'}):
                with self.subTest(fields=fields), self.assertRaises(auth.Invalid):
                    self.write(**fields)
            for repo in ('owner/..', 'owner/.', '--repo=other/name', 'https://github.com/a/b'):
                with self.subTest(repo=repo), self.assertRaises(auth.Invalid):
                    self.write(issue=True, repo=repo)
            run.assert_not_called()

    def test_write_result_requires_exact_host_target_and_kind(self):
        rejected = ['https://github.com.evil.invalid/owner/repo',
                    'https://evilgithub.com/owner/repo',
                    'https://github.com@evil.invalid/owner/repo',
                    'https://github.com/other/repo',
                    'https://github.com/owner/repo?token=SYNTHETIC_SECRET',
                    'https://github.com/owner/repo/issues/7', 'SYNTHETIC_SECRET']
        for output in rejected:
            with self.subTest(output=output), patch.object(auth, '_run', return_value=output):
                with self.assertRaises(auth.OutcomeUnknown) as error:
                    self.write()
                self.assertNotIn('SYNTHETIC_SECRET', str(error.exception))
                self.assertIn('before retrying', str(error.exception))
        self.assertEqual(auth._result_url('https://github.com/Owner/Repo', 'owner/repo'),
                         'https://github.com/Owner/Repo')
        self.assertEqual(auth._result_url('https://github.com/Owner/Repo', 'repo'),
                         'https://github.com/Owner/Repo')
        with self.assertRaises(auth.OutcomeUnknown):
            auth._result_url('https://github.com/owner/repo/pull/7', 'owner/repo', issue=True)

    def test_lost_write_reply_is_uncertain_and_redacted(self):
        for failure in (subprocess.TimeoutExpired('gh', 45, output='SYNTHETIC_SECRET'),
                        subprocess.CompletedProcess([], 1, 'SYNTHETIC_SECRET', 'SYNTHETIC_SECRET')):
            with self.subTest(failure=type(failure).__name__), patch.object(
                    auth.subprocess, 'run', **({'side_effect': failure} if isinstance(failure, Exception)
                                              else {'return_value': failure})):
                with self.assertRaises(auth.OutcomeUnknown) as error:
                    self.write()
                self.assertNotIn('SYNTHETIC_SECRET', str(error.exception))
                self.assertIs(error.exception.outcome_unknown, True)

    def test_child_host_and_stdin_are_fixed(self):
        done = subprocess.CompletedProcess([], 0, 'https://github.com/owner/repo/issues/7')
        with patch.dict(os.environ, {'GH_HOST': 'other.invalid', 'GH_REPO': 'other/repo'}), \
                patch.object(auth.subprocess, 'run', return_value=done) as run:
            self.write(issue=True, body='')
        self.assertEqual(run.call_args.kwargs['env']['GH_HOST'], 'github.com')
        self.assertEqual(run.call_args.kwargs['input'], '')
        self.assertNotIn('stdin', run.call_args.kwargs)
        self.assertIn('github.com/owner/repo', run.call_args.args[0])

    def test_account_rejects_bad_records_and_uses_canonical_profile(self):
        for record in ([], {'login': ['owner']}, {'login': 123}, {'login': 'bad/name'}):
            with self.subTest(record=record), patch.object(auth, '_run', return_value='\n\n' + json.dumps(record)):
                self.assertFalse(auth.account()['authenticated'])
        raw = 'X-OAuth-Scopes: repo, read:org\n\n' + json.dumps(
            {'login': 'owner', 'name': 'Owner', 'html_url': 'https://evil.invalid/'})
        with patch.object(auth, '_run', side_effect=[raw, '{}']) as run:
            state = auth.account()
        self.assertEqual(state['url'], 'https://github.com/owner')
        self.assertEqual(state['scopes'], ['repo', 'read:org'])
        self.assertTrue(all(c.args[0][1:3] == ['--hostname', 'github.com']
                            for c in run.call_args_list))

    def test_macos_install_guidance(self):
        with patch.object(auth.sys, 'platform', 'darwin'), patch.object(auth, 'gh_path', return_value=None):
            self.assertEqual(auth.account()['command'], 'brew install gh')

    def test_cancel_keeps_original_worker_and_blocks_another_login_and_logout(self):
        worker = Mock()
        worker.is_alive.return_value = True
        login = auth.Login()
        with patch.object(auth.threading, 'Thread', return_value=worker) as make:
            login.start('operator')
            original_cancel = login._cancel
            state = login.cancel()
            self.assertEqual(state['state'], 'finishing')
            self.assertTrue(original_cancel.is_set())
            worker.join.assert_called_once_with(timeout=auth.LOGIN_JOIN_TIMEOUT)
            self.assertIs(login.thread, worker)
            with self.assertRaises(auth.Invalid):
                login.start('someone-else')
            with self.assertRaises(auth.Invalid):
                auth.Login().start('someone-else')
            with self.assertRaises(auth.Invalid):
                auth.logout('operator')
            self.assertEqual(make.call_count, 1)

    def test_finished_worker_is_joined_before_replacement(self):
        old, new = Mock(), Mock()
        old.is_alive.return_value = False
        new.is_alive.return_value = True
        login = auth.Login()
        login.thread = old
        events = []
        old.join.side_effect = lambda: events.append('joined')
        new.start.side_effect = lambda: events.append('started')
        with patch.object(auth.threading, 'Thread', return_value=new):
            login.start('operator')
        self.assertEqual(events, ['joined', 'started'])

    def test_worker_start_failure_releases_credentials(self):
        worker = Mock()
        worker.start.side_effect = RuntimeError('SYNTHETIC_SECRET')
        login = auth.Login()
        with patch.object(auth.threading, 'Thread', return_value=worker):
            with self.assertRaises(auth.Unavailable) as error:
                login.start('operator')
        self.assertNotIn('SYNTHETIC_SECRET', str(error.exception))
        self.assertEqual(login.state, 'error')
        self.assertFalse(auth._CREDENTIAL_LOCK.locked())

    def test_pty_failure_finishes_with_safe_error(self):
        login = self.claim_login()
        with patch.object(auth.pty, 'openpty', side_effect=OSError('SYNTHETIC_SECRET')):
            login._run(login._cancel, '/fixture/gh', 'operator')
        self.assertEqual(login.state, 'error')
        self.assertNotIn('SYNTHETIC_SECRET', login.error)
        self.assertFalse(auth._CREDENTIAL_LOCK.locked())

    def test_cancel_before_spawn_does_not_allocate_a_pty(self):
        login = self.claim_login()
        login._cancel.set()
        login._run(login._cancel, '/fixture/gh', 'operator')
        self.assertEqual(login.state, 'idle')
        self.assertFalse(auth._CREDENTIAL_LOCK.locked())

    def test_kill_is_followed_by_wait_on_the_same_process(self):
        login = self.claim_login()
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('gh', 5), -9]
        with patch.object(auth.pty, 'openpty', return_value=(101, 102)), \
                patch.object(auth.subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(auth.os, 'close') as close, \
                patch.object(auth.time, 'monotonic', side_effect=[0, 301]):
            login._run(login._cancel, '/selected/gh', 'operator')
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_args_list, [call(timeout=auth.LOGIN_STOP_TIMEOUT), call()])
        self.assertEqual(close.call_args_list, [call(102), call(101)])
        self.assertEqual(spawn.call_args.args[0][0], '/selected/gh')
        self.assertIsNone(login._process)
        self.assertFalse(auth._CREDENTIAL_LOCK.locked())

    def test_cleanup_failure_keeps_the_process_and_credential_owner(self):
        login = self.claim_login()
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = OSError('SYNTHETIC_SECRET')
        with patch.object(auth.pty, 'openpty', return_value=(101, 102)), \
                patch.object(auth.subprocess, 'Popen', return_value=process), \
                patch.object(auth.os, 'close'), \
                patch.object(auth.time, 'monotonic', side_effect=[0, 301]):
            login._run(login._cancel, '/fixture/gh', 'operator')
        self.assertEqual(login.state, 'finishing')
        self.assertIs(login._process, process)
        self.assertTrue(auth._CREDENTIAL_LOCK.locked())
        self.assertNotIn('SYNTHETIC_SECRET', login.error)
        with self.assertRaises(auth.Invalid):
            login.start('operator')

    def test_device_link_is_fixed_and_journal_keeps_original_actor(self):
        journal = Mock()
        login = self.claim_login(journal)
        login.actor = 'later-actor'
        process = Mock()
        process.poll.return_value = 0
        process.wait.return_value = 0
        seen = []
        with patch.object(auth.pty, 'openpty', return_value=(101, 102)), \
                patch.object(auth.subprocess, 'Popen', return_value=process), \
                patch.object(auth.os, 'close'), \
                patch.object(auth.select, 'select', return_value=([101], [], [])), \
                patch.object(auth.os, 'read', return_value=b'ABCD-1234 https://evilgithub.com/login/device'), \
                patch.object(auth.os, 'write', side_effect=lambda *args: seen.append(login.snapshot())):
            login._run(login._cancel, '/fixture/gh', 'original-actor')
        self.assertEqual(seen[0]['url'], auth.DEVICE_URL)
        self.assertEqual(seen[0]['code'], 'ABCD-1234')
        self.assertEqual(login.state, 'done')
        self.assertIsNone(login.code)
        self.assertEqual(journal.call_args.args[0]['actor'], 'original-actor')

    def test_cancel_reconciles_only_the_retained_stopped_process(self):
        login = self.claim_login()
        worker, process = Mock(), Mock()
        worker.is_alive.return_value = False
        process.wait.side_effect = [subprocess.TimeoutExpired('gh', 0), 0]
        login.thread, login._process = worker, process
        self.assertEqual(login.cancel()['state'], 'finishing')
        self.assertIs(login._process, process)
        self.assertTrue(auth._CREDENTIAL_LOCK.locked())
        self.assertEqual(login.cancel()['state'], 'idle')
        self.assertIsNone(login._process)
        self.assertFalse(auth._CREDENTIAL_LOCK.locked())
        self.assertEqual(process.wait.call_args_list, [call(timeout=0), call(timeout=0)])

    def test_logout_releases_the_credential_lock_after_failure(self):
        with patch.object(auth, '_run', side_effect=auth.Unavailable('failed')):
            with self.assertRaises(auth.Unavailable):
                auth.logout('operator')
        self.assertFalse(auth._CREDENTIAL_LOCK.locked())

    def test_origin_identity_rejects_lookalikes_and_preserves_common_urls(self):
        for origin in ('https://github.com/Owner/Repo.git', 'git@github.com:Owner/Repo.git',
                       'ssh://git@github.com:22/Owner/Repo.git'):
            with self.subTest(origin=origin):
                self.assertEqual(panel.origin_identity(origin), 'Owner/Repo')
        for origin in ('https://evilgithub.com/Owner/Repo.git',
                       'https://github.com.evil.invalid/Owner/Repo.git',
                       'https://github.com@evil.invalid/Owner/Repo.git',
                       'https://github.com/Owner/Repo.git?secret=value',
                       'https://github.com/Owner/..', 'https://github.com:invalid/Owner/Repo',
                       'file:///tmp/github.com/Owner/Repo.git'):
            with self.subTest(origin=origin):
                self.assertIsNone(panel.origin_identity(origin))

    def snapshot_runner(self, origin='https://github.com/owner/repo.git', prs='[]', runs='[]'):
        def run(argv, cwd=None):
            if argv[0] == '/fixture/gh':
                self.assertEqual(argv[-2:], ['--repo', 'github.com/owner/repo'])
                return prs if argv[1] == 'pr' else runs
            command = argv[3:]
            if command == ['rev-parse', '--abbrev-ref', 'HEAD']:
                return 'HEAD\n'
            if command == ['remote', 'get-url', 'origin']:
                return origin
            if command[:1] == ['status']:
                return '?? line\nfile\0'
            if command == ['rev-parse', '--abbrev-ref', '@{upstream}']:
                return 'origin/main\n'
            if command[:1] == ['rev-list']:
                return '2 3\n'
            if command[:1] == ['log']:
                return '123abc\x1fSubject\x1f2026-10-16T00:00:00Z\n'
            raise AssertionError(argv)
        return run

    def test_snapshot_pins_origin_and_labels_local_tracking_freshness(self):
        with patch.object(panel, 'run', side_effect=self.snapshot_runner()) as run:
            result = panel.repo_snapshot({'name': 'configured', 'path': str(self.home)}, '/fixture/gh')
        self.assertEqual(result['name'], 'configured')
        self.assertEqual(result['nwo'], 'owner/repo')
        self.assertEqual((result['branch'], result['dirty_files'], result['ahead'], result['behind']),
                         ('HEAD', 1, 2, 3))
        self.assertEqual(result['tracking_freshness'], 'possibly_stale')
        self.assertEqual(result['tracking_source'], 'local_refs')
        self.assertEqual(sum(c.args[0][0] == '/fixture/gh' for c in run.call_args_list), 2)
        self.assertFalse(any('fetch' in c.args[0] or 'merge' in c.args[0] for c in run.call_args_list))

    def test_unverified_origin_keeps_git_state_without_remote_queries(self):
        with patch.object(panel, 'run', side_effect=self.snapshot_runner('https://evilgithub.com/owner/repo')) as run:
            result = panel.repo_snapshot({'path': str(self.home)}, '/fixture/gh')
        self.assertEqual(result['ahead'], 2)
        self.assertIsNone(result['nwo'])
        self.assertEqual(result['prs'], [])
        self.assertTrue(result['errors'])
        self.assertFalse(any(c.args[0][0] == '/fixture/gh' for c in run.call_args_list))

    def test_partial_gh_failure_is_redacted_and_preserves_other_results(self):
        prs = json.dumps([{'statusCheckRollup': ['SYNTHETIC_SECRET']}])
        runs = json.dumps([{'databaseId': 7, 'conclusion': 'success', 'status': 'completed'}])
        with patch.object(panel, 'run', side_effect=self.snapshot_runner(prs=prs, runs=runs)):
            result = panel.repo_snapshot({'path': str(self.home)}, '/fixture/gh')
        self.assertEqual(result['runs'][0]['databaseId'], 7)
        self.assertEqual(result['prs'], [])
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(result))
        self.assertEqual(len(result['errors']), 1)

    def test_snapshot_returns_only_selected_fields_and_target_links(self):
        prs = json.dumps([{'number': 1, 'title': 'PR', 'token': 'SYNTHETIC_SECRET',
                           'url': 'https://evilgithub.com/owner/repo/pull/1'}])
        runs = json.dumps([{'databaseId': 7, 'status': 'completed',
                            'url': 'https://github.com/owner/repo/actions/runs/7'}])
        with patch.object(panel, 'run', side_effect=self.snapshot_runner(prs=prs, runs=runs)):
            result = panel.repo_snapshot({'path': str(self.home)}, '/fixture/gh')
        self.assertIsNone(result['prs'][0]['url'])
        self.assertEqual(result['runs'][0]['url'], 'https://github.com/owner/repo/actions/runs/7')
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(result))

    def test_configured_paths_and_unknown_config_fields_are_preserved(self):
        settings = {'repos': [{'name': 'preserved', 'path': '/synthetic/repo', 'future': {'keep': True}}],
                    'future_setting': 7}
        file = self.home / 'github.json'
        original = json.dumps(settings)
        file.write_text(original)
        self.assertEqual(panel.configured_repos(self.home), settings['repos'])
        self.assertEqual(file.read_text(), original)


if __name__ == '__main__':
    unittest.main()
