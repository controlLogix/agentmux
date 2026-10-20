#!/usr/bin/env python3
"""Isolated GitHub suite: temporary repositories, mocked gh, ephemeral HTTP port."""
import http.client
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
import github_panel as panel
import github_auth as auth


class GithubTests(unittest.TestCase):
    def setUp(self):
        panel._CACHE.clear()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-b', 'main')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Fixture')
        (self.repo / 'file').write_text('one')
        self.git('add', 'file')
        self.git('commit', '-m', 'first')
        self.git('remote', 'add', 'origin', 'https://github.com/fixture/repo.git')
        self.config = {'name': 'fixture', 'path': str(self.repo)}
        (self.root / 'github.json').write_text(json.dumps({'repos': [self.config]}))

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.DEVNULL, text=True)

    def test_windows_discovery_and_native_precedence(self):
        windows = '/mnt/c/Program Files/GitHub CLI/gh.exe'
        with patch.object(auth.shutil, 'which', side_effect=lambda name: windows if name == 'gh.exe' else None) as which:
            self.assertEqual(auth.gh_path(), windows)
            self.assertEqual([c.args for c in which.call_args_list], [('gh',), ('gh.exe',)])
        with patch.object(auth.shutil, 'which', return_value='/usr/bin/gh') as which:
            self.assertEqual(auth.gh_path(), '/usr/bin/gh')
            which.assert_called_once_with('gh')

    def test_windows_account_cannot_login_and_guidance(self):
        raw = 'X-Oauth-Scopes: repo\n\n{"login": "octo"}'
        with patch.object(auth, 'gh_path', return_value='/mnt/c/Program Files/GitHub CLI/gh.exe'), patch.object(auth, 'HAVE_PTY', True):
            for response in (raw, auth.Unavailable('gh api failed (exit 1).')):
                with self.subTest(response=str(response)), patch.object(auth, '_run', side_effect=[response, '{}']):
                    state = auth.account()
                    self.assertTrue(state['cli'])
                    self.assertIs(state['can_login'], False)
                    self.assertEqual(state['authenticated'], isinstance(response, str))
                    self.assertIn('Windows side', state['message'])
                    self.assertIn('gh auth login', state['command'])
                    self.assertNotIn('apt install', str(state))

    def test_windows_login_unavailable(self):
        with patch.object(auth, 'gh_path', return_value='/mnt/c/Program Files/GitHub CLI/gh.exe'), patch.object(auth, 'HAVE_PTY', True):
            self.assertIs(auth.Login().available(), False)

    def test_windows_login_start_refused_before_thread(self):
        with patch.object(auth, 'gh_path', return_value='/mnt/c/Program Files/GitHub CLI/gh.exe'), patch.object(auth, 'HAVE_PTY', True), patch.object(auth.threading, 'Thread') as thread:
            with self.assertRaisesRegex(auth.Unavailable, 'Windows side'):
                auth.Login().start('operator')
            thread.assert_not_called()

    def test_auth_resolved_binary_and_closed_stdin(self):
        binary = '/mnt/c/Program Files/GitHub CLI/gh.exe'
        with patch.object(auth, 'gh_path', return_value=binary), patch.object(auth.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'ok')) as run:
            self.assertEqual(auth._run(['auth', 'logout', '--hostname', 'github.com']), 'ok')
            self.assertEqual(run.call_args.args[0], [binary, 'auth', 'logout', '--hostname', 'github.com'])
            self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
            self.assertNotIn('input', run.call_args.kwargs)

    def test_issue_body_keeps_pipe(self):
        with patch.object(auth, 'gh_path', return_value='/bin/gh'), patch.object(auth.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'https://github.com/a/b/issues/1')) as run:
            auth.create_issue({'repo': 'a/b', 'title': 'Issue', 'body': 'body\ntext', 'actor': 'operator', 'confirm': True})
            self.assertEqual(run.call_args.args[0], ['/bin/gh', 'issue', 'create', '--repo', 'github.com/a/b', '--title=Issue', '--body-file', '-'])
            self.assertEqual(run.call_args.kwargs['input'], 'body\ntext')
            self.assertNotIn('stdin', run.call_args.kwargs)

    def test_panel_closes_stdin(self):
        with patch.object(panel.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'ok')) as run:
            self.assertEqual(panel.run(['/resolved/gh.exe', 'auth', 'status']), 'ok')
            self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)

    def test_windows_panel_resolved_calls_and_remediation(self):
        binary = '/mnt/c/Program Files/GitHub CLI/gh.exe'
        real_run = panel.run
        calls = []
        def fake(argv, cwd=None):
            if argv[0] == 'git':
                return real_run(argv, cwd)
            calls.append(argv)
            self.assertEqual(argv[0], binary)
            return '[]'
        with patch.object(auth.shutil, 'which', side_effect=lambda name: binary if name == 'gh.exe' else None), patch.object(panel, 'run', side_effect=fake):
            row = panel.snapshot(self.root)
            self.assertEqual(row['gh']['state'], 'ready')
            self.assertEqual([c[1:3] for c in calls], [['auth', 'status'], ['pr', 'list'], ['run', 'list']])
            self.assertNotIn('apt install', str(row))
        panel._CACHE.clear()
        def failed(argv, cwd=None):
            if argv[0] == binary:
                raise ValueError('auth failed')
            return real_run(argv, cwd)
        with patch.object(auth, 'gh_path', return_value=binary), patch.object(panel, 'run', side_effect=failed):
            row = panel.snapshot(self.root)
            self.assertEqual(row['gh']['state'], 'unauthenticated')
            self.assertIn('Windows side', row['gh']['message'])
            self.assertEqual(row['gh']['command'], 'gh auth login')
            self.assertNotIn('apt install', str(row))

    def test_ahead_behind_dirty_commits(self):
        self.git('branch', 'tracking')
        self.git('branch', '--set-upstream-to=tracking')
        (self.repo / 'file').write_text('two')
        self.git('commit', '-am', 'second')
        (self.repo / 'newline\nfile').write_text('dirty')
        row = panel.repo_snapshot(self.config, False)
        self.assertEqual((row['branch'], row['ahead'], row['behind'], row['dirty_files']), ('main', 1, 0, 1))
        self.assertEqual(row['commits'][0]['subject'], 'second')
        self.git('checkout', 'tracking')
        (self.repo / 'other').write_text('behind')
        self.git('add', 'other')
        self.git('commit', '-m', 'other')
        self.git('checkout', 'main')
        row = panel.repo_snapshot(self.config, False)
        self.assertEqual((row['ahead'], row['behind']), (1, 1))

    def test_rename_count_and_no_upstream(self):
        self.git('mv', 'file', 'renamed')
        row = panel.repo_snapshot(self.config, False)
        self.assertEqual(row['dirty_files'], 1)
        self.assertIsNone(row['ahead'])
        self.assertIn('upstream', row['errors'][0])

    def test_detached_and_invalid_repo(self):
        self.git('checkout', '--detach')
        self.assertEqual(panel.repo_snapshot(self.config, False)['branch'], 'HEAD')
        self.assertTrue(panel.repo_snapshot({'path': str(self.root / 'absent')}, False)['errors'])

    def test_missing_auth_and_cache(self):
        with patch.object(auth.shutil, 'which', return_value=None):
            row = panel.snapshot(self.root)
            self.assertEqual(row['gh']['state'], 'missing')
            self.assertEqual(row['gh']['command'], auth.install_command())
            self.assertEqual(row['repos'][0]['branch'], 'main')
            with patch.object(panel, 'configured_repos', side_effect=AssertionError('cache miss')):
                self.assertEqual(panel.snapshot(self.root), row)
        panel._CACHE.clear()
        real_run = panel.run
        def auth_failure(argv, cwd=None):
            if argv[0] == '/bin/gh':
                raise ValueError('failed')
            return real_run(argv, cwd)
        with patch.object(auth.shutil, 'which', return_value='/bin/gh'), patch.object(panel, 'run', side_effect=auth_failure):
            self.assertEqual(panel.snapshot(self.root)['gh']['command'], 'gh auth login')

    def test_pr_checks_runs_order_duration_and_read_only_commands(self):
        real_run = panel.run
        calls = []
        def fake(argv, cwd=None):
            calls.append(argv)
            if argv[0] != 'gh':
                return real_run(argv, cwd)
            if argv[1] == 'pr':
                return json.dumps([{'number': 1, 'reviewDecision': 'APPROVED', 'statusCheckRollup': [{'conclusion': 'SUCCESS'}]},
                                   {'number': 2, 'reviewDecision': 'CHANGES_REQUESTED', 'statusCheckRollup': [{'state': 'FAILURE'}]}])
            return json.dumps([{'conclusion': c, 'status': 'completed', 'startedAt': '2026-09-23T00:00:00Z', 'updatedAt': '2026-09-23T00:01:03Z'} for c in ['success', 'failure']])
        with patch.object(panel, 'run', side_effect=fake):
            row = panel.repo_snapshot(self.config, 'gh')
        self.assertEqual(row['prs'][0]['number'], 2)
        self.assertEqual(row['prs'][0]['reviewDecision'], 'CHANGES_REQUESTED')
        self.assertEqual(row['runs'][0]['conclusion'], 'failure')
        self.assertEqual(row['runs'][0]['duration_seconds'], 63)
        self.assertTrue(all(c[1:3] in [['pr', 'list'], ['run', 'list']] for c in calls if c[0] == 'gh'))
        self.assertEqual(panel.ci_state([{'status': 'IN_PROGRESS'}]), 'PENDING')
        self.assertEqual(panel.ci_state([]), 'NO_CHECKS')

    def test_config_errors(self):
        (self.root / 'github.json').write_text('{broken')
        with patch.object(auth.shutil, 'which', return_value=None):
            self.assertTrue(panel.snapshot(self.root)['errors'])

    def test_cli_errors_redact_stderr(self):
        result = subprocess.CompletedProcess([], 1, '', 'secret-token')
        with patch.object(panel.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(ValueError, 'exit 1') as error:
                panel.run(['gh', 'auth', 'status'])
        self.assertNotIn('secret-token', str(error.exception))
        with patch.object(panel.subprocess, 'run', side_effect=subprocess.TimeoutExpired('gh', 12)):
            with self.assertRaisesRegex(ValueError, 'timed out'):
                panel.run(['gh', 'auth', 'status'])

    def test_partial_gh_failure(self):
        real_run = panel.run
        def fake(argv, cwd=None):
            if argv[0] == 'gh':
                return 'invalid json'
            return real_run(argv, cwd)
        with patch.object(panel, 'run', side_effect=fake):
            row = panel.repo_snapshot(self.config, 'gh')
        self.assertEqual(row['branch'], 'main')
        self.assertEqual(len([e for e in row['errors'] if e.startswith(('prs:', 'runs:'))]), 2)

    def test_frontend_rendering(self):
        # Match agentmux.sh node_bin(): newest nvm version before inherited PATH.
        env = os.environ.copy()
        bins = [p for p in (Path.home() / '.nvm/versions/node').glob('*/bin')
                if p.is_dir()]
        if bins:
            newest = max(bins, key=lambda p: tuple(
                int(part) if part.isdigit() else part
                for part in re.split(r'(\d+)', p.parent.name)))
            env['PATH'] = str(newest) + os.pathsep + env.get('PATH', os.defpath)
        node = shutil.which('node', path=env.get('PATH', os.defpath))
        if node is None:
            message = 'node unavailable after nvm discovery; skipping frontend rendering check'
            print('SKIP ' + message, flush=True)
            self.skipTest(message)
        script = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
  constructor(tag, cls, text) { this.tag = tag; this.text = text || ''; this.children = []; this.dataset = {}; }
  // Real code sets textContent after creating a node as often as it passes text
  // in; the fixture has to model both or it silently drops half the output.
  get textContent() { return this.text; }
  set textContent(value) { this.text = value === undefined ? '' : String(value); }
  appendChild(n) { this.children.push(n); return n; }
  append(...nodes) { nodes.forEach(n => this.appendChild(n)); }
  replaceChildren(...nodes) { this.children = nodes; }
  addEventListener() {}
  setAttribute() {}
}
const root = new Element('section');
let loader;
let data = {checked_at: 'now', gh: {state: 'ready'}, errors: [], repos: [{
  name: '<img src=x onerror=alert(1)>', path: '/repo', branch: 'main', ahead: 19,
  behind: 0, dirty_files: 2, upstream: 'origin/main', errors: [], commits: [],
  prs: [{number: 1, title: 'PR', ci: 'FAILURE', reviewDecision: 'CHANGES_REQUESTED', url: 'javascript:alert(1)'}],
  runs: [{displayTitle: 'Build', conclusion: 'failure', status: 'completed', duration_seconds: 63, url: 'https://github.com/a/b/actions/runs/1'}]
}]};
// The panel reads TWO snapshots now: the account (for sign-in state and the write
// forms) and the repository list. A token is never part of either.
let auth = {account: {cli: true, authenticated: true, login: 'octo', name: 'Octo',
                      url: 'https://github.com/octo', scopes: ['repo'], rate: null,
                      can_login: true, hostname: 'github.com', scopes_requested: ['repo']},
            login: {state: 'idle', code: null, url: 'https://github.com/login/device',
                    error: null, available: true, command: 'gh auth login --web'}};
const seen = [];
global.window = {CCC: {
  el: (...args) => new Element(...args),
  getJSON: async path => {
    seen.push(path);
    if (path === 'api/github/auth') return auth;
    assert.equal(path, 'api/github');
    return data;
  },
  post: async () => ({}),
  registerView: (name, fn, ms) => { assert.equal(name, 'github'); assert.equal(ms, 30000); loader = fn; }
}, confirm: () => true, addEventListener: (name, fn) => { assert.equal(name, 'ccc:ready'); fn(); }};
global.document = {getElementById: () => root, createElement: tag => new Element(tag)};
global.navigator = {clipboard: {writeText: async () => {}}};
vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'));
function flatten(n) { return [n, ...n.children.flatMap(flatten)]; }
(async () => {
  await loader();
  assert.deepEqual(seen.sort(), ['api/github', 'api/github/auth']);
  const nodes = flatten(root), text = nodes.map(n => n.text).join(' ');
  for (const expected of ['19 UNPUSHED COMMITS', 'DIRTY: 2 files', 'CHANGES_REQUESTED',
                          'FAILURE', 'failure', '63s', '<img src=x',
                          'Signed in as octo']) assert(text.includes(expected), expected);
  assert.equal(nodes.filter(n => n.tag === 'a').length, 1);

  // A one-time device code is displayed; it is not a secret and is useless without
  // the operator's own GitHub session. A TOKEN must never appear anywhere.
  auth = {account: {...auth.account, authenticated: false, login: null},
          login: {...auth.login, state: 'waiting', code: 'ABCD-1234'}};
  await loader();
  const signedOut = flatten(root).map(n => n.text).join(' ');
  assert(signedOut.includes('ABCD-1234'), 'the one-time code is shown');
  assert(signedOut.includes('Not signed in.'));
  assert(!/gh[pousr]_[A-Za-z0-9]/.test(signedOut), 'no token-shaped string is rendered');

  data = {...data, gh: {state: 'missing', message: 'gh is missing', command: 'sudo apt install gh'}, repos: []};
  await loader();
  assert(flatten(root).some(n => n.text.includes('sudo apt install gh')));
  window.CCC.getJSON = async () => { throw Error('offline'); };
  await loader();
  assert(flatten(root).some(n => n.text.includes('offline')));
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
        subprocess.run([node, '-e', script, str(Path(__file__).with_name('github.js'))],
                       check=True, env=env)

    def test_http_and_frontend_wiring(self):
        import server
        from http.server import ThreadingHTTPServer
        httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        httpd.daemon_threads = False
        thread = threading.Thread(target=httpd.serve_forever)
        try:
            thread.start()
        except BaseException:
            httpd.server_close()
            raise
        def stop_server():
            httpd.shutdown()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), 'original HTTP server thread is still running')
            httpd.server_close()
        self.addCleanup(stop_server)
        with patch.object(server.github_panel, 'snapshot', return_value={'repos': []}) as snap:
            conn = http.client.HTTPConnection('127.0.0.1', httpd.server_port)
            self.addCleanup(conn.close)
            conn.request('GET', '/api/github?path=/untrusted')
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), {'repos': []})
            snap.assert_called_once_with(server.HOME_DIR)
            conn.request('GET', '/github.js')
            response = conn.getresponse()
            self.assertIn('text/javascript', response.getheader('Content-Type'))
            self.assertEqual(response.getheader('X-Content-Type-Options'), 'nosniff')
            script = response.read().decode()
            self.assertIn("registerView('github', load, 30000)", script)
            self.assertNotIn('innerHTML', script)
            conn.request('POST', '/api/github', '{}', {'Content-Type': 'application/json'})
            response = conn.getresponse()
            self.assertGreaterEqual(response.status, 400)
            response.read()
            self.assertEqual(snap.call_count, 1)
        index = Path(server.ROOT / 'index.html').read_text()
        self.assertIn('data-view="github"', index)
        self.assertLess(index.index('src="github.js"'), index.index('src="app.js"'))


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(GithubTests))
    failures = len(result.failures) + len(result.errors)
    print(f'passed {result.testsRun - failures - len(result.skipped)}, failed {failures}', flush=True)
    raise SystemExit(bool(failures))
