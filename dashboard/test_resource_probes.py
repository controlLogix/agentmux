"""Offline checks for fixed client probes. No client processes are started."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from dashboard import resource_probes as probes


class ResourceProbes(unittest.TestCase):
    def check(self, argv, output='', returncode=0, **fields):
        check = dict(id='stable-id', label='Client', type='command', argv=argv, **fields)
        with patch.object(probes, '_capture', return_value=(returncode, output, None)) as capture:
            result = probes.run_check(check)
        self.assertEqual(result['id'], 'stable-id')
        self.assertEqual(result['ok'], result['status'] == 'configured')
        return result, capture

    def test_only_fixed_argv_can_execute(self):
        for argv in [['sh', '-c', 'echo secret'], ['codex', 'mcp', 'list', '--json'],
                     ['codex', 'doctor'], 'codex --version', ['codex', 1]]:
            result, capture = self.check(argv)
            capture.assert_not_called()
            self.assertEqual(result['code'], 'invalid_probe')

    def test_nonzero_cannot_pass_regex_or_version(self):
        for argv, output in [(['codex', 'mcp', 'list'], 'atlassian SECRET'),
                             (['claude', '--version'], '2.1.19 (Claude Code)')]:
            result, _ = self.check(argv, output, 1, expect='atlassian|Claude')
            self.assertEqual(result['status'], 'unknown')
            self.assertNotIn('SECRET', json.dumps(result))

    def test_versions_and_minimum(self):
        outputs = [('codex', 'codex-cli 0.112.0', '0.112.0'),
                   ('claude', '2.1.19 (Claude Code)', '2.1.19'),
                   ('pi', '0.58.3', '0.58.3')]
        for client, output, version in outputs:
            result, _ = self.check([client, '--version'], output, minimum_version='0.50.0')
            self.assertTrue(result['ok'])
            self.assertEqual(result['version'], version)
            for other, _, _ in outputs:
                if other != client:
                    result, _ = self.check([other, '--version'], output)
                    self.assertEqual(result['status'], 'unknown')
                    self.assertNotIn('version', result)
        for output in ['codex-cli', '1.2', '01.2.3', '1.2.3-beta', '1.2.3 and 2.3.4',
                       'codex-cli 1234567890.2.3', 'error: codex-cli 1.2.3',
                       'codex-cli 1.2.3\nSENTINEL']:
            result, _ = self.check(['codex', '--version'], output)
            self.assertEqual(result['status'], 'unknown')
            self.assertNotIn('version', result)
        result, _ = self.check(['codex', '--version'], 'codex-cli 0.40.0', minimum_version='0.50.0')
        self.assertEqual(result['code'], 'version_old')
        self.assertEqual(result['version'], '0.40.0')
        result, _ = self.check(['codex', '--version'], 'codex-cli 0.40.0',
                               minimum_version='1' * 5000 + '.0.0')
        self.assertEqual(result['code'], 'invalid_probe')

    def test_codex_auth_is_anchored_and_secret_free(self):
        for output in ['Logged in using ChatGPT', 'Logged in using an API key - SENTINEL_SECRET']:
            result, _ = self.check(['codex', 'login', 'status'], output)
            self.assertTrue(result['ok'])
            self.assertNotIn('SENTINEL', json.dumps(result))
        for output in ['not logged in\nLogged in using ChatGPT', 'Logged in', 'error: Logged in using ChatGPT']:
            result, _ = self.check(['codex', 'login', 'status'], output)
            self.assertEqual(result['status'], 'unknown')
        result, _ = self.check(['codex', 'login', 'status'], 'Not logged in', 1)
        self.assertEqual(result['code'], 'not_authenticated')

    def test_claude_auth_requires_structured_supported_state(self):
        result, _ = self.check(['claude', 'auth', 'status'],
                               json.dumps(dict(loggedIn=True, authMethod='claude.ai', email='SENTINEL')))
        self.assertTrue(result['ok'])
        self.assertNotIn('SENTINEL', json.dumps(result))
        for value in [[], {'loggedIn': 'true'}, {'loggedIn': True, 'authMethod': 'new-method'}]:
            result, _ = self.check(['claude', 'auth', 'status'], json.dumps(value))
            self.assertEqual(result['status'], 'unknown')
        result, _ = self.check(['claude', 'auth', 'status'], '{"loggedIn":false,"authMethod":"none"}', 1)
        self.assertEqual(result['code'], 'not_authenticated')
        result, _ = self.check(['claude', 'auth', 'status'],
                               '{"loggedIn":false,"loggedIn":true,"authMethod":"claude.ai"}')
        self.assertEqual(result['status'], 'unknown')

    def test_timeout_clamped_and_invalid_timeout_rejected(self):
        _, capture = self.check(['pi', '--version'], '0.58.3', timeout=500)
        capture.assert_called_once_with(['pi', '--version'], 25.0)
        for value in ['nan', 'inf', None, 'bad']:
            result, capture = self.check(['pi', '--version'], timeout=value)
            capture.assert_not_called()
            self.assertEqual(result['code'], 'invalid_probe')

    def test_missing_failed_and_bounded_probes(self):
        check = dict(id='installed', type='command', argv=['pi', '--version'])
        for failure in ['timeout', 'output_limit']:
            with patch.object(probes, '_capture', return_value=(None, 'SENTINEL', failure)):
                result = probes.run_check(check)
            self.assertEqual(result['code'], failure)
            self.assertNotIn('SENTINEL', json.dumps(result))
        for error, code in [(FileNotFoundError('SENTINEL'), 'missing_tool'),
                            (OSError('SENTINEL'), 'probe_failed')]:
            with patch.object(probes, '_capture', side_effect=error):
                result = probes.run_check(check)
            self.assertEqual(result['code'], code)
            self.assertNotIn('SENTINEL', json.dumps(result))

    def test_native_files_use_metadata_only_and_effective_root(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            custom = root / 'custom'
            custom.mkdir()
            config = custom / 'settings.json'
            config.write_text('SENTINEL_SECRET')
            config.chmod(0o600)
            auth = custom / 'auth.json'
            auth.write_text('SENTINEL_SECRET')
            with patch.dict(os.environ, {'HOME': home, 'PI_CODING_AGENT_DIR': str(custom)}, clear=True), \
                    patch('builtins.open', side_effect=AssertionError('No content reads')):
                result = probes.run_check(dict(type='file', native_ref='pi.config', want_mode='600'))
                self.assertTrue(result['ok'])
                self.assertNotIn('SENTINEL', json.dumps(result))
                result = probes.run_check(dict(type='file', native_ref='pi.auth'))
                self.assertEqual(result['code'], 'credential_reference')
                auth.unlink()
                result = probes.run_check(dict(type='file', native_ref='pi.auth'))
                self.assertEqual(result['status'], 'unknown')
                result = probes.run_check(dict(type='file', native_ref='pi.config', want_mode='400'))
                self.assertEqual(result['code'], 'permissions')
                result = probes.run_check(dict(type='file', path=str(config)))
                self.assertEqual(result['code'], 'invalid_probe')
                result = probes.run_check(dict(type='file', native_ref='codex.config'))
                self.assertEqual(result['code'], 'missing_file')
            self.assertEqual(config.read_text(), 'SENTINEL_SECRET')

    def test_every_native_reference_tracks_fixture_changes_and_preserves_contents(self):
        for ref, (env_name, relative_root, filename) in probes.NATIVE_REFS.items():
            for override in ([False, True] if env_name else [False]):
                with self.subTest(ref=ref, override=override), tempfile.TemporaryDirectory() as home:
                    root = Path(home)
                    env = {'HOME': home}
                    base = root / relative_root
                    if override:
                        base = root / 'custom-client-root'
                        env[env_name] = str(base)
                    base.mkdir(parents=True)
                    path = base / filename
                    unrelated = root / 'unrelated.json'
                    unrelated.write_text('UNRELATED_SENTINEL')
                    check = dict(type='file', native_ref=ref, want_mode='600')
                    with patch.dict(os.environ, env, clear=True):
                        result = probes.run_check(check)
                        self.assertEqual(result['code'], 'missing_file')
                        self.assertEqual(result['status'], 'unknown' if ref in {'pi.auth', 'grok.auth'} else 'unavailable')
                        path.write_text('CLIENT_SECRET_SENTINEL')
                        path.chmod(0o600)
                        with patch.object(Path, 'open', side_effect=AssertionError('No content reads')):
                            result = probes.run_check(check)
                        self.assertEqual(result['code'], 'credential_reference' if ref in {'pi.auth', 'grok.auth'} else 'metadata_present')
                        self.assertNotIn('SENTINEL', json.dumps(result))
                        self.assertEqual(path.read_text(), 'CLIENT_SECRET_SENTINEL')
                        path.chmod(0o644)
                        self.assertEqual(probes.run_check(check)['code'], 'permissions')
                        path.unlink()
                        self.assertEqual(probes.run_check(check)['code'], 'missing_file')
                        path.write_text('RECOVERED_SECRET_SENTINEL')
                        path.chmod(0o600)
                        self.assertEqual(probes.run_check(check)['code'], 'credential_reference' if ref in {'pi.auth', 'grok.auth'} else 'metadata_present')
                        self.assertEqual(path.read_text(), 'RECOVERED_SECRET_SENTINEL')
                        self.assertEqual(unrelated.read_text(), 'UNRELATED_SENTINEL')

    def test_capture_closes_pipe_if_final_wait_fails(self):
        proc = MagicMock()
        proc.returncode = None
        proc.wait.side_effect = OSError('wait failed')
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {4: True}
        with patch.object(probes.subprocess, 'Popen', return_value=proc), \
                patch.object(probes.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(probes.os, 'set_blocking'), \
                patch.object(probes.time, 'monotonic', side_effect=[0, 26]), \
                patch.object(probes.os, 'killpg'), \
                self.assertRaises(OSError):
            probes._capture(['pi', '--version'], 25)
        proc.stdout.close.assert_called_once_with()

    def test_claude_plugins_empty_disabled_enabled_and_load_errors(self):
        plugin = dict(id='fixture@skills-dir', version='1.0.0', scope='user',
                      enabled=True, installPath='/PRIVATE_SENTINEL',
                      mcpServers={'private': {'env': {'TOKEN': 'PRIVATE_SENTINEL'}}})
        for entries, code, status in [
                ([], 'no_plugins_enabled', 'unavailable'),
                ([dict(plugin, enabled=False)], 'no_plugins_enabled', 'unavailable'),
                ([plugin], 'plugins_enabled', 'configured'),
                ([dict(plugin, errors=[])], 'plugins_enabled', 'configured'),
                ([dict(plugin, errors=['PRIVATE_SENTINEL'])], 'plugin_load_errors', 'unavailable'),
                ([plugin, dict(plugin, enabled=False, errors=['PRIVATE_SENTINEL'])], 'plugin_load_errors', 'unavailable')]:
            result, _ = self.check(['claude', 'plugin', 'list', '--json'], json.dumps(entries))
            self.assertEqual((result['code'], result['status']), (code, status))
            self.assertNotIn('PRIVATE_SENTINEL', json.dumps(result))
            self.assertNotIn('installPath', result)
        result, _ = self.check(['claude', 'plugin', 'list', '--json'], json.dumps([plugin]), 1)
        self.assertEqual(result['code'], 'probe_failed')

    def test_claude_plugins_strict_schema_and_duplicate_keys(self):
        plugin = dict(id='fixture@skills-dir', version='1.0.0', scope='user',
                      enabled=True, installPath='/fixture')
        malformed = [{}, [None], [dict(plugin, enabled=1)],
                     [dict(plugin, enabled='true')], [dict(plugin, scope='future')],
                     [dict(plugin, errors='PRIVATE_SENTINEL')], [dict(plugin, errors=[False])]]
        for field in plugin:
            malformed.append([{key: value for key, value in plugin.items() if key != field}])
        for value in malformed:
            result, _ = self.check(['claude', 'plugin', 'list', '--json'], json.dumps(value))
            self.assertEqual(result['code'], 'malformed')
        duplicate = json.dumps([plugin]).replace('"enabled": true', '"enabled": false, "enabled": true')
        for raw in [duplicate, 'not JSON PRIVATE_SENTINEL', json.dumps([plugin]) + '[]']:
            result, _ = self.check(['claude', 'plugin', 'list', '--json'], raw)
            self.assertEqual(result['code'], 'malformed')
            self.assertNotIn('PRIVATE_SENTINEL', json.dumps(result))

    def test_unsupported_lookup_is_explicit(self):
        result = probes.run_check(dict(type='manual', hint='Use the native client to inspect login.'))
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(result['code'], 'unsupported')
        self.assertEqual(result['hint'], 'Use the native client to inspect login.')

    def test_capture_timeout_joins_original_process_without_reading(self):
        proc = MagicMock()
        proc.pid = 456
        proc.returncode = None
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {4: True}
        with patch.object(probes.subprocess, 'Popen', return_value=proc), \
                patch.object(probes.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(probes.os, 'set_blocking'), \
                patch.object(probes.time, 'monotonic', side_effect=[0, 26]), \
                patch.object(probes.os, 'read') as read, \
                patch.object(probes.os, 'killpg') as kill:
            _, output, failure = probes._capture(['pi', '--version'], 25)
        self.assertEqual((output, failure), ('', 'timeout'))
        read.assert_not_called()
        kill.assert_called_once_with(456, probes.signal.SIGKILL)
        proc.wait.assert_called_once_with()
        proc.stdout.close.assert_called_once_with()

    def test_capture_kills_and_joins_original_process_on_output_limit(self):
        proc = MagicMock()
        proc.pid = 123
        proc.returncode = None
        proc.stdout.fileno.return_value = 4
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {4: True}
        key = MagicMock()
        key.fileobj = proc.stdout
        selector.select.return_value = [(key, 1)]
        with patch.object(probes.subprocess, 'Popen', return_value=proc) as popen, \
                patch.object(probes.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(probes.os, 'set_blocking'), \
                patch.object(probes.os, 'read', return_value=b'x' * 4096), \
                patch.object(probes.os, 'killpg') as kill:
            code, output, failure = probes._capture(['pi', '--version'], 12)
        self.assertEqual(failure, 'output_limit')
        self.assertEqual(output, '')
        kill.assert_called_once_with(123, probes.signal.SIGKILL)
        proc.wait.assert_called_once_with()
        proc.stdout.close.assert_called_once_with()
        self.assertEqual(popen.call_args.kwargs['stdin'], probes.subprocess.DEVNULL)
        self.assertTrue(popen.call_args.kwargs['start_new_session'])


if __name__ == '__main__':
    unittest.main()
