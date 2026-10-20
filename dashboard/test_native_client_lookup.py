"""Opt-in native lookup checks in disposable client-owned configuration homes."""
import json
import os
from pathlib import Path
import platform
import tempfile
from unittest.mock import patch

from dashboard.resource_probes import _capture, _claude_plugins, run_check


def check_native_plugin_listing(home):
    """Prepare only local Markdown/plugin metadata; no install or provider work.

    Documented native layout and enabledPlugins setting:
    https://code.claude.com/docs/en/plugins/create#make-a-plugin-load-in-every-session
    https://code.claude.com/docs/en/plugins/loading#find-where-a-plugin-came-from
    """
    claude = home / 'claude plugin fixture'
    claude.mkdir()
    os.environ['CLAUDE_CONFIG_DIR'] = str(claude)
    settings = claude / 'settings.json'
    original = {'env': {'AMUX_FIXTURE_SENTINEL': 'private plugin fixture sentinel'}}
    original_text = json.dumps(original) + '\n'
    settings.write_text(original_text)
    query = {'id': 'claude-plugins', 'type': 'command',
             'argv': ['claude', 'plugin', 'list', '--json']}

    def observe(expected, settings_text, plugin_present=False):
        code, output, failure = _capture(query['argv'], 12)
        if failure or code != 0:
            raise RuntimeError('Native JSON plugin lookup failed; details withheld.')
        result = _claude_plugins(output, {})
        try:
            entries = json.loads(output)
        except ValueError:
            raise RuntimeError('Native JSON plugin shape is unsupported.') from None
        if not isinstance(entries, list) or len(entries) != (1 if plugin_present else 0):
            raise RuntimeError('Native plugin fixture isolation was not established.')
        if plugin_present and (not isinstance(entries[0], dict)
                               or entries[0].get('id') != 'agentmux-diagnostic-fixture@skills-dir'):
            raise RuntimeError('Native plugin fixture identity was not established.')
        if result['code'] != expected:
            raise RuntimeError('Native plugin listing did not match the fixture state; details withheld.')
        if 'private plugin fixture sentinel' in json.dumps(result):
            raise RuntimeError('Native plugin fixture content appeared in diagnostics.')
        if settings.read_text() != settings_text:
            raise RuntimeError('Native plugin lookup changed unrelated fixture settings.')

    observe('no_plugins_enabled', original_text)
    plugin = claude / 'skills' / 'agentmux-diagnostic-fixture'
    metadata = plugin / '.claude-plugin'
    metadata.mkdir(parents=True)
    manifest = metadata / 'plugin.json'
    manifest_text = json.dumps({'name': 'agentmux-diagnostic-fixture', 'version': '1.0.0',
                                'description': 'Local diagnostic fixture.',
                                'defaultEnabled': False}) + '\n'
    manifest.write_text(manifest_text)
    skill = plugin / 'SKILL.md'
    skill_text = ('---\nname: agentmux-diagnostic-fixture\n'
                  'description: Local diagnostic fixture.\n'
                  'disable-model-invocation: true\n---\n'
                  'This fixture is never invoked. It defines no executable actions.\n')
    skill.write_text(skill_text)
    plugin_id = 'agentmux-diagnostic-fixture@skills-dir'
    for enabled in (False, True, False):
        changed = dict(original, enabledPlugins={plugin_id: enabled})
        changed_text = json.dumps(changed) + '\n'
        settings.write_text(changed_text)
        observe('plugins_enabled' if enabled else 'no_plugins_enabled', changed_text, True)
    settings.write_text(original_text)
    observe('no_plugins_enabled', original_text, True)
    # Remove only this fixture-owned contribution from native discovery, keeping
    # its bytes for restoration. This is not an Agentmux installer/uninstaller.
    retained = home / 'retained diagnostic plugin'
    plugin.rename(retained)
    observe('no_plugins_enabled', original_text)
    retained.rename(plugin)
    observe('no_plugins_enabled', original_text, True)
    if manifest.read_text() != manifest_text or skill.read_text() != skill_text:
        raise RuntimeError('Native plugin lookup changed the local fixture plugin.')
    print('PASS: Claude JSON plugin listing follows enable/disable, contribution removal/restore and unchanged unrelated settings')


def main():
    if os.environ.get('AGENTMUX_NATIVE_LOOKUP_TEST') != '1':
        raise SystemExit('Reserve the live slot and set AGENTMUX_NATIVE_LOOKUP_TEST=1.')
    if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise SystemExit('Native macOS ARM64 is required.')
    native_path = os.environ.get('PATH', '/usr/bin:/bin')
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix='native lookup fixture ') as temporary:
        home = Path(temporary)
        codex = home / 'codex configuration'
        codex.mkdir()
        config = codex / 'config.toml'
        original = 'cli_auth_credentials_store = "file"\n# unrelated fixture setting\n'
        config.write_text(original)
        env = {'HOME': str(home), 'TMPDIR': str(home), 'PATH': native_path,
               'CODEX_HOME': str(codex), 'AGENTMUX_HOME': str(home / 'agentmux'),
               'PI_CODING_AGENT_DIR': str(home / 'pi')}
        unrelated = home / 'unrelated.txt'
        unrelated.write_text('fixture sentinel must remain private')
        try:
            os.chdir(home)
            with patch.dict(os.environ, env, clear=True):
                # Each Claude root selects a fresh native credential namespace.
                for name in ('claude first', 'claude changed'):
                    claude = home / name
                    claude.mkdir()
                    settings = claude / 'settings.json'
                    settings.write_text('{}\n')
                    os.environ['CLAUDE_CONFIG_DIR'] = str(claude)
                    code, output, failure = _capture(['claude', 'auth', 'status'], 12)
                    if failure or code != 1:
                        raise RuntimeError('Claude fixture signed-out status was not established; details withheld.')
                    try:
                        status = json.loads(output)
                    except ValueError:
                        raise RuntimeError('Claude native status format is unsupported.') from None
                    if status.get('loggedIn') is not False or status.get('configDirectory') != str(claude):
                        raise RuntimeError('Claude did not report the selected fixture configuration directory.')
                    assert settings.read_text() == '{}\n'
                print('PASS: Claude native status follows two fixture configuration roots with spaces')
                query = {'id': 'auth', 'type': 'command', 'argv': ['codex', 'login', 'status']}
                before = run_check(query)
                if before['code'] != 'not_authenticated':
                    raise RuntimeError('Codex fixture file-backed signed-out state was not established.')
                config.write_text('cli_auth_credentials_store = "invalid-fixture-store"\n')
                changed = run_check(query)
                if changed['status'] != 'unknown':
                    raise RuntimeError('Codex did not refuse the changed invalid fixture configuration.')
                config.write_text(original)
                restored = run_check(query)
                if restored['code'] != 'not_authenticated':
                    raise RuntimeError('Codex fixture configuration did not recover after restore.')
                assert config.read_text() == original
                print('PASS: Codex native status sees fixture config change and recovery without credential copying')
                check_native_plugin_listing(home)
            assert unrelated.read_text() == 'fixture sentinel must remain private'
        finally:
            os.chdir(previous)
    print('Pi auth and Desktop native lookup remain unqualified; no provider/model call was made')


if __name__ == '__main__':
    main()
