"""Opt-in installed CLI version checks; these do not qualify client workflows."""
import os
from pathlib import Path
import platform
import tempfile
from unittest.mock import patch

from dashboard.resource_probes import run_check


def main():
    if os.environ.get('AGENTMUX_NATIVE_VERSION_TEST') != '1':
        raise SystemExit('Reserve the live slot and set AGENTMUX_NATIVE_VERSION_TEST=1.')
    if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise SystemExit('Native macOS ARM64 is required.')
    # Keep stable command lookup, but remove credentials, overrides and project state.
    native_path = os.environ.get('PATH', '/usr/bin:/bin')
    previous = Path.cwd()
    failures = []
    with tempfile.TemporaryDirectory(prefix='native client versions ') as temporary:
        home = Path(temporary)
        env = {'HOME': str(home), 'TMPDIR': str(home), 'PATH': native_path,
               'CODEX_HOME': str(home / 'codex'), 'CLAUDE_CONFIG_DIR': str(home / 'claude'),
               'PI_CODING_AGENT_DIR': str(home / 'pi'), 'AGENTMUX_HOME': str(home / 'agentmux')}
        for name in ('codex', 'claude', 'pi'):
            (home / name).mkdir()
        unrelated = home / 'unrelated.txt'
        unrelated.write_text('sentinel fixture content')
        try:
            os.chdir(home)
            with patch.dict(os.environ, env, clear=True):
                for client in ('codex', 'claude', 'pi'):
                    result = run_check({'id': 'installed', 'type': 'command',
                                        'argv': [client, '--version'], 'timeout': 12})
                    if result['status'] != 'configured':
                        failures.append(client)
                    print(f"{client}: {result['status']} ({result['code']})"
                          + (f" version {result['version']}" if 'version' in result else ''))
            assert unrelated.read_text() == 'sentinel fixture content'
        finally:
            os.chdir(previous)
    if failures:
        raise SystemExit('Native version checks failed or remain unknown: ' + ', '.join(failures))
    print('PASS: three installed CLI version checks only; native auth/config workflows remain unqualified')


if __name__ == '__main__':
    main()
