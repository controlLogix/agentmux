"""Opt-in native browser check using an isolated real dashboard and empty PATH."""
import argparse
import importlib.util
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch


def main():
    if os.environ.get('AGENTMUX_RESOURCE_BROWSER_TEST') != '1':
        raise SystemExit('Live slot required: set AGENTMUX_RESOURCE_BROWSER_TEST=1 only after assignment.')
    if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise SystemExit('This check requires native macOS ARM64.')
    parser = argparse.ArgumentParser()
    parser.add_argument('--node', required=True)
    parser.add_argument('--playwright', required=True)
    parser.add_argument('--browser', required=True)
    args = parser.parse_args()
    for path in (args.node, args.playwright, args.browser):
        if not Path(path).is_absolute() or not Path(path).exists():
            raise SystemExit('A required prepared executable or driver is unavailable.')
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root))
    with tempfile.TemporaryDirectory(prefix='resources-browser-') as temporary:
        home = Path(temporary)
        empty_bin = home / 'empty-bin'
        empty_bin.mkdir()
        config = home / 'codex'
        config.mkdir()
        sentinel = config / 'config.toml'
        sentinel.write_text('# fixture-secret-must-stay-private\n')
        env = {'HOME': str(home), 'PATH': str(empty_bin), 'TMPDIR': str(home),
               'AGENTMUX_HOME': str(home), 'CODEX_HOME': str(config),
               'CLAUDE_CONFIG_DIR': str(home / 'claude'),
               'PI_CODING_AGENT_DIR': str(home / 'pi')}
        with patch.dict(os.environ, env, clear=True):
            spec = importlib.util.spec_from_file_location('resources_browser_server', root / 'server.py')
            server = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(server)
            httpd = server.BacklogServer(('127.0.0.1', 0), server.Handler)
            thread = threading.Thread(target=httpd.serve_forever)
            thread.start()
            process = None
            try:
                process = subprocess.Popen([
                    args.node, str(root / 'test_resources_browser.mjs'),
                    f'http://127.0.0.1:{httpd.server_port}', args.playwright, args.browser],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    env=env, cwd=home)
                output, _ = process.communicate(timeout=60)
                if process.returncode:
                    # The browser has only this disposable fixture and intercepted APIs.
                    detail = output.decode('utf-8', errors='replace')[-4000:]
                    detail = detail.replace('fixture-secret-must-stay-private', '[fixture secret]')
                    raise RuntimeError('Resource browser fixture failed: ' + detail)
                if b'PASS: native browser Resources' not in output:
                    raise RuntimeError('Resource browser check did not return its completion marker.')
                assert sentinel.read_text() == '# fixture-secret-must-stay-private\n'
                print('PASS: isolated native Resources browser and unchanged sentinel configuration')
            finally:
                if process is not None:
                    if process.poll() is None:
                        # Node retains the original browser handle and closes it
                        # on SIGTERM before we join the original child process.
                        process.terminate()
                    process.communicate()
                    process.stdout.close()
                httpd.shutdown()
                thread.join()
                httpd.server_close()


if __name__ == '__main__':
    main()
