"""Read fixed client diagnostics without returning command output or file contents."""
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

MAX_OUTPUT = 64 * 1024
ALLOWED_COMMANDS = frozenset({
    ('codex', '--version'), ('codex', 'login', 'status'), ('codex', 'mcp', 'list'),
    ('claude', '--version'), ('claude', 'auth', 'status'),
    ('claude', 'plugin', 'list'), ('claude', 'plugin', 'list', '--json'),
    ('claude', 'mcp', 'list'),
    ('grok', '--version'), ('grok', 'models'), ('grok', 'mcp', 'list'),
    ('grok', 'plugin', 'list'), ('pi', '--version'), ('tmux', '-V'),
})
# Only inherited native client settings select these roots. Requests cannot do so.
NATIVE_REFS = {
    'codex.config': ('CODEX_HOME', '.codex', 'config.toml'),
    'codex.profile': ('CODEX_HOME', '.codex', 'yolo.config.toml'),
    'claude.config': ('CLAUDE_CONFIG_DIR', '.claude', 'settings.json'),
    'pi.config': ('PI_CODING_AGENT_DIR', '.pi/agent', 'settings.json'),
    'pi.auth': ('PI_CODING_AGENT_DIR', '.pi/agent', 'auth.json'),
    'desktop.config': (None, 'Library/Application Support/Claude', 'claude_desktop_config.json'),
    'agentmux.atlassian': ('AGENTMUX_HOME', '.agentmux', 'atlassian.json'),
    'agentmux.env': ('AGENTMUX_HOME', '.agentmux', 'env'),
    'agentmux.launcher': (None, '.local/bin', 'agentmux'),
    'claude.legacy-agent-config': (None, '.agentmux/claude-config', 'settings.json'),
    'grok.auth': (None, '.grok', 'auth.json'),
}
LEGACY_PATHS = {'~/' + root + '/' + name: ref
                for ref, (_, root, name) in NATIVE_REFS.items()}
MESSAGES = {
    'configured': 'Check passed.', 'missing_tool': 'Client tool is not installed.',
    'missing_file': 'Native configuration file is absent.',
    'metadata_present': 'Native configuration file is present; contents were not read.',
    'credential_reference': 'Credential file is present; login has not been verified.',
    'permissions': 'File permissions do not match the required mode.',
    'file_unreadable': 'File metadata could not be checked.',
    'unsupported': 'No supported lookup is available for this check.',
    'invalid_probe': 'The manifest probe is not supported.',
    'probe_failed': 'Client probe failed; status is unknown.',
    'timeout': 'Client probe exceeded its time limit.',
    'output_limit': 'Client probe exceeded its output limit.',
    'malformed': 'Client returned an unrecognized status.',
    'not_configured': 'The requested configuration was not found.',
    'not_authenticated': 'Client reports that it is not logged in.',
    'version_old': 'Installed version is below the required version.',
    'no_plugins_enabled': 'No enabled plugin was reported.',
    'plugin_load_errors': 'The native client reported plugin load errors; inspect them privately.',
    'plugins_enabled': 'The native client reported an enabled plugin without load errors.',
}


def _capture(argv, timeout):
    """Own the process and pipe until both are closed, including failed probes."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, start_new_session=True)
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None, '', 'timeout'
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), min(4096, MAX_OUTPUT + 1 - len(data)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        if len(data) + len(chunk) > MAX_OUTPUT:
                            return None, '', 'output_limit'
                        data.extend(chunk)
            try:
                code = proc.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                return None, '', 'timeout'
        return code, data.decode('utf-8', errors='strict'), None
    finally:
        # The original process remains unreaped on timeout. Its process group
        # also owns any children that inherited the diagnostic output pipe.
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            proc.wait()
        finally:
            proc.stdout.close()


def _finish(out, status, code):
    out.update(status=status, code=code, ok=status == 'configured', detail=MESSAGES[code])
    return out


def _file(check, out):
    raw_path = check.get('path')
    ref = check.get('native_ref') or (LEGACY_PATHS.get(raw_path) if isinstance(raw_path, str) else None)
    if not isinstance(ref, str) or ref not in NATIVE_REFS:
        return _finish(out, 'unknown', 'invalid_probe')
    env, root, name = NATIVE_REFS[ref]
    base = os.environ.get(env) if env else None
    path = (Path(base).expanduser() if base else Path.home() / root) / name
    try:
        info = path.stat()
    except FileNotFoundError:
        return _finish(out, 'unknown' if ref in {'pi.auth', 'grok.auth'} else 'unavailable', 'missing_file')
    except OSError:
        return _finish(out, 'unknown', 'file_unreadable')
    if not stat.S_ISREG(info.st_mode):
        return _finish(out, 'unknown', 'file_unreadable')
    if check.get('want_mode') and format(stat.S_IMODE(info.st_mode), 'o') != str(check['want_mode']):
        return _finish(out, 'unavailable', 'permissions')
    if ref in {'pi.auth', 'grok.auth'}:
        return _finish(out, 'unknown', 'credential_reference')
    return _finish(out, 'configured', 'metadata_present')


_VERSION_NUMBER = r'(?:0|[1-9][0-9]{0,8})'
_VERSION_TEXT = rf'{_VERSION_NUMBER}\.{_VERSION_NUMBER}\.{_VERSION_NUMBER}'
_VERSION = re.compile(rf'(?<![\w.])({_VERSION_TEXT})(?![\w.+-])')
_VERSION_FORMATS = {
    'codex': re.compile(rf'codex-cli ({_VERSION_TEXT})'),
    'claude': re.compile(rf'({_VERSION_TEXT}) \(Claude Code\)'),
    'pi': re.compile(rf'({_VERSION_TEXT})'),
}


def _unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate status field')
        value[key] = item
    return value


def _claude_plugins(output, out):
    """Validate the documented listing without returning IDs, paths or errors."""
    try:
        plugins = json.loads(output, object_pairs_hook=_unique_json_object)
    except (ValueError, TypeError, RecursionError):
        return _finish(out, 'unknown', 'malformed')
    if not isinstance(plugins, list):
        return _finish(out, 'unknown', 'malformed')
    enabled = False
    load_errors = False
    for plugin in plugins:
        if not isinstance(plugin, dict):
            return _finish(out, 'unknown', 'malformed')
        if any(not isinstance(plugin.get(field), str)
               for field in ('id', 'version', 'scope', 'installPath')):
            return _finish(out, 'unknown', 'malformed')
        if (not plugin['id'] or type(plugin.get('enabled')) is not bool
                or plugin['scope'] not in {'user', 'project', 'local', 'managed', 'session', 'synced'}):
            return _finish(out, 'unknown', 'malformed')
        errors = plugin.get('errors', [])
        if not isinstance(errors, list) or any(not isinstance(error, str) for error in errors):
            return _finish(out, 'unknown', 'malformed')
        enabled = enabled or plugin['enabled']
        load_errors = load_errors or bool(errors)
    if load_errors:
        return _finish(out, 'unavailable', 'plugin_load_errors')
    if enabled:
        return _finish(out, 'configured', 'plugins_enabled')
    return _finish(out, 'unavailable', 'no_plugins_enabled')


def run_check(check):
    """Check a server-owned manifest entry; never accept request probe definitions."""
    out = {'id': check.get('id'), 'label': check.get('label'),
           'optional': bool(check.get('optional')), 'ok': False, 'detail': ''}
    hint = check.get('hint')
    if isinstance(hint, str):
        out['hint'] = ''.join(c for c in hint if c.isprintable())[:300]
    if check.get('type') == 'file':
        return _file(check, out)
    if check.get('type') != 'command':
        return _finish(out, 'unknown', 'unsupported')
    argv = check.get('argv')
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv) or tuple(argv) not in ALLOWED_COMMANDS:
        return _finish(out, 'unknown', 'invalid_probe')
    try:
        timeout = float(check.get('timeout', 12))
        if not math.isfinite(timeout):
            raise ValueError
        timeout = max(0.1, min(25.0, timeout))
    except (ValueError, TypeError):
        return _finish(out, 'unknown', 'invalid_probe')
    try:
        code, output, failure = _capture(argv, timeout)
    except FileNotFoundError:
        return _finish(out, 'unavailable', 'missing_tool')
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return _finish(out, 'unknown', 'probe_failed')
    if failure:
        return _finish(out, 'unknown', failure)
    if tuple(argv) == ('codex', 'login', 'status'):
        value = output.strip()
        if code in (0, 1) and value.lower() == 'not logged in':
            return _finish(out, 'unavailable', 'not_authenticated')
        # The API-key display suffix is consumed but never returned.
        if code == 0 and re.fullmatch(r'Logged in using (?:ChatGPT|an API key(?: - [^\r\n]+)?)', value, re.I):
            return _finish(out, 'configured', 'configured')
        return _finish(out, 'unknown', 'malformed')
    if tuple(argv) == ('claude', 'auth', 'status'):
        try:
            value = json.loads(output, object_pairs_hook=_unique_json_object)
        except (ValueError, TypeError):
            return _finish(out, 'unknown', 'malformed')
        if not isinstance(value, dict) or type(value.get('loggedIn')) is not bool:
            return _finish(out, 'unknown', 'malformed')
        if value['loggedIn'] is False and code in (0, 1) and value.get('authMethod') == 'none':
            return _finish(out, 'unavailable', 'not_authenticated')
        if code != 0 or value['loggedIn'] is False or value.get('authMethod') not in {'claude.ai', 'oauth_token', 'api_key', 'api_key_helper', 'third_party'}:
            return _finish(out, 'unknown', 'malformed')
        return _finish(out, 'configured', 'configured')
    if code != 0:
        return _finish(out, 'unknown', 'probe_failed')
    if tuple(argv) == ('claude', 'plugin', 'list', '--json'):
        return _claude_plugins(output, out)
    if argv[-1] == '--version':
        pattern = _VERSION_FORMATS.get(argv[0])
        match = pattern.fullmatch(output.strip()) if pattern else None
        versions = ([match.group(1)] if match else []) if pattern else _VERSION.findall(output)
        if len(versions) != 1:
            return _finish(out, 'unknown', 'malformed')
        minimum = check.get('minimum_version')
        if minimum is not None:
            if not isinstance(minimum, str) or not _VERSION.fullmatch(minimum):
                return _finish(out, 'unknown', 'invalid_probe')
            if tuple(map(int, versions[0].split('.'))) < tuple(map(int, minimum.split('.'))):
                out['version'] = versions[0]
                return _finish(out, 'unavailable', 'version_old')
        out['version'] = versions[0]
        return _finish(out, 'configured', 'configured')
    try:
        matched = not check.get('expect') or re.search(check['expect'], output, re.I | re.M) is not None
    except (re.error, TypeError):
        return _finish(out, 'unknown', 'invalid_probe')
    return _finish(out, 'configured' if matched else 'unavailable',
                   'configured' if matched else 'not_configured')
