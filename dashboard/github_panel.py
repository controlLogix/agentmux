"""Read-only Git/gh snapshots. Configure AGENTMUX_HOME/github.json:
{"repos": [{"name": "agentmux", "path": "/path/to/repo"}]}.
No request-supplied commands or paths; tracking counts use local remote refs.
"""
import datetime as dt
import json
import os
from pathlib import Path
import re
import github_auth
import subprocess
import threading
import time
from urllib.parse import urlsplit

_LOCK = threading.Lock()
_CACHE = {}
FAILURES = {'failure', 'timed_out', 'startup_failure', 'action_required'}


def run(argv, cwd=None):
    try:
        # encoding/errors are explicit: text=True alone decodes with the system
        # codepage, and one non-ASCII commit subject then throws out of subprocess'
        # reader thread rather than being reported as a repository error.
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', stdin=subprocess.DEVNULL,
                           timeout=12, env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0',
                                           'GH_PROMPT_DISABLED': '1', 'GH_HOST': 'github.com'})
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError(f'{argv[0]} unavailable or timed out') from None
    if p.returncode:
        # Do not return CLI stderr: auth diagnostics can include credentials.
        raise ValueError(f'{argv[0]} {argv[1]} failed (exit {p.returncode})')
    return p.stdout


def configured_repos(home):
    config = Path(home) / 'github.json'
    if config.exists():
        data = json.loads(config.read_text())['repos']
    else:
        data = [{'name': 'agentmux', 'path': str(Path(__file__).resolve().parents[1])}]
        try:
            entry = json.loads((Path.home() / '.claude/plugins/known_marketplaces.json').read_text())['adaggroup']
            path = entry.get('source', {}).get('path') or entry['installLocation']
            if os.name != 'nt' and re.match(r'^[A-Za-z]:[\\/]', path):
                path = '/mnt/' + path[0].lower() + '/' + path[3:].replace('\\', '/')
            data.append({'name': 'adaggroup', 'path': path})
        except (OSError, ValueError, KeyError, TypeError):
            pass
    if not isinstance(data, list) or len(data) > 20 or any(
            not isinstance(r, dict) or not isinstance(r.get('path'), str) or not r['path']
            for r in data):
        raise ValueError('repos must be a list of at most 20 objects with path strings')
    return data


def ci_state(checks):
    if not checks:
        return 'NO_CHECKS'
    states = [str(c.get('conclusion') or c.get('state') or c.get('status') or '').lower() for c in checks]
    if any(s in FAILURES | {'error', 'cancelled'} for s in states):
        return 'FAILURE'
    if any(s not in {'success', 'neutral', 'skipped'} for s in states):
        return 'PENDING'
    return 'SUCCESS'


def duration(row):
    try:
        start = dt.datetime.fromisoformat(row['startedAt'].replace('Z', '+00:00'))
        end = (dt.datetime.fromisoformat(row['updatedAt'].replace('Z', '+00:00'))
               if row['status'] == 'completed' else dt.datetime.now(dt.timezone.utc))
        return max(0, int((end - start).total_seconds()))
    except (KeyError, ValueError, TypeError):
        return None


def origin_identity(origin):
    """Read a github.com owner/name without accepting a lookalike host."""
    if '\\' in origin or any(ord(character) < 0x20 for character in origin):
        return None
    scp = re.fullmatch(r'(?:git@)?github\.com:([^/]+/[^/]+)', origin)
    if scp:
        path = scp.group(1)
    else:
        try:
            parsed = urlsplit(origin)
            if (parsed.hostname != 'github.com' or parsed.scheme not in ('https', 'ssh')
                    or parsed.query or parsed.fragment
                    or parsed.port not in (None, 443 if parsed.scheme == 'https' else 22)):
                return None
            path = parsed.path.removeprefix('/')
        except ValueError:
            return None
    path = path.removesuffix('.git')
    if not github_auth.NWO_RE.fullmatch(path) or path.rsplit('/', 1)[1] in ('.', '..'):
        return None
    return path


def repo_snapshot(config, gh_binary):
    path = str(Path(config['path']).expanduser().resolve())
    result = {'name': config.get('name') or Path(path).name, 'path': path,
              'errors': [], 'prs': [], 'runs': [], 'nwo': None,
              'tracking_source': 'local_refs', 'tracking_freshness': 'possibly_stale'}
    def git(*args):
        return run(['git', '-C', path, *args])
    try:
        result['branch'] = git('rev-parse', '--abbrev-ref', 'HEAD').strip()
        # owner/name, parsed from the origin URL so the issue form can offer the
        # repositories already on screen instead of asking you to retype one.
        try:
            origin = git('remote', 'get-url', 'origin').strip()
            result['nwo'] = origin_identity(origin)
        except ValueError:
            pass
        # -z keeps newlines and rename pairs from inflating the file count.
        records = iter(git('status', '--porcelain=v1', '-z').split('\0'))
        count = 0
        for record in records:
            if not record:
                continue
            count += 1
            if 'R' in record[:2] or 'C' in record[:2]:
                next(records, None)
        result['dirty_files'] = count
        result['ahead'] = result['behind'] = None
        result['upstream'] = None
        try:
            result['upstream'] = git('rev-parse', '--abbrev-ref', '@{upstream}').strip()
            result['ahead'], result['behind'] = map(int, git('rev-list', '--left-right', '--count', 'HEAD...@{upstream}').split())
        except ValueError:
            result['errors'].append('No usable upstream; ahead/behind unknown.')
        result['commits'] = [dict(zip(('sha', 'subject', 'date'), line.split('\x1f', 2)))
                             for line in git('log', '-5', '--format=%h%x1f%s%x1f%cI').splitlines()]
    except ValueError as exc:
        result['errors'].append(str(exc))
        return result
    if gh_binary:
        if result['nwo'] is None:
            result['errors'].extend([
                'prs: No verified github.com origin; pull requests are unavailable.',
                'runs: No verified github.com origin; workflow runs are unavailable.'])
            return result
        queries = [('prs', ['pr', 'list', '--state', 'open', '--limit', '30', '--json',
                           'number,title,url,reviewDecision,statusCheckRollup']),
                   ('runs', ['run', 'list', '--limit', '20', '--json',
                            'databaseId,displayTitle,url,status,conclusion,startedAt,updatedAt'])]
        for key, args in queries:
            try:
                rows = json.loads(run([gh_binary, *args, '--repo', f"github.com/{result['nwo']}"], cwd=path))
                limit = 30 if key == 'prs' else 20
                if (not isinstance(rows, list) or len(rows) > limit
                        or any(not isinstance(r, dict) for r in rows)):
                    raise ValueError('Invalid gh response')
                fields = ({'number', 'title', 'url', 'reviewDecision'} if key == 'prs' else
                          {'databaseId', 'displayTitle', 'url', 'status', 'conclusion', 'startedAt', 'updatedAt'})
                public = []
                for row in rows:
                    item = {field: row[field] for field in fields if field in row}
                    suffix = r'/pull/[1-9][0-9]*' if key == 'prs' else r'/actions/runs/[1-9][0-9]*'
                    url = item.get('url')
                    if (not isinstance(url, str) or len(url) > 250
                            or not re.fullmatch(r'https://github\.com/' + re.escape(result['nwo']) + suffix,
                                                url, re.IGNORECASE)):
                        item['url'] = None
                    if key == 'prs':
                        item['ci'] = ci_state(row.get('statusCheckRollup'))
                    else:
                        item['duration_seconds'] = duration(row)
                    public.append(item)
                result[key] = sorted(public, key=lambda r: not (
                    r.get('ci') == 'FAILURE' or r.get('conclusion') in FAILURES))
            except (ValueError, TypeError, AttributeError):
                result['errors'].append(f'{key}: GitHub data is unavailable or unreadable.')
    return result


def snapshot(home):
    # Serialize refreshes and cache for 30s, including failure results.
    with _LOCK:
        key = str(home)
        now = time.monotonic()
        if key in _CACHE and now - _CACHE[key][0] < 30:
            return _CACHE[key][1]
        gh = {'state': 'ready', 'message': 'gh authenticated', 'command': ''}
        binary = github_auth.gh_path()
        if not binary:
            gh = {'state': 'missing', 'message': 'gh is not installed or not on PATH.',
                  'command': github_auth.install_command()}
        else:
            try:
                run([binary, 'auth', 'status', '--hostname', 'github.com'])
            except ValueError:
                gh = {'state': 'unauthenticated', 'message': 'gh authentication check failed; credentials may be missing or expired.',
                      'command': 'gh auth login'}
                if github_auth.is_windows_gh(binary):
                    gh['message'] += ' ' + github_auth.WINDOWS_LOGIN
        data = {'gh': gh, 'repos': [], 'errors': [],
                'checked_at': dt.datetime.now(dt.timezone.utc).isoformat()}
        try:
            data['repos'] = [repo_snapshot(r, binary if gh['state'] == 'ready' else None) for r in configured_repos(home)]
        except (OSError, ValueError, KeyError, TypeError):
            data['errors'].append('Invalid github.json. Expected {"repos": [{"name": "repo", "path": "/path/to/repo"}]}.')
        _CACHE[key] = (time.monotonic(), data)
        return data
