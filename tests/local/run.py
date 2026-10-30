"""Run the Python test modules locally and report only failures the baseline does not expect.

Every test module runs in its own process, with a timeout and a private AGENTMUX_HOME, so
modules can run side by side without sharing a Hub, a socket or ~/.agentmux. The checked-in
baseline (baseline.json, next to this file) records each module's time on the reference
machine and the tests that already fail there, so a run needs no second run of the old
commit to tell a new failure from an old one.

    python tests/local/run.py                 # quick tier: modules under QUICK_SECONDS
    python tests/local/run.py --changed       # modules within two imports of what changed since upstream
    python tests/local/run.py --tier full     # everything except the excluded directories and live modules
    python tests/local/run.py hub.tests.test_work_operation_cli capability_owner/test_x.py
    python tests/local/run.py --tier full --record   # rerun failures once, then rewrite the baseline
    python tests/local/run.py --tier live     # only the modules that need a coordinated live slot

dashboard/ is excluded: its suites need tmux, agents and their own server, and
dashboard/run_tests.sh runs them without touching the operator's dashboard. tests/contracts/
is excluded: its suites need the SDKs built with npm, which tests/contracts/ci.py does.

A module whose every error is its own "A coordinated ... is required" refusal needs a live
slot (a broker, Docker or an identity provider and the AMX_*_LIVE variables). It is reported
apart from failures, and the quick, slow and full tiers leave out the ones the baseline knows.
"""
import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
BASELINE = Path(__file__).with_name('baseline.json')
# sdk/python is importable as a top-level root, as in every documented test command.
IMPORT_ROOTS = (ROOT / 'sdk' / 'python', ROOT)
# Imported by bare name; the dispatcher and task runner append them at run time (taskmgmt/run.py).
# Neither holds a name that shadows the standard library or a root package.
BARE_ROOTS = (ROOT / 'dashboard', ROOT / 'taskmgmt')
SKIP_DIRS = {'.git', '.venv', 'node_modules', '__pycache__', 'testdata'}
EXCLUDED = ('dashboard/', 'docs/', 'tests/contracts/')
QUICK_SECONDS = 30
TIMEOUT_SECONDS = 1200
# A module the baseline has timed gets this many times its time, and at least the floor,
# so a hang shows up in minutes instead of at TIMEOUT_SECONDS.
TIMEOUT_FACTOR, TIMEOUT_FLOOR = 5, 120
RESULT = re.compile(r'^(ERROR|FAIL): (\S+) \(([^)]+)\)', re.M)
LIVE_GATE = re.compile(r'^RuntimeError: (A coordinated .* required)$', re.M)


def walk(top, suffix):
    for path, dirs, files in os.walk(top):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith('.'))
        for name in sorted(files):
            if name.endswith(suffix):
                yield Path(path) / name


def module_name(path):
    """Dotted name under an import root when every parent is a package, else None."""
    for root in IMPORT_ROOTS:
        try:
            parts = path.relative_to(root).with_suffix('').parts
        except ValueError:
            continue
        if all((root.joinpath(*parts[:i]) / '__init__.py').exists() for i in range(1, len(parts))):
            return '.'.join(parts[:-1] if parts[-1] == '__init__' else parts)
    return None


def discover():
    """Every test module as {name: (path, unittest arguments)}."""
    targets = {}
    for path in walk(ROOT, '.py'):
        relative = path.relative_to(ROOT).as_posix()
        if not path.name.startswith('test_') or relative.startswith(EXCLUDED):
            continue
        dotted = module_name(path)
        if dotted is not None and not path.is_relative_to(IMPORT_ROOTS[0]):
            targets[dotted] = (path, ['-m', 'unittest', dotted])
        else:
            folder = path.parent.relative_to(ROOT).as_posix()
            targets[relative] = (path, ['-m', 'unittest', 'discover', '-s', folder, '-t', folder, '-p', path.name])
    return targets


def import_graph():
    """{file: files it imports}, from a static scan of the repository's Python sources."""
    files = list(walk(ROOT, '.py'))
    by_module = {}
    for path in files:
        dotted = module_name(path)
        if dotted is not None:
            by_module[dotted] = path
    graph = {}
    for path in files:
        try:
            tree = ast.parse(path.read_bytes(), str(path))
        except (SyntaxError, ValueError):
            continue
        package = (module_name(path) or '').split('.')
        if path.name != '__init__.py':
            package = package[:-1]
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = (package[:len(package) - node.level + 1] if node.level else [])
                stem = '.'.join(base + ([node.module] if node.module else []))
                names.add(stem)
                names.update(f'{stem}.{alias.name}' if stem else alias.name for alias in node.names)
        found = set()
        for name in names:
            parts = name.split('.')
            for end in range(len(parts), 0, -1):
                target = by_module.get('.'.join(parts[:end]))
                if target is not None:
                    found.add(target)
                    break
            else:
                # A test outside a package imports its siblings, and dashboard and taskmgmt
                # modules, by bare name.
                for folder in (path.parent, *BARE_ROOTS):
                    if (folder / (parts[0] + '.py')).exists():
                        found.add(folder / (parts[0] + '.py'))
                        break
        graph[path] = found
    return graph


def changed_files(since):
    def git(*args):
        result = subprocess.run(['git', *args], cwd=ROOT, capture_output=True, text=True)
        return result.stdout.split() if result.returncode == 0 else []
    names = set(git('diff', '--name-only', since)) if since else set()
    names.update(git('diff', '--name-only', 'HEAD'))
    names.update(git('ls-files', '--others', '--exclude-standard'))
    return {ROOT / name for name in names if name.endswith('.py')}


def affected(targets, changed, depth):
    """Test modules within depth imports of a changed file (0: any depth).

    Tests import fixtures from other tests, so the full closure reaches most modules;
    two levels is the default for quick feedback, not a substitute for the full tier."""
    graph = import_graph()
    users = {}
    for path, imports in graph.items():
        for imported in imports:
            users.setdefault(imported, set()).add(path)
    reached, frontier, level = set(changed), list(changed), 0
    while frontier and (depth == 0 or level < depth):
        frontier = [user for path in frontier for user in users.get(path, ()) if user not in reached]
        reached.update(frontier)
        level += 1
    return [name for name, (path, _) in targets.items() if path in reached]


def run_one(name, arguments, python, logs, timeout):
    home = tempfile.mkdtemp(prefix='amt-')
    env = dict(os.environ, AGENTMUX_HOME=home,
               PYTHONPATH=os.pathsep.join(str(root) for root in (*IMPORT_ROOTS, *BARE_ROOTS)))
    log = logs / (re.sub(r'[^A-Za-z0-9_.-]', '_', name) + '.log')
    started = time.monotonic()
    with open(log, 'w') as output:
        process = subprocess.Popen([python, *arguments], cwd=ROOT, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            process.wait(timeout)
            status = None
        except subprocess.TimeoutExpired:
            status = 'timeout'
        finally:
            # Hubs, brokers and panes a module started go with it.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    seconds = time.monotonic() - started
    shutil.rmtree(home, ignore_errors=True)
    text = log.read_text(errors='replace')
    failures = sorted({match.group(3) for match in RESULT.finditer(text)})
    ran = re.search(r'^Ran (\d+) tests?', text, re.M)
    if status is None:
        # unittest exits 5 when a module defines no tests to run.
        status = 'ok' if process.returncode in (0, 5) and not failures else 'failed'
        if status == 'failed' and not failures:
            failures = [f'{name}:exit-{process.returncode}']
    gates = LIVE_GATE.findall(text)
    if status == 'failed' and gates and len(gates) >= len(RESULT.findall(text)):
        status, failures = 'needs-slot', [gates[0]]
    return {'name': name, 'status': status, 'seconds': round(seconds, 1),
            'tests': int(ran.group(1)) if ran else 0, 'failures': failures, 'log': str(log)}


def time_limit(entry, ceiling):
    """Seconds one module may take: a known hang gets the floor, a timed module a multiple of its time."""
    if not entry:
        return ceiling
    if entry.get('status') == 'timeout':
        return min(ceiling, TIMEOUT_FLOOR)
    return min(ceiling, max(TIMEOUT_FLOOR, TIMEOUT_FACTOR * entry.get('seconds', 0)))


def run(names, targets, python, logs, jobs, limits, report=True):
    results = {}
    def one(name):
        result = run_one(name, targets[name][1], python, logs, limits[name])
        if report:
            print(f"{result['status']:8} {result['seconds']:7.1f}s  {name}", flush=True)
        return result
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for result in pool.map(one, names):
            results[result['name']] = result
    return results


def unexpected(result, expected):
    allowed = set(expected.get('known', ())) | set(expected.get('flaky', ()))
    return [test for test in result['failures'] if test not in allowed]


def confirm_alone(results, entries, targets, python, logs, limits):
    """Rerun modules with unexpected failures one at a time, and drop the failures that do not repeat.

    Several modules hold 5 s capability windows that a busy machine can outlast; a failure
    that does not repeat alone is reported apart and does not fail the run."""
    retry = [name for name, result in results.items()
             if result['status'] == 'failed' and unexpected(result, entries.get(name, {}))]
    if not retry:
        return []
    print(f'\nRerunning {len(retry)} modules with unexpected failures one at a time...')
    (logs / 'alone').mkdir()
    again = run(retry, targets, python, logs / 'alone', 1, limits)
    alone = []
    for name in retry:
        if again[name]['status'] not in ('ok', 'failed'):
            continue
        repeated = set(again[name]['failures'])
        passed = [test for test in unexpected(results[name], entries.get(name, {})) if test not in repeated]
        alone += [(name, test) for test in passed]
        results[name]['failures'] = [test for test in results[name]['failures'] if test not in passed]
    return alone


def summarize(results, baseline, started, alone=()):
    known = baseline.get('targets', {})
    new, flaky, fixed, timeouts, hangs, gated = [], [], [], [], [], []
    for name, result in sorted(results.items()):
        expected = known.get(name, {})
        expected_failures = set(expected.get('known', ())) | set(expected.get('flaky', ()))
        if result['status'] == 'timeout':
            (hangs if expected.get('status') == 'timeout' else timeouts).append(name)
            continue
        if result['status'] == 'needs-slot':
            gated.append(name)
            continue
        new += [(name, test) for test in result['failures'] if test not in expected_failures]
        flaky += [(name, test) for test in result['failures'] if test in expected.get('flaky', ())]
        fixed += [(name, test) for test in expected.get('known', ()) if test not in result['failures']]
    print(f"\n{len(results)} modules, {sum(r['tests'] for r in results.values())} tests, "
          f"{time.monotonic() - started:.0f}s wall")
    for title, rows in (('NEW failures', new), ('Known flaky, failed this time', flaky),
                        ('Failed beside other modules, passed alone', list(alone)),
                        ('Known failures that passed', fixed)):
        if rows:
            print(f'{title} ({len(rows)}):')
            for name, test in rows:
                print(f'  {test}    [{name}]')
    if timeouts:
        print(f'NEW timeouts ({len(timeouts)}): ' + ', '.join(timeouts))
    if hangs:
        print(f'Known hangs, stopped at {TIMEOUT_FLOOR}s ({len(hangs)}): ' + ', '.join(hangs))
    if gated:
        print(f'Need a live slot, not run ({len(gated)}): ' + ', '.join(gated))
    slow = sorted(results.values(), key=lambda r: -r['seconds'])[:5]
    print('Slowest: ' + ', '.join(f"{r['name']} {r['seconds']:.0f}s" for r in slow))
    return 1 if new or timeouts else 0


def record(results, targets, python, logs, limits, baseline):
    """Rerun each failing module once on its own: failing twice is known, once is flaky."""
    reruns = [name for name, r in results.items() if r['status'] in ('failed', 'timeout')]
    print(f'\nRerunning {len(reruns)} failing modules one at a time to separate flaky tests...')
    (logs / 'rerun').mkdir()
    again = run(reruns, targets, python, logs / 'rerun', 1, limits)
    entries = baseline.setdefault('targets', {})
    for name, first in results.items():
        second = again.get(name, first)
        both = set(first['failures']) & set(second['failures'])
        status = first['status'] if first['status'] == second['status'] in ('timeout', 'needs-slot') else (
            'failed' if both else 'ok')
        if status == 'needs-slot':
            both = set()
        entries[name] = {'seconds': first['seconds'], 'status': status, 'known': sorted(both),
                         'flaky': sorted(set(first['failures']) ^ set(second['failures']))}
    for name in set(entries) - set(targets):
        del entries[name]
    head = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], cwd=ROOT, capture_output=True, text=True)
    baseline['recorded'] = {'commit': head.stdout.strip(), 'date': datetime.now(timezone.utc).date().isoformat(),
        'machine': f'{platform.system()} {platform.machine()}, {os.cpu_count()} CPUs',
        'python': subprocess.run([python, '-V'], capture_output=True, text=True).stdout.strip()}
    BASELINE.write_text(json.dumps(baseline, indent=1, sort_keys=True) + '\n')
    print(f'Baseline written: {BASELINE.relative_to(ROOT)}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('modules', nargs='*', help='module names or test file paths')
    parser.add_argument('--tier', choices=('quick', 'slow', 'full', 'live'), default='quick')
    parser.add_argument('--changed', nargs='?', const='@{upstream}', metavar='SINCE',
                        help='only modules affected by changes since SINCE (default: upstream) and uncommitted changes')
    parser.add_argument('--depth', type=int, default=2, help='import levels --changed follows (0: all)')
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--timeout', type=int, default=TIMEOUT_SECONDS,
                        help=f'most seconds per module; a timed module gets {TIMEOUT_FACTOR}x its baseline time, '
                             f'at least {TIMEOUT_FLOOR}s')
    parser.add_argument('--python', default=str(ROOT / '.venv' / 'bin' / 'python')
                        if (ROOT / '.venv' / 'bin' / 'python').exists() else sys.executable)
    parser.add_argument('--record', action='store_true', help='rewrite the baseline for the modules run')
    parser.add_argument('--list', action='store_true', help='show the selected modules and stop')
    options = parser.parse_args(argv)
    targets = discover()
    baseline = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    entries = baseline.get('targets', {})
    seconds = {name: entry.get('seconds', 0) for name, entry in entries.items()}
    live = {name for name, entry in entries.items() if entry.get('status') == 'needs-slot'}
    if options.modules:
        names = []
        for given in options.modules:
            key = Path(given).as_posix() if given.endswith('.py') else given
            if key not in targets:
                parser.error(f'unknown test module: {given}')
            names.append(key)
    elif options.changed is not None:
        names = affected(targets, changed_files(options.changed), options.depth)
    elif options.tier == 'live':
        names = [name for name in targets if name in live]
    elif options.tier == 'full':
        names = [name for name in targets if name not in live]
    else:
        # A module the baseline has not timed yet counts as quick.
        quick = options.tier == 'quick'
        names = [name for name in targets
                 if name not in live and (seconds.get(name, 0) <= QUICK_SECONDS) == quick]
    # Longest first, so one slow module does not finish alone at the end.
    names.sort(key=lambda name: -seconds.get(name, QUICK_SECONDS))
    if options.list or not names:
        for name in names:
            print(f'{seconds.get(name, 0):7.1f}s  {name}')
        print(f'{len(names)} modules')
        return 0
    logs = Path.home() / '.cache' / 'agentmux-tests' / datetime.now().strftime('%Y%m%d-%H%M%S')
    logs.mkdir(parents=True)
    print(f'{len(names)} modules, {options.jobs} at a time, logs in {logs}')
    started = time.monotonic()
    limits = {name: time_limit(entries.get(name), options.timeout) for name in names}
    results = run(names, targets, options.python, logs, options.jobs, limits)
    if options.record:
        record(results, targets, options.python, logs, limits, baseline)
        return 0
    alone = confirm_alone(results, entries, targets, options.python, logs, limits) if options.jobs > 1 else []
    return summarize(results, baseline, started, alone)


if __name__ == '__main__':
    sys.exit(main())
