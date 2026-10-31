"""Run the GitHub workflow jobs' own run: steps on this machine, one job after another.

DELIVERY-LOCAL-01 keeps CI off for this branch until every P00-P14 gate is accepted. This reads
the steps from .github/workflows, so it cannot drift from them, and runs them locally. It is not
CI or phase qualification: local tools stand in for the setup actions, and this machine stands in
for the pinned hosted image. A version the workflow pins and this machine lacks is reported.

    python3 tests/local/workflows.py                         # tests and design-patterns
    python3 tests/local/workflows.py contracts foundation    # P01 (~5 min) and P02 (~10 min)
    python3 tests/local/workflows.py --list

Steps run in a reused virtual environment (~/.cache/agentmux-tests/workflow-venv) made from the
repository's .venv interpreter, so the jobs' pip installs never change .venv. Each job gets a fresh
temporary directory for runner.temp and a private AGENTMUX_HOME inside it, as a hosted runner has
no ~/.agentmux; it is removed after a passing job and kept after a failure.
darwin-install and the enrolled Compose job are not offered: they install protected fixtures, or
need an enrolled self-hosted runner and its pinned inputs.
"""
import argparse
from datetime import datetime
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'
CACHE = Path.home() / '.cache' / 'agentmux-tests'
VENV = CACHE / 'workflow-venv'
JOBS = {
    'tests': ('tests.yml', 'tests'),
    'design-patterns': ('design-patterns.yml', 'design-patterns'),
    'contracts': ('contracts.yml', 'qualification'),
    'foundation': ('platform-foundation.yml', 'foundation'),
    # Fails by design: tests/platform/README.md, "Native P02 named cohorts".
    'darwin-research': ('platform-foundation.yml', 'darwin-research'),
}
DEFAULT = ('tests', 'design-patterns')
EXPRESSION = re.compile(r'\$\{\{\s*([^}]*?)\s*\}\}')
KEY = re.compile(r'^(\s*)(?:- )?([A-Za-z][\w-]*):(?:\s+(.*))?$')


def steps(workflow, job):
    """The job's steps as dicts of name, uses, run, env, with, if and shell.

    Reads only the block layout these workflows use: two-space indents, `run: |` blocks,
    and `env:`/`with:` maps of scalars. Anything else in a step is refused, not guessed."""
    lines = (WORKFLOWS / workflow).read_text().splitlines()
    start = lines.index(f'  {job}:')
    end = next((i for i in range(start + 1, len(lines)) if re.match(r'^  \S', lines[i])), len(lines))
    body = lines[start + 1:end]
    first = body.index('    steps:') + 1
    result, i = [], first
    while i < len(body):
        line = body[i]
        if not line.strip() or line.lstrip().startswith('#'):
            i += 1
            continue
        if not line.startswith('      '):
            break
        match = KEY.match(line)
        if match is None:
            raise SystemExit(f'{workflow} {job}: cannot read step line: {line!r}')
        if line.startswith('      - '):
            result.append({})
        key, value = match.group(2), (match.group(3) or '').strip()
        i += 1
        if value in ('|', ''):
            block = []
            while i < len(body) and (not body[i].strip() or len(body[i]) - len(body[i].lstrip()) > 8):
                block.append(body[i])
                i += 1
            while block and not block[-1].strip():
                block.pop()
            value = literal(block) if value == '|' else mapping(block, f'{workflow} {job}')
        elif key == 'uses':
            value = value.split(' #')[0].strip()
        if key not in ('name', 'uses', 'run', 'env', 'with', 'if', 'shell'):
            raise SystemExit(f'{workflow} {job}: unsupported step key {key!r}')
        result[-1][key] = value
    return result


def literal(block):
    indent = min(len(line) - len(line.lstrip()) for line in block if line.strip())
    return '\n'.join(line[indent:] for line in block) + '\n'


def mapping(block, where):
    """A map of scalars, where a value may be its own `|` block."""
    block = [line for line in block if line.strip() and not line.lstrip().startswith('#')]
    indent = len(block[0]) - len(block[0].lstrip())
    result, i = {}, 0
    while i < len(block):
        pair = KEY.match(block[i])
        if pair is None or len(pair.group(1)) != indent or pair.group(3) is None:
            raise SystemExit(f'{where}: cannot read map entry: {block[i]!r}')
        i += 1
        if pair.group(3).strip() == '|':
            nested = []
            while i < len(block) and (not block[i].strip() or len(block[i]) - len(block[i].lstrip()) > indent):
                nested.append(block[i])
                i += 1
            result[pair.group(2)] = literal(nested)
        else:
            result[pair.group(2)] = unquote(pair.group(3).strip())
    return result


def job_settings(workflow, job):
    """The job's timeout-minutes (GitHub's default 360 when unset) and job-level env."""
    lines = (WORKFLOWS / workflow).read_text().splitlines()
    start = lines.index(f'  {job}:')
    body = lines[start + 1:lines.index('    steps:', start)]
    minutes = next((int(m.group(1)) for m in map(re.compile(r'^    timeout-minutes: (\d+)$').match, body) if m), 360)
    env = {}
    if '    env:' in body:
        first = body.index('    env:') + 1
        block = []
        for line in body[first:]:
            if line.strip() and len(line) - len(line.lstrip()) <= 4:
                break
            block.append(line)
        env = mapping(block, f'{workflow} {job}')
    return minutes, env


def unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in '\'"':
        return value[1:-1]
    return value


def substitute(text, context):
    def replace(match):
        if match.group(1) not in context:
            raise SystemExit(f'no local value for ${{{{ {match.group(1)} }}}}')
        return context[match.group(1)]
    return EXPRESSION.sub(replace, text)


def prepare_venv():
    if not (VENV / 'bin' / 'python').exists():
        base = ROOT / '.venv' / 'bin' / 'python'
        subprocess.run([str(base if base.exists() else sys.executable), '-m', 'venv', str(VENV)], check=True)
    return VENV / 'bin'


def check_versions(step, binaries):
    """Report a pinned Python or Node version that this machine does not have."""
    wanted = step.get('with', {})
    for action, key, command in (('actions/setup-python', 'python-version', [str(binaries / 'python'), '-V']),
                                 ('actions/setup-node', 'node-version', ['node', '--version'])):
        if step['uses'].startswith(action + '@') and key in wanted:
            try:
                local = subprocess.run(command, capture_output=True, text=True).stdout.split()[-1].lstrip('v')
            except (OSError, IndexError):
                local = 'none'
            pin = wanted[key]
            if local != pin and not local.startswith(pin + '.'):
                print(f'  note: workflow pins {key} {pin}; this machine has {local}')


def run_job(name, logs, binaries):
    workflow, job = JOBS[name]
    temp = logs / f'{name}-temp'
    temp.mkdir()
    machine = platform.machine()
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    context = {'runner.temp': str(temp), 'matrix.os': 'local', 'github.sha': head, 'github.workspace': str(ROOT),
               'matrix.arch': {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64'}.get(machine, machine)}
    log = logs / f'{name}.log'
    minutes, job_env = job_settings(workflow, job)
    # A hosted runner has no ~/.agentmux; this keeps the operator's Hub and stores out of reach.
    home = temp / 'agentmux-home'
    home.mkdir()
    base = dict(os.environ, AGENTMUX_HOME=str(home), PATH=f'{binaries}{os.pathsep}{os.environ["PATH"]}',
                **{key: substitute(value, context) for key, value in job_env.items()})
    deadline = time.monotonic() + minutes * 60
    print(f'{name} ({workflow}, job {job}, {minutes} min limit)', flush=True)
    for number, step in enumerate(steps(workflow, job), 1):
        title = step.get('name') or step.get('uses') or step['run'].splitlines()[0][:60]
        if 'uses' in step:
            print(f'  skip  {title}: local tools stand in')
            check_versions(step, binaries)
            continue
        if step.get('if', 'always()') != 'always()' or step.get('shell', 'bash') != 'bash':
            raise SystemExit(f'{workflow} {job}: step {title!r} needs a condition or shell this runner does not model')
        env = dict(base, **{key: substitute(value, context) for key, value in step.get('env', {}).items()})
        started = time.monotonic()
        with open(log, 'a') as output:
            output.write(f'\n===== step {number}: {title}\n')
            output.flush()
            process = subprocess.Popen(['bash', '-e', '-c', substitute(step['run'], context)], cwd=ROOT, env=env,
                                       stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                       start_new_session=True)
            try:
                code = process.wait(max(1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                code = 'timeout'
            finally:
                # Brokers and helpers a step started go with it, as when a hosted job ends. Some
                # (ci.py's nats-server) start their own session, so anything still naming this
                # job's temporary directory goes too.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                subprocess.run(['pkill', '-KILL', '-f', str(temp)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        status = 'ok' if code == 0 else 'TIMEOUT' if code == 'timeout' else 'FAIL'
        print(f"  {status:4}  {title}  ({time.monotonic() - started:.0f}s)", flush=True)
        if code != 0:
            tail = log.read_text(errors='replace').splitlines()[-15:]
            print('\n'.join('        ' + line for line in tail))
            print(f'  log: {log}\n  kept for inspection: {temp}')
            return False
    # Go keeps its module cache read-only.
    subprocess.run(['chmod', '-R', 'u+w', str(temp)], stderr=subprocess.DEVNULL)
    shutil.rmtree(temp, ignore_errors=True)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('jobs', nargs='*', help=f'{", ".join(JOBS)} (default: {" ".join(DEFAULT)})')
    parser.add_argument('--list', action='store_true', help='show each job and its steps, then stop')
    options = parser.parse_args(argv)
    names = options.jobs or list(DEFAULT)
    for name in names:
        if name not in JOBS:
            parser.error(f'unknown job: {name}')
    if options.list:
        for name, (workflow, job) in JOBS.items():
            print(f'{name}: {workflow}, job {job}')
            for step in steps(workflow, job):
                print(f"    {'uses ' + step['uses'] if 'uses' in step else 'run  ' + (step.get('name') or step['run'].splitlines()[0])}")
        return 0
    binaries = prepare_venv()
    logs = CACHE / ('workflows-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    logs.mkdir(parents=True)
    failed = [name for name in names if not run_job(name, logs, binaries)]
    print(f"\n{len(names) - len(failed)} of {len(names)} jobs passed" + (f"; failed: {', '.join(failed)}" if failed else '')
          + f'. Logs: {logs}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
