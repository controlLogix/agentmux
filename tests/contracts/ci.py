"""Run portable P01 checks with locked dependencies and fresh, source-bound evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
RELEASE = 'https://github.com/nats-io/nats-server/releases/download/v2.15.0'
# Reviewed against that release's SHA256SUMS on October 9, 2026.
ARCHIVE_SHA256 = {
    'darwin-amd64': '5bd8b59ca5bf93fab3da2c5843cf564cd6e2e291e22ae3b861746e7ebe259b95',
    'darwin-arm64': 'e1c4e22d70bd44abfa0bcb3c16f7cf0c66f648c2e728c58924e8a1ce88913cc8',
    'linux-amd64': '5d2c51caca950333aba84911df7d377f826f3a59ec36061c6539105084f65c92',
    'linux-arm64': 'cdc208f5a3f42963a52b6ab06ef65626bb870315dc936e26ba571780c6351112',
}
NSC_RELEASE = 'https://github.com/nats-io/nsc/releases/download/v2.15.0'
# Reviewed against the official SHA256SUMS-nsc.txt and release asset digests.
NSC_SHA256 = {
    'darwin-amd64': 'bc8230bbbac2f6a7828e0fa3d47f5ecac3fb7b09790f4e8dcfa6a22e03dd6c2f',
    'darwin-arm64': '18ef004eded116886607c3797aa7170624b38ab7eb4b0bce0586c30a5ab811c5',
    'linux-amd64': '7d55eda757dc9f233675a3038fcf8779bcda99753b1603f7009fc8537e126b7e',
    'linux-arm64': '4556613503e2d3e91c970e2c78f17b3f369a3b987c00aa4ffe95d08ea5059a0c',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = []
    for name in ('contracts/v1', 'sdk', 'tests/contracts', 'tests/storage', 'tests/leaf', 'tests/platform',
                 'plugins/agentmux-orchestration'):
        paths.extend(p for p in (ROOT / name).rglob('*') if p.is_file()
                     and not set(p.parts) & {'node_modules', 'dist', '__pycache__'}
                     and p.suffix != '.pyc')
    paths += list((ROOT / 'hub').rglob('*.py'))
    paths += list((ROOT / 'taskmgmt').rglob('*.py'))
    paths += [ROOT / name for name in ('dashboard/auth.json', 'dashboard/test_orchestration_plugin.py',
                                     'dashboard/test_plugin_skills.py')]
    paths += [ROOT / name for name in ('hub/requirements.lock','hub/requirements.txt',
              'agentmux.sh','agentmux.cmd','agentmux_windows.py','deploy/nats/circle.sh','.github/workflows/contracts.yml')]
    for name in ('docs/planning/2026-10-09', '.bytedesk/design-patterns', '.context'):
        paths.extend(p for p in (ROOT / name).rglob('*') if p.is_file()
                     and not set(p.parts) & {'evidence', '__pycache__', 'node_modules'}
                     and p.suffix in ('.py', '.json', '.md', '.mjs'))
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in sorted(paths)}


def download(url):
    # Only fixed official release URLs are used; no token or user-supplied URL.
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def broker(workspace, report):
    system = {'Linux': 'linux', 'Darwin': 'darwin'}[platform.system()]
    arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]
    asset = f'nats-server-v2.15.0-{system}-{arch}.tar.gz'
    sums = download(f'{RELEASE}/SHA256SUMS').decode('ascii')
    matches = [line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip('*') == asset]
    if len(matches) != 1 or matches[0] != ARCHIVE_SHA256[f'{system}-{arch}']:
        raise ValueError('Release checksum missing or ambiguous')
    archive = workspace / asset
    archive.write_bytes(download(f'{RELEASE}/{asset}'))
    if digest(archive) != matches[0]:
        raise ValueError('Release checksum mismatch')
    target = workspace / 'nats-server'
    with tarfile.open(archive, 'r:gz') as package:
        members = [m for m in package.getmembers() if m.name == asset[:-7] + '/nats-server' and m.isfile()]
        if len(members) != 1:
            raise ValueError('Release binary missing or ambiguous')
        with package.extractfile(members[0]) as source:
            target.write_bytes(source.read())
    target.chmod(0o700)
    version = subprocess.check_output([str(target), '--version'], text=True, timeout=15).strip()
    if version != 'nats-server: v2.15.0':
        raise ValueError('Unexpected broker version')
    report['broker'] = {'version': version, 'archiveUrl': f'{RELEASE}/{asset}',
                        'checksumUrl': f'{RELEASE}/SHA256SUMS', 'archiveSha256': matches[0],
                        'binarySha256': digest(target), 'checksumVerified': True}
    return target


def negative_fixture(evidence):
    """Prove a malformed positive fixture fails the real cross-language test."""
    import test_conformance as conformance
    original = conformance.VECTORS
    before = digest(original)
    fixture = json.loads(original.read_text(encoding='utf-8'))['plugin-manifest']
    del fixture['packageId']
    with tempfile.TemporaryDirectory(prefix='agentmux-negative-fixture-') as directory:
        mutant = Path(directory) / 'invalid-positive.json'
        mutant.write_text(json.dumps({'plugin-manifest': fixture}), encoding='utf-8')
        conformance.VECTORS = mutant
        try:
            suite = unittest.TestSuite([conformance.Conformance('test_all_schema_examples')])
            result = unittest.TestResult()
            suite.run(result)
        finally:
            conformance.VECTORS = original
    observed = [dict(getattr(test, 'params', {})) for test, _ in result.failures]
    expected = [{'client':'python','schema':'plugin-manifest'}, {'client':'typescript','schema':'plugin-manifest'}]
    ok = (result.testsRun == 1 and observed == expected and not result.errors and not result.skipped
          and not result.expectedFailures and before == digest(original))
    record = {'status':'passed' if ok else 'failed', 'mutation':'Removed packageId from a copied positive plugin-manifest fixture.',
              'expectedAssertionFailures':expected, 'observedAssertionFailures':observed,
              'errorCount':len(result.errors), 'skipCount':len(result.skipped),
              'originalFixtureSha256':before, 'originalFixtureUnchanged':before==digest(original),
              'sourceHashes':source_hashes(), 'limits':['Isolated negative check; no fixture or SDK source was changed.']}
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence/'negative-fixture.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    return 0 if ok else 1


def nsc(workspace, report):
    system = {'Linux':'linux', 'Darwin':'darwin'}[platform.system()]
    arch = {'x86_64':'amd64', 'AMD64':'amd64', 'arm64':'arm64', 'aarch64':'arm64'}[platform.machine()]
    asset = f'nsc-{system}-{arch}.zip'
    sums = download(f'{NSC_RELEASE}/SHA256SUMS-nsc.txt').decode('ascii')
    matches = [line.split()[0] for line in sums.splitlines() if line.split() and line.split()[-1].lstrip('*') == asset]
    if matches != [NSC_SHA256[f'{system}-{arch}']]:
        raise ValueError('NSC release checksum missing or changed')
    archive = workspace / asset
    archive.write_bytes(download(f'{NSC_RELEASE}/{asset}'))
    if digest(archive) != matches[0]:
        raise ValueError('NSC release checksum mismatch')
    target = workspace / 'nsc'
    with zipfile.ZipFile(archive) as package:
        members = [m for m in package.infolist() if m.filename == 'nsc' and not m.is_dir()]
        if len(members) != 1:
            raise ValueError('NSC release binary missing or ambiguous')
        target.write_bytes(package.read(members[0]))
    target.chmod(0o700)
    tool_home = workspace/'nsc-version-home'
    tool_home.mkdir(mode=0o700)
    version_env = dict(HOME=str(tool_home),XDG_CONFIG_HOME=str(tool_home/'config'),
                       XDG_DATA_HOME=str(tool_home/'data'),XDG_CACHE_HOME=str(tool_home/'cache'))
    version = subprocess.check_output([str(target),'--version'],text=True,timeout=15,env=version_env).strip()
    if version != 'nsc version 2.15.0':
        raise ValueError('Unexpected NSC version')
    report['nsc'] = {'version':version,'archiveUrl':f'{NSC_RELEASE}/{asset}',
                     'checksumUrl':f'{NSC_RELEASE}/SHA256SUMS-nsc.txt',
                     'archiveSha256':matches[0],'binarySha256':digest(target),'checksumVerified':True}
    return target


def hub_preservation(workspace, evidence, env, run, report):
    """Run the existing full profile against disposable home and cache state."""
    home = workspace / 'hub-home'
    home.mkdir(mode=0o700)
    cache = home / 'cache'; cache.mkdir(mode=0o700)
    # Allow only host locale and executable search paths from the parent. A denylist
    # can miss future instance selectors, provider credentials or shell startup files.
    child = {key:env[key] for key in ('LANG','LC_ALL','LC_CTYPE','TZ') if key in env}
    # The Hub imports agentmux_contracts from sdk/python (the documented PYTHONPATH=sdk/python:.).
    # Those sources are pinned with the rest of the run in sourceHashes, not in the hub-only source map.
    child.update(HOME=str(home), XDG_CACHE_HOME=str(cache),
                 XDG_CONFIG_HOME=str(home/'config'), XDG_DATA_HOME=str(home/'data'),
                 CODEX_HOME=str(home/'codex'), CLAUDE_CONFIG_DIR=str(home/'claude'),
                 PYTHONPATH=os.pathsep.join((str(ROOT/'sdk'/'python'), str(ROOT))), PYTHONNOUSERSITE='1',
                 GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(home/'gitconfig'),
                 AGENTMUX_HOME=str(home/'agentmux'), AGENTMUX_FED_KIND='0',
                 PATH=str(workspace)+os.pathsep+str(Path(sys.executable).parent)+os.pathsep+env.get('PATH',''))
    before = {p.relative_to(ROOT).as_posix():digest(p) for p in (ROOT/'hub').rglob('*.py')}
    before.update({name:digest(ROOT/name) for name in ('hub/requirements.txt','hub/requirements.lock')})
    ok = run('original-hub-full-profile',[sys.executable,'-m','hub.tests.run_local','--profile','full'],child_env=child)
    results = list(cache.glob('agentmux-tests/*/*/result.json'))
    if len(results) != 1:
        raise RuntimeError('Original hub run did not produce one fresh result')
    target = evidence/'hub-full-result.json'
    if target.exists():
        raise RuntimeError('Original hub evidence already exists')
    shutil.copyfile(results[0],target)
    result = json.loads(target.read_text(encoding='utf-8'))
    after = {path:digest(ROOT/path) for path in before}
    expected = ['hub.tests.test_local_runner','hub.tests.test_governance','hub.tests.test_fed_unit',
                'hub.tests.test_hub_offline','hub.tests.test_nats_federation','hub.tests.test_fed_live']
    complete = (ok and result['status']=='passed' and result['profile']=='full'
                and result['selection']==expected and result['tests'] >= 125
                and not result['failures'] and not result['skips'] and not result['expectedFailures']
                and result['sourceSha256']==before==after)
    report['hubPreservation'] = {'report':'hub-full-result.json','reportSha256':digest(target),
        'tests':result['tests'],'noSkippedTests':not result['skips'],'sourceUnchangedDuringRun':before==after,
        'isolatedHome':True,'isolatedCache':True,'accepted':complete,
        'limits':['Existing local full profile only; not R3, power loss or final bilateral platform acceptance.']}
    report['checks'].append({'name':'original-hub-evidence','exitCode':0 if complete else 1})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--negative-fixture', action='store_true')
    args = parser.parse_args()
    if args.negative_fixture:
        return negative_fixture(args.evidence.resolve())
    if args.workspace is None:
        parser.error('--workspace is required for the full run')
    args.workspace = args.workspace.resolve()
    args.evidence = args.evidence.resolve()
    args.workspace.mkdir(parents=True, exist_ok=True)
    args.evidence.mkdir(parents=True, exist_ok=True)
    if any(args.workspace.iterdir()):
        parser.error('Build workspace must be empty to prevent stale compiled files')
    if any(args.evidence.iterdir()):
        parser.error('Evidence directory must be empty to prevent stale results')
    report = {'recordedAt': datetime.now(timezone.utc).isoformat(), 'checks': [],
              'platform': platform.platform(), 'python': platform.python_version(),
              'sourceHashes': source_hashes(), 'exitCode': 1,
              'limits': ['Native host execution only; this is not WSL proof or phase approval.',
                         'Broker fixtures do not establish production enrollment or final bilateral release acceptance.']}
    env = os.environ.copy()

    def run(name, command, cwd=ROOT, timeout=300, child_env=None):
        started = time.monotonic()
        item = {'name': name, 'command': command, 'exitCode': 1}
        report['checks'].append(item)
        process = None
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env if child_env is None else child_env, start_new_session=True)
            item['exitCode'] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            item['failure'] = 'timeout'
        item['seconds'] = round(time.monotonic() - started, 3)
        return item['exitCode'] == 0

    try:
        report['sourceCommit'] = subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True, timeout=15).strip()
        report['node'] = subprocess.check_output(['node','--version'], text=True, timeout=15).strip()
        report['npm'] = subprocess.check_output(['npm','--version'], text=True, timeout=15).strip()
        if not run('locked-python-dependencies', [sys.executable,'-m','pip','install','-r',str(ROOT/'sdk/python/requirements.lock'),'-r',str(ROOT/'hub/requirements.lock')]):
            raise RuntimeError('Python setup failed')
        builds = {}
        for name, relative in (('contracts','sdk/typescript'),('storage','tests/storage/typescript')):
            build = args.workspace / name
            shutil.copytree(ROOT / relative, build, dirs_exist_ok=True, ignore=shutil.ignore_patterns('node_modules','dist','__pycache__'))
            if not run(name+'-dependencies',['npm','ci','--ignore-scripts','--no-audit','--no-fund'],build) or not run(name+'-build',['npm','run','build'],build):
                raise RuntimeError('TypeScript setup failed')
            builds[name] = build
        server = broker(args.workspace, report)
        nsc(args.workspace, report)
        env.update(PYTHONPATH=str(ROOT/'sdk/python'), AGENTMUX_CONTRACT_PYTHON=sys.executable,
                   AGENTMUX_CONTRACT_TS_CLI=str(builds['contracts']/'dist/cli.js'),
                   AGENTMUX_SCHEMA_DIR=str(ROOT/'contracts/v1/schemas'),
                   AGENTMUX_CONTRACT_EXAMPLES=str(ROOT/'tests/contracts/vectors/valid-examples.json'),
                   AGENTMUX_STORAGE_TS_CLIENT=str(builds['storage']/'dist/client.js'),
                   AGENTMUX_STORAGE_SERVER=str(server), AGENTMUX_LEAF_SERVER=str(server),
                   AGENTMUX_EVIDENCE_DIR=str(args.evidence))
        run('python-sdk-units',[sys.executable,'-m','unittest','discover','-s','sdk/python/tests','-v'])
        run('typescript-sdk-units',['npm','test'],builds['contracts'])
        run('cross-language-contracts',[sys.executable,'tests/contracts/run.py','--evidence',str(args.evidence/'contracts.json')])
        delivery = 'docs/planning/2026-10-09/delivery'
        run('conformance-evidence-admission',[sys.executable,delivery+'/check_conformance_evidence.py',
            '--report',str(args.evidence/'contracts.json'),'--candidate',report['sourceCommit'],
            '--environment','macos' if platform.system() == 'Darwin' else 'linux',
            '--evidence',str(args.evidence/'conformance-admission.json')])
        run('conformance-evidence-negative-checks',[sys.executable,delivery+'/test_conformance_evidence.py',
            '--evidence',str(args.evidence/'conformance-admission-negative.json')])
        run('negative-contract-fixture',[sys.executable,'tests/contracts/ci.py','--negative-fixture','--evidence',str(args.evidence)])
        for suite, output in (('storage','storage-result.json'),('leaf','leaf-result.json'),('leaf/signed','signed-leaf-result.json')):
            source = args.evidence / output
            if source.exists():
                raise RuntimeError('Fixture evidence already exists before execution')
            script = 'tests/leaf/signed_run.py' if suite == 'leaf/signed' else f'tests/{suite}/run.py'
            run(suite,[sys.executable,script])
            if not source.is_file():
                report['checks'].append({'name':suite+'-fresh-evidence','exitCode':1})
        hub_preservation(args.workspace,args.evidence,env,run,report)
        import plugin_preservation
        plugin_report = args.evidence/'plugin-preservation.json'
        plugin_before = plugin_preservation.source_hashes()
        plugin_ok = run('maintained-plugin-preservation',
                        [sys.executable, 'tests/contracts/plugin_preservation.py', '--evidence', str(plugin_report)],
                        child_env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'})
        plugin_record = json.loads(plugin_report.read_text(encoding='utf-8')) if plugin_report.is_file() else {}
        plugin_log = plugin_report.with_suffix('.log')
        plugin_accepted = (plugin_ok and plugin_preservation.admitted(plugin_record, plugin_before)
                           and plugin_before == plugin_preservation.source_hashes()
                           and plugin_record.get('isolatedHomeRemoved') is True
                           and plugin_log.is_file() and plugin_record.get('logSha256') == digest(plugin_log))
        report['checks'][-1]['exitCode'] = 0 if plugin_accepted else 1
        report['pluginPreservation'] = {'accepted': plugin_accepted, 'report': plugin_report.name,
                                      'reportSha256': digest(plugin_report) if plugin_report.is_file() else None,
                                      'tests': plugin_record.get('tests', 0)}
        run('platform-placement-contract',[sys.executable,'-m','unittest','discover','-s','tests/platform','-p','test_*.py','-v'])
        run('windows-callback-contract',[sys.executable,'-m','unittest','hub.tests.test_windows_callbacks','-v'])
        run('tracker-tests',[sys.executable,'-m','unittest','discover','-s',delivery,'-p','test_track.py','-v'])
        run('regression-preservation',[sys.executable,delivery+'/check_regressions.py','--self-test'])
        run('component-preservation',[sys.executable,'docs/planning/2026-10-09/verify-component-coverage.py'])
        run('pattern-review',['node','.bytedesk/design-patterns/check.mjs','check','--root','.'])
        report['sourceUnchangedDuringRun'] = report['sourceHashes'] == source_hashes()
        report['exitCode'] = 0 if report['sourceUnchangedDuringRun'] and all(c['exitCode']==0 for c in report['checks']) else 1
    except Exception as exc:
        report['failureType'] = type(exc).__name__
    finally:
        (args.evidence/'ci-result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report['exitCode']


if __name__ == '__main__':
    sys.exit(main())
