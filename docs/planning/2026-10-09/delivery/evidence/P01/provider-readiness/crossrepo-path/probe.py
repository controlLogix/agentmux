import hashlib
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent / 'retry'
REPO = pathlib.Path('C:/Users/RyanHelms/GitHub/agentmux')
COMMIT = '2aed3e7206e81cf119562647879c90a29457b08a'
commands = []

def run(argv, *, env=None, cwd=None, input=None):
    p = subprocess.run(argv, env=env, cwd=cwd, input=input, capture_output=True, text=True, timeout=30)
    commands.append({'argv': argv, 'cwd': str(cwd) if cwd else None, 'exitCode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
    if p.returncode:
        raise RuntimeError('Fixture command failed: ' + str(argv))
    return p.stdout

report = {'scope': 'Private crossrepo home-path resolution with Python and Git only. No client or provider execution.', 'commands': commands, 'sourceCommit': COMMIT, 'passed': False}
try:
    root_linux = run(['wsl', '-d', 'Ubuntu-26.04', '--exec', 'wslpath', '-u', str(ROOT)]).strip()
    native = run(['wsl', '-d', 'Ubuntu-26.04', '--exec', 'python3', '-c', "import tempfile;print(tempfile.mkdtemp(prefix='agentmux-crossrepo-path-'))"]).strip()
    report['nativeFixture'] = native
    setup = subprocess.check_output(['git', '-C', str(REPO), 'show', COMMIT + ':hub/demo/setup_repos.sh'])
    (ROOT / 'setup_repos.sh').write_bytes(setup)
    report['setupSource'] = {'path': 'hub/demo/setup_repos.sh', 'sha256': hashlib.sha256(setup).hexdigest()}
    base = ROOT / 'shared repos'
    winhome = ROOT / 'private Windows home'
    winhome.mkdir()
    assert base.resolve().is_relative_to(ROOT.resolve()) and not base.exists()
    linux_setup = "import pathlib,os,subprocess,json,sys; root=pathlib.Path(sys.argv[1]); native=pathlib.Path(sys.argv[2]); home=native/'home';home.mkdir(); base=root/'shared repos'; env=dict(os.environ,HOME=str(home),HUBDEMO_BASE=str(base)); p=subprocess.run(['bash',str(root/'setup_repos.sh'),'--reset'],env=env,capture_output=True,text=True); print(json.dumps({'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})); assert p.returncode==0; (home/'hubdemo').symlink_to(base,target_is_directory=True)"
    run(['wsl', '-d', 'Ubuntu-26.04', '--exec', 'python3', '-c', linux_setup, root_linux, native])
    # Only create a junction inside the newly created private Windows home.
    target = str(base)
    link = str(winhome / 'hubdemo')
    ps = "New-Item -ItemType Junction -Path $env:AGENTMUX_FIXTURE_LINK -Target $env:AGENTMUX_FIXTURE_TARGET -ErrorAction Stop | Select-Object FullName,LinkType,Target | ConvertTo-Json -Compress"
    junction_env = dict(os.environ, AGENTMUX_FIXTURE_LINK=link, AGENTMUX_FIXTURE_TARGET=target)
    run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', ps], env=junction_env)
    (base / 'calc' / 'fixture-marker.txt').write_text('Private shared calc marker.\n')
    probe = '''import pathlib,os,json,subprocess
from report import summary
homecalc=pathlib.Path(os.path.expanduser('~/hubdemo/calc'))
assert summary('a',[1,2,3])=='a: n=3 mean=2.00'
expected=pathlib.Path(os.environ['FIXTURE_CALC'])
assert homecalc.samefile(expected)
marker=homecalc/'fixture-marker.txt'
assert marker.read_text()=='Private shared calc marker.\\n'
git=subprocess.run(['git','-C',str(homecalc),'rev-parse','HEAD'],capture_output=True,text=True)
assert git.returncode==0
print(json.dumps({'expandedHomeCalc':str(homecalc),'sameFile':homecalc.samefile(expected),'marker':marker.read_text(),'summary':summary('a',[1,2,3]),'calcGitHead':git.stdout.strip(),'resolvedCalcModule':__import__('calc').__file__}))
'''
    (ROOT / 'import-probe.py').write_text(probe, encoding='utf-8')
    env = dict(os.environ, USERPROFILE=str(winhome), HOME=str(winhome), FIXTURE_CALC=str(base / 'calc'))
    env.pop('CALC_PATH', None)
    # These are paths only. This probe never opens these client profiles.
    env.update(CODEX_HOME='C:/Users/RyanHelms/.codex', CLAUDE_CONFIG_DIR='C:/Users/RyanHelms/.claude', GROK_HOME='C:/Users/RyanHelms/.grok')
    # -c retains the report checkout on sys.path, unlike executing an external script.
    windows = json.loads(run([sys.executable, '-c', probe], env=env, cwd=base / 'report'))
    linux_driver = "import os,pathlib,subprocess,sys; root=pathlib.Path(sys.argv[1]); home=sys.argv[2]+'/home';env=dict(os.environ,HOME=home,FIXTURE_CALC=str(root/'shared repos/calc'));env.pop('CALC_PATH',None);p=subprocess.run(['python3','-c',(root/'import-probe.py').read_text()],cwd=root/'shared repos/report',env=env,capture_output=True,text=True);print(p.stdout,end='');print(p.stderr,file=sys.stderr,end='');raise SystemExit(p.returncode)"
    linux = json.loads(run(['wsl', '-d', 'Ubuntu-26.04', '--exec', 'python3', '-c', linux_driver, root_linux, native]))
    assert linux['calcGitHead'] == windows['calcGitHead']
    report.update(windows=windows, linux=linux, windowsProfileOverrides={'USERPROFILE': str(winhome), 'HOME': str(winhome), 'CODEX_HOME': env['CODEX_HOME'], 'CLAUDE_CONFIG_DIR': env['CLAUDE_CONFIG_DIR'], 'GROK_HOME': env['GROK_HOME']}, passed=True)
except Exception as exc:
    report['error'] = {'type': type(exc).__name__, 'message': str(exc)}
finally:
    report['limits'] = ['Python and Git path resolution only; actual clients honoring canonical profile overrides remain unqualified.', 'No auth/config files were read, copied or modified.', 'All home mappings, repositories and markers are disposable fixtures; no hubdemo directory was created in a real user home.', 'The marker changes the disposable checkout after its initial commit; this is a path probe, not a clean orchestration acceptance run.']
    (ROOT / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
raise SystemExit(0 if report['passed'] else 1)
