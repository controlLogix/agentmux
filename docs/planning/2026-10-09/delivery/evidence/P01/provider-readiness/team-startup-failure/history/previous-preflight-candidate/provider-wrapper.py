#!/usr/bin/python3
import hashlib,json,os,pathlib,re,shutil,subprocess,sys
P=pathlib.Path
manifest=json.loads(P(__file__).resolve().with_name('fixture.json').read_text())
if os.environ.get('CALIB_MODEL_AUTHORIZED')!='1':raise SystemExit('Root authorization is required before the original model attempt.')
provider=P(sys.argv[0]).name;assert provider in ['codex','claude','grok']
agent=os.environ['AGENTMUX_AGENT'];assert re.fullmatch(r'[a-z0-9_-]+',agent)
if provider=='codex':assert sys.argv[1:]==['--no-daemon','--dangerously-bypass-approvals-and-sandbox']
elif provider=='grok':assert sys.argv[1:]==['--permission-mode','bypassPermissions']
else:assert len(sys.argv[1:])==4 and sys.argv[1]=='--settings' and sys.argv[3:]==['--setting-sources','']
root=P(manifest['ntfsFixture'])/'windows-supervisors'/agent;root.mkdir(parents=True,exist_ok=False)
source=P('/mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux original TEAM preparation _fwm3fqa/provider-supervisor')
for name,expected in {'supervisor.py': '315d24bf92e57900a5f9b12c9fdac7603e95386845ddd9c91e1758527722f7a1', 'observer.py': '565d60edfa49005f97a815eabed916674c8c3812fd5c8e7fd22e61c1ee342097', 'observer_api.py': '13382ba6c650ec841136805bdeb0dabcd92a9ec1035df44314f4415c56581a93'}.items():
 path=source/name;assert hashlib.sha256(path.read_bytes()).hexdigest()==expected;shutil.copyfile(path,root/name)

def win(value):return subprocess.check_output(['wslpath','-w',value],text=True).strip()
keys=['AGENTMUX_WINDOWS_CALLBACK','AGENTMUX_AGENT','AGENTMUX_HUB_URL','AGENTMUX_WSL_DISTRO','AGENTMUX_WSL_BIN','AGENTMUX_WSL_CWD','AGENTMUX_SOCKET','AGENTMUX_HOME','AGENTMUX_HUB_TOKEN_FILE','TMUX_TMPDIR'];paths={'AGENTMUX_HOME','AGENTMUX_HUB_TOKEN_FILE','TMUX_TMPDIR','AGENTMUX_REPO'}
context={key:os.environ[key] for key in keys}
if 'AGENTMUX_REPO' in os.environ:context['AGENTMUX_REPO']=os.environ['AGENTMUX_REPO']
assert not os.environ.get('AGENTMUX_HUB_TOKEN')
token=P(context['AGENTMUX_HUB_TOKEN_FILE']);assert token.is_file() and str(token).startswith(manifest['state']+'/')
assert token.stat().st_mode & 0o777 == 0o600
for key in paths:
 if key in context:context[key]=win(context[key])
context.update(GIT_CONFIG_COUNT='2',GIT_CONFIG_KEY_0='user.name',GIT_CONFIG_VALUE_0='hubdemo',GIT_CONFIG_KEY_1='user.email',GIT_CONFIG_VALUE_1='hubdemo@localhost')
request={'provider':provider,'originalArgs':sys.argv[1:],'cwd':win(os.getcwd()),'helperDirectory':manifest['helperDirectory'],'callbackEnvironment':context,'additionalMcpNames':[]}
(root/'input-request.json').write_text(json.dumps(request,indent=2)+'\n')
py='/mnt/c/Users/RyanHelms/AppData/Local/Programs/Python/Python314/python.exe';supervisor=win(str(root/'supervisor.py'))
# Forward the actual tmux pane TERM through WSL interop; do not invent a terminal.
term=os.environ.get('TERM','');assert term and term!='dumb',term
entries=[x for x in os.environ.get('WSLENV','').split(':') if x and x.split('/',1)[0]!='TERM']
os.environ['WSLENV']=':'.join(entries+['TERM/w'])
r=subprocess.run([py,supervisor,'--prepare',win(str(root/'input-request.json'))]);assert r.returncode==0
os.execv(py,[py,supervisor,'--run'])