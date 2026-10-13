#!/usr/bin/python3
import hashlib,json,os,pathlib,re,shutil,subprocess,sys
P=pathlib.Path
manifest=json.loads(P(__file__).resolve().with_name('fixture.json').read_text())
if os.environ.get('CALIB_MODEL_AUTHORIZED')!='1':raise SystemExit('Root authorization is required before the original model attempt.')
agent=os.environ['AGENTMUX_AGENT'];assert re.fullmatch(r'[a-z0-9_-]+',agent)
assert sys.argv[1:]==['--no-daemon','--dangerously-bypass-approvals-and-sandbox'],sys.argv[1:]
root=P(manifest['ntfsFixture'])/'windows-supervisors'/agent;root.mkdir(parents=True,exist_ok=False)
source=P('/mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-calib-observer-checked-d4a4c78894e24e4eaa9e1b21effb7456')
for name,expected in {'supervisor.py': 'cd2787e2723e875ce9a5171d5823e0f560eff6cf1e994436b8e2bf5e213f8f6a', 'observer.py': 'bbf09f1d6d8cfd45588a40dc3230e6b03f6c1305406715dc5712bb22f26fc1bf', 'observer_api.py': '13382ba6c650ec841136805bdeb0dabcd92a9ec1035df44314f4415c56581a93'}.items():
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
request={'originalArgs':sys.argv[1:],'cwd':win(os.getcwd()),'helperDirectory':manifest['helperDirectory'],'callbackEnvironment':context,'additionalMcpNames':[]}
(root/'input-request.json').write_text(json.dumps(request,indent=2)+'\n')
py='/mnt/c/Users/RyanHelms/AppData/Local/Programs/Python/Python314/python.exe';supervisor=win(str(root/'supervisor.py'))
# Forward the actual tmux pane TERM through WSL interop; do not invent a terminal.
term=os.environ.get('TERM','');assert term and term!='dumb',term
entries=[x for x in os.environ.get('WSLENV','').split(':') if x and x.split('/',1)[0]!='TERM']
os.environ['WSLENV']=':'.join(entries+['TERM/w'])
r=subprocess.run([py,supervisor,'--prepare',win(str(root/'input-request.json'))]);assert r.returncode==0
os.execv(py,[py,supervisor,'--run'])