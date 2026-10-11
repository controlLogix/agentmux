import hashlib,io,json,os,pathlib,shlex,socket,subprocess,sys,tarfile,tempfile,time
P=pathlib.Path
source=P('/mnt/c/Users/RyanHelms/GitHub/agentmux'); ntfs=P(__file__).resolve().parent
base=P(tempfile.mkdtemp(prefix='calib-readiness-',dir='/home/ryan/.cache/agentmux-governance')); native=base/'snapshot'; native.mkdir(); home=base/'home';home.mkdir();state=base/'state';(state/'hub').mkdir(parents=True)
commit='36cc149a774d823716c81d7b5443b852cb0c63d1'
paths=['agentmux.sh','agentmux.cmd','agentmux_windows.py','coordination.py','hub','taskmgmt']
blob=subprocess.check_output(['git','-C',str(source),'archive',commit,*paths]); tarfile.open(fileobj=io.BytesIO(blob)).extractall(native,filter='data')
hashes={str(p.relative_to(native)):hashlib.sha256(p.read_bytes()).hexdigest() for p in native.rglob('*') if p.is_file()}
(native/'agentmux.sh').chmod(0o700); (home/'.local/bin').mkdir(parents=True); (home/'.local/bin/agentmux').symlink_to(native/'agentmux.sh')
bridge=ntfs/'callback bin';bridge.mkdir();
for f in ('agentmux.cmd','agentmux_windows.py'):(bridge/f).write_bytes((native/f).read_bytes())
repos=ntfs/'original demo repos'; assert not repos.exists();
py='/home/ryan/.cache/agentmux-governance/venv/bin/python'; assert P(py).is_file()
sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close();(state/'hub/config.toml').write_text(f'tcp_port = {port}\npoll_s = 10000\n')
env={k:v for k,v in os.environ.items() if not k.startswith('AGENTMUX_') and k not in ('CODEX_HOME','CLAUDE_CONFIG_DIR','HUBDEMO_NO_CLAUDE')}
env.update(HOME=str(home),AGENTMUX_HOME=str(state),AGENTMUX_REPO=str(native),AGENTMUX_BIN=str(native/'agentmux.sh'),TMUX_TMPDIR=str(base),AGENTMUX_SOCKET='agentmux',AGENTMUX_WINDOWS_CALLBACKS='1',AGENTMUX_WSL_DISTRO='Ubuntu-26.04',AGENTMUX_IDLE_MINUTES='0',HUBDEMO_BASE=str(repos),PATH=str(home/'.local/bin')+':'+str(P(py).parent)+':'+os.environ['PATH'])
keys=['AGENTMUX_WINDOWS_CALLBACK','AGENTMUX_AGENT','AGENTMUX_HUB_URL','AGENTMUX_WSL_DISTRO','AGENTMUX_WSL_BIN','AGENTMUX_WSL_CWD','AGENTMUX_SOCKET'];pathkeys=['AGENTMUX_HOME','AGENTMUX_REPO','AGENTMUX_HUB_TOKEN_FILE','TMUX_TMPDIR']
env['WSLENV']=':'.join([k+'/w' for k in keys]+[k+'/pw' for k in pathkeys])
records=[];server=None;log=None
report={'scope':'Original calibration preparation and synthetic callback prerequisite only; no model execution.','commit':commit,'linuxFixture':str(base),'ntfsFixture':str(ntfs),'demoBase':str(repos),'sourceHashes':hashes,'records':records,'failures':[],'limitations':['Synthetic shell/Windows Python workers do not replace the Codex calibration or E1-E6.','No provider auth/config read or credential copying.','The crossrepo hard-coded home path is not qualified.']}
def run(name,args,e=env,cwd=None,timeout=25):
 p=subprocess.run(args,env=e,cwd=cwd,capture_output=True,text=True,timeout=timeout);r={'name':name,'argv':args,'cwd':str(cwd) if cwd else os.getcwd(),'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr};records.append(r);return p
def op(*args):
 p=run('operator-'+args[0],[py,str(native/'hub/cli.py'),*args],timeout=130);assert p.returncode==0,(p.stdout,p.stderr);return p
worker=r'''import os,json,subprocess,sys,pathlib
out=pathlib.Path(sys.argv[1]);bridge=pathlib.Path(sys.argv[2]);own,other=sys.argv[3:5]
context={k:os.environ.get(k) for k in ['AGENTMUX_WINDOWS_CALLBACK','AGENTMUX_AGENT','AGENTMUX_HUB_URL','AGENTMUX_HUB_TOKEN_FILE','AGENTMUX_WSL_DISTRO','AGENTMUX_WSL_BIN','AGENTMUX_WSL_CWD','AGENTMUX_HOME','TMUX_TMPDIR']}
result={'argv':sys.argv,'cwd':os.getcwd(),'userProfile':os.environ.get('USERPROFILE'),'context':context,'inlineTokenPresent':bool(os.environ.get('AGENTMUX_HUB_TOKEN')),'calls':[]}
def invoke(*args):
 argv=[str(bridge/'agentmux.cmd'),'hub',*args]; command='cmd.exe /d /s /c "'+subprocess.list2cmdline(argv)+'"';p=subprocess.run(command,capture_output=True,text=True,timeout=20);result['calls'].append({'argv':argv,'command':command,'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});return p
try:
 assert context['AGENTMUX_WINDOWS_CALLBACK']=='1' and not result['inlineTokenPresent']; p=invoke('whoami'); assert p.returncode==0 and p.stdout.startswith(context['AGENTMUX_AGENT']), (p.stdout,p.stderr)
 p=invoke('done',other,'--result','wrong synthetic worker');assert p.returncode!=0
 p=invoke('--json','claim',own);assert p.returncode==0,(p.stdout,p.stderr)
 pathlib.Path('windows-synthetic-'+context['AGENTMUX_AGENT']+'.bin').write_bytes(b'Windows selected cwd proof\x00\xff')
 p=invoke('done',own,'--result','Synthetic Windows callback prerequisite complete');assert p.returncode==0,(p.stdout,p.stderr)
 result['passed']=True
except Exception as e:result['passed']=False;result['failure']=repr(e)
out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
'''
workerpath=ntfs/'windows-worker.py';workerpath.write_text(worker,encoding='utf-8')
win=lambda p:subprocess.check_output(['wslpath','-w',str(p)],text=True).strip()
try:
 setup=run('original-setup',['bash',str(native/'hub/demo/setup_repos.sh'),'--reset']);assert setup.returncode==0,(setup.stdout,setup.stderr)
 test=run('original-calc-baseline-tests',[py,'-m','unittest','discover','-s','tests'],cwd=repos/'calc');assert test.returncode==0
 log=open(base/'hub.log','w');server=subprocess.Popen([py,str(native/'hub/server.py')],env=env,stdout=log,stderr=log)
 for _ in range(150):
  if (state/'hub/hub.sock').exists():break
  if server.poll() is not None:raise RuntimeError('Hub exited before readiness')
  time.sleep(.1)
 op('repo','add','calc',str(repos/'calc'))
 sessions=[]
 for a in ('prereqone','prereqtwo'):
  op('spawn','calc','worker',a,'--cli','shell');sessions.append('calc-worker-'+a)
 work=[]
 for session in sessions:work.append(json.loads(op('--json','work','add','--to','agent:'+session,'--title','Synthetic Windows callback prerequisite').stdout)['id'])
 results=[]
 for i,session in enumerate(sessions):
  out=ntfs/(session+'.json');command=shlex.join(['/mnt/c/Users/RyanHelms/AppData/Local/Programs/Python/Python314/python.exe',win(workerpath),win(out),win(bridge),work[i],work[1-i]])
  r=run('pane-windows-child-launch',['tmux','-L','agentmux','send-keys','-t',session,command,'Enter']);assert r.returncode==0
  deadline=time.monotonic()+90
  while not out.exists() and time.monotonic()<deadline:time.sleep(.2)
  assert out.exists(),'Windows child did not produce result'
  result=json.loads(out.read_text());results.append(result);assert result['passed'],result
 report['windowsChildren']=results
 for session in sessions:
  marker=repos/'calc'/('windows-synthetic-'+session+'.bin');assert marker.read_bytes()==b'Windows selected cwd proof\x00\xff';records.append({'name':'wsl-marker-verification','path':str(marker),'sha256':hashlib.sha256(marker.read_bytes()).hexdigest(),'passed':True})
 report['workResults']=[json.loads(op('--json','work','show',w).stdout) for w in work]
 assert all(w['state']=='done' for w in report['workResults'])
 report['calibrationScenario']={'agents':[['calc','worker','codex_<tag>','codex']],'originalAssertions':'E1-E6 in unchanged hub/demo/orchestrate.py','modelExecuted':False,'calibAccepted':False}
 report['passed']=True
except BaseException as e:report['passed']=False;report['failures'].append(repr(e))
finally:
 cleanup=run('private-tmux-cleanup',['tmux','-L','agentmux','kill-server']);report['cleanup']={'tmuxKillExit':cleanup.returncode}
 if server is not None:
  server.terminate()
  try:server.wait(timeout=15)
  except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5);report['cleanup']['hubForceKill']=True
  report['cleanup']['hubExited']=server.poll() is not None
 if log:log.close()
 tokenfiles=list(state.rglob('token'))+list(state.rglob('operator.token'))
 for p in tokenfiles:p.unlink(missing_ok=True)
 report['cleanup']['privateTokenFilesRemoved']=len(tokenfiles)
 actual={str(p.relative_to(native)):hashlib.sha256(p.read_bytes()).hexdigest() for p in native.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
 report['originalSourceUnchanged']=all(actual.get(k)==v for k,v in hashes.items())
 report['scripts']=[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [P(__file__),workerpath]]
 (ntfs/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'result':str(ntfs/'result.json'),'linuxFixture':str(base),'passed':report.get('passed'),'failures':report['failures'],'sha256':hashlib.sha256((ntfs/'result.json').read_bytes()).hexdigest()}))
