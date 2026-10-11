#!/usr/bin/python3
import hashlib,json,os,pathlib,signal,socket,subprocess,sys,time
P=pathlib.Path;root=P(__file__).resolve().parent;m=json.loads((root/'fixture.json').read_text());base=P(m['linuxFixture']);native=P(m['nativeSnapshot']);home=P(m['home']);state=P(m['state']);py='/home/ryan/.cache/agentmux-governance/venv/bin/python'
if sys.argv[1:]!=['--run-authorized']:raise SystemExit('Prepared only. Root must review this runner before --run-authorized.')
assert not (root/'attempt-result.json').exists() and not (root/'windows-supervisors').exists()
assert not (state/'hub').exists()
assert all(hashlib.sha256((native/k).read_bytes()).hexdigest()==v for k,v in m['sourceHashes'].items())
(state/'hub').mkdir();s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close();(state/'hub/config.toml').write_text(f'tcp_port = {port}\n')
env={k:v for k,v in os.environ.items() if not k.startswith('AGENTMUX_') and k not in ['CODEX_HOME','CLAUDE_CONFIG_DIR','HUBDEMO_NO_CLAUDE','CALIB_MODEL_AUTHORIZED']}
env.update(HOME=str(home),AGENTMUX_HOME=str(state),AGENTMUX_REPO=str(native),AGENTMUX_BIN=str(native/'agentmux.sh'),AGENTMUX_WINDOWS_CALLBACKS='1',AGENTMUX_WSL_DISTRO='Ubuntu-26.04',TMUX_TMPDIR=str(base),AGENTMUX_SOCKET='agentmux',AGENTMUX_IDLE_MINUTES='0',HUBDEMO_BASE=m['demoBase'],CALIB_MODEL_AUTHORIZED='1',PATH=str(home/'.local/bin')+':'+str(P(py).parent)+':'+os.environ['PATH'],GIT_CONFIG_COUNT='2',GIT_CONFIG_KEY_0='user.name',GIT_CONFIG_VALUE_0='hubdemo',GIT_CONFIG_KEY_1='user.email',GIT_CONFIG_VALUE_1='hubdemo@localhost')
scalar=['AGENTMUX_WINDOWS_CALLBACK','AGENTMUX_AGENT','AGENTMUX_HUB_URL','AGENTMUX_WSL_DISTRO','AGENTMUX_WSL_BIN','AGENTMUX_WSL_CWD','AGENTMUX_SOCKET','GIT_CONFIG_COUNT','GIT_CONFIG_KEY_0','GIT_CONFIG_VALUE_0','GIT_CONFIG_KEY_1','GIT_CONFIG_VALUE_1'];paths=['AGENTMUX_HOME','AGENTMUX_REPO','AGENTMUX_HUB_TOKEN_FILE','TMUX_TMPDIR'];env['WSLENV']=':'.join([k+'/w' for k in scalar]+[k+'/pw' for k in paths])
report={'scope':'One original Codex calibration attempt, unchanged scenario and E1-E6.','commit':m['commit'],'originalCommand':m['originalCommand'],'outerTimeoutSeconds':840,'originalDrainSeconds':120,'modelAttemptAuthorized':True,'cleanup':{},'errors':[]};proc=None;log=open(root/'orchestrate.log','w');start=time.monotonic()
def supervisors():return list((root/'windows-supervisors').glob('*')) if (root/'windows-supervisors').exists() else []
try:
 proc=subprocess.Popen(m['originalCommand'],cwd=native,env=env,stdout=log,stderr=log,start_new_session=True)
 (root/'attempt-live.json').write_text(json.dumps({'pid':proc.pid,'started':time.time(),'commit':m['commit']}))
 try:report['harnessExitCode']=proc.wait(timeout=840)
 except subprocess.TimeoutExpired:report['outerTimedOut']=True
except BaseException as e:report['errors'].append(repr(e))
finally:
 for folder in supervisors():(folder/'cancel.request').write_text('End of the single original calibration attempt.\n')
 deadline=time.monotonic()+15
 while any(not (folder/'launch-result.json').exists() for folder in supervisors()) and time.monotonic()<deadline:time.sleep(.1)
 report['cleanup']['supervisors']=[{'path':str(folder),'launchResult':json.loads((folder/'launch-result.json').read_text()) if (folder/'launch-result.json').exists() else None} for folder in supervisors()]
 if proc is not None and proc.poll() is None:
  os.killpg(proc.pid,signal.SIGTERM)
  try:proc.wait(timeout=5)
  except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=5);report['cleanup']['harnessExactGroupForceKill']=True
 report['cleanup']['harnessExited']=proc is not None and proc.poll() is not None
 for name,args in [('hub-stop',[py,str(native/'hub/cli.py'),'stop']),('tmux-kill',['tmux','-L','agentmux','kill-server']),('tmux-verify',['tmux','-L','agentmux','list-sessions'])]:
  try:
   p=subprocess.run(args,env=env,capture_output=True,text=True,timeout=15);report['cleanup'][name]={'argv':args,'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
  except Exception as e:report['cleanup'][name]={'failure':repr(e)}
 log.close();(root/'attempt-live.json').unlink(missing_ok=True)
 files=list((native/'evals/orchestrations').glob('*.json')) if (native/'evals/orchestrations').exists() else []
 for f in files:(root/f.name).write_bytes(f.read_bytes())
 report['originalReports']=[{'path':str(f),'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'report':json.loads(f.read_text())} for f in files]
 report['gitEvidence']={}
 for name in ('calc','report'):
  cwd=P(m['demoBase'])/name;data={}
  for label,args in [('log',['git','log','--oneline','-5']),('status',['git','status','--porcelain']),('diff',['git','diff','HEAD'])]:
   p=subprocess.run(args,cwd=cwd,env=env,capture_output=True,text=True,timeout=10);data[label]={'argv':args,'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
  report['gitEvidence'][name]=data
 tokens=list(state.rglob('token'))+list(state.rglob('operator.token'))
 for p in tokens:p.unlink(missing_ok=True)
 report['cleanup']['tokenFilesRemoved']=len(tokens)
 report['sourceUnchanged']=all(hashlib.sha256((native/k).read_bytes()).hexdigest()==v for k,v in m['sourceHashes'].items());report['elapsedSeconds']=time.monotonic()-start
 (root/'attempt-result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'result':str(root/'attempt-result.json'),'originalReportCount':len(files),'sourceUnchanged':report['sourceUnchanged'],'elapsedSeconds':report['elapsedSeconds']}))