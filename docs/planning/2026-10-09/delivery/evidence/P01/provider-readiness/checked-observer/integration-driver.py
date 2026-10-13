import pathlib,sys,subprocess,shlex,time,json,hashlib,ctypes
root=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(root));from observer_api import *
report={'passed':False,'scope':'Non-model integration of the copied calibration supervisor and independent observer.','cases':[],'noRealClientOrProfileAccess':True,'limits':['Synthetic config only; no actual Windows profile byte comparison tested.','The 840-second bound is configured but was not waited out in these short tests.','Actual model integration remains unqualified.']}
start=time.monotonic()
def cmd(socket,*args):
 return subprocess.run(['wsl','-d','Ubuntu-26.04','--exec','bash','-lc',shlex.join(['tmux','-L',socket,*args])],capture_output=True,text=True,timeout=5)
def wait_file(path,seconds=8):
 deadline=time.monotonic()+seconds
 while not path.exists():
  if time.monotonic()>deadline:raise RuntimeError('Expected fixture record missing: '+path.name)
  time.sleep(.05)
try:
 for kind in ['teardown','cancel','observer-setup-failure','observer-afterready-exit','observer-afterready-error']:
  case=root/kind;case.mkdir()
  for name in ['supervisor.py','observer.py','observer_api.py','synthetic.py','synthetic-wrapper.py','synthetic-config.toml']:(case/name).write_bytes((root/name).read_bytes())
  if kind=='observer-setup-failure':(case/'observer.py').write_text('raise SystemExit(17)\n')
  if kind in ['observer-afterready-exit','observer-afterready-error']:
   observer_source=(case/'observer.py').read_text()
   injected=' time.sleep(.8)\n '+('os._exit(23)' if kind=='observer-afterready-exit' else "raise RuntimeError('deliberate observer failure after readiness')")+'\n while True:'
   (case/'observer.py').write_text(observer_source.replace(' while True:',injected,1))
  socket='agentmux-integrated-'+root.name.rsplit('-',1)[-1]+'-'+kind
  command=shlex.join(['/mnt/c/Users/RyanHelms/AppData/Local/Programs/Python/Python314/python.exe',str(case/'synthetic-wrapper.py')])+'; sleep 15'
  handles=[];entry={'kind':kind,'socket':socket,'command':command,'passed':False}
  try:
   launched=cmd(socket,'-f','/dev/null','new-session','-d','-s','fixture',command);assert launched.returncode==0,launched.stderr
   if kind in ['observer-setup-failure','observer-afterready-exit','observer-afterready-error']:
    wait_file(case/'launch-result.json');launch=json.loads((case/'launch-result.json').read_text());entry['launchResult']=launch
    assert launch['passed'] is False
    assert launch['cleanup']['verified'] and launch['cleanup']['activeProcesses']==0 and launch['cleanup']['parentWait']==0
    if kind=='observer-setup-failure':assert 'Observer exited before readiness' in launch['error']['message'] and launch['cleanup']['observerExit']==17
    elif kind=='observer-afterready-exit':assert 'Independent observer exited unexpectedly' in launch['error']['message'] and launch['cleanup']['observerExit']==23 and (case/'launch-ready.json').exists() and not (case/'observer-result.json').exists()
    else:
     observed=json.loads((case/'observer-result.json').read_text());assert observed['passed'] is False and observed['cleanup']['verified'] and observed['cleanup']['activeProcesses']==0 and observed['windowsConfigBytesUnchanged'] is True
     entry['observerResult']=observed
   else:
    wait_file(case/'child-ready.json');wait_file(case/'launch-ready.json')
    ready=json.loads((case/'launch-ready.json').read_text());request=json.loads((case/'observer-input.json').read_text());child=json.loads((case/'child-ready.json').read_text());ack=json.loads((case/'observer-ready.json').read_text())
    assert ack['jobUid']==ready['jobUid'] and ack['parentPid']==ready['parentPid'] and ack['parentAlive'] and ack['parentInJob'] and not ack['observerInJob'] and ack['observerConsoleWindow']==0
    entry['ready']=ready;entry['observerAcknowledgedBeforeResume']=True
    for label,pid in [('supervisor',request['supervisorPid']),('parent',ready['parentPid']),('child',child['pid']),('observer',ready['observerPid'])]:
     h=k.OpenProcess(0x100000|0x1000,False,pid);assert h;handles.append((label,h));assert k.WaitForSingleObject(h,0)==258
    if kind=='teardown':assert cmd(socket,'kill-session','-t','fixture').returncode==0
    else:(case/'cancel.request').write_text('Cancel only this fixture job.\n')
    wait_file(case/'observer-result.json');observed=json.loads((case/'observer-result.json').read_text());entry['observerResult']=observed
    assert observed['jobUid']==ready['jobUid'] and observed['passed'] and observed['cleanup']['verified'] and observed['afterJob']['ActiveProcesses']==0 and observed['windowsConfigBytesUnchanged'] and not observed['observerInJob'] and observed['observerConsoleWindow']==0
    outcomes={}
    for label,h in handles:
     wait=k.WaitForSingleObject(h,4000);code=w.DWORD();assert wait==0 and k.GetExitCodeProcess(h,c.byref(code));outcomes[label]={'waitResult':wait,'exitCode':code.value}
    entry['exactHandleOutcomes']=outcomes
    assert outcomes['observer']['exitCode']==0
    if kind=='teardown':entry['supervisorFinalRecordPresent']=(case/'launch-result.json').exists()
   entry['passed']=True
  finally:
   if not (case/'cancel.request').exists():(case/'cancel.request').write_text('Cancel only this fixture job.\n')
   try:
    stopped=cmd(socket,'kill-server')
    absent=cmd(socket,'list-sessions')
    entry['tmuxCleanup']={'killExit':stopped.returncode,'probeExit':absent.returncode,'noServer':absent.returncode!=0 and ('no server running' in absent.stderr or 'error connecting' in absent.stderr and 'No such file or directory' in absent.stderr)}
    if not entry['tmuxCleanup']['noServer']:entry['passed']=False
   except subprocess.TimeoutExpired:entry['tmuxCleanupTimeout']=True;entry['passed']=False
   for _,h in handles:k.CloseHandle(h)
   report['cases'].append(entry)
 report['passed']=all(c['passed'] for c in report['cases'])
except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
finally:
 report['elapsedSeconds']=round(time.monotonic()-start,4)
 (root/'integration-result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
raise SystemExit(0 if report['passed'] else 1)