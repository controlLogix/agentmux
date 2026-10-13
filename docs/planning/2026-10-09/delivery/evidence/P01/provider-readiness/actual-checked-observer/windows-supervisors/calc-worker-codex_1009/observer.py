from observer_api import *
import pathlib,json,time,os,sys,hashlib,uuid
root=pathlib.Path(__file__).resolve().parent
assert sys.argv[1:]==['observer-input.json']
req=json.loads((root/'observer-input.json').read_text())
assert str(uuid.UUID(req['jobUid']))==req['jobUid'] and req['jobName']=='Local\\agentmux-p01-'+req['jobUid']
assert req['maxSeconds']==840
assert hashlib.sha256((root/'observer.py').read_bytes()).hexdigest()==req['observerSha256']
assert hashlib.sha256((root/'observer_api.py').read_bytes()).hexdigest()==req['apiSha256']
result={'jobUid':req['jobUid'],'jobName':req['jobName'],'parentPid':req['parentPid'],'supervisorPid':req['supervisorPid'],'observerPid':os.getpid(),'passed':False,'events':[],'terminalReason':None,'limitations':['Job accounting and byte comparison concern this exact fixture only.','No auth or config contents or hashes are logged.','Holding the observer job handle delays kill-on-last-handle-close; explicit job termination is required.']}
job=None;parent=None;supervisor=None;config_before=None;start=time.monotonic()
def event(action):result['events'].append({'action':action,'elapsedSeconds':round(time.monotonic()-start,4)})
def accounting():
 a=BASICACCOUNTING();assert k.QueryInformationJobObject(job,1,c.byref(a),c.sizeof(a),None)
 return {key:int(getattr(a,key)) for key in ['TotalProcesses','ActiveProcesses','TotalTerminatedProcesses']}
try:
 job=k.OpenJobObjectW(0xC,False,req['jobName']);assert job;event('Open exact named job')
 parent=k.OpenProcess(0x100000|0x1000,False,req['parentPid']);assert parent
 supervisor=k.OpenProcess(0x100000|0x1000,False,req['supervisorPid']);assert supervisor
 member=w.BOOL();assert k.IsProcessInJob(parent,job,c.byref(member)) and member.value and k.WaitForSingleObject(parent,0)==258
 observer_member=w.BOOL();assert k.IsProcessInJob(k.GetCurrentProcess(),job,c.byref(observer_member)) and not observer_member.value
 console_window=int(k.GetConsoleWindow() or 0);assert console_window==0
 result['observerInJob']=False;result['observerConsoleWindow']=console_window
 config=pathlib.Path(req['configPath']);config_before=config.read_bytes()
 result['heldHandles']={'job':int(job),'parent':int(parent),'supervisor':int(supervisor)}
 result['before']=accounting();event('Hold exact handles and config bytes before parent resume')
 ready_temp=root/'observer-ready.tmp';ready_temp.write_text(json.dumps({'jobUid':req['jobUid'],'parentPid':req['parentPid'],'observerPid':os.getpid(),'parentInJob':True,'parentAlive':True,'observerInJob':False,'observerConsoleWindow':console_window}));os.replace(ready_temp,root/'observer-ready.json')
 while True:
  wait=k.WaitForSingleObject(parent,100)
  if wait==0:result['terminalReason']='parent-exit';break
  assert wait==258
  if (root/'cancel.request').exists():result['terminalReason']='fixture-cancellation';break
  if k.WaitForSingleObject(supervisor,0)==0:result['terminalReason']='supervisor-exit';break
  if time.monotonic()-start>=840:result['terminalReason']='14-minute-bound';break
 assert k.TerminateJobObject(job,133);event('Terminate exact held job')
 assert k.WaitForSingleObject(parent,5000)==0
 code=w.DWORD();assert k.GetExitCodeProcess(parent,c.byref(code));result['parentExitCode']=code.value
 deadline=time.monotonic()+5
 while True:
  final=accounting()
  if final['ActiveProcesses']==0:break
  if time.monotonic()>deadline:raise RuntimeError('Contained processes remain active')
  time.sleep(.05)
 result['afterJob']=final;event('Verify zero active job processes')
 result['passed']=True
except Exception as exc:result['error']={'type':type(exc).__name__,'message':str(exc),'winerror':getattr(exc,'winerror',None)}
finally:
 cleanup={'verified':False}
 if job:cleanup['terminateJobOk']=bool(k.TerminateJobObject(job,134))
 if parent:cleanup['parentWait']=k.WaitForSingleObject(parent,3000)
 if job:
  deadline=time.monotonic()+3
  while True:
   a=BASICACCOUNTING()
   if not k.QueryInformationJobObject(job,1,c.byref(a),c.sizeof(a),None):
    cleanup['accountingError']=c.get_last_error();break
   cleanup['activeProcesses']=int(a.ActiveProcesses)
   if a.ActiveProcesses==0 or time.monotonic()>deadline:break
   time.sleep(.05)
 cleanup['verified']=cleanup.get('terminateJobOk') is True and cleanup.get('parentWait')==0 and cleanup.get('activeProcesses')==0
 result['cleanup']=cleanup
 if not cleanup['verified']:result['passed']=False
 if config_before is not None:
  try:result['windowsConfigBytesUnchanged']=config.exists() and config.read_bytes()==config_before
  except OSError as exc:result['windowsConfigBytesUnchanged']=None;result['configComparisonErrorType']=type(exc).__name__
  del config_before
 for handle in [parent,supervisor,job]:
  if handle:k.CloseHandle(handle)
 result['elapsedSeconds']=round(time.monotonic()-start,4)
 target=root/'observer-result.json';temp=root/'observer-result.tmp';temp.write_text(json.dumps(result,indent=2)+'\n');os.replace(temp,target)
raise SystemExit(0 if result['passed'] else 1)
