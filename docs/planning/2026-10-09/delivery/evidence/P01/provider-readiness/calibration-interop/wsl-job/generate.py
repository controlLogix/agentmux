from pathlib import Path
import json,sys
root=Path(sys.argv[1]); old=Path(r'C:\Users\RyanHelms\AppData\Local\Temp\agentmux-windows-cleanup-0333675031384ad188d92c73f1917a77\probe.py').read_text(encoding='utf-8')
api=old[old.index("k=c.WinDLL"):old.index("result={'schemaVersion'")]
prefix='import ctypes as c\nfrom ctypes import wintypes as w\nimport hashlib,json,os,pathlib,subprocess,sys,time,traceback\nroot=pathlib.Path(__file__).resolve().parent\n'
body=r'''
request_path=pathlib.Path(sys.argv[1]).resolve()
assert request_path.parent==root and request_path.name=='request.json'
request=json.loads(request_path.read_text(encoding='utf-8'))
argv=request['argv']; assert isinstance(argv,list) and all(isinstance(x,str) for x in argv)
assert pathlib.Path(argv[0]).resolve()==pathlib.Path(sys.executable).resolve()
assert pathlib.Path(argv[1]).resolve()==root/'synthetic.py'
assert request['cwd']==str(root)
result={'scope':'WSL/tmux-launched synthetic Windows processes only.','passed':False,'argv':argv,'cwd':request['cwd'],'events':[],'cancelMethod':'Only this fixture cancel.request file triggers TerminateJobObject.','limits':['This fixture supervisor is not product code.','No real provider, auth, model or hub callback was invoked.','WSLENV propagation proves only the explicitly named synthetic values.']}
job=None;pi=PROCESSINFO();child_handle=None;assigned=False;start=time.monotonic()
def check(ok,action):
    if not ok:raise c.WinError(c.get_last_error())
    result['events'].append({'action':action,'elapsedSeconds':round(time.monotonic()-start,4)})
try:
    job=k.CreateJobObjectW(None,None);check(job,'Create unnamed job')
    limits=EXTENDEDLIMIT();limits.BasicLimitInformation.LimitFlags=0x2000
    check(k.SetInformationJobObject(job,9,c.byref(limits),c.sizeof(limits)),'Set kill-on-close')
    si=STARTUPINFO();si.cb=c.sizeof(si)
    cmd=c.create_unicode_buffer(subprocess.list2cmdline(argv))
    check(k.CreateProcessW(argv[0],cmd,None,None,False,0x4|0x08000000,None,request['cwd'],c.byref(si),c.byref(pi)),'Create suspended parent')
    check(k.AssignProcessToJobObject(job,pi.hProcess),'Assign parent before resume');assigned=True
    if k.ResumeThread(pi.hThread)==0xffffffff:raise c.WinError(c.get_last_error())
    deadline=time.monotonic()+10
    while not (root/'child-ready.json').exists():
        if time.monotonic()>deadline:raise RuntimeError('Child readiness timeout')
        time.sleep(.05)
    parent=json.loads((root/'parent-ready.json').read_text(encoding='utf-8'));child=json.loads((root/'child-ready.json').read_text(encoding='utf-8'))
    assert parent['pid']==pi.dwProcessId and parent['childPid']==child['pid'] and child['parentPid']==pi.dwProcessId
    child_handle=k.OpenProcess(0x100000|0x1000,False,child['pid']);check(child_handle,'Open exact child handle')
    result['parent']=parent;result['child']=child
    result['handles']={'job':int(job),'parent':int(pi.hProcess),'thread':int(pi.hThread),'child':int(child_handle)}
    for label,handle in [('parent',pi.hProcess),('child',child_handle)]:
        member=w.BOOL();check(k.IsProcessInJob(handle,job,c.byref(member)),label+' membership')
        assert member.value and k.WaitForSingleObject(handle,0)==258
    (root/'supervisor-ready.json').write_text(json.dumps({'supervisorPid':os.getpid(),'parentPid':parent['pid'],'childPid':child['pid']}),encoding='utf-8')
    deadline=time.monotonic()+20
    while not (root/'cancel.request').exists():
        if time.monotonic()>deadline:raise RuntimeError('Cancellation timeout')
        time.sleep(.05)
    check(k.TerminateJobObject(job,83),'Terminate fixture job after cancellation file')
    for label,handle in [('parent',pi.hProcess),('child',child_handle)]:
        wait=k.WaitForSingleObject(handle,5000);assert wait==0
        code=w.DWORD();check(k.GetExitCodeProcess(handle,c.byref(code)),label+' exit')
        assert code.value==83
        result[label+'After']={'waitResult':wait,'exitCode':code.value}
    result['passed']=True
except Exception as exc:
    result['error']={'type':type(exc).__name__,'message':str(exc),'winerror':getattr(exc,'winerror',None)};traceback.print_exc()
finally:
    if job and assigned:k.TerminateJobObject(job,84)
    elif pi.hProcess:k.TerminateProcess(pi.hProcess,84)
    if pi.hProcess:k.WaitForSingleObject(pi.hProcess,5000)
    if child_handle:k.WaitForSingleObject(child_handle,5000)
    for handle in [child_handle,pi.hThread,pi.hProcess,job]:
        if handle:k.CloseHandle(handle)
    result['elapsedSeconds']=round(time.monotonic()-start,4)
    result['scriptSha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,indent=2))
raise SystemExit(0 if result['passed'] else 1)
'''
(root/'supervisor.py').write_text(prefix+api+body,encoding='utf-8')
(root/'synthetic.py').write_text('''import json,os,pathlib,subprocess,sys,time
root=pathlib.Path(__file__).resolve().parent
selected=['AGENTMUX_WSL_DISTRO','AGENTMUX_WSL_CWD','AGENTMUX_HUB_URL','AGENTMUX_FIXTURE_MARKER']
data={'pid':os.getpid(),'parentPid':os.getppid(),'cwd':os.getcwd(),'argv':sys.argv,'environment':{key:os.environ.get(key) for key in selected}}
if sys.argv[1]=='parent':
    child=subprocess.Popen([sys.executable,str(__file__),'child'],cwd=root)
    data['childPid']=child.pid
(root/('parent-ready.json' if sys.argv[1]=='parent' else 'child-ready.json')).write_text(json.dumps(data,indent=2),encoding='utf-8')
time.sleep(45)
''',encoding='utf-8')
(root/'request.json').write_text(json.dumps({'argv':[sys.executable,str(root/'synthetic.py'),'parent'],'cwd':str(root)},indent=2),encoding='utf-8')
(root/'fixture-path.txt').write_text(str(root),encoding='utf-8')
print(str(root))
