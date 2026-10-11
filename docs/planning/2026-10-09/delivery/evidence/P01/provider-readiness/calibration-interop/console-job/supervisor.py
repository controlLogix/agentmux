import ctypes as c
from ctypes import wintypes as w
import hashlib,json,os,pathlib,subprocess,sys,time
root=pathlib.Path(__file__).resolve().parent
k=c.WinDLL('kernel32',use_last_error=True)
class STARTUPINFO(c.Structure):
    _fields_=[('cb',w.DWORD),('lpReserved',w.LPWSTR),('lpDesktop',w.LPWSTR),('lpTitle',w.LPWSTR),('dwX',w.DWORD),('dwY',w.DWORD),('dwXSize',w.DWORD),('dwYSize',w.DWORD),('dwXCountChars',w.DWORD),('dwYCountChars',w.DWORD),('dwFillAttribute',w.DWORD),('dwFlags',w.DWORD),('wShowWindow',w.WORD),('cbReserved2',w.WORD),('lpReserved2',c.POINTER(c.c_ubyte)),('hStdInput',w.HANDLE),('hStdOutput',w.HANDLE),('hStdError',w.HANDLE)]
class PROCESSINFO(c.Structure):
    _fields_=[('hProcess',w.HANDLE),('hThread',w.HANDLE),('dwProcessId',w.DWORD),('dwThreadId',w.DWORD)]
class BASICLIMIT(c.Structure):
    _fields_=[('PerProcessUserTimeLimit',c.c_longlong),('PerJobUserTimeLimit',c.c_longlong),('LimitFlags',w.DWORD),('MinimumWorkingSetSize',c.c_size_t),('MaximumWorkingSetSize',c.c_size_t),('ActiveProcessLimit',w.DWORD),('Affinity',c.c_size_t),('PriorityClass',w.DWORD),('SchedulingClass',w.DWORD)]
class IOCOUNTERS(c.Structure):
    _fields_=[(n,c.c_ulonglong) for n in ['ReadOperationCount','WriteOperationCount','OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount']]
class EXTENDEDLIMIT(c.Structure):
    _fields_=[('BasicLimitInformation',BASICLIMIT),('IoInfo',IOCOUNTERS),('ProcessMemoryLimit',c.c_size_t),('JobMemoryLimit',c.c_size_t),('PeakProcessMemoryUsed',c.c_size_t),('PeakJobMemoryUsed',c.c_size_t)]
for name,args,ret in [
 ('CreateJobObjectW',[c.c_void_p,w.LPCWSTR],w.HANDLE),
 ('SetInformationJobObject',[w.HANDLE,c.c_int,c.c_void_p,w.DWORD],w.BOOL),
 ('CreateProcessW',[w.LPCWSTR,w.LPWSTR,c.c_void_p,c.c_void_p,w.BOOL,w.DWORD,c.c_void_p,w.LPCWSTR,c.POINTER(STARTUPINFO),c.POINTER(PROCESSINFO)],w.BOOL),
 ('AssignProcessToJobObject',[w.HANDLE,w.HANDLE],w.BOOL),
 ('ResumeThread',[w.HANDLE],w.DWORD),
 ('OpenProcess',[w.DWORD,w.BOOL,w.DWORD],w.HANDLE),
 ('IsProcessInJob',[w.HANDLE,w.HANDLE,c.POINTER(w.BOOL)],w.BOOL),
 ('WaitForSingleObject',[w.HANDLE,w.DWORD],w.DWORD),
 ('TerminateJobObject',[w.HANDLE,w.UINT],w.BOOL),
 ('TerminateProcess',[w.HANDLE,w.UINT],w.BOOL),
 ('GetExitCodeProcess',[w.HANDLE,c.POINTER(w.DWORD)],w.BOOL),
 ('CloseHandle',[w.HANDLE],w.BOOL)]:
    f=getattr(k,name);f.argtypes=args;f.restype=ret


k.GetCurrentProcess.restype=w.HANDLE
k.GetStdHandle.argtypes=[w.DWORD];k.GetStdHandle.restype=w.HANDLE
k.DuplicateHandle.argtypes=[w.HANDLE,w.HANDLE,w.HANDLE,c.POINTER(w.HANDLE),w.DWORD,w.BOOL,w.DWORD];k.DuplicateHandle.restype=w.BOOL
k.GetFileType.argtypes=[w.HANDLE];k.GetFileType.restype=w.DWORD

request=json.loads((root/sys.argv[1]).read_text(encoding='utf-8'))
manifest=json.loads((root/'allowlist.json').read_text(encoding='utf-8'))
assert sys.argv[1] in ['synthetic-request.json','help-request.json']
argv=request['argv'];assert argv==manifest[request['kind']]['argv']
for item in manifest[request['kind']]['files']:
    assert hashlib.sha256(pathlib.Path(item['path']).read_bytes()).hexdigest()==item['sha256']
assert request['cwd']==str(root)
result={'passed':False,'kind':request['kind'],'argv':argv,'cwd':str(root),'events':[],'limits':['No inference or authentication command ran.','This verifies inherited console input/output and job cleanup for these exact commands only.','Interactive Codex startup and live hub callbacks remain untested.']}
job=None;pi=PROCESSINFO();child_handle=None;assigned=False;dups=[];start=time.monotonic()
def check(ok,action):
    if not ok:raise c.WinError(c.get_last_error())
    result['events'].append({'action':action,'elapsedSeconds':round(time.monotonic()-start,4)})
try:
    job=k.CreateJobObjectW(None,None);check(job,'Create job')
    limits=EXTENDEDLIMIT();limits.BasicLimitInformation.LimitFlags=0x2000
    check(k.SetInformationJobObject(job,9,c.byref(limits),c.sizeof(limits)),'Set kill-on-close')
    si=STARTUPINFO();si.cb=c.sizeof(si);si.dwFlags=0x100
    process=k.GetCurrentProcess()
    result['stdio']=[]
    for field,code in [('hStdInput',-10),('hStdOutput',-11),('hStdError',-12)]:
        handle=k.GetStdHandle(code & 0xffffffff)
        if not handle or handle==c.c_void_p(-1).value:raise RuntimeError('Invalid '+field)
        kind=k.GetFileType(handle)
        if not kind:raise RuntimeError('Unknown handle type '+field)
        dup=w.HANDLE();check(k.DuplicateHandle(process,handle,process,c.byref(dup),0,True,2),'Duplicate '+field)
        dups.append(dup.value);setattr(si,field,dup.value)
        result['stdio'].append({'name':field,'sourceHandle':int(handle),'inheritedHandle':int(dup.value),'fileType':kind})
    cmd=c.create_unicode_buffer(subprocess.list2cmdline(argv))
    check(k.CreateProcessW(argv[0],cmd,None,None,True,0x4,None,str(root),c.byref(si),c.byref(pi)),'Create suspended child with inherited stdio; no CREATE_NO_WINDOW')
    check(k.AssignProcessToJobObject(job,pi.hProcess),'Assign before resume');assigned=True
    result['parentPid']=pi.dwProcessId
    if k.ResumeThread(pi.hThread)==0xffffffff:raise c.WinError(c.get_last_error())
    if request['kind']=='help':
        wait=k.WaitForSingleObject(pi.hProcess,15000);assert wait==0
        code=w.DWORD();check(k.GetExitCodeProcess(pi.hProcess,c.byref(code)),'Read help exit')
        result['exitCode']=code.value;assert code.value==0
    else:
        deadline=time.monotonic()+15
        while not (root/'child-ready.json').exists():
            if time.monotonic()>deadline:raise RuntimeError('Synthetic input/child readiness timeout')
            time.sleep(.05)
        parent=json.loads((root/'parent-ready.json').read_text());child=json.loads((root/'child-ready.json').read_text())
        assert parent['input']=='agentmux-console-handshake' and parent['pid']==pi.dwProcessId and parent['childPid']==child['pid'] and child['parentPid']==pi.dwProcessId
        result['parent']=parent;result['child']=child
        child_handle=k.OpenProcess(0x100000|0x1000,False,child['pid']);check(child_handle,'Open exact child')
        for label,handle in [('parent',pi.hProcess),('child',child_handle)]:
            member=w.BOOL();check(k.IsProcessInJob(handle,job,c.byref(member)),label+' job membership')
            assert member.value and k.WaitForSingleObject(handle,0)==258
        (root/'supervisor-ready.json').write_text(json.dumps({'parentPid':pi.dwProcessId,'childPid':child['pid']}))
        deadline=time.monotonic()+15
        while not (root/'cancel.request').exists():
            if time.monotonic()>deadline:raise RuntimeError('Cancellation timeout')
            time.sleep(.05)
        check(k.TerminateJobObject(job,93),'Cancel this fixture job')
        for label,handle in [('parent',pi.hProcess),('child',child_handle)]:
            wait=k.WaitForSingleObject(handle,5000);assert wait==0
            code=w.DWORD();check(k.GetExitCodeProcess(handle,c.byref(code)),label+' exit')
            assert code.value==93;result[label+'After']={'waitResult':wait,'exitCode':code.value}
    result['passed']=True
except Exception as exc:
    result['error']={'type':type(exc).__name__,'message':str(exc),'winerror':getattr(exc,'winerror',None)}
finally:
    if assigned:k.TerminateJobObject(job,94)
    elif pi.hProcess:k.TerminateProcess(pi.hProcess,94)
    if pi.hProcess:k.WaitForSingleObject(pi.hProcess,5000)
    if child_handle:k.WaitForSingleObject(child_handle,5000)
    for handle in dups+[child_handle,pi.hThread,pi.hProcess,job]:
        if handle:k.CloseHandle(handle)
    result['elapsedSeconds']=round(time.monotonic()-start,4)
    (root/(request['kind']+'-result.json')).write_text(json.dumps(result,indent=2)+'\n')
raise SystemExit(0 if result['passed'] else 1)
