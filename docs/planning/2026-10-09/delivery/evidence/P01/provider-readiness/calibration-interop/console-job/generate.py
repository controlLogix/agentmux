import pathlib,json,hashlib,sys
root=pathlib.Path(sys.argv[1]).resolve()
old=pathlib.Path(r'C:\Users\RyanHelms\AppData\Local\Temp\agentmux-wsl-job-351571061b144f89a2540eb8ba8258df\supervisor.py').read_text(encoding='utf-8')
api=old[old.index("k=c.WinDLL"):old.index('request_path=')]
api+='''
k.GetCurrentProcess.restype=w.HANDLE
k.GetStdHandle.argtypes=[w.DWORD];k.GetStdHandle.restype=w.HANDLE
k.DuplicateHandle.argtypes=[w.HANDLE,w.HANDLE,w.HANDLE,c.POINTER(w.HANDLE),w.DWORD,w.BOOL,w.DWORD];k.DuplicateHandle.restype=w.BOOL
k.GetFileType.argtypes=[w.HANDLE];k.GetFileType.restype=w.DWORD
'''
body=r'''
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
'''
(root/'supervisor.py').write_text('import ctypes as c\nfrom ctypes import wintypes as w\nimport hashlib,json,os,pathlib,subprocess,sys,time\nroot=pathlib.Path(__file__).resolve().parent\n'+api+body,encoding='utf-8')
(root/'synthetic.py').write_text('''import json,os,pathlib,subprocess,sys,time
root=pathlib.Path(__file__).resolve().parent
if sys.argv[1]=='parent':
    print('CONSOLE_READY',flush=True)
    line=input().strip()
    print('CONSOLE_ACK:'+line,flush=True)
    child=subprocess.Popen([sys.executable,str(__file__),'child'],cwd=root)
    (root/'parent-ready.json').write_text(json.dumps({'pid':os.getpid(),'childPid':child.pid,'input':line}))
else:
    (root/'child-ready.json').write_text(json.dumps({'pid':os.getpid(),'parentPid':os.getppid()}))
time.sleep(45)
''',encoding='utf-8')
node=r'C:\nvm4w\nodejs\node.exe';codex=r'C:\Users\RyanHelms\AppData\Local\nvm\v24.19.0\node_modules\@openai\codex\bin\codex.js'
manifest={}
for kind,argv in [('synthetic',[sys.executable,str(root/'synthetic.py'),'parent']),('help',[node,codex,'--no-daemon','--help'])]:
    manifest[kind]={'argv':argv,'files':[{'path':x,'sha256':hashlib.sha256(pathlib.Path(x).read_bytes()).hexdigest()} for x in argv[:2]]}
    (root/(kind+'-request.json')).write_text(json.dumps({'kind':kind,'argv':argv,'cwd':str(root)},indent=2))
(root/'allowlist.json').write_text(json.dumps(manifest,indent=2))
print(root)