import ctypes as c
from ctypes import wintypes as w
import hashlib,json,os,pathlib,subprocess,sys,time,tomllib,uuid
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


class BASICACCOUNTING(c.Structure):
    _fields_=[('TotalUserTime',c.c_longlong),('TotalKernelTime',c.c_longlong),('ThisPeriodTotalUserTime',c.c_longlong),('ThisPeriodTotalKernelTime',c.c_longlong),('TotalPageFaultCount',w.DWORD),('TotalProcesses',w.DWORD),('ActiveProcesses',w.DWORD),('TotalTerminatedProcesses',w.DWORD)]
k.QueryInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.c_void_p];k.QueryInformationJobObject.restype=w.BOOL

NODE=pathlib.Path(r'C:\nvm4w\nodejs\node.exe')
CODEX=pathlib.Path(r'C:\nvm4w\nodejs\node_modules\@openai\codex\bin\codex.js')
CONFIG=pathlib.Path(os.environ.get('CODEX_HOME',r'C:\Users\RyanHelms\.codex'))/'config.toml'
CALLBACK_KEYS=['AGENTMUX_WINDOWS_CALLBACK','AGENTMUX_AGENT','AGENTMUX_HUB_URL','AGENTMUX_WSL_DISTRO','AGENTMUX_WSL_BIN','AGENTMUX_WSL_CWD','AGENTMUX_SOCKET','AGENTMUX_HOME','AGENTMUX_HUB_TOKEN_FILE','TMUX_TMPDIR']
def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def toml_string(value):return json.dumps(value,ensure_ascii=False)
def prepare(request_path):
    req=json.loads(request_path.read_text(encoding='utf-8'))
    assert request_path.parent==root
    assert req['originalArgs']==['--no-daemon','--dangerously-bypass-approvals-and-sandbox']
    cwd=pathlib.Path(req['cwd']).resolve();assert cwd.is_dir()
    helper=pathlib.Path(req['helperDirectory']).resolve();assert (helper/'agentmux.cmd').is_file()
    env=req['callbackEnvironment'];assert set(CALLBACK_KEYS).issubset(env) and set(env).issubset(set(CALLBACK_KEYS)|{'AGENTMUX_REPO','GIT_CONFIG_COUNT','GIT_CONFIG_KEY_0','GIT_CONFIG_VALUE_0','GIT_CONFIG_KEY_1','GIT_CONFIG_VALUE_1'})
    assert all(isinstance(v,str) and '\0' not in v for v in env.values())
    assert env['AGENTMUX_WSL_CWD'].startswith('/') and env['AGENTMUX_WSL_BIN'].startswith('/')
    assert 'AGENTMUX_HUB_TOKEN' not in env
    # Read the parsed MCP names only; do not save or print the config document.
    config=tomllib.loads(CONFIG.read_text(encoding='utf-8'))
    names=set(config.get('mcp_servers',{}))
    names.update(req.get('additionalMcpNames',[]))
    del config
    argv=[str(NODE),str(CODEX),*req['originalArgs']]
    overrides=[]
    for name in sorted(names):overrides.append('mcp_servers.'+toml_string(name)+'.enabled=false')
    overrides += ['features.'+name+'=false' for name in ['hooks','codex_hooks','plugin_hooks','plugins','apps','connectors']]
    sqlite=root/'sqlite';logs=root/'logs';sqlite.mkdir(exist_ok=True);logs.mkdir(exist_ok=True)
    overrides += ['notify=[]','history.persistence="none"','sqlite_home='+toml_string(str(sqlite)),'log_dir='+toml_string(str(logs))]
    instructions='Work only in this private calibration repository: '+str(cwd)+'. Use only its files and the assigned Agentmux hub callbacks through agentmux.cmd. Do not inspect or modify other repositories, credentials, client settings or user files. Preserve the original calibration task and return its requested evidence.'
    overrides.append('developer_instructions='+toml_string(instructions))
    # Include PATH explicitly so the provider tool environment retains the private helper.
    windows_path=str(helper)+os.pathsep+os.environ.get('PATH','')
    terminal=req.get('terminalEnvironment',{})
    assert isinstance(terminal,dict) and set(terminal).issubset({'TERM','COLORTERM'}) and all(isinstance(value,str) and value and '\0' not in value for value in terminal.values())
    if terminal:assert terminal.get('TERM') and terminal['TERM']!='dumb'
    toolenv={**env,**terminal,'PATH':windows_path}
    overrides.append('shell_environment_policy.set={'+','.join(toml_string(key)+'='+toml_string(value) for key,value in toolenv.items())+'}')
    for value in overrides:argv+=['-c',value]
    out={'schemaVersion':1,'jobUid':str(uuid.uuid4()),'preparedOnly':True,'originalArgv':[str(NODE),str(CODEX),*req['originalArgs']],'argv':argv,'cwd':str(cwd),'helperDirectory':str(helper),'callbackEnvironment':env,'PATH':windows_path,'terminalEnvironment':terminal,'mcpNames':sorted(names),'files':[{'path':str(path),'sha256':sha(path)} for path in [NODE,CODEX,pathlib.Path(r'C:\nvm4w\nodejs\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe')]],'maxSeconds':840,'limitations':['Uses the existing Windows auth/config in place; no credential or config copies.','Rollouts and ordinary auth refresh may still write to the Windows-owned profile.','Per-process disable flags require actual runtime verification.','No real Codex startup or inference has been executed by preparation.','Installed host/user/project instructions remain effective unless separately characterized.']}
    (root/'prepared-request.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    return out

def launch(req):
    # This function is prepared for root review only. No call occurs in --prepare mode.
    assert req['maxSeconds']==840 and req['originalArgv']==[str(NODE),str(CODEX),'--no-daemon','--dangerously-bypass-approvals-and-sandbox'] and req['argv'][:4]==req['originalArgv']
    assert not (root/'cancel.request').exists() and not (root/'launch-ready.json').exists() and not (root/'launch-result.json').exists()
    for item in req['files']:assert sha(item['path'])==item['sha256']
    assert pathlib.Path(req['cwd']).is_dir()
    result={'jobUid':req['jobUid'],'originalArgv':req['originalArgv'],'argv':req['argv'],'passed':False,'events':[],'terminalReason':None}
    job=None;pi=PROCESSINFO();assigned=False;dups=[];start=time.monotonic()
    config_before=CONFIG.read_bytes()
    def check(ok,action):
        if not ok:raise c.WinError(c.get_last_error())
        result['events'].append({'action':action,'elapsedSeconds':round(time.monotonic()-start,4)})
    try:
        job=k.CreateJobObjectW(None,None);check(job,'Create private job')
        limits=EXTENDEDLIMIT();limits.BasicLimitInformation.LimitFlags=0x2000
        check(k.SetInformationJobObject(job,9,c.byref(limits),c.sizeof(limits)),'Set kill-on-close')
        si=STARTUPINFO();si.cb=c.sizeof(si);si.dwFlags=0x100
        process=k.GetCurrentProcess()
        for field,code in [('hStdInput',-10),('hStdOutput',-11),('hStdError',-12)]:
            handle=k.GetStdHandle(code & 0xffffffff)
            assert handle and handle!=c.c_void_p(-1).value and k.GetFileType(handle)
            dup=w.HANDLE();check(k.DuplicateHandle(process,handle,process,c.byref(dup),0,True,2),'Duplicate '+field)
            dups.append(dup.value);setattr(si,field,dup.value)
        env=dict(os.environ);env.update(req['callbackEnvironment']);env.update(req.get('terminalEnvironment',{}));env['PATH']=req['PATH']
        # Do not override CODEX_HOME: retain any existing Windows-owned profile setting.
        assert 'AGENTMUX_HUB_TOKEN' not in env
        result['usesInheritedWindowsCodexHome']=bool(env.get('CODEX_HOME'))
        envblock=c.create_unicode_buffer('\0'.join(key+'='+value for key,value in sorted(env.items(),key=lambda item:item[0].upper()))+'\0\0')
        cmd=c.create_unicode_buffer(subprocess.list2cmdline(req['argv']))
        check(k.CreateProcessW(req['argv'][0],cmd,None,None,True,0x4|0x400,c.cast(envblock,c.c_void_p),req['cwd'],c.byref(si),c.byref(pi)),'Create suspended Codex with inherited console')
        check(k.AssignProcessToJobObject(job,pi.hProcess),'Assign before resume');assigned=True
        result['parentPid']=pi.dwProcessId;result['handles']={'job':int(job),'parent':int(pi.hProcess),'thread':int(pi.hThread)}
        if k.ResumeThread(pi.hThread)==0xffffffff:raise c.WinError(c.get_last_error())
        (root/'launch-ready.json').write_text(json.dumps({'jobUid':req['jobUid'],'parentPid':pi.dwProcessId}))
        while True:
            wait=k.WaitForSingleObject(pi.hProcess,100)
            if wait==0:result['terminalReason']='natural-exit';break
            assert wait==258
            if (root/'cancel.request').exists():result['terminalReason']='fixture-cancellation';break
            if time.monotonic()-start>=840:result['terminalReason']='14-minute-bound';break
        check(k.TerminateJobObject(job,103),'Stop any remaining processes in this exact job')
        assert k.WaitForSingleObject(pi.hProcess,5000)==0
        code=w.DWORD();check(k.GetExitCodeProcess(pi.hProcess,c.byref(code)),'Read exact parent exit');result['exitCode']=code.value
        deadline=time.monotonic()+5
        while True:
            accounting=BASICACCOUNTING();check(k.QueryInformationJobObject(job,1,c.byref(accounting),c.sizeof(accounting),None),'Read job process accounting')
            if accounting.ActiveProcesses==0:break
            if time.monotonic()>deadline:raise RuntimeError('Job still contains active processes')
            time.sleep(.05)
        result['jobAccounting']={name:int(getattr(accounting,name)) for name in ['TotalProcesses','ActiveProcesses','TotalTerminatedProcesses']}
        result['passed']=True
    except Exception as exc:result['error']={'type':type(exc).__name__,'message':str(exc),'winerror':getattr(exc,'winerror',None)}
    finally:
        if assigned:k.TerminateJobObject(job,104)
        elif pi.hProcess:k.TerminateProcess(pi.hProcess,104)
        if pi.hProcess:k.WaitForSingleObject(pi.hProcess,5000)
        for handle in dups+[pi.hThread,pi.hProcess,job]:
            if handle:k.CloseHandle(handle)
        result['windowsConfigBytesUnchanged']=CONFIG.exists() and CONFIG.read_bytes()==config_before
        del config_before
        result['elapsedSeconds']=round(time.monotonic()-start,4)
        (root/'launch-result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
if __name__=='__main__':
    if sys.argv[1:] and sys.argv[1]=='--prepare':
        prepared=prepare(pathlib.Path(sys.argv[2]).resolve());print(json.dumps({'preparedOnly':True,'jobUid':prepared['jobUid'],'mcpNames':prepared['mcpNames'],'overrideCount':(len(prepared['argv'])-4)//2}));raise SystemExit(0)
    # A separate explicit --run entry point prevents preparation from starting a client.
    if sys.argv[1:]==['--run']:
        result=launch(json.loads((root/'prepared-request.json').read_text()));raise SystemExit(0 if result['passed'] else 1)
    raise SystemExit('Use --prepare <fixture request> or the separately authorized --run.')
