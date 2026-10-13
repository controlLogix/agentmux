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
def prepare_codex(request_path):
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
    assert all(name and all(char in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for char in name) for name in names), 'MCP names must support the installed CLI dotted-key syntax'
    for name in sorted(names):overrides.append('mcp_servers.'+name+'.enabled=false')
    overrides += ['features.'+name+'=false' for name in ['hooks','codex_hooks','plugin_hooks','plugins','apps','connectors']]
    sqlite=root/'sqlite';logs=root/'logs';sqlite.mkdir(exist_ok=True);logs.mkdir(exist_ok=True)
    overrides += ['notify=[]','history.persistence="none"','sqlite_home='+toml_string(str(sqlite)),'log_dir='+toml_string(str(logs))]
    instructions='Work only in this private calibration repository: '+str(cwd)+'. Use only its files and the assigned Agentmux hub callbacks through agentmux.cmd. Do not inspect or modify other repositories, credentials, client settings or user files. Preserve the original calibration task and return its requested evidence.'
    overrides.append('developer_instructions='+toml_string(instructions))
    # Include PATH explicitly so the provider tool environment retains the private helper.
    windows_path=str(helper)+os.pathsep+os.environ.get('PATH','')
    toolenv={**env,'PATH':windows_path}
    overrides.append('shell_environment_policy.set={'+','.join(toml_string(key)+'='+toml_string(value) for key,value in toolenv.items())+'}')
    for value in overrides:argv+=['-c',value]
    out={'schemaVersion':1,'jobUid':str(uuid.uuid4()),'preparedOnly':True,'originalArgv':[str(NODE),str(CODEX),*req['originalArgs']],'argv':argv,'cwd':str(cwd),'helperDirectory':str(helper),'callbackEnvironment':env,'PATH':windows_path,'mcpNames':sorted(names),'files':[{'path':str(path),'sha256':sha(path)} for path in [NODE,CODEX,pathlib.Path(r'C:\nvm4w\nodejs\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe')]],'maxSeconds':2700,'limitations':['Uses the existing Windows auth/config in place; no credential or config copies.','Rollouts and ordinary auth refresh may still write to the Windows-owned profile.','Per-process disable flags require actual runtime verification.','No real Codex startup or inference has been executed by preparation.','Installed host/user/project instructions remain effective unless separately characterized.']}
    (root/'prepared-request.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    return out

def launch(req, synthetic=False):
    # This function is prepared for root review only. No call occurs in --prepare mode.
    global CONFIG
    CONFIG=pathlib.Path(req['configPath'])
    assert req['maxSeconds']==2700
    if not synthetic:assert req['provider'] in ['codex','claude','grok'] and req['argv'][:len(req['originalArgv'])]==req['originalArgv']
    else:assert req['argv']==[sys.executable,str(root/'synthetic.py'),'parent']
    assert not any((root/name).exists() for name in ['cancel.request','launch-ready.json','launch-result.json','observer-ready.json','observer-result.json','observer-input.json'])
    for item in req['files']:assert sha(item['path'])==item['sha256']
    assert pathlib.Path(req['cwd']).is_dir()
    result={'jobUid':req['jobUid'],'originalArgv':req['originalArgv'],'argv':req['argv'],'passed':False,'events':[],'terminalReason':None}
    job=None;pi=PROCESSINFO();assigned=False;dups=[];observer=None;start=time.monotonic()
    config_before=CONFIG.read_bytes()
    def check(ok,action):
        if not ok:raise c.WinError(c.get_last_error())
        result['events'].append({'action':action,'elapsedSeconds':round(time.monotonic()-start,4)})
    try:
        job_name='Local\\agentmux-p01-'+req['jobUid']
        c.set_last_error(0)
        job=k.CreateJobObjectW(None,job_name)
        existing=c.get_last_error()==183
        check(job,'Create unique named fixture job')
        if existing:raise RuntimeError('Named job already exists; do not reuse it')
        limits=EXTENDEDLIMIT();limits.BasicLimitInformation.LimitFlags=0x2000
        check(k.SetInformationJobObject(job,9,c.byref(limits),c.sizeof(limits)),'Set kill-on-close')
        si=STARTUPINFO();si.cb=c.sizeof(si);si.dwFlags=0x100
        process=k.GetCurrentProcess()
        for field,code in [('hStdInput',-10),('hStdOutput',-11),('hStdError',-12)]:
            handle=k.GetStdHandle(code & 0xffffffff)
            assert handle and handle!=c.c_void_p(-1).value and k.GetFileType(handle)
            dup=w.HANDLE();check(k.DuplicateHandle(process,handle,process,c.byref(dup),0,True,2),'Duplicate '+field)
            dups.append(dup.value);setattr(si,field,dup.value)
        env={key:value for key,value in os.environ.items() if not key.startswith('ORCA_') and key not in ['GROK_CONFIG','GROK_CONFIG_PATH']};env.update(req['callbackEnvironment']);env.update(req.get('processEnvironment',{}));env['PATH']=req['PATH']
        # Do not override CODEX_HOME: retain any existing Windows-owned profile setting.
        assert 'AGENTMUX_HUB_TOKEN' not in env
        result['usesInheritedWindowsCodexHome']=bool(env.get('CODEX_HOME'))
        if not synthetic:
            import importlib.util
            spec=importlib.util.spec_from_file_location('fixture_preflight',root/'launch-preflight.py');preflight=importlib.util.module_from_spec(spec);spec.loader.exec_module(preflight)
            result['launchPreflight']=preflight.verify_launch(req,root,env)
        envblock=c.create_unicode_buffer('\0'.join(key+'='+value for key,value in sorted(env.items(),key=lambda item:item[0].upper()))+'\0\0')
        cmd=c.create_unicode_buffer(subprocess.list2cmdline(req['argv']))
        check(k.CreateProcessW(req['argv'][0],cmd,None,None,True,0x4|0x400,c.cast(envblock,c.c_void_p),req['cwd'],c.byref(si),c.byref(pi)),'Create suspended Codex with inherited console')
        check(k.AssignProcessToJobObject(job,pi.hProcess),'Assign before resume');assigned=True
        result['parentPid']=pi.dwProcessId;result['handles']={'job':int(job),'parent':int(pi.hProcess),'thread':int(pi.hThread)}
        observer_request={'jobUid':req['jobUid'],'jobName':job_name,'parentPid':pi.dwProcessId,'supervisorPid':os.getpid(),'configPath':str(CONFIG),'maxSeconds':2700,'observerSha256':sha(root/'observer.py'),'apiSha256':sha(root/'observer_api.py')}
        (root/'observer-input.json').write_text(json.dumps(observer_request,indent=2)+'\n')
        with (root/'observer.stderr.log').open('wb') as observer_log:
            observer=subprocess.Popen([sys.executable,str(root/'observer.py'),'observer-input.json'],cwd=root,stdin=subprocess.DEVNULL,stdout=observer_log,stderr=observer_log,creationflags=0x08000000,close_fds=True)
        deadline=time.monotonic()+5
        while not (root/'observer-ready.json').exists():
            if observer.poll() is not None:raise RuntimeError('Observer exited before readiness')
            if time.monotonic()>deadline:raise RuntimeError('Observer readiness exceeded five seconds')
            time.sleep(.05)
        observer_ready=json.loads((root/'observer-ready.json').read_text())
        assert observer_ready['jobUid']==req['jobUid'] and observer_ready['parentPid']==pi.dwProcessId and observer_ready['observerPid']==observer.pid and observer_ready['parentInJob'] is True and observer_ready['parentAlive'] is True and observer_ready['observerInJob'] is False and observer_ready['observerConsoleWindow']==0
        if observer.poll() is not None:raise RuntimeError('Observer died before parent resume')
        result['observerPid']=observer.pid;result['jobName']=job_name
        check(True,'Independent observer holds exact job and parent before resume')
        if k.ResumeThread(pi.hThread)==0xffffffff:raise c.WinError(c.get_last_error())
        (root/'launch-ready.json').write_text(json.dumps({'jobUid':req['jobUid'],'parentPid':pi.dwProcessId,'jobName':job_name,'observerPid':observer.pid}))
        while True:
            if observer.poll() is not None and k.WaitForSingleObject(pi.hProcess,0)==258:raise RuntimeError('Independent observer exited unexpectedly while parent was live')
            wait=k.WaitForSingleObject(pi.hProcess,100)
            if wait==0:result['terminalReason']='natural-exit';break
            assert wait==258
            if (root/'cancel.request').exists():result['terminalReason']='fixture-cancellation';break
            if time.monotonic()-start>=2700:result['terminalReason']='45-minute-bound';break
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
        cleanup={'verified':False}
        if assigned:cleanup['terminateJobOk']=bool(k.TerminateJobObject(job,104))
        elif pi.hProcess:cleanup['terminateUnassignedProcessOk']=bool(k.TerminateProcess(pi.hProcess,104))
        if pi.hProcess:cleanup['parentWait']=k.WaitForSingleObject(pi.hProcess,3000)
        if assigned:
            cleanup_deadline=time.monotonic()+3
            while True:
                a=BASICACCOUNTING()
                if not k.QueryInformationJobObject(job,1,c.byref(a),c.sizeof(a),None):
                    cleanup['accountingError']=c.get_last_error();break
                cleanup['activeProcesses']=int(a.ActiveProcesses)
                if a.ActiveProcesses==0 or time.monotonic()>cleanup_deadline:break
                time.sleep(.05)
            cleanup['verified']=cleanup.get('terminateJobOk') is True and cleanup.get('parentWait')==0 and cleanup.get('activeProcesses')==0
        elif pi.hProcess:cleanup['verified']=cleanup.get('terminateUnassignedProcessOk') is True and cleanup.get('parentWait')==0
        else:cleanup['verified']=True
        if observer is not None:
            try:cleanup['observerExit']=observer.wait(timeout=3)
            except subprocess.TimeoutExpired:cleanup['observerExit']=None
            observer_record=root/'observer-result.json'
            if observer_record.exists():
                observer_result=json.loads(observer_record.read_text())
                observer_ok=observer_result.get('jobUid')==req['jobUid'] and observer_result.get('passed') is True and observer_result.get('afterJob',{}).get('ActiveProcesses')==0 and observer_result.get('cleanup',{}).get('verified') is True and isinstance(observer_result.get('windowsConfigBytesUnchanged'),bool)
                cleanup['observerEvidenceVerified']=observer_ok
            else:cleanup['observerEvidenceVerified']=False
            if not cleanup['observerEvidenceVerified']:result['passed']=False
        result['cleanup']=cleanup
        if not cleanup['verified']:result['passed']=False
        for handle in dups+[pi.hThread,pi.hProcess,job]:
            if handle:k.CloseHandle(handle)
        result['windowsConfigBytesUnchanged']=CONFIG.exists() and CONFIG.read_bytes()==config_before
        del config_before
        result['elapsedSeconds']=round(time.monotonic()-start,4)
        (root/'launch-result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

PROVIDERS={
 'claude':pathlib.Path(r'C:/nvm4w/nodejs/node_modules/@anthropic-ai/claude-code/bin/claude.exe'),
 'grok':pathlib.Path(r'C:/Users/RyanHelms/.grok/bin/grok.exe')}
CONFIGS={'codex':CONFIG,'claude':pathlib.Path(r'C:/Users/RyanHelms/.claude.json'),'grok':pathlib.Path(r'C:/Users/RyanHelms/.grok/config.toml')}
def prepare(request_path):
 req=json.loads(request_path.read_text(encoding='utf-8'));provider=req.get('provider','codex')
 assert provider in CONFIGS
 if provider=='codex':
  out=prepare_codex(request_path);out.update(provider='codex',configPath=str(CONFIGS['codex']))
 else:
  assert request_path.parent==root
  original=req['originalArgs']
  if provider=='grok':assert original==['--permission-mode','bypassPermissions']
  else:
   assert len(original)==4 and original[0]=='--settings' and original[2:]==['--setting-sources','']
   assert original[1].startswith('/home/ryan/.cache/agentmux-governance/')
  cwd=pathlib.Path(req['cwd']).resolve();helper=pathlib.Path(req['helperDirectory']).resolve()
  assert cwd.is_dir() and (helper/'agentmux.cmd').is_file()
  env=req['callbackEnvironment'];assert set(CALLBACK_KEYS).issubset(env) and set(env).issubset(set(CALLBACK_KEYS)|{'AGENTMUX_REPO','GIT_CONFIG_COUNT','GIT_CONFIG_KEY_0','GIT_CONFIG_VALUE_0','GIT_CONFIG_KEY_1','GIT_CONFIG_VALUE_1'})
  assert all(isinstance(value,str) and '\0' not in value for value in env.values())
  assert 'AGENTMUX_HUB_TOKEN' not in env and env['AGENTMUX_WSL_CWD'].startswith('/') and env['AGENTMUX_WSL_BIN'].startswith('/')
  executable=PROVIDERS[provider];assert executable.is_file()
  process_env={};windows_path=str(helper)+os.pathsep+os.environ.get('PATH','')
  if provider=='claude':
   # Recreate the original unrestricted generated settings, without profile copies.
   settings=root/'claude-process-settings.json'
   generated=req['generatedClaudeSettings'];assert generated=={'permissions':{'defaultMode':'bypassPermissions','allow':[],'deny':[]}}, 'Unsupported original generated Claude permission/gate settings'
   assert len(req['generatedClaudeSettingsSha256'])==64
   settings.write_text(json.dumps(generated)+'\n')
   mapped=['--settings',str(settings),'--setting-sources','']
   extra=['--safe-mode','--strict-mcp-config','--mcp-config','{"mcpServers":{}}','--no-chrome']
   process_env['CLAUDE_CONFIG_DIR']=r'C:/Users/RyanHelms/.claude'
  else:
   mapped=original;extra=[]
   process_env.update({key:'0' for key in ['GROK_CLAUDE_HOOKS_ENABLED','GROK_CURSOR_HOOKS_ENABLED','GROK_CLAUDE_MCPS_ENABLED','GROK_CURSOR_MCPS_ENABLED','GROK_MANAGED_MCPS_ENABLED','GROK_MANAGED_MCP_GATEWAY_TOOLS_ENABLED']})
   process_env['GROK_HOME']=r'C:/Users/RyanHelms/.grok'
  argv=[str(executable),*mapped,*extra]
  out={'schemaVersion':1,'provider':provider,'configPath':str(CONFIGS[provider]),'jobUid':str(uuid.uuid4()),'preparedOnly':True,'sourceOriginalArgs':original,'originalArgv':[str(executable),*mapped],'argv':argv,'cwd':str(cwd),'helperDirectory':str(helper),'callbackEnvironment':env,'processEnvironment':process_env,'PATH':windows_path,'files':[{'path':str(executable),'sha256':sha(executable)}],'maxSeconds':2700,'limitations':['Canonical Windows auth/config remains in place without copies.','Grok native hook side effects require the independently reviewed empty ORCA environment and pinned early-return hook.','CLI help documents controls; actual native provider startup remains unqualified.']}
 if provider=='claude':
  out['generatedClaudeSettings']=req['generatedClaudeSettings'];out['generatedClaudeSettingsSha256']=req['generatedClaudeSettingsSha256']
  out['files'].append({'path':str(root/'claude-process-settings.json'),'sha256':sha(root/'claude-process-settings.json')})
 if provider=='grok':
  out['grokReadinessSha256']=req['grokReadinessSha256'];assert sha(root/'grok-readiness-review.json')==out['grokReadinessSha256']
  out['files'].append({'path':str(root/'grok-readiness-review.json'),'sha256':out['grokReadinessSha256']})
 out['files'].append({'path':str(root/'launch-preflight.py'),'sha256':sha(root/'launch-preflight.py')})
 (root/'prepared-request.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
 return out

if __name__=='__main__':
    if sys.argv[1:] and sys.argv[1]=='--prepare':
        prepared=prepare(pathlib.Path(sys.argv[2]).resolve());print(json.dumps({'preparedOnly':True,'jobUid':prepared['jobUid'],'provider':prepared['provider'],'preparedOnly':True}));raise SystemExit(0)
    # A separate explicit --run entry point prevents preparation from starting a client.
    if sys.argv[1:]==['--run']:
        result=launch(json.loads((root/'prepared-request.json').read_text()));raise SystemExit(0 if result['passed'] else 1)
    raise SystemExit('Use --prepare <fixture request> or the separately authorized --run.')
