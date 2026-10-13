import pathlib,json,subprocess,hashlib,sys,ctypes
P=pathlib.Path;root=P(r'C:/Users/RyanHelms/AppData/Local/Temp/agentmux original calibration checked observer mb_jlr5y');m=json.loads((root/'fixture.json').read_text());a=json.loads((root/'attempt-result.json').read_text());folder=root/'windows-supervisors/calc-worker-codex_1009';o=json.loads((folder/'observer-result.json').read_text());ready=json.loads((folder/'launch-ready.json').read_text());report=json.loads((root/'20261013-100906-calib.json').read_text())
assert a['harnessExitCode']==0 and a['sourceUnchanged'] and report['error_free'] and all(report['checks'].values())
assert o['jobUid']==ready['jobUid'] and o['parentPid']==ready['parentPid'] and o['observerPid']==ready['observerPid']
assert o['passed'] and o['afterJob']['ActiveProcesses']==0 and o['cleanup']['verified'] and isinstance(o['windowsConfigBytesUnchanged'],bool)
calc=root/'original demo repos/calc';tests=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-v'],cwd=calc,capture_output=True,text=True);assert tests.returncode==0
commands={}
for label,args in [('commit',['git','log','-1','--format=%H%n%s']),('status',['git','status','--porcelain']),('changedFiles',['git','diff','HEAD~1','--name-only'])]:
 p=subprocess.run(args,cwd=calc,capture_output=True,text=True);assert p.returncode==0;commands[label]={'argv':args,'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
assert commands['status']['stdout']=='' and commands['commit']['stdout'].splitlines()[1]=='add median'
code='''import os,pathlib,json,hashlib
base=pathlib.Path("/home/ryan/.cache/agentmux-governance/original-calib-cp4p41wo")
state=base/"state"
residue=[]
for p in pathlib.Path("/proc").iterdir():
 if not p.name.isdigit() or int(p.name)==os.getpid():continue
 try:
  env=(p/"environ").read_bytes().split(b"\\0")
  if ("AGENTMUX_HOME="+str(state)).encode() in env:residue.append(int(p.name))
 except (PermissionError,FileNotFoundError,ProcessLookupError):pass
print(json.dumps({"fixtureEnvironmentProcessPids":residue,"tokenFilesRemaining":len(list(state.rglob("token")))+len(list(state.rglob("operator.token"))),"hubPidFileExists":(state/"hub/hub.pid").exists()}))
'''
p=subprocess.run(['wsl','-d','Ubuntu-26.04','--','python3','-'],input=code,capture_output=True,text=True);assert p.returncode==0,p.stderr;linux=json.loads(p.stdout)
k=ctypes.WinDLL('kernel32',use_last_error=True);k.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong];k.OpenProcess.restype=ctypes.c_void_p;k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_ulong];k.CloseHandle.argtypes=[ctypes.c_void_p]
pids=[]
for pid in [o['parentPid'],o['supervisorPid'],o['observerPid']]:
 h=k.OpenProcess(0x100000|0x1000,False,pid)
 entry={'pid':pid,'handleOpened':bool(h),'errorIfAbsent':ctypes.get_last_error() if not h else None,'waitState':k.WaitForSingleObject(h,0) if h else None}
 if h:k.CloseHandle(h)
 pids.append(entry)
compact={key:value for key,value in report.items() if key!='pane_tails'}
(root/'original-report-without-pane-tails.json').write_text(json.dumps(compact,indent=2)+'\n')
result={'scope':'One original Codex calibration and exact fixture cleanup; not P01 phase acceptance.','sourceBranchCommit':'2aed3e7206e81cf119562647879c90a29457b08a','originalReportSha256':hashlib.sha256((root/'20261013-100906-calib.json').read_bytes()).hexdigest(),'checks':report['checks'],'errorFree':report['error_free'],'taskId':report['work'][0]['id'],'actualCallbackActor':report['work'][0]['claimed_by'],'tests':{'argv':[sys.executable,'-m','unittest','discover','-s','tests','-v'],'exitCode':tests.returncode,'stdout':tests.stdout,'stderr':tests.stderr},'git':commands,'observer':{'jobUid':o['jobUid'],'passed':o['passed'],'afterJobActiveProcesses':o['afterJob']['ActiveProcesses'],'cleanupVerified':o['cleanup']['verified'],'windowsConfigBytesUnchanged':o['windowsConfigBytesUnchanged'],'terminalReason':o['terminalReason']},'knownWindowsProcesses':pids,'linuxCleanup':linux,'source67Unchanged':a['sourceUnchanged'],'launchResultExists':(folder/'launch-result.json').exists(),'limitations':['Windows config bytes changed; this does not qualify unchanged-profile or unrelated-settings claims.','The observer proves exact Windows job cleanup when console teardown prevented the supervisor result.','No full pane reasoning, auth contents, profile files, or token files are included in this compact proof.']}
(root/'independent-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))