import pathlib,json,hashlib,subprocess,ctypes
P=pathlib.Path;root=P(r'C:/Users/RyanHelms/AppData/Local/Temp/agentmux original TEAM preparation _fwm3fqa');a=json.loads((root/'attempt-result.json').read_text());m=json.loads((root/'fixture.json').read_text());k=ctypes.WinDLL('kernel32',use_last_error=True);k.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong];k.OpenProcess.restype=ctypes.c_void_p;k.CloseHandle.argtypes=[ctypes.c_void_p];k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_ulong]
actors=[]
for folder in (root/'windows-supervisors').iterdir():
 launch=json.loads((folder/'launch-result.json').read_text()) if (folder/'launch-result.json').exists() else None
 observed=json.loads((folder/'observer-result.json').read_text()) if (folder/'observer-result.json').exists() else None
 ready=json.loads((folder/'launch-ready.json').read_text()) if (folder/'launch-ready.json').exists() else None
 entry={'actor':folder.name,'launchResultExists':launch is not None,'observerResultExists':observed is not None,'launchPassed':launch['passed'] if launch else None,'error':launch.get('error') if launch else None}
 if observed:
  assert ready['jobUid']==observed['jobUid'] and ready['parentPid']==observed['parentPid'] and ready['observerPid']==observed['observerPid']
  assert observed['passed'] and observed['cleanup']['verified'] and observed['afterJob']['ActiveProcesses']==0 and isinstance(observed['windowsConfigBytesUnchanged'],bool)
  entry['observer']={key:observed[key] for key in ['jobUid','parentPid','supervisorPid','observerPid','passed','terminalReason','afterJob','cleanup','windowsConfigBytesUnchanged']};entry['knownPids']=[]
  for pid in [observed['parentPid'],observed['supervisorPid'],observed['observerPid']]:
   h=k.OpenProcess(0x100000|0x1000,False,pid);entry['knownPids'].append({'pid':pid,'handleOpened':bool(h),'errorIfAbsent':ctypes.get_last_error() if not h else None,'waitState':k.WaitForSingleObject(h,0) if h else None})
   if h:k.CloseHandle(h)
 else:assert launch and launch['error']['message']=='Native Grok hook source set changed' and launch['cleanup']['verified']
 actors.append(entry)
code='''import pathlib,json,os
base=pathlib.Path('/home/ryan/.cache/agentmux-governance/original-team-lqm0dwqz');state=base/'state';residue=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit() or int(p.name)==os.getpid():continue
 try:
  if ('AGENTMUX_HOME='+str(state)).encode() in (p/'environ').read_bytes().split(b'\\0'):residue.append(int(p.name))
 except (PermissionError,FileNotFoundError,ProcessLookupError):pass
pidfile=state/'hub/hub.pid';pid=pidfile.read_text().strip() if pidfile.exists() else None
print(json.dumps({'fixtureEnvironmentProcessPids':residue,'tokenFilesRemaining':len(list(state.rglob('token')))+len(list(state.rglob('operator.token'))),'recordedHubPid':pid,'recordedHubPidExistsNow':pathlib.Path('/proc/'+pid).exists() if pid else False}))
'''
p=subprocess.run(['wsl','-d','Ubuntu-26.04','--','python3','-'],input=code,capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr;linux=json.loads(p.stdout)
proof=json.loads((root/'grok-readiness-review.json').read_text());expected=proof['nativeHookFiles'];current=[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in P(proof['canonicalProfile']).joinpath('hooks').rglob('*') if p.is_file()];by={P(item['path']).resolve():item['sha256'] for item in expected};inventory={'expected':expected,'current':current,'expectedFileContentsUnchanged':all(hashlib.sha256(P(path).read_bytes()).hexdigest()==h for path,h in by.items()),'additionalPaths':[item['path'] for item in current if P(item['path']).resolve() not in by],'modelExecutedByGrok':False}
(root/'grok-hook-source-inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
result={'scope':'Failed original TEAM startup before task posting or original scoring. Exact cleanup is separate from scenario success.','sourceCommit':m['commit'],'harnessExitCode':a['harnessExitCode'],'originalReportsCount':len(a['originalReports']),'source67Unchanged':a['sourceUnchanged'],'actors':actors,'linuxCleanup':linux,'runnerCleanup':{key:value for key,value in a['cleanup'].items() if key!='supervisors'},'hookInventory':'grok-hook-source-inventory.json','noRetry':True,'limitations':['Claude Windows config byte comparison is false; no setting-change attribution is asserted.','The failed startup produced no E1-E6 score or task completion.']}
(root/'failed-team-independent-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'result':str(root/'failed-team-independent-verification.json'),'harnessExitCode':result['harnessExitCode'],'actors':[{key:e[key] for key in ['actor','launchPassed','observerResultExists']} for e in actors],'linuxCleanup':linux,'hookInventory':inventory},indent=2))