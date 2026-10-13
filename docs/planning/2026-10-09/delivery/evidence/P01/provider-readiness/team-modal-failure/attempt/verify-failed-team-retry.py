import pathlib,json,hashlib,subprocess,ctypes
P=pathlib.Path;root=P(r'C:/Users/RyanHelms/AppData/Local/Temp/agentmux original TEAM active JSON retry f1bj61xm');a=json.loads((root/'attempt-result.json').read_text());m=json.loads((root/'fixture.json').read_text());assert len(a['originalReports'])==1
original=a['originalReports'][0];r=original['report'];assert r['scenario']=='team' and r['error_free'] is False
compact={key:value for key,value in r.items() if key!='pane_tails'};(root/'original-score-without-pane-tails.json').write_text(json.dumps(compact,indent=2)+'\n')
ca=dict(a);ca['originalReports']=[{**original,'report':compact}];(root/'attempt-result-without-pane-tails.json').write_text(json.dumps(ca,indent=2)+'\n')
k=ctypes.WinDLL('kernel32',use_last_error=True);k.OpenProcess.argtypes=[ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong];k.OpenProcess.restype=ctypes.c_void_p;k.CloseHandle.argtypes=[ctypes.c_void_p];k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_ulong]
actors=[]
for folder in (root/'windows-supervisors').iterdir():
 o=json.loads((folder/'observer-result.json').read_text());ready=json.loads((folder/'launch-ready.json').read_text());assert o['jobUid']==ready['jobUid'] and o['parentPid']==ready['parentPid'] and o['observerPid']==ready['observerPid'];assert o['passed'] and o['afterJob']['ActiveProcesses']==0 and o['cleanup']['verified'] and isinstance(o['windowsConfigBytesUnchanged'],bool)
 entry={'actor':folder.name,'observer':{key:o[key] for key in ['jobUid','parentPid','supervisorPid','observerPid','passed','terminalReason','afterJob','cleanup','windowsConfigBytesUnchanged']},'knownPids':[]}
 for pid in [o['parentPid'],o['supervisorPid'],o['observerPid']]:
  h=k.OpenProcess(0x100000|0x1000,False,pid);entry['knownPids'].append({'pid':pid,'handleOpened':bool(h),'errorIfAbsent':ctypes.get_last_error() if not h else None,'waitState':k.WaitForSingleObject(h,0) if h else None})
  if h:k.CloseHandle(h)
 actors.append(entry)
code='''import pathlib,json,os,sqlite3
base=pathlib.Path('/home/ryan/.cache/agentmux-governance/original-team-5w9f4uj7');state=base/'state';residue=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit() or int(p.name)==os.getpid():continue
 try:
  if ('AGENTMUX_HOME='+str(state)).encode() in (p/'environ').read_bytes().split(b'\\0'):residue.append(int(p.name))
 except (PermissionError,FileNotFoundError,ProcessLookupError):pass
pidfile=state/'hub/hub.pid';pid=pidfile.read_text().strip() if pidfile.exists() else None
connection=sqlite3.connect((state/'hub/hub.db').as_uri()+'?mode=ro',uri=True);connection.row_factory=sqlite3.Row;connection.execute('PRAGMA query_only=ON')
work=[dict(row) for row in connection.execute('SELECT id,state,claimed_by,attempts FROM work_items WHERE id=?',('W-EFEKFESPVD',))];claims=connection.execute("SELECT count(*) FROM events WHERE entity='work' AND event='claimed'").fetchone()[0];connection.close()
print(json.dumps({'fixtureEnvironmentProcessPids':residue,'tokenFilesRemaining':len(list(state.rglob('token')))+len(list(state.rglob('operator.token'))),'recordedHubPid':pid,'recordedHubPidExistsNow':pathlib.Path('/proc/'+pid).exists() if pid else False,'actualWork':work,'claimEventCount':claims}))
'''
p=subprocess.run(['wsl','-d','Ubuntu-26.04','--','python3','-'],input=code,capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr;linux=json.loads(p.stdout)
result={'scope':'Root-authorized early diagnostic cancellation of unchanged unsupported Claude startup modal; genuine original failed TEAM score retained.','sourceCommit':m['commit'],'originalReportSha256':original['sha256'],'checks':r['checks'],'errorFree':r['error_free'],'work':r['work'],'harnessExitCode':a['harnessExitCode'],'elapsedSeconds':a['elapsedSeconds'],'source67Unchanged':a['sourceUnchanged'],'originalProviders':['claude','codex','grok'],'rootAuthorizedCancellation':True,'modalText':'Security notes: Press Enter to continue…','manualModalInput':False,'actors':actors,'linuxCleanup':linux,'gitEvidence':a['gitEvidence'],'limitations':['Original task was not claimed or implemented; no successful TEAM acceptance.','Claude and Codex config byte comparisons are false; no setting attribution is inferred.','Compact original report omits pane tails; raw original report remains in its external fixture with the recorded digest.','Harness exit zero is not scenario success.']}
(root/'failed-team-independent-verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'checks':result['checks'],'errorFree':result['errorFree'],'harnessExitCode':result['harnessExitCode'],'linuxCleanup':linux,'actors':[{'actor':x['actor'],'configBytesUnchanged':x['observer']['windowsConfigBytesUnchanged'],'activeProcesses':x['observer']['afterJob']['ActiveProcesses']} for x in actors],'originalReportSha256':original['sha256']},indent=2))