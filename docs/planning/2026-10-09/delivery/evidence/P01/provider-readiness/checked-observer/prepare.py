import pathlib,sys,difflib,json,hashlib
root=pathlib.Path(sys.argv[1]).resolve();old=pathlib.Path(r'C:\Users\RyanHelms\AppData\Local\Temp\agentmux-calib-observer-integration-8243b8901b07416b8e35746958890214')
for name in ['supervisor.py','observer.py','observer_api.py','synthetic.py','synthetic-wrapper.py','synthetic-config.toml','integration-driver.py']:(root/name).write_bytes((old/name).read_bytes())
(root/'previous-supervisor.py').write_bytes((old/'supervisor.py').read_bytes());(root/'previous-observer.py').write_bytes((old/'observer.py').read_bytes())
(root/'previous-candidate-reference.json').write_text(json.dumps({'fixture':str(old),'files':[{'name':name,'sha256':hashlib.sha256((old/name).read_bytes()).hexdigest()} for name in ['supervisor.py','observer.py','observer_api.py','integration-result.json','integration-final.log']]},indent=2)+'\n')
p=root/'observer.py';s=p.read_text();s=s.replace(" if job:k.TerminateJobObject(job,134)\n if parent:k.WaitForSingleObject(parent,5000)",""" cleanup={'verified':False}
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
 if not cleanup['verified']:result['passed']=False""")
p.write_text(s)
p=root/'supervisor.py';s=p.read_text();s=s.replace("        result['observerPid']=observer.pid;result['jobName']=job_name", "        if observer.poll() is not None:raise RuntimeError('Observer died before parent resume')\n        result['observerPid']=observer.pid;result['jobName']=job_name")
s=s.replace("        while True:\n            wait=k.WaitForSingleObject(pi.hProcess,100)", "        while True:\n            if observer.poll() is not None and k.WaitForSingleObject(pi.hProcess,0)==258:raise RuntimeError('Independent observer exited unexpectedly while parent was live')\n            wait=k.WaitForSingleObject(pi.hProcess,100)")
s=s.replace("            except subprocess.TimeoutExpired:cleanup['observerExit']=None", """            except subprocess.TimeoutExpired:cleanup['observerExit']=None
            observer_record=root/'observer-result.json'
            if observer_record.exists():
                observer_result=json.loads(observer_record.read_text())
                observer_ok=observer_result.get('jobUid')==req['jobUid'] and observer_result.get('passed') is True and observer_result.get('afterJob',{}).get('ActiveProcesses')==0 and observer_result.get('cleanup',{}).get('verified') is True and isinstance(observer_result.get('windowsConfigBytesUnchanged'),bool)
                cleanup['observerEvidenceVerified']=observer_ok
            else:cleanup['observerEvidenceVerified']=False
            if not cleanup['observerEvidenceVerified']:result['passed']=False""")
p.write_text(s)
p=root/'integration-driver.py';s=p.read_text();s=s.replace("['teardown','cancel','observer-setup-failure']", "['teardown','cancel','observer-setup-failure','observer-afterready-exit','observer-afterready-error']")
s=s.replace("case=root/(kind+'-final');case.mkdir()", "case=root/kind;case.mkdir()")
s=s.replace("  if kind=='observer-setup-failure':(case/'observer.py').write_text('raise SystemExit(17)\\n')", """  if kind=='observer-setup-failure':(case/'observer.py').write_text('raise SystemExit(17)\\n')
  if kind in ['observer-afterready-exit','observer-afterready-error']:
   observer_source=(case/'observer.py').read_text()
   injected=' time.sleep(.8)\\n '+('os._exit(23)' if kind=='observer-afterready-exit' else "raise RuntimeError('deliberate observer failure after readiness')")+'\\n while True:'
   (case/'observer.py').write_text(observer_source.replace(' while True:',injected,1))""")
s=s.replace("   if kind=='observer-setup-failure':\n    wait_file", "   if kind in ['observer-setup-failure','observer-afterready-exit','observer-afterready-error']:\n    wait_file")
s=s.replace("    assert launch['passed'] is False and 'Observer exited before readiness' in launch['error']['message']\n    assert launch['cleanup']['verified'] and launch['cleanup']['activeProcesses']==0 and launch['cleanup']['parentWait']==0 and launch['cleanup']['observerExit']==17", """    assert launch['passed'] is False
    assert launch['cleanup']['verified'] and launch['cleanup']['activeProcesses']==0 and launch['cleanup']['parentWait']==0
    if kind=='observer-setup-failure':assert 'Observer exited before readiness' in launch['error']['message'] and launch['cleanup']['observerExit']==17
    elif kind=='observer-afterready-exit':assert 'Independent observer exited unexpectedly' in launch['error']['message'] and launch['cleanup']['observerExit']==23 and (case/'launch-ready.json').exists() and not (case/'observer-result.json').exists()
    else:
     observed=json.loads((case/'observer-result.json').read_text());assert observed['passed'] is False and observed['cleanup']['verified'] and observed['cleanup']['activeProcesses']==0 and observed['windowsConfigBytesUnchanged'] is True
     entry['observerResult']=observed""")
s=s.replace("assert observed['jobUid']==ready['jobUid'] and observed['passed'] and observed['afterJob']['ActiveProcesses']==0", "assert observed['jobUid']==ready['jobUid'] and observed['passed'] and observed['cleanup']['verified'] and observed['afterJob']['ActiveProcesses']==0")
s=s.replace("   try:cmd(socket,'kill-server')\n   except subprocess.TimeoutExpired:entry['tmuxCleanupTimeout']=True", """   try:
    stopped=cmd(socket,'kill-server')
    absent=cmd(socket,'list-sessions')
    entry['tmuxCleanup']={'killExit':stopped.returncode,'probeExit':absent.returncode,'noServer':absent.returncode!=0 and ('no server running' in absent.stderr or 'error connecting' in absent.stderr and 'No such file or directory' in absent.stderr)}
    if not entry['tmuxCleanup']['noServer']:entry['passed']=False
   except subprocess.TimeoutExpired:entry['tmuxCleanupTimeout']=True;entry['passed']=False""")
p.write_text(s)
(root/'supervisor-fix.diff').write_text(''.join(difflib.unified_diff((root/'previous-supervisor.py').read_text().splitlines(keepends=True),(root/'supervisor.py').read_text().splitlines(keepends=True),fromfile='previous-supervisor.py',tofile='supervisor.py')))
(root/'observer-fix.diff').write_text(''.join(difflib.unified_diff((root/'previous-observer.py').read_text().splitlines(keepends=True),(root/'observer.py').read_text().splitlines(keepends=True),fromfile='previous-observer.py',tofile='observer.py')))
print(root)