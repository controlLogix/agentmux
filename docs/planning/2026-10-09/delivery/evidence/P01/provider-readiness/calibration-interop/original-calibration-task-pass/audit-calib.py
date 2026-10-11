import pathlib,os,json,hashlib,subprocess,shutil
P=pathlib.Path;root=P(__file__).resolve().parent;m=json.loads((root/'fixture.json').read_text());attempt=json.loads((root/'attempt-result.json').read_text());score=attempt['originalReports'][0]['report'];repo=P(m['demoBase'])/'calc';outdir=root/'compact-output';outdir.mkdir();py='/home/ryan/.cache/agentmux-governance/venv/bin/python';env=dict(os.environ,HOME=m['home'],AGENTMUX_HOME=m['state'],TMUX_TMPDIR=m['linuxFixture']);records=[]
for name,args in [('tests',[py,'-m','unittest','discover','-s','tests','-v']),('empty-input-check',[py,'-c','from calc import median\ntry: median([])\nexcept ValueError: print("empty input raises ValueError")\nelse: raise AssertionError("median accepted empty input")']),('git-head',['git','rev-parse','HEAD']),('git-show',['git','show','--format=fuller','--stat','HEAD']),('git-status',['git','status','--porcelain']),('git-diff',['git','diff','HEAD'])]:
 p=subprocess.run(args,cwd=repo,env=env,capture_output=True,text=True,timeout=20);records.append({'name':name,'argv':args,'cwd':str(repo),'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});assert p.returncode==0,(name,p.stdout,p.stderr)
assert records[-2]['stdout']=='' and records[-1]['stdout']==''
for path in ('calc/__init__.py','tests/test_calc.py'):
 target=outdir/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((repo/path).read_bytes())
callbacks=[]
log=P(m['state'])/'logs/calc-worker-codex_1833.log'
# Keep a raw log hash for provenance only. Do not copy the model pane or reasoning.
if log.exists():panehash=hashlib.sha256(log.read_bytes()).hexdigest()
else:panehash=None
compact={key:score[key] for key in ['run','scenario','started','agents','work','errors','timeline','checks','verify','error_free','stats']}
(root/'original-score-compact.json').write_text(json.dumps(compact,indent=2)+'\n')
left=[]
for p in P('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  pe=(p/'environ').read_bytes().split(bytes([0]));args=(p/'cmdline').read_bytes().split(bytes([0]))
  if ('AGENTMUX_HOME='+m['state']).encode() in pe and any(m['nativeSnapshot'].encode() in a for a in args):left.append({'pid':int(p.name),'argv':[a.decode(errors='replace') for a in args if a]})
 except OSError:pass
out={'status':'original-calibration-task-pass-with-cleanup-record-gap','candidateCommit':m['commit'],'originalChecks':score['checks'],'errorFree':score['error_free'],'automaticModalHandling':score['stats']['modal_answers'],'extraEnters':score['stats']['extra_enters'],'manualInputProvided':False,'records':records,'sourceReferences':len(m['sourceHashes']),'sourceUnchanged':all(hashlib.sha256((P(m['nativeSnapshot'])/k).read_bytes()).hexdigest()==v for k,v in m['sourceHashes'].items()),'privateRuntimeProcessesRemaining':left,'tokenFilesRemaining':[str(p) for p in P(m['state']).rglob('token')]+[str(p) for p in P(m['state']).rglob('operator.token')],'knownWindowsJob':json.loads((root/'windows-supervisors/calc-worker-codex_1833/launch-ready.json').read_text()),'finalSupervisorRecordPresent':False,'windowsConfigBytesUnchanged':None,'windowsJobActiveProcesses':None,'privatePaneLogSha256':panehash,'limitations':['Task execution and E1-E6 passed; final exact job accounting and config byte comparison are missing.','Known Windows parent absence does not replace exact job accounting.','Other team, crossrepo and swarm scenarios have not passed.','No personal profile/session logs or model pane reasoning are included in this compact proof.'],'artifacts':[{'path':str(p.relative_to(root)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [root/'original-score-compact.json',*(p for p in outdir.rglob('*') if p.is_file())]]}
(root/'independent-task-audit.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'auditSha256':hashlib.sha256((root/'independent-task-audit.json').read_bytes()).hexdigest(),'sourceUnchanged':out['sourceUnchanged'],'remainingPrivateProcesses':left,'testOutput':records[0]['stderr'],'emptyCheck':records[1]['stdout']}))
