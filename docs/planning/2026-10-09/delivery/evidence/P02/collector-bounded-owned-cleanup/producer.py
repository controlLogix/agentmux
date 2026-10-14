from pathlib import Path
import difflib,hashlib,json,platform,subprocess,sys,time
p=Path(__file__).parent
sha=lambda q:hashlib.sha256(q.read_bytes()).hexdigest()
owned=['original.py','native_go.py','run_controls.py','bounded_api_control.py','producer.py']
before={f:sha(p/f) for f in owned};results=[]
for name,args,wanted in [('before',['bounded_api_control.py','original.py'],1),('after',['bounded_api_control.py','native_go.py'],0),('focused',['run_controls.py','focused'],0),('affected',['run_controls.py','affected'],0)]:
 cmd=[sys.executable,str(p/args[0]),*args[1:]];start=time.monotonic()
 with (p/(name+'.stdout')).open('wb') as out,(p/(name+'.stderr')).open('wb') as err:
  run=subprocess.run(cmd,stdout=out,stderr=err,timeout=60)
 results.append({'name':name,'command':cmd,'exitCode':run.returncode,'expectedExitCode':wanted,'seconds':time.monotonic()-start,'stdoutSHA256':sha(p/(name+'.stdout')),'stderrSHA256':sha(p/(name+'.stderr'))})
 if run.returncode!=wanted:break
(p/'candidate.diff').write_text(''.join(difflib.unified_diff((p/'original.py').read_text().splitlines(True),(p/'native_go.py').read_text().splitlines(True),fromfile='original/tests/platform/native_go.py',tofile='candidate/tests/platform/native_go.py')))
record={'scope':'Cache-only thread-free collector cleanup repair; durable focused RunnerTests, not native collection or phase acceptance','sourceSHA256':before,'sourceStable':before=={f:sha(p/f) for f in owned},'runs':results,'counts':{'focused':7,'affectedRunnerTests':37},'runtime':{'implementation':platform.python_implementation(),'version':platform.python_version()},'history':{'v1ReviewSHA256':sha(p.parent/'p02-native-collector-cleanup-repair-v1-history/review.json'),'v2ReviewSHA256':sha(p.parent/'p02-native-collector-cleanup-repair-v2/review.json'),'v3PreControlsSHA256':'5d538d91c73f0895cee31721c3c05a7a1cd627dfc44ef8485dcd6d04b28029c9'},'limits':['Builtin Popen wait uses the original remaining collection deadline and existing five-second reserve; no spawned cleanup thread exists.','If a bounded wait cannot confirm exit, its exact owner is retained and a serialized atexit fallback waits after the earlier waiter returned. Physical kernel wait, collector exit and artifact upload remain unbounded.','Actual owned-child reap and shutdown are real; timeout/interruption/stop-failure boundaries use test-only mocks/wrappers, not native kernel failure injection.','V1/v2 delayed subclass ignored the wait contract and is historical diagnostic evidence only, not this acceptance requirement. V1/v2 review findings and structural setup failure remain preserved.','Five new durable tests are in RunnerTests, with two existing interruption assertions updated to require timeout-bearing cleanup.','No Docker, native Linux/macOS collection, CI Python3.12 execution, shared source or global metadata change.']}
(p/'review.json').write_text(json.dumps(record,indent=2)+'\n')
(p/'manifest.json').write_text(json.dumps({q.name:sha(q) for q in p.iterdir() if q.is_file() and q.name!='manifest.json'},indent=2)+'\n')
print(json.dumps({'reviewSHA256':sha(p/'review.json'),'candidateSHA256':sha(p/'native_go.py'),'sourceStable':record['sourceStable'],'runs':[(x['name'],x['exitCode']) for x in results]}))
sys.exit(0 if len(results)==4 and record['sourceStable'] and all(x['exitCode']==x['expectedExitCode'] for x in results) else 1)
