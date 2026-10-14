from pathlib import Path
import hashlib,json,os,shutil,subprocess,time
repo=Path('/mnt/c/Users/RyanHelms/GitHub/agentmux')
draft=Path('/mnt/c/Users/RyanHelms/.cache/agentmux-governance/p02-root-occupied-history-draft')
run=Path(__file__).parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,v):(run/n).write_text(json.dumps(v,indent=2)+'\n')
review=json.loads((draft/'review.json').read_text())
for n,h in review['draftFiles'].items():
 if sha(draft/n)!=h:raise RuntimeError('draft hash mismatch')
paths=sorted([p for p in (repo/'platform').rglob('*') if p.is_file() and (p.suffix=='.go' or p.name in ('go.mod','go.sum','bootstrap_history.schema.json'))]+[p for p in (repo/'contracts').rglob('*') if p.is_file()])
before={str(p.relative_to(repo)):sha(p) for p in paths};save('shared-before.json',before)
if sha(repo/'platform/launcher/installed_cli_compose_failures_integration_test.go')!=review['baseSHA256']:raise RuntimeError('base drift')
for p in paths:
 q=run/'src'/p.relative_to(repo);q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q)
names=['installed_cli_compose_failures_integration_test.go','installed_cli_history_controls_test.go']
for n in names:shutil.copyfile(draft/n,run/'src/platform/launcher'/n)
copy_after={str(p.relative_to(repo)):sha(p) for p in paths};save('shared-copy-after.json',copy_after)
if before!=copy_after:raise RuntimeError('copy drift')
raw={n:sha(run/'src/platform/launcher'/n) for n in names};save('original-draft-pins.json',raw)
go='/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go'
fmt='/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/gofmt'
argv=[fmt,'-w',*[str(run/'src/platform/launcher'/n) for n in names]]
save('format-invocation.json',{'argv':argv})
with (run/'format.stdout').open('wb') as out,(run/'format.stderr').open('wb') as err:code=subprocess.run(argv,stdout=out,stderr=err).returncode
(run/'format.exit').write_text(str(code)+'\n')
if code:raise RuntimeError('format failed')
manifest={str(p.relative_to(run/'src')):sha(p) for p in sorted((run/'src').rglob('*')) if p.is_file()};save('source-manifest.json',manifest)
env=os.environ.copy();env.update(GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',GOWORK='off',GOFLAGS='-mod=readonly',GORACE='atexit_sleep_ms=0',AMX_BOOTSTRAP_DOCKER_AUTHORIZED='0')
for n in ['AMX_BOOTSTRAP_SELECTION_FILE','AMX_BOOTSTRAP_SELECTION_SHA256']:env.pop(n,None)
argv=[go,'test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestComposeCLIFailureHistoryIsExact$']
save('invocation.json',{'argv':argv,'cwd':str(run/'src/platform'),'environment':{n:env.get(n) for n in ['GOTOOLCHAIN','GOPROXY','GOSUMDB','GOWORK','GOFLAGS','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED']},'selectionEnvironmentAbsent':True})
started=time.monotonic()
with (run/'events.jsonl').open('wb') as out,(run/'stderr.log').open('wb') as err:code=subprocess.run(argv,cwd=run/'src/platform',env=env,stdout=out,stderr=err).returncode
(run/'exit.txt').write_text(str(code)+'\n')
events=[json.loads(x) for x in (run/'events.jsonl').read_text().splitlines() if x.strip()]
passes=[e['Test'] for e in events if e.get('Test') and e.get('Action')=='pass'];failures=[e for e in events if e.get('Action') in ['fail','skip']]
after={str(p.relative_to(repo)):sha(p) for p in paths};save('shared-after.json',after)
post={str(p.relative_to(run/'src')):sha(p) for p in sorted((run/'src').rglob('*')) if p.is_file()};save('post-source-manifest.json',post)
r={'scope':'Pure occupied failure history decoder controls only; no engine, port or live process fixture','draftReviewSHA256':sha(draft/'review.json'),'baseSHA256':review['baseSHA256'],'originalDraftPins':raw,'formattedPins':{n:sha(run/'src/platform/launcher'/n) for n in names},'directExit':code,'elapsedSeconds':time.monotonic()-started,'namedPasses':passes,'namedCount':len(passes),'topLevelCount':sum('/' not in n for n in passes),'failuresOrSkips':failures,'sourceStable':before==copy_after==after,'snapshotStable':manifest==post,'engineAuthorization':0,'limits':['History means past terminal failure, never current readiness.','Occupied-port actionable matcher remains false.','No production, native installed startup or phase acceptance.','No vet or broader affected selection run for this bounded request.']}
save('review.json',r)
print(json.dumps({'run':str(run),'directExit':code,'namedCount':len(passes),'sourceStable':r['sourceStable'],'snapshotStable':r['snapshotStable'],'reviewSHA256':sha(run/'review.json')}),flush=True)
raise SystemExit(0 if code==0 and passes and not failures and r['sourceStable'] and r['snapshotStable'] else 1)