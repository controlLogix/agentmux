from pathlib import Path
import hashlib,json,os,shutil,subprocess,tempfile,time
repo=Path('/mnt/c/Users/RyanHelms/GitHub/agentmux')
draft=Path('/home/ryan/.cache/agentmux-governance/p02-current-wsl-selection-draft-674dc329')
run=Path(tempfile.mkdtemp(prefix='p02-current-wsl-selection-pure-',dir='/home/ryan/.cache/agentmux-governance'))
print(str(run),flush=True)
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save(name,value): (run/name).write_text(json.dumps(value,indent=2)+'\n')
paths=sorted(p for p in (repo/'platform').rglob('*') if p.is_file() and (p.suffix=='.go' or p.name in ('go.mod','go.sum','bootstrap_history.schema.json')))
before={str(p.relative_to(repo)):sha(p) for p in paths}
save('shared-before.json',before)
for p in paths:
    target=run/'src'/p.relative_to(repo)
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(p,target)
for name in ('bootstrap_docker_selection_test.go','bootstrap_docker_current_qualification_controls_test.go'):
    shutil.copyfile(draft/'src/platform/launcher'/name,run/'src/platform/launcher'/name)
manifest={str(p.relative_to(run/'src')):sha(p) for p in sorted((run/'src').rglob('*')) if p.is_file()}
save('source-manifest.json',manifest)
copy_after={str(p.relative_to(repo)):sha(p) for p in paths}
save('shared-copy-after.json',copy_after)
if before!=copy_after: raise RuntimeError('source changed during copy')
go='/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go'
selection='^TestBootstrapSelection(NativeMatrixAndLegacyWSL|RejectsUnpinnedOrAmbiguousInput|RejectsWrongHostAndAmbientTargets|BuildCommandsStayNative|DescriptorRejectsActualSubstitutions|CurrentWSLQualificationLiteral|CurrentWSLQualificationRejectsUnapprovedTuples|CurrentWSLQualificationRequiresActualHostAndPin)$'
env=os.environ.copy()
env.update(GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',GOWORK='off',GOFLAGS='-mod=readonly',GORACE='atexit_sleep_ms=0',AMX_BOOTSTRAP_DOCKER_AUTHORIZED='0')
env.pop('AMX_BOOTSTRAP_SELECTION_FILE',None)
env.pop('AMX_BOOTSTRAP_SELECTION_SHA256',None)
results=[]
def command(label,args):
    argv=[go,*args]
    save(label+'-invocation.json',{'argv':argv,'cwd':str(run/'src/platform'),'environment':{k:env.get(k) for k in ('GOTOOLCHAIN','GOPROXY','GOSUMDB','GOWORK','GOFLAGS','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED')},'selectionEnvironmentAbsent':True})
    started=time.monotonic()
    with (run/(label+'.jsonl')).open('wb') as out,(run/(label+'.stderr')).open('wb') as err:
        code=subprocess.run(argv,cwd=run/'src/platform',env=env,stdout=out,stderr=err).returncode
    (run/(label+'.exit')).write_text(str(code)+'\n')
    result={'label':label,'argv':argv,'exit':code,'elapsedSeconds':time.monotonic()-started}
    results.append(result);save('results.json',results)
    return code
code=command('selector-race',['test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run',selection])
events=[]
for line in (run/'selector-race.jsonl').read_text().splitlines():
    try: events.append(json.loads(line))
    except json.JSONDecodeError: pass
passed=[e['Test'] for e in events if e.get('Action')=='pass' and e.get('Test')]
fail_skip=[e for e in events if e.get('Action') in ('fail','skip')]
vet=None
if code==0 and passed and not fail_skip:
    vet=command('launcher-vet',['vet','-tags=agentmux_bootstrap_docker','./launcher'])
after={str(p.relative_to(repo)):sha(p) for p in paths}
save('shared-after.json',after)
post={str(p.relative_to(run/'src')):sha(p) for p in sorted((run/'src').rglob('*')) if p.is_file()}
save('post-source-manifest.json',post)
report={'scope':'Cache-only pure selector validation, no engine, image, port, daemon or helper process tests. No shared promotion/native/phase acceptance.','results':results,'namedPass':passed,'namedCount':len(passed),'topLevelCount':sum('/' not in p for p in passed),'namedFailSkip':fail_skip,'sourceStable':before==copy_after==after,'snapshotStable':manifest==post,'currentSelectionRemainsExplicit':True,'selectionJSONSHA256':sha(draft/'selection.json'),'sourceSHA256':{name:sha(run/'src/platform/launcher'/name) for name in ('bootstrap_docker_selection_test.go','bootstrap_docker_current_qualification_controls_test.go')},'baselineSourceSHA256':sha(draft/'baseline/bootstrap_docker_selection_test.go'),'independentSourceReview':'p02-current-wsl-selection-independent-miicvx5a/independent-review.json','engineAuthorization':0,'engineMutations':0,'limits':['Pure structural host values do not qualify actual Windows/WSL/native installed startup.','Current target is separately root-approved exact tuple, never old profile rebinding or dynamic adoption.','Existing default remains historical legacy; no selection env supplied to pure run.']}
save('review.json',report)
print(json.dumps({'run':str(run),'named':len(passed),'raceExit':code,'vetExit':vet,'sourceStable':before==copy_after==after,'snapshotStable':manifest==post}),flush=True)
raise SystemExit(0 if code==0 and vet==0 and passed and not fail_skip and before==copy_after==after and manifest==post else 1)
