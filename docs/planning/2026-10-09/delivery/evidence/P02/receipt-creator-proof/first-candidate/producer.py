import pathlib,shutil,tempfile,hashlib,json,os,subprocess,time
repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux/platform')
base=pathlib.Path(tempfile.mkdtemp(prefix='p02-receipt-proof-',dir='/home/ryan/.cache/agentmux-governance'))
files=['runtime/bootstrap_receipt.go','runtime/bootstrap_receipt_test.go','runtime/bootstrap_receipt_linux_test.go']
shutil.copytree(repo,base/'platform',ignore=shutil.ignore_patterns('node_modules','.git'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source={f:sha(repo/f) for f in files}
env=os.environ.copy();env.update(GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',GOWORK='off',GOFLAGS='-mod=readonly',GORACE='atexit_sleep_ms=0')
go='/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go'
results=[]
for name,args in [('focused',['test','-race','-count=1','-json','./runtime','-run','^TestBootstrapReceiptValidatedProofRequiresCompletionSignal$']),('affected',['test','-race','-count=1','-json','./runtime','-run','^TestBootstrapReceipt']),('vet',['vet','./runtime'])]:
    cmd=[go,*args]; (base/(name+'-invocation.json')).write_text(json.dumps({'argv':cmd,'cwd':str(base/'platform'),'envOverrides':{k:env[k] for k in ['GOTOOLCHAIN','GOPROXY','GOSUMDB','GOWORK','GOFLAGS','GORACE']}},indent=2)+'\n')
    start=time.monotonic()
    with (base/(name+'.jsonl')).open('w') as out,(base/(name+'.stderr')).open('w') as err:
        done=subprocess.run(cmd,cwd=base/'platform',env=env,stdout=out,stderr=err)
    result={'name':name,'exitCode':done.returncode,'elapsedSeconds':time.monotonic()-start}
    if name!='vet':
        rows=[json.loads(x) for x in (base/(name+'.jsonl')).read_text().splitlines()]
        result.update({a:sum(r.get('Action')==a and bool(r.get('Test')) for r in rows) for a in ['pass','fail','skip']})
    (base/(name+'-result.json')).write_text(json.dumps(result,indent=2)+'\n');results.append(result)
    if done.returncode:break
record={'ownedSourceSHA256':source,'currentSourceMatches':all(sha(repo/f)==h for f,h in source.items()),'snapshotSourceMatches':all(sha(base/'platform'/f)==h for f,h in source.items()),'results':results,'limits':['Native Linux receipt transport/accepted-proof component only; no actual kernel operation admission, history integration, Docker, native Darwin or phase acceptance.','Private-state adversarial controls do not prove a public factory mint; existing actual sealed-child control proves that connection.']}
record['artifacts']={p.name:sha(p) for p in base.iterdir() if p.is_file()}
shutil.copyfile(__file__,base/'producer.py');record['artifacts']['producer.py']=sha(base/'producer.py')
(base/'review.json').write_text(json.dumps(record,indent=2)+'\n')
print(str(base));print(json.dumps(results));print('reviewSHA256='+sha(base/'review.json'))