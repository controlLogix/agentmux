import pathlib,hashlib,json,tempfile,shutil,subprocess,os,time
cache=pathlib.Path('/home/ryan/.cache/agentmux-governance');repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');out=pathlib.Path(tempfile.mkdtemp(prefix='p02-host-diagnostic-cli-consumer-',dir=cache));pins=json.loads((cache/'p02-host-policy-history-parity-x9y2c317/preparation.json').read_text())['sourcePins'];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();assert all(sha(repo/'platform/launcher'/n)==v for n,v in pins.items()),'promoted_candidate_pin_drift'
def scan(root):return {str(f.relative_to(root)):sha(f)for sub in ['platform','contracts']for f in sorted((root/sub).rglob('*'))if f.is_file()}
before=scan(repo)
for sub in ['platform','contracts']:shutil.copytree(repo/sub,out/'snapshot'/sub)
copied=scan(out/'snapshot');after=scan(repo);assert before==copied==after,'source_snapshot_drift'
docs=['AGENTS.md','.claude/rules/plain-language.md','docs/LOCAL_TESTING.md'];docpins={n:sha(repo/n)for n in docs};(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n');(out/'source-copy.json').write_text(json.dumps(copied,indent=2)+'\n');(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
env=os.environ.copy();cleared=[]
for k in list(env):
 if(k.startswith('AMX_')and('FIXTURE'in k or k in ['AMX_BOOTSTRAP_SELECTION_FILE','AMX_BOOTSTRAP_SELECTION_SHA256']))or k in ['AGENTMUX_TEST_NATS','AGENTMUX_NATS_SERVER']:cleared.append(k);env.pop(k)
env.update({'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GOENV':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'})
go=cache/'runtime-comparison/go/bin/go';commands={'test':[str(go),'test','-race','-count=1','-json','./cmd/agentmux-runtime'],'vet':[str(go),'vet','./cmd/agentmux-runtime']};inv={'cwd':str(out/'snapshot/platform'),'environment':{k:env[k]for k in ['GOPROXY','GOSUMDB','GOWORK','GOENV','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED']},'clearedOverrideNames':cleared,'candidatePins':pins,'documentationPins':docpins,'sourceCount':len(before),'commands':{},'startedUnix':time.time()};(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');shutil.copyfile('/mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-host-diagnostic-cli-consumer.py',out/'run.py');print(out,flush=True)
for name,argv in commands.items():
 started=time.time()
 with(out/(name+'.stdout')).open('wb')as a,(out/(name+'.stderr')).open('wb')as b:r=subprocess.run(argv,cwd=out/'snapshot/platform',env=env,stdout=a,stderr=b)
 inv['commands'][name]={'argv':argv,'startedUnix':started,'endedUnix':time.time(),'directExit':r.returncode};(out/(name+'-exit.txt')).write_text(str(r.returncode)+'\n');(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');print(name,'exit',r.returncode,flush=True)
 if r.returncode!=0:break
inv.update({'sharedSourceUnchanged':scan(repo)==before,'candidateUnchanged':all(sha(out/'snapshot/platform/launcher'/n)==v for n,v in pins.items()),'documentationUnchanged':all(sha(repo/n)==v for n,v in docpins.items())});(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n')