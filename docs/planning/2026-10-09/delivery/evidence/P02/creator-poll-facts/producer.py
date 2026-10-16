from pathlib import Path
import hashlib,json,shutil,tempfile,subprocess,os,time,sys,datetime
base=Path('/home/ryan/.cache/agentmux-governance');candidate=base/'p02-creator-poll-diagnostic-zh8bwjjt';p=Path(tempfile.mkdtemp(prefix='p02-creator-poll-control-',dir=base));print(str(p),flush=True);sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();live=Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');prepared=base/'p02-current-wsl-coldwarm-context-zWYKUv/src'
def scan(root):return {str(f.relative_to(root)):sha(f) for sub in ('platform','contracts') for f in sorted((root/sub).rglob('*')) if f.is_file()}
before=scan(live);assert before==scan(prepared) and len(before)==282,'prepared_source_drift'
for sub in ('platform','contracts'):shutil.copytree(prepared/sub,p/'src'/sub)
assert scan(p/'src')==before,'snapshot_copy_mismatch';record=json.loads((candidate/'review-before-tests.json').read_text());pins=record['sourcePins']
for n,h in pins.items():
 assert sha(candidate/'candidate/platform/launcher'/n)==h;shutil.copy2(candidate/'candidate/platform/launcher'/n,p/'src/platform/launcher'/n)
after=scan(live);assert before==after;assert all(sha(candidate/'candidate/platform/launcher'/n)==h==sha(p/'src/platform/launcher'/n) for n,h in pins.items())
executed=scan(p/'src')
for name,obj in [('shared-before.json',before),('shared-after.json',after),('source-manifest.json',executed)]: (p/name).write_text(json.dumps(obj,indent=2)+'\n')
env=dict(os.environ);removed=[]
for k in list(env):
 if k.startswith(('AMX_','AGENTMUX_')) or k.startswith('DOCKER_'):removed.append(k);env.pop(k,None)
fixed={'GOTOOLCHAIN':'local','GOENV':'off','GOFLAGS':'-mod=readonly','GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'};env.update(fixed)
argv=[str(base/'runtime-comparison/go/bin/go'),'test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestComposeCLICreatorObservation$'];(p/'producer.py').write_bytes(Path(__file__).read_bytes());(p/'invocation.json').write_text(json.dumps({'argv':argv,'environment':fixed,'removedOverrideNames':removed,'cwd':str(p/'src/platform'),'overlayPins':pins,'sourceCount':len(executed),'producerSHA256':sha(p/'producer.py'),'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n');started=time.monotonic()
with (p/'events.jsonl').open('wb') as out,(p/'stderr.log').open('wb') as err:r=subprocess.run(argv,cwd=p/'src/platform',env=env,stdout=out,stderr=err)
(p/'exit.txt').write_text(str(r.returncode)+'\n');(p/'completion.json').write_text(json.dumps({'exit':r.returncode,'elapsedSeconds':time.monotonic()-started},indent=2)+'\n');assert scan(p/'src')==executed;assert all(sha(candidate/'candidate/platform/launcher'/n)==h for n,h in pins.items());sys.exit(r.returncode)