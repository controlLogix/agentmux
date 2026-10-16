from pathlib import Path
import json,os,hashlib,subprocess,time,datetime,sys
p=Path('/home/ryan/.cache/agentmux-governance/p02-bridge-context-focused-5wusriyi');out=p/'affected';src=p/'src';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
manifest=json.loads((p/'source-manifest.json').read_text())
def scan():return {str(f.relative_to(src)):sha(f) for sub in ('platform','contracts') for f in sorted((src/sub).rglob('*')) if f.is_file()}
assert scan()==manifest,'snapshot_source_drift';(out/'source-before.json').write_text(json.dumps(manifest,indent=2)+'\n')
selection=json.loads((out/'selection.json').read_text());env=dict(os.environ);removed=[]
for k in list(env):
 if k.startswith(('AMX_','AGENTMUX_')) or k in ('DOCKER_CONTEXT','DOCKER_HOST','DOCKER_CONFIG','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):
  removed.append(k);env.pop(k,None)
base=Path('/home/ryan/.cache/agentmux-governance');fixed={'GOTOOLCHAIN':'local','GOENV':'off','GOFLAGS':'-mod=readonly','GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0','AGENTMUX_TEST_NATS':str(base/'tools/nats-server')};env.update(fixed)
(out/'producer.py').write_bytes(Path(__file__).read_bytes());plans=[]
for key,package in [('launcher','./launcher'),('cmd','./cmd/agentmux-runtime')]:
 plans.append((key,[str(base/'runtime-comparison/go/bin/go'),'test','-race','-failfast','-count=1','-json',package,'-run','^('+'|'.join(selection[key])+')$']))
plans.append(('vet',[str(base/'runtime-comparison/go/bin/go'),'vet','./launcher','./cmd/agentmux-runtime']))
(out/'invocation.json').write_text(json.dumps({'plans':[{'stage':key,'argv':argv} for key,argv in plans],'environment':fixed,'removedOverrideNames':sorted(removed),'cwd':str(src/'platform'),'producerSHA256':sha(out/'producer.py'),'selectionSHA256':sha(out/'selection.json'),'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
result=0
for key,argv in plans:
 started=time.monotonic()
 with (out/(key+'-events.jsonl' if key!='vet' else 'vet-stdout.log')).open('wb') as stdout,(out/(key+'-stderr.log')).open('wb') as stderr:r=subprocess.run(argv,cwd=src/'platform',env=env,stdout=stdout,stderr=stderr)
 (out/(key+'-exit.txt')).write_text(str(r.returncode)+'\n');(out/(key+'-completion.json')).write_text(json.dumps({'directExit':r.returncode,'elapsedSeconds':time.monotonic()-started,'endedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
 print(key+'_terminal_'+str(r.returncode),flush=True)
 if r.returncode:result=r.returncode;break
current=scan();(out/'source-after.json').write_text(json.dumps(current,indent=2)+'\n');assert current==manifest,'snapshot_changed';sys.exit(result)