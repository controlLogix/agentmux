from pathlib import Path
import os,json,hashlib,shutil,tempfile,subprocess,sys,time,datetime
base=Path('/home/ryan/.cache/agentmux-governance');candidate=base/'p02-bridge-context-diagnostic-a1tq7c0e';out=Path(tempfile.mkdtemp(prefix='p02-bridge-context-focused-',dir=base));print(str(out),flush=True)
shutil.copy2(Path(__file__),out/'producer.py')
live=Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');prepared=base/'p02-current-wsl-coldwarm-stage-bePN2c/src'
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def scan(root):return {str(f.relative_to(root)):sha(f) for name in ('platform','contracts') for f in sorted((root/name).rglob('*')) if f.is_file()}
before=scan(live);basepins=scan(prepared);assert before==basepins,'prepared_dependency_drift'
for name in ('platform','contracts'):shutil.copytree(prepared/name,out/'src'/name)
copy=scan(out/'src');assert copy==before,'snapshot_copy_mismatch'
record=json.loads((candidate/'fixture-repair-review.json').read_text());overlay=record['sourcePins'];assert all(sha(candidate/'candidate/platform/launcher'/n)==v for n,v in overlay.items())
for n in overlay:shutil.copy2(candidate/'candidate/platform/launcher'/n,out/'src/platform/launcher'/n)
after=scan(live);assert before==after,'shared_source_changed';assert all(sha(candidate/'candidate/platform/launcher'/n)==v for n,v in overlay.items()),'candidate_changed'
executed=scan(out/'src');assert all(executed['platform/launcher/'+n]==v for n,v in overlay.items())
for name,obj in [('shared-before.json',before),('shared-after.json',after),('dependency-copy.json',copy),('source-manifest.json',executed)]: (out/name).write_text(json.dumps(obj,indent=2)+'\n')
env=dict(os.environ)
removed=[]
for key in list(env):
 if key.startswith(('AMX_','AGENTMUX_')) and key!='AGENTMUX_TEST_NATS' or key in ('DOCKER_CONTEXT','DOCKER_HOST','DOCKER_CONFIG','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'):
  removed.append(key);env.pop(key,None)
fixed={'GOTOOLCHAIN':'local','GOENV':'off','GOFLAGS':'-mod=readonly','GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0','AGENTMUX_TEST_NATS':str(base/'tools/nats-server')};env.update(fixed)
argv=[str(base/'runtime-comparison/go/bin/go'),'test','-race','-count=1','-json','./launcher','-run','^(TestBridgeContextDiagnosticActualRequestDeadline|TestBridgeContextDiagnosticPresentationAndSentinels|TestBridgeContextDiagnosticUnknownAndPriority|TestBridgeContextDiagnosticActualReplyWaitDeadline)$']
(out/'invocation.json').write_text(json.dumps({'argv':argv,'cwd':str(out/'src/platform'),'environment':fixed,'removedOverrideNames':sorted(removed),'overlayPins':overlay,'sourceFileCount':len(executed),'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'producerSHA256':sha(out/'producer.py'),'scope':'One local NATS component selection; no Docker engine; cleared TestMain and init fixture overrides.'},indent=2)+'\n')
started=time.monotonic()
with (out/'events.jsonl').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:r=subprocess.run(argv,cwd=out/'src/platform',env=env,stdout=stdout,stderr=stderr)
(out/'exit.txt').write_text(str(r.returncode)+'\n');(out/'completion.json').write_text(json.dumps({'directExit':r.returncode,'elapsedSeconds':time.monotonic()-started,'endedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n');sys.exit(r.returncode)