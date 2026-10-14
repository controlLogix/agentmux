set -eu
umask 077
root=/home/ryan/.cache/agentmux-governance
out=$(mktemp -d "$root/p02-current-wsl-pending-real-XXXXXX")
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-current-wsl-pending-real.sh "$out/producer.sh"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=1 AGENTMUX_TEST_NATS="$root/tools/nats-server"
export AMX_BOOTSTRAP_SELECTION_FILE="$root/p02-current-wsl-selection-draft-674dc329/selection.json" AMX_BOOTSTRAP_SELECTION_SHA256=724f2d7863838b26114a45ab335a93cce9b9a44b47df9bb3ecb5bff3d53c11fb
GO="$root/runtime-comparison/go/bin/go"
python3 - "$out" "$GO" <<'PY'
import json,sys,os,datetime,hashlib,shutil,time,subprocess,re
from pathlib import Path
p=Path(sys.argv[1]);live=Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');begin=time.monotonic()
def scan(root): return {str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for sub in ['platform','contracts'] for f in sorted((root/sub).rglob('*')) if f.is_file()}
before=scan(live)
for sub in ['platform','contracts']:shutil.copytree(live/sub,p/'src'/sub)
after=scan(live);copied=scan(p/'src');assert before==after==copied,'source_changed'
expected={'platform/launcher/owner_bridge.go':'9cfd0a38d4b40c060759200dbef226cc5bf9dd60d7759f67e756f2d9949e19f2','platform/launcher/bootstrap_operation.go':'3d4a7531863e2f1ee03820a13767c9eace5bbd3812fcef7eccf48124277c7562','platform/cmd/agentmux-runtime/main.go':'9ba174b070fe08d76944d2a2f6cbd5da448f0a02f6e1c70c6aabc0a15ad17620','platform/launcher/bootstrap_network_cleanup_integration_test.go':'5347669150b3bf622cde6634389e564ef67b9eabbe5849393f6ffd711f57b00e','platform/launcher/installed_cli_compose_integration_linux_test.go':'6d0021d99531507ea5232ff81f1d18477ce1def1a8c228b3069d1d785895073c'}
expected['platform/launcher/bootstrap_docker_selection_test.go']='6b5e550b2cc89f0b9fc873a4891623ed01c1277ee8947dbcb147650c312b34ae'
expected['platform/launcher/bootstrap_docker_current_qualification_controls_test.go']='f4b578067fcecf022600f818709ac95185e787e7c5727f6b602485f178bfc831'
for k,v in expected.items():assert before[k]==v,k
selection=Path(os.environ['AMX_BOOTSTRAP_SELECTION_FILE']);assert hashlib.sha256(selection.read_bytes()).hexdigest()==os.environ['AMX_BOOTSTRAP_SELECTION_SHA256'];assert os.environ['AMX_BOOTSTRAP_SELECTION_SHA256']=='724f2d7863838b26114a45ab335a93cce9b9a44b47df9bb3ecb5bff3d53c11fb'
(p/'selection.json').write_bytes(selection.read_bytes())
for name,m in [('shared-before',before),('shared-after',after),('source-manifest',copied)]: (p/(name+'.json')).write_text(json.dumps(m,indent=2)+'\n')
argv=[sys.argv[2],'test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestInstalledCLIRealComposeAuthenticatedPending$']
(p/'invocation.json').write_text(json.dumps({'argv':argv,'environment':{k:os.environ[k] for k in ['GOPROXY','GOSUMDB','GOWORK','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED','AGENTMUX_TEST_NATS','AMX_BOOTSTRAP_SELECTION_FILE','AMX_BOOTSTRAP_SELECTION_SHA256']},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'producerSHA256':hashlib.sha256((p/'producer.sh').read_bytes()).hexdigest(),'requiredPins':expected,'snapshotSeconds':time.monotonic()-begin,'snapshotFileCount':len(copied),'batchSourceVerification':True},indent=2)+'\n')
# Read-only preliminary checks complement the fixture's full admitted driver and ledgers.
docker='/mnt/c/Users/RyanHelms/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe'
for key in ['DOCKER_HOST','DOCKER_CONTEXT','AMX_BROKER_INSPECT_FIXTURE','AMX_DOCKER_FIXTURE','AMX_OWNER_BRIDGE_DOCKER_FIXTURE','AGENTMUX_NATS_SERVER']:assert not os.environ.get(key),'environment_override'
steps=[('endpoint',['context','inspect','desktop-linux','--format','{{json .Endpoints.docker.Host}}']),('engine',['info','--format','{{json .ID}}']),('image',['image','inspect','docker.io/library/nats@sha256:fdae708d900cb150ce13f203359719bdd9cefd3dbbbc32a4c6224b23ea3e0b2c','--format','{{json .RepoDigests}}']),('networks',['network','ls','--quiet','--no-trunc']),('containers',['ps','--all','--quiet','--no-trunc'])]
facts=[]
try:
 for stage,args in steps:
  start=time.monotonic();cmd=[docker,'--context','desktop-linux']+args
  r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4)
  for suffix,raw in [('stdout.private',r.stdout),('stderr.private',r.stderr)]:
   path=p/(stage+'-'+suffix);path.write_bytes(raw);path.chmod(0o600)
  fact={'stage':stage,'elapsedSeconds':time.monotonic()-start,'directExit':r.returncode,'stdoutBytes':len(r.stdout),'stderrBytes':len(r.stderr),'argv':cmd}
  facts.append(fact);assert r.returncode==0 and len(r.stdout)<=1048576,'read_failed'
  if stage=='endpoint':assert json.loads(r.stdout)=='npipe:////./pipe/dockerDesktopLinuxEngine','endpoint_mismatch'
  if stage=='engine':assert json.loads(r.stdout)=='772de646-ba89-42ac-8675-45b2025fbdee','engine_mismatch'
  if stage=='image':assert any(x.endswith('@sha256:fdae708d900cb150ce13f203359719bdd9cefd3dbbbc32a4c6224b23ea3e0b2c') for x in json.loads(r.stdout)),'image_mismatch'
  if stage in ['networks','containers']:
   ids=r.stdout.decode().split();assert len(set(ids))==len(ids) and all(re.fullmatch('[0-9a-f]{64}',x) for x in ids),'roster_invalid'
   fact['count']=len(ids)
   if stage=='networks':assert len(ids)<32,'capacity_unsafe'
 (p/'preflight.json').write_text(json.dumps({'admitted':True,'steps':facts,'limits':'Preliminary read-only checks; actual test repeats full driver admission and complete ownership baselines.'},indent=2)+'\n')
except Exception as e:
 (p/'preflight.json').write_text(json.dumps({'admitted':False,'steps':facts,'failureType':type(e).__name__},indent=2)+'\n');raise
PY
printf '%s\n' snapshot_and_preflight_pinned
cd "$out/src/platform"
set +e
"$GO" test -race -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestInstalledCLIRealComposeAuthenticatedPending$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
python3 - "$out" "$code" <<'PY'
import json,sys,datetime
from pathlib import Path
p=Path(sys.argv[1]);(p/'completion.json').write_text(json.dumps({'directExit':int(sys.argv[2]),'endedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
exit "$code"