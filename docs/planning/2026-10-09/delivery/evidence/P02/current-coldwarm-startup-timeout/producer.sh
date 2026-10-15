set -eu
umask 077
root=/home/ryan/.cache/agentmux-governance
out=$(mktemp -d "$root/p02-current-wsl-coldwarm-XXXXXX")
printf '%s\n' "$out"
cp "/home/ryan/.cache/agentmux-governance/p02-current-coldwarm-prepared-dx_pqauj/producer.sh" "$out/producer.sh"
export GOTOOLCHAIN=local GOENV=off GOFLAGS=-mod=readonly GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=1 AGENTMUX_TEST_NATS="$root/tools/nats-server"
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
compiled_manifest=scan(p/'src')
expected=json.loads(Path('/home/ryan/.cache/agentmux-governance/p02-current-coldwarm-prepared-dx_pqauj/source-before.json').read_text())
assert before==expected,'current_candidate_source_mismatch'
selection=Path(os.environ['AMX_BOOTSTRAP_SELECTION_FILE']);assert hashlib.sha256(selection.read_bytes()).hexdigest()==os.environ['AMX_BOOTSTRAP_SELECTION_SHA256'];assert os.environ['AMX_BOOTSTRAP_SELECTION_SHA256']=='724f2d7863838b26114a45ab335a93cce9b9a44b47df9bb3ecb5bff3d53c11fb'
(p/'selection.json').write_bytes(selection.read_bytes())
for name,m in [('shared-before',before),('shared-after',after),('source-manifest',compiled_manifest)]: (p/(name+'.json')).write_text(json.dumps(m,indent=2)+'\n')
argv=[sys.argv[2],'test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestInstalledCLIRealComposeColdWarmAndRefresh$']
(p/'invocation.json').write_text(json.dumps({'argv':argv,'environment':{k:os.environ[k] for k in ['GOTOOLCHAIN','GOENV','GOFLAGS','GOPROXY','GOSUMDB','GOWORK','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED','AGENTMUX_TEST_NATS','AMX_BOOTSTRAP_SELECTION_FILE','AMX_BOOTSTRAP_SELECTION_SHA256']},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'producerSHA256':hashlib.sha256((p/'producer.sh').read_bytes()).hexdigest(),'requiredPins':expected,'snapshotSeconds':time.monotonic()-begin,'snapshotFileCount':len(compiled_manifest),'overlayPins':{},'batchSourceVerification':True},indent=2)+'\n')
# Read-only preliminary checks complement the fixture's full admitted driver and ledgers.
docker='/mnt/c/Users/RyanHelms/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe'
assert hashlib.sha256(Path(docker).read_bytes()).hexdigest()=='575b19fdc3cc3054714e6cbe92bcf86b708cc5dc46ad5e75bfd7591220de86fe','cli_hash_changed'
powershell='/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
encoded_signature='JABFAHIAcgBvAHIAQQBjAHQAaQBvAG4AUAByAGUAZgBlAHIAZQBuAGMAZQA9ACcAUwB0AG8AcAAnADsAIAAkAG0AbwBkAHUAbABlAD0ASgBvAGkAbgAtAFAAYQB0AGgAIAAkAFAAUwBIAE8ATQBFACAAJwBNAG8AZAB1AGwAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AUwBlAGMAdQByAGkAdAB5AFwATQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AUwBlAGMAdQByAGkAdAB5AC4AcABzAGQAMQAnADsAIABJAG0AcABvAHIAdAAtAE0AbwBkAHUAbABlACAALQBOAGEAbQBlACAAJABtAG8AZAB1AGwAZQAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwB0AG8AcAA7ACAAJABzAD0ATQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AUwBlAGMAdQByAGkAdAB5AFwARwBlAHQALQBBAHUAdABoAGUAbgB0AGkAYwBvAGQAZQBTAGkAZwBuAGEAdAB1AHIAZQAgAC0ATABpAHQAZQByAGEAbABQAGEAdABoACAAJwBDADoAXABVAHMAZQByAHMAXABSAHkAYQBuAEgAZQBsAG0AcwBcAEEAcABwAEQAYQB0AGEAXABMAG8AYwBhAGwAXABQAHIAbwBnAHIAYQBtAHMAXABEAG8AYwBrAGUAcgBEAGUAcwBrAHQAbwBwAFwAcgBlAHMAbwB1AHIAYwBlAHMAXABiAGkAbgBcAGQAbwBjAGsAZQByAC4AZQB4AGUAJwA7ACAAQAB7AHMAdABhAHQAdQBzAD0AWwBzAHQAcgBpAG4AZwBdACQAcwAuAFMAdABhAHQAdQBzADsAcwB1AGIAagBlAGMAdAA9ACQAcwAuAFMAaQBnAG4AZQByAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAuAFMAdQBiAGoAZQBjAHQAOwBtAG8AZAB1AGwAZQBQAGEAdABoAD0AJABtAG8AZAB1AGwAZQA7AHAAcwBNAG8AZAB1AGwAZQBQAGEAdABoAD0AJABlAG4AdgA6AFAAUwBNAG8AZAB1AGwAZQBQAGEAdABoADsAcABzAEgAbwBtAGUAPQAkAFAAUwBIAE8ATQBFAH0AIAB8ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuACAALQBDAG8AbQBwAHIAZQBzAHMA'
cli_hash_before=hashlib.sha256(Path(docker).read_bytes()).hexdigest()
sig_started=time.monotonic()
sig=subprocess.run([powershell,'-NoProfile','-NonInteractive','-EncodedCommand',encoded_signature],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
for name,raw in [('signature-stdout.private',sig.stdout),('signature-stderr.private',sig.stderr)]:path=p/name;path.write_bytes(raw);path.chmod(0o600)
assert sig.returncode==0 and len(sig.stdout)<=16384 and len(sig.stderr)<=65536,'signature_read_failed'
observed_sig=json.loads(sig.stdout.decode('utf-8-sig'));assert observed_sig['status']=='Valid' and re.search(r'(^|,\s*)(O|CN)=Docker Inc(,|$)',observed_sig['subject']),'signature_invalid'
assert observed_sig['modulePath']==r'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1','signature_module_path_invalid'
streams=[]
if sig.stderr:
 import xml.etree.ElementTree as ET
 text=sig.stderr.decode('utf-8');tree=ET.fromstring(text[text.index('<Objs'):]);streams=sorted({x.attrib['S'] for x in tree.iter() if 'S' in x.attrib});assert streams==['progress'],'signature_stderr_unknown'
cli_hash_after=hashlib.sha256(Path(docker).read_bytes()).hexdigest();assert cli_hash_before==cli_hash_after=='575b19fdc3cc3054714e6cbe92bcf86b708cc5dc46ad5e75bfd7591220de86fe','cli_changed_during_signature'
(p/'windows-signature-summary.json').write_text(json.dumps({'signatureValid':True,'dockerPublisher':True,'cliSHA256Before':cli_hash_before,'cliSHA256After':cli_hash_after,'directExit':sig.returncode,'elapsedSeconds':time.monotonic()-sig_started,'stderrXMLStreams':streams,'reader':'Explicit system PowerShell Security module via fixed EncodedCommand','inheritedModulePathEntryCount':len(observed_sig['psModulePath'].split(';'))},indent=2)+'\n')
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
 assert hashlib.sha256(Path(docker).read_bytes()).hexdigest()==cli_hash_before,'cli_changed_before_fixture'
 (p/'preflight.json').write_text(json.dumps({'admitted':True,'steps':facts,'limits':'Preliminary read-only checks; actual test repeats full driver admission and complete ownership baselines.'},indent=2)+'\n')
except Exception as e:
 (p/'preflight.json').write_text(json.dumps({'admitted':False,'steps':facts,'failureType':type(e).__name__},indent=2)+'\n');raise
PY
printf '%s\n' snapshot_and_preflight_pinned
cd "$out/src/platform"
set +e
"$GO" test -race -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestInstalledCLIRealComposeColdWarmAndRefresh$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
python3 - "$out" "$code" <<'PY'
import json,sys,datetime
from pathlib import Path
p=Path(sys.argv[1]);(p/'completion.json').write_text(json.dumps({'directExit':int(sys.argv[2]),'endedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
exit "$code"