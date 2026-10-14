set -eu
umask 077
root=/home/ryan/.cache/agentmux-governance
out=$(mktemp -d "$root/p02-history-run-postnonce-XXXXXX")
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-history-run-postnonce.sh "$out/producer.sh"
mkdir "$out/private-output"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=0 AGENTMUX_TEST_NATS="$root/tools/nats-server" AGENTMUX_OWNER_BRIDGE_FIXTURE_ROOT="$out/private-output"
GO="$root/runtime-comparison/go/bin/go"
python3 - "$out" "$GO" <<'PY'
import json,sys,os,datetime,hashlib,shutil,time
from pathlib import Path
p=Path(sys.argv[1]);live=Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');begin=time.monotonic()
def scan(root):
 return {str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for sub in ['platform','contracts'] for f in sorted((root/sub).rglob('*')) if f.is_file()}
before=scan(live)
for sub in ['platform','contracts']:shutil.copytree(live/sub,p/'src'/sub)
after=scan(live);copied=scan(p/'src')
assert before==after==copied,'source changed during copy'
expected={'platform/launcher/owner_bridge.go':'9cfd0a38d4b40c060759200dbef226cc5bf9dd60d7759f67e756f2d9949e19f2','platform/launcher/bootstrap_operation.go':'3d4a7531863e2f1ee03820a13767c9eace5bbd3812fcef7eccf48124277c7562','platform/launcher/owner_bridge_nonce_window_test.go':'1b2df523535cfcb54af1155f244c61b5cd70057ac07dd8fd538c083fb4eef24a'}
# Root's exact nonce control file is admitted by its actual hash, not a guessed filename.
assert before["platform/launcher/owner_bridge.go"]==expected["platform/launcher/owner_bridge.go"]
assert before["platform/launcher/bootstrap_operation.go"]==expected["platform/launcher/bootstrap_operation.go"]
assert '1b2df523535cfcb54af1155f244c61b5cd70057ac07dd8fd538c083fb4eef24a' in before.values()
companion=Path('/home/ryan/.cache/agentmux-governance/p02-history-run-stage-draft-m1ll8apy/owner_bridge_history_running_linux_test.go')
assert hashlib.sha256(companion.read_bytes()).hexdigest()=='aafaea629d3b943d20f5c65a77ce8079f5b17f2b0c9c194a93ba6c034deae397'
target=p/'src/platform/launcher/owner_bridge_history_running_linux_test.go'
assert not target.exists();shutil.copyfile(companion,target)
manifest=scan(p/'src')
(p/'shared-before.json').write_text(json.dumps(before,indent=2)+'\n');(p/'shared-after.json').write_text(json.dumps(after,indent=2)+'\n');(p/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
(p/'invocation.json').write_text(json.dumps({'argv':[sys.argv[2],'test','-race','-count=1','-json','./launcher','-run','^TestOwnerBridgeHistoryActualRunFailurePublishesAndReleases$'],'environment':{k:os.environ[k] for k in ['GOPROXY','GOSUMDB','GOWORK','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED','AGENTMUX_TEST_NATS','AGENTMUX_OWNER_BRIDGE_FIXTURE_ROOT']},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'producerSHA256':hashlib.sha256((p/'producer.sh').read_bytes()).hexdigest(),'companionSHA256':hashlib.sha256(target.read_bytes()).hexdigest(),'snapshotSeconds':time.monotonic()-begin,'snapshotFileCount':len(manifest),'batchSourceVerification':True,'engineMutations':0},indent=2)+'\n')
PY
printf '%s\n' snapshot_pinned
cd "$out/src/platform"
set +e
"$GO" test -race -count=1 -json ./launcher -run '^TestOwnerBridgeHistoryActualRunFailurePublishesAndReleases$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
python3 - "$out" "$code" <<'PY'
import json,sys,datetime
from pathlib import Path
p=Path(sys.argv[1]);(p/'completion.json').write_text(json.dumps({'directExit':int(sys.argv[2]),'endedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
exit "$code"
