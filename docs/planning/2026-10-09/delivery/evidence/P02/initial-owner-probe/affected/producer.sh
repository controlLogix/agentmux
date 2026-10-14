set -eu
out=/home/ryan/.cache/agentmux-governance/p02-probe-final-focused-QTdfh9
mkdir "$out/affected"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-probe-affected.sh "$out/affected/producer.sh"
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=0
export AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
python3 - "$out" <<'PY'
import json,datetime,sys
from pathlib import Path
p=Path(sys.argv[1])/'affected';(p/'invocation.json').write_text(json.dumps({'argv':['go','test','-race','-count=1','-json','./launcher','-run','^Test(OwnerBridge|InstalledHostPolicy|InstalledReceiptBinding|TransportCleanup)'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0','AGENTMUX_TEST_NATS':'/home/ryan/.cache/agentmux-governance/tools/nats-server'},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
set +e
"$GO" test -race -count=1 -json ./launcher -run '^Test(OwnerBridge|InstalledHostPolicy|InstalledReceiptBinding|TransportCleanup)' > "$out/affected/events.jsonl" 2> "$out/affected/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/affected/exit.txt"
if test "$code" -ne 0; then exit "$code"; fi
"$GO" vet ./launcher > "$out/affected/vet.stdout" 2> "$out/affected/vet.stderr"
code=$?
printf '%s\n' "$code" > "$out/affected/vet-exit.txt"
exit "$code"