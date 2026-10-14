set -eu
out=/home/ryan/.cache/agentmux-governance/p02-real-installed-cli-abrupt-szNYOQ
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-real-cli-final-four.sh "$out/final-producer.sh"
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=1
export AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
python3 - "$out" <<'PY'
import json,sys,datetime
from pathlib import Path
out=Path(sys.argv[1]);json.dump({'argv':['go','test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestInstalledCLIRealCompose'],'vetArgv':['go','vet','-tags=agentmux_bootstrap_docker','./launcher'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'1'},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},open(out/'final-invocation.json','w'),indent=2)
PY
set +e
"$GO" test -race -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestInstalledCLIRealCompose' > "$out/final-events.jsonl" 2> "$out/final-stderr.log"
code=$?
printf '%s\n' "$code" > "$out/final-exit.txt"
if [ "$code" -ne 0 ]; then exit "$code"; fi
"$GO" vet -tags=agentmux_bootstrap_docker ./launcher > "$out/vet.stdout" 2> "$out/vet.stderr"
vetcode=$?
printf '%s\n' "$vetcode" > "$out/vet.exit"
exit "$vetcode"