set -eu
root=/home/ryan/.cache/agentmux-governance
out=$(mktemp -d "$root/p02-network-policy-final-XXXXXX")
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-network-policy-final.sh "$out/producer.sh"
mkdir "$out/src"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$out/src/platform"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/contracts "$out/src/contracts"
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=0
export AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
FMT=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/gofmt
"$FMT" -w launcher/bootstrap_docker_integration_test.go launcher/installed_cli_compose_integration_linux_test.go
python3 - "$out" <<'PY'
import json,sys,datetime
from pathlib import Path
out=Path(sys.argv[1]);json.dump({'argv':['go','test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestBootstrapNetwork(CreationAndStoppedPolicy|ProjectionRequiresCompleteExactRoster|ProjectionPreservesExactUnknownNumbers|ImmutableProjectionAndRemovalOutput)$'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},open(out/'invocation.json','w'),indent=2)
PY
set +e
"$GO" test -race -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestBootstrapNetwork(CreationAndStoppedPolicy|ProjectionRequiresCompleteExactRoster|ProjectionPreservesExactUnknownNumbers|ImmutableProjectionAndRemovalOutput)$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
exit "$code"