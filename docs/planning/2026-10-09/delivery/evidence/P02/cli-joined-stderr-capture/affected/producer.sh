set -eu
root=/home/ryan/.cache/agentmux-governance
out=$(mktemp -d "$root/p02-capture-affected-XXXXXX")
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-capture-affected.sh "$out/producer.sh"
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
FMT=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/gofmt
"$FMT" -w /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/launcher/installed_cli_compose_integration_linux_test.go
mkdir "$out/src"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$out/src/platform"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/contracts "$out/src/contracts"
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=0
python3 - "$out" <<'PY'
import sys,json,datetime
from pathlib import Path
p=Path(sys.argv[1]);(p/'invocation.json').write_text(json.dumps({'argv':['go','test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestComposeCLI'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
set +e
"$GO" test -race -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestComposeCLI' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
if test "$code" -ne 0; then exit "$code"; fi
"$GO" vet -tags=agentmux_bootstrap_docker ./launcher > "$out/vet.stdout" 2> "$out/vet.stderr"
code=$?
printf '%s\n' "$code" > "$out/vet-exit.txt"
exit "$code"