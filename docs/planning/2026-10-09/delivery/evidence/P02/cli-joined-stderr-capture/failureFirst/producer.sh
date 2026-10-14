set -eu
out=/home/ryan/.cache/agentmux-governance/p02-stderr-capture-before-p_zlta13
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-stderr-before-run.sh "$out/producer.sh"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-stderr-before-prepare.py "$out/preparation-producer.py"
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=0
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/gofmt -w launcher/installed_cli_compose_integration_linux_test.go
python3 - "$out" <<'PY'
import json,sys,datetime
from pathlib import Path
p=Path(sys.argv[1]);(p/'invocation.json').write_text(json.dumps({'argv':['go','test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestComposeCLIOutputCaptureRequiresJoinedWait$'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
set +e
"$GO" test -race -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestComposeCLIOutputCaptureRequiresJoinedWait$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
exit "$code"