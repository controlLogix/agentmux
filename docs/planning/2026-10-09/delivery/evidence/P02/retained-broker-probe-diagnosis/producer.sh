set -eu
out=/home/ryan/.cache/agentmux-governance/p02-retained-initial-probe-dor9zl_x
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-retained-probe-run.sh "$out/producer.sh"
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=0
export AMX_RETAINED_PROBE_OUTPUT="$out"
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
python3 - "$out" <<'PY'
import json,sys,datetime
from pathlib import Path
p=Path(sys.argv[1]);(p/'invocation.json').write_text(json.dumps({'argv':['go','test','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestRetainedInitialProbeReadOnly$'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
set +e
"$GO" test -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestRetainedInitialProbeReadOnly$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
exit "$code"