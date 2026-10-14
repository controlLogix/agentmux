set -eu
out=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-yxc-readonly-XXXXXX)
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-yxc-qualification-run.sh "$out/producer.sh"
cp -a /home/ryan/.cache/agentmux-governance/p02-probe-pending-real-Yxc908/src "$out/src"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-yxc-recovery-qualification.go "$out/src/platform/launcher/yxc_recovery_qualification_test.go"
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=1 AMX_YXC_QUALIFICATION_OUTPUT="$out"
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/gofmt -w launcher/yxc_recovery_qualification_test.go
python3 - "$out" <<'PY'
import json,datetime,sys
from pathlib import Path
p=Path(sys.argv[1]);(p/'invocation.json').write_text(json.dumps({'argv':['go','test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestYxcRetainedFixtureReadOnlyQualification$'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'1','AMX_YXC_QUALIFICATION_OUTPUT':str(p)},'engineMutations':0,'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
set +e
"$GO" test -race -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestYxcRetainedFixtureReadOnlyQualification$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
exit "$code"