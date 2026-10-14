set -eu
umask 077
out=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-yxc-poststop-readonly-XXXXXX)
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-yxc-poststop-run.sh "$out/producer.sh"
cp -a /home/ryan/.cache/agentmux-governance/p02-yxc-readonly-IqcXT9/src "$out/src"
cp /home/ryan/.cache/agentmux-governance/p02-yxc-poststop-source/source.go "$out/src/platform/launcher/yxc_recovery_qualification_test.go"
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=1 AMX_YXC_POSTSTOP_READONLY_AUTHORIZED=1 AMX_YXC_QUALIFICATION_OUTPUT="$out"
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
python3 - "$out" "$GO" <<'PY'
import json,datetime,sys,hashlib
from pathlib import Path
p=Path(sys.argv[1]);s=p/'src/platform/launcher/yxc_recovery_qualification_test.go'
assert hashlib.sha256(s.read_bytes()).hexdigest()=='74aacb5689897570c9c2aff9a2e429d61c16f49364acdce3a6421ac5378285c6'
record={'argv':[sys.argv[2],'test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestYxcRetainedFixturePostStopReadOnly$'],'environment':{k:__import__('os').environ[k] for k in ['GOPROXY','GOSUMDB','GOWORK','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED','AMX_YXC_POSTSTOP_READONLY_AUTHORIZED','AMX_YXC_QUALIFICATION_OUTPUT']},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sourceSHA256':hashlib.sha256(s.read_bytes()).hexdigest(),'producerSHA256':hashlib.sha256((p/'producer.sh').read_bytes()).hexdigest()}
(p/'invocation.json').write_text(json.dumps(record,indent=2)+'\n')
PY
set +e
"$GO" test -race -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestYxcRetainedFixturePostStopReadOnly$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
python3 - "$out" "$code" <<'PY'
import json,datetime,sys
from pathlib import Path
p=Path(sys.argv[1]);(p/'completion.json').write_text(json.dumps({'endedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'directExit':int(sys.argv[2])},indent=2)+'\n')
PY
exit "$code"
