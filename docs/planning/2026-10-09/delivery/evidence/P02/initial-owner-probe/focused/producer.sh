set -eu
root=/home/ryan/.cache/agentmux-governance
out=$(mktemp -d "$root/p02-probe-final-focused-XXXXXX")
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-probe-final-focused.sh "$out/producer.sh"
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
FMT=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/gofmt
"$FMT" -w /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/launcher/owner_bridge_probe.go /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/launcher/owner_bridge_probe_test.go /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/launcher/owner_bridge.go /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/launcher/host_policy.go
mkdir "$out/src"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$out/src/platform"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/contracts "$out/src/contracts"
cd "$out/src/platform"
export AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=0
python3 - "$out" <<'PY'
import sys,json,datetime
from pathlib import Path
p=Path(sys.argv[1]);(p/'invocation.json').write_text(json.dumps({'argv':['go','test','-race','-count=1','-json','./launcher','-run','^TestOwnerBridge(NativeNoRespondersFrame|InitialProbeNoResponderHint|ProbeNativeHintShapeRefusals|OptionalReplyMustMatchValidatedNonce|ProbeAvailablePreservesLegacyRouting|ProbeRejectsActualMalformedHint|ProbePermissionFailureStaysHard|ProbeCanceledContextHasNoHint|DelayedSubscriptionRepeatsExactRequest)$'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2)+'\n')
PY
set +e
"$GO" test -race -count=1 -json  ./launcher -run '^TestOwnerBridge(NativeNoRespondersFrame|InitialProbeNoResponderHint|ProbeNativeHintShapeRefusals|OptionalReplyMustMatchValidatedNonce|ProbeAvailablePreservesLegacyRouting|ProbeRejectsActualMalformedHint|ProbePermissionFailureStaysHard|ProbeCanceledContextHasNoHint|DelayedSubscriptionRepeatsExactRequest)$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
exit "$code"