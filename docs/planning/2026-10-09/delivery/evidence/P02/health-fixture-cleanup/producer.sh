set -eu
G=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin
$G/gofmt -w /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/deployment/probe_cleanup_test.go
base=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-health-fixture-cleanup-XXXXXX)
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$base/platform"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-health-fixture-cleanup.sh "$base/producer.sh"
cd "$base/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0
printf '%s\n' 'go test -race -json ./deployment -run ^TestProbeCleanup(FailureRetainsConcreteOwner|EarlyFailuresJoinOwnedResources)$ -count=1' > "$base/invocation.txt"
date -u +%FT%T.%NZ > "$base/test-start"
set +e
$G/go test -race -json ./deployment -run '^TestProbeCleanup(FailureRetainsConcreteOwner|EarlyFailuresJoinOwnedResources)$' -count=1 > "$base/focused.jsonl" 2> "$base/focused.stderr"
status=$?
printf '%s\n' "$status" > "$base/test-exit"
date -u +%FT%T.%NZ > "$base/test-end"
if [ "$status" -eq 0 ]; then
 date -u +%FT%T.%NZ > "$base/vet-start"
 $G/go vet ./deployment > "$base/vet.stdout" 2> "$base/vet.stderr"
 printf '%s\n' "$?" > "$base/vet-exit"
 date -u +%FT%T.%NZ > "$base/vet-end"
fi
printf '%s\n' "$base"