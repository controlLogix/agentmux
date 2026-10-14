set -eu
base=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-health-cleanup-affected-XXXXXX)
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$base/platform"
cd "$base/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
G=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
set +e
$G test -race -json ./deployment -count=1 > "$base/affected.jsonl" 2> "$base/affected.stderr"
status=$?
printf '%s\n' "$status" > "$base/test-exit"
if [ "$status" -eq 0 ]; then
 $G vet ./deployment > "$base/vet.stdout" 2> "$base/vet.stderr"
 printf '%s\n' "$?" > "$base/vet-exit"
fi
printf '%s\n' "$base"