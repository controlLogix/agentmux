set -eu
base=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-health-cleanup-negative-XXXXXX)
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$base/platform"
cd "$base/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0
set +e
/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go test -race -json ./deployment -run '^TestProbeCleanupFailureRetainsConcreteOwner$' -count=1 > "$base/focused.jsonl" 2> "$base/focused.stderr"
printf '%s\n' "$?" > "$base/exit-code"
printf '%s\n' "$base"