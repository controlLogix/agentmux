set -eu
G=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin
$G/gofmt -w /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/deployment/local_tls_probe_transport.go /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/deployment/probe.go /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/deployment/observe.go /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/deployment/probe_cleanup.go /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/deployment/probe_cleanup_test.go
base=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-health-cleanup-first-XXXXXX)
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$base/platform"
cd "$base/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0
set +e
$G/go test -race -json ./deployment -run '^TestProbeCleanupFailureRetainsConcreteOwner$' -count=1 > "$base/focused.jsonl" 2> "$base/focused.stderr"
printf '%s\n' "$?" > "$base/exit-code"
printf '%s\n' "$base"