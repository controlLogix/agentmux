set -euo pipefail
base="$HOME/.cache/agentmux-governance"
run=$(mktemp -d "$base/p02-host-receipt-binding-XXXXXX")
mkdir -p "$run/src" "$run/tmp"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$run/src/platform"
mkdir -p "$run/src/contracts"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/contracts/v1 "$run/src/contracts/v1"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GORACE=atexit_sleep_ms=0
export TMPDIR="$run/tmp" AGENTMUX_TEST_NATS="$base/tools/nats-server"
go="$base/runtime-comparison/go/bin/go"
"$base/runtime-comparison/go/bin/gofmt" -w /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/launcher/host_receipt_binding.go /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/launcher/host_receipt_binding_test.go
cp /mnt/c/Users/RyanHelms/GitHub/agentmux/platform/launcher/host_receipt_binding*.go "$run/src/platform/launcher/"
cd "$run/src/platform"
set +e
"$go" test -race -json -count=1 -timeout=90s ./launcher -run '^TestInstalledReceiptBinding' > "$run/events.jsonl" 2> "$run/stderr.log"
code=$?
printf '%s\n' "$code" > "$run/exit.txt"
printf '%s\n' "$run"
tail -n 12 "$run/events.jsonl"
exit "$code"