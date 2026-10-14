set -uo pipefail
base="$HOME/.cache/agentmux-governance"
run=$(mktemp -d "$base/p02-foundation-current-XXXXXX")
mkdir -p "$run/src/contracts" "$run/tmp"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$run/src/platform"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/contracts/v1 "$run/src/contracts/v1"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GORACE=atexit_sleep_ms=0
export TMPDIR="$run/tmp" AGENTMUX_TEST_NATS="$base/tools/nats-server"
go="$base/runtime-comparison/go/bin/go"
cd "$run/src/platform"
printf '%s\n' "$run"
"$go" test -race -json -count=1 -timeout=300s ./... > "$run/events.jsonl" 2> "$run/stderr.log"
code=$?
printf '%s\n' "$code" > "$run/exit.txt"
"$go" vet ./... > "$run/vet.stdout" 2> "$run/vet.stderr"
vet=$?
printf '%s\n' "$vet" > "$run/vet.exit"
printf 'foundation=%s vet=%s\n' "$code" "$vet"
tail -n 6 "$run/events.jsonl"
if [ "$code" -ne 0 ]; then exit "$code"; fi
exit "$vet"