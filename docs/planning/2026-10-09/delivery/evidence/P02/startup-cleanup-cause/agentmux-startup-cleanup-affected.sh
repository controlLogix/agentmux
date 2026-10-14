set -uo pipefail
base="$HOME/.cache/agentmux-governance"
run="$base/p02-startup-cleanup-cause-Y0FwcH"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GORACE=atexit_sleep_ms=0
export TMPDIR="$run/tmp" AGENTMUX_TEST_NATS="$base/tools/nats-server"
go="$base/runtime-comparison/go/bin/go"
cd "$run/src/platform"
"$go" test -race -json -count=1 -timeout=90s ./runtime -run '^(TestParentCancellationReapsProcesses|TestCanceledStartupCreatesNoProcesses|TestCancellationDuringPartialStartupReapsOwnedChildren)$' > "$run/affected.jsonl" 2> "$run/affected.stderr"
code=$?
printf '%s\n' "$code" > "$run/affected.exit"
"$go" vet ./runtime > "$run/vet.stdout" 2> "$run/vet.stderr"
vet=$?
printf '%s\n' "$vet" > "$run/vet.exit"
printf 'affected=%s vet=%s\n' "$code" "$vet"
tail -n 5 "$run/affected.jsonl"
if [ "$code" -ne 0 ]; then exit "$code"; fi
exit "$vet"