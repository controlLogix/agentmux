set -uo pipefail
base="$HOME/.cache/agentmux-governance"
source_run="$base/p02-foundation-current-EWrjCk"
run=$(mktemp -d "$base/p02-compose-current-XXXXXX")
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GORACE=atexit_sleep_ms=0
export TMPDIR="$source_run/tmp" AGENTMUX_TEST_NATS="$base/tools/nats-server" AMX_BOOTSTRAP_DOCKER_AUTHORIZED=1
unset DOCKER_HOST DOCKER_CONTEXT AMX_BROKER_INSPECT_FIXTURE AMX_DOCKER_FIXTURE AGENTMUX_NATS_SERVER
cd "$source_run/src/platform"
go="$base/runtime-comparison/go/bin/go"
printf '%s\n' "$run"
printf '%s\n' "$source_run" > "$run/source-snapshot.txt"
"$go" test -race -json -count=1 -timeout=300s -tags=agentmux_bootstrap_docker -run '^TestBootstrapRealDockerIdentityPreflight$' ./launcher > "$run/preflight.jsonl" 2> "$run/preflight.stderr"
code=$?
printf '%s\n' "$code" > "$run/preflight.exit"
if [ "$code" -ne 0 ]; then tail -n 15 "$run/preflight.jsonl"; exit "$code"; fi
"$go" test -race -json -count=1 -timeout=300s -tags=agentmux_bootstrap_docker -run '^TestBootstrapRealComposeConcurrentColdWarmAndOwnerRecovery$' ./launcher > "$run/compose.jsonl" 2> "$run/compose.stderr"
code=$?
printf '%s\n' "$code" > "$run/compose.exit"
tail -n 12 "$run/compose.jsonl"
exit "$code"