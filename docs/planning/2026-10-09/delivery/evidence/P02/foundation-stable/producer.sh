set -eu
cache=/home/ryan/.cache/agentmux-governance
candidate=$(mktemp -d "$cache/p02-foundation-stable-XXXXXX")
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$candidate/platform"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/docs/planning/2026-10-09/delivery/contracts "$candidate/contracts"
cp "$0" "$candidate/producer.sh"
cd "$candidate/platform"
export PATH="$cache/runtime-comparison/go/bin:$cache/tools:$PATH"
export AGENTMUX_TEST_NATS="$cache/tools/nats-server"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GORACE=atexit_sleep_ms=0
unset DOCKER_HOST DOCKER_CONTEXT AMX_BOOTSTRAP_DOCKER_AUTHORIZED AMX_BROKER_INSPECT_FIXTURE AMX_DOCKER_FIXTURE
printf '%s\n' "$candidate"
set +e
go test -race -json -count=1 -timeout=300s ./... > "$candidate/foundation.jsonl" 2> "$candidate/foundation.stderr"
r=$?
printf '%s\n' "$r" > "$candidate/foundation.exit"
if [ "$r" -ne 0 ]; then exit "$r"; fi
go vet ./... > "$candidate/vet.stdout" 2> "$candidate/vet.stderr"
r=$?
printf '%s\n' "$r" > "$candidate/vet.exit"
exit "$r"