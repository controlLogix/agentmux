set -eu
cache=/home/ryan/.cache/agentmux-governance
candidate="$cache/p02-foundation-stable-SlyUk1"
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/contracts/v1 "$candidate/contracts/v1"
cp "$0" "$candidate/schema-input-repair-producer.sh"
cd "$candidate/platform"
export PATH="$cache/runtime-comparison/go/bin:$cache/tools:$PATH"
export AGENTMUX_TEST_NATS="$cache/tools/nats-server"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GORACE=atexit_sleep_ms=0
unset DOCKER_HOST DOCKER_CONTEXT AMX_BOOTSTRAP_DOCKER_AUTHORIZED AMX_BROKER_INSPECT_FIXTURE AMX_DOCKER_FIXTURE
set +e
go test -race -json -count=1 -timeout=90s -run '^TestOwnerBridgeSchemaCopiesAndFullAdmission$' ./launcher > "$candidate/schema-focused.jsonl" 2> "$candidate/schema-focused.stderr"
r=$?
printf '%s\n' "$r" > "$candidate/schema-focused.exit"
if [ "$r" -ne 0 ]; then exit "$r"; fi
go test -race -json -count=1 -timeout=300s ./launcher > "$candidate/launcher-affected.jsonl" 2> "$candidate/launcher-affected.stderr"
r=$?
printf '%s\n' "$r" > "$candidate/launcher-affected.exit"
if [ "$r" -ne 0 ]; then exit "$r"; fi
go vet ./... > "$candidate/vet.stdout" 2> "$candidate/vet.stderr"
r=$?
printf '%s\n' "$r" > "$candidate/vet.exit"
exit "$r"