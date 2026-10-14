#!/usr/bin/env bash
set -eu
export PATH=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin:/usr/bin:/bin
export GOTOOLCHAIN=local GOWORK=off GOENV=off GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly GORACE=atexit_sleep_ms=0
export AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
task_repo=/mnt/c/Users/RyanHelms/GitHub/agentmux
task_evidence="$task_repo/docs/planning/2026-10-09/delivery/evidence/P02/team-connection/basic-worker"
task_snapshot=$(mktemp -d /home/ryan/.cache/agentmux-governance/basic-worker-XXXXXX)
cp -a "$task_repo/platform" "$task_snapshot/platform"
cd "$task_snapshot/platform"
rg --files -g '*.go' -g go.mod -g go.sum | sort | xargs sha256sum > "$task_snapshot/source-before.sha256"
preserve_results() {
  sha256sum -c "$task_snapshot/source-before.sha256" > "$task_snapshot/source-after.txt"
  mkdir -p "$task_evidence/$(basename "$task_snapshot")"
  for task_file in source-before.sha256 source-after.txt focused.jsonl focused.stderr focused.exit tools.txt; do
    if [ -f "$task_snapshot/$task_file" ]; then cp "$task_snapshot/$task_file" "$task_evidence/$(basename "$task_snapshot")/$task_file"; fi
  done
  printf 'Retained basic worker snapshot: %s\n' "$task_snapshot"
}
trap preserve_results EXIT
task_selection='^TestTeamBasic'
if [ "${1:-all}" = failed ]; then task_selection='^TestTeamBasicCallerCancellationAndEarlierDeadlineDuringSetup$'; fi
if [ "${1:-all}" = info ]; then task_selection='^TestTeamBasicRealTLSPrivateResolverAndScopedSnapshot$/^info-unavailable$'; fi
{
  go version
  "$AGENTMUX_TEST_NATS" -v
  go list -mod=readonly -m github.com/nats-io/nats.go github.com/nats-io/nkeys
  sha256sum "$(command -v go)" "$AGENTMUX_TEST_NATS"
  printf 'Command: go test -race -count=1 -timeout=90s -run %s -json ./deployment\n' "$task_selection"
} > "$task_snapshot/tools.txt"
set +e
go test -race -count=1 -timeout=90s -run "$task_selection" -json ./deployment > "$task_snapshot/focused.jsonl" 2> "$task_snapshot/focused.stderr"
task_result=$?
set -e
printf '%s\n' "$task_result" > "$task_snapshot/focused.exit"
exit "$task_result"
