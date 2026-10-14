#!/usr/bin/env bash
set -eu
export PATH=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin:/usr/bin:/bin
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly GORACE=atexit_sleep_ms=0
export AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
task_evidence=/mnt/c/Users/RyanHelms/GitHub/agentmux/docs/planning/2026-10-09/delivery/evidence/P02/local-sync-policy
task_cache=/home/ryan/.cache/agentmux-governance/local-sync-policy
if [ -e "$task_evidence/results" ]; then
  printf 'Existing evidence is retained. Select a new evidence directory for another run.\n' >&2
  exit 2
fi
mkdir -p "$task_cache"
task_snapshot=$(mktemp -d "$task_cache/candidate-XXXXXX")
cp -a /mnt/c/Users/RyanHelms/GitHub/agentmux/platform "$task_snapshot/platform"
cd "$task_snapshot/platform"
rg --files -g '*.go' -g go.mod -g go.sum | sort | xargs sha256sum > "$task_snapshot/source-before.sha256"
preserve_results() {
  sha256sum -c "$task_snapshot/source-before.sha256" > "$task_snapshot/source-after.txt"
  mkdir "$task_evidence/results"
  for task_file in source-before.sha256 source-after.txt focused.jsonl focused.stderr focused.exit affected.jsonl affected.stderr affected.exit vet.stderr vet.exit; do
    if [ -f "$task_snapshot/$task_file" ]; then
      cp "$task_snapshot/$task_file" "$task_evidence/results/$task_file"
    fi
  done
  printf 'Retained snapshot: %s\n' "$task_snapshot"
}
trap preserve_results EXIT
set +e
go test -race -count=1 -timeout=90s -run '^Test(LocalSyncPolicy|StorageFactory)' -json ./deployment > "$task_snapshot/focused.jsonl" 2> "$task_snapshot/focused.stderr"
task_result=$?
set -e
printf '%s\n' "$task_result" > "$task_snapshot/focused.exit"
if [ "$task_result" -ne 0 ]; then exit "$task_result"; fi
set +e
go test -race -count=1 -timeout=180s -json ./deployment > "$task_snapshot/affected.jsonl" 2> "$task_snapshot/affected.stderr"
task_result=$?
set -e
printf '%s\n' "$task_result" > "$task_snapshot/affected.exit"
if [ "$task_result" -ne 0 ]; then exit "$task_result"; fi
set +e
go vet ./deployment > "$task_snapshot/vet.stderr" 2>&1
task_result=$?
set -e
printf '%s\n' "$task_result" > "$task_snapshot/vet.exit"
exit "$task_result"
