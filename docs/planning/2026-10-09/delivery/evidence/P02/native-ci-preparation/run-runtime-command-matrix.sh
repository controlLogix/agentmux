#!/usr/bin/env bash
set -eu
export PATH=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin:/usr/bin:/bin
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOENV=off GOWORK=off GOFLAGS=-mod=readonly GORACE=atexit_sleep_ms=0
export AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
task_root=/mnt/c/Users/RyanHelms/GitHub/agentmux
task_evidence="$task_root/docs/planning/2026-10-09/delivery/evidence/P02/native-ci-preparation/ten-package-matrix"
if [ -e "$task_evidence" ]; then exit 2; fi
task_cache=/home/ryan/.cache/agentmux-governance/runtime-command-matrix
mkdir -p "$task_cache"
task_snapshot=$(mktemp -d "$task_cache/candidate-XXXXXX")
cp -a "$task_root/platform" "$task_snapshot/platform"
cp "$task_root/tests/platform/native_go.py" "$task_snapshot/native_go.py"
cd "$task_snapshot"
rg --files -g '*.go' -g go.mod -g go.sum -g native_go.py | sort | xargs sha256sum > source-before.sha256
preserve_results() {
 cd "$task_snapshot"
 sha256sum -c "$task_snapshot/source-before.sha256" > "$task_snapshot/source-after.txt"
 mkdir -p "$task_evidence"
 for task_file in source-before.sha256 source-after.txt inventory.json inventory.stderr inventory.exit matrix.json matrix.stderr matrix.exit command.jsonl command.stderr command.exit vet.stderr vet.exit; do
  if [ -f "$task_snapshot/$task_file" ]; then cp "$task_snapshot/$task_file" "$task_evidence/$task_file"; fi
 done
 printf 'Runtime command matrix snapshot retained: %s\n' "$task_snapshot"
}
trap preserve_results EXIT
cd platform
set +e
go list -mod=readonly -json ./... > "$task_snapshot/inventory.json" 2> "$task_snapshot/inventory.stderr"
task_result=$?
set -e
printf '%s\n' "$task_result" > "$task_snapshot/inventory.exit"
if [ "$task_result" -ne 0 ]; then exit "$task_result"; fi
set +e
python3 -B -c 'import importlib.util,json,pathlib,sys; spec=importlib.util.spec_from_file_location("reviewed_collector",sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); print(json.dumps(module.validate_package_matrix(pathlib.Path(sys.argv[2]).read_text()),indent=2))' "$task_snapshot/native_go.py" "$task_snapshot/inventory.json" > "$task_snapshot/matrix.json" 2> "$task_snapshot/matrix.stderr"
task_result=$?
set -e
printf '%s\n' "$task_result" > "$task_snapshot/matrix.exit"
if [ "$task_result" -ne 0 ]; then exit "$task_result"; fi
set +e
go test -race -count=1 -timeout=180s -json ./cmd/agentmux-runtime ./localtls ./privatefs > "$task_snapshot/command.jsonl" 2> "$task_snapshot/command.stderr"
task_result=$?
set -e
printf '%s\n' "$task_result" > "$task_snapshot/command.exit"
if [ "$task_result" -ne 0 ]; then exit "$task_result"; fi
set +e
go vet ./cmd/agentmux-runtime ./localtls ./privatefs > "$task_snapshot/vet.stderr" 2>&1
task_result=$?
set -e
printf '%s\n' "$task_result" > "$task_snapshot/vet.exit"
exit "$task_result"
