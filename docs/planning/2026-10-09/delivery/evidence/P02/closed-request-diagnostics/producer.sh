#!/bin/bash
set +e
cd "$(dirname "$0")/src/platform"
export GOPROXY=off GOSUMDB=off GORACE=atexit_sleep_ms=0 AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
$GO test -race -json ./launcher -run '^TestRequestDiagnostic(UnknownAncestryIsNotInvoked|RawCleanupPriority)$' -count=1 > ../../repaired.jsonl 2> ../../repaired-stderr.log
code=$?; printf '%s\n' "$code" > ../../repaired-exit.txt
if [ "$code" != 0 ]; then exit "$code"; fi
$GO test -race -json ./launcher ./cmd/agentmux-runtime -run '^Test(RequestDiagnostic|Frontend|OwnedBootstrapProgress|InstalledLauncher|TransportCleanup|RuntimeCleanup|KernelStatusStage|DockerInspectionStages|OwnerBridge(Refresh|ObservationCleanup|JoinedCompletion))' -count=1 > ../../affected.jsonl 2> ../../affected-stderr.log
printf '%s\n' "$?" > ../../affected-exit.txt
$GO vet ./launcher ./cmd/agentmux-runtime > ../../vet.log 2>&1
printf '%s\n' "$?" > ../../vet-exit.txt
