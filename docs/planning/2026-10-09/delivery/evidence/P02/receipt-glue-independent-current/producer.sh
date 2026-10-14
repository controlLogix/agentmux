set -eu
cache=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-receipt-glue-independent-XXXXXX)
printf '%s\n' "$cache"
cp "$0" "$cache/producer.sh"
cp -a /home/ryan/.cache/agentmux-tests/p02-owner-bridge-tls-candidate-utm1v8x6/platform "$cache/platform"
cp /mnt/c/Users/RyanHelms/GitHub/agentmux/docs/planning/2026-10-09/delivery/evidence/P02/owner-bridge-receipt/review.json "$cache/worker-review.json"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0
export AGENTMUX_TEST_NATS=/home/ryan/.cache/agentmux-governance/tools/nats-server
cd "$cache/platform"
go=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
date -u +%FT%TZ > "$cache/start.txt"
set +e
"$go" test -race -count=1 -json ./launcher -run '^(TestOwnerBridgeReceiptRequiresFreshEnteredOwner|TestOwnerBridgeJoinedCompletionRetainsExactCleanupCause|TestOwnerBridgeReceiptActualEntryAndDepartedFrontend|TestOwnerBridgeReceiptFixtureClosesBeforeAdoption)$' > "$cache/focused.jsonl" 2> "$cache/focused.stderr"
result=$?
printf '%s\n' "$result" > "$cache/focused.exit"
date -u +%FT%TZ > "$cache/end.txt"
exit "$result"