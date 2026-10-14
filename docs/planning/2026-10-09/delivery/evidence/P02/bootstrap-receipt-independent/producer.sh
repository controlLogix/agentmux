set -eu
cache=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-receipt-independent-XXXXXX)
printf '%s\n' "$cache"
cp "$0" "$cache/producer.sh"
cp -a /home/ryan/.cache/agentmux-governance/p02-bootstrap-receipt-repaired-1e5ce2c4/platform "$cache/platform"
cp /home/ryan/.cache/agentmux-governance/p02-bootstrap-receipt-repaired-1e5ce2c4/review.json "$cache/worker-review.json"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0
cd "$cache/platform"
go=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
date -u +%FT%TZ > "$cache/start.txt"
set +e
"$go" test -race -count=1 -json ./runtime -run '^(TestBootstrapReceipt|TestInstalledHost)' > "$cache/focused.jsonl" 2> "$cache/focused.stderr"
result=$?
printf '%s\n' "$result" > "$cache/focused.exit"
"$go" vet ./runtime > "$cache/vet.stdout" 2> "$cache/vet.stderr"
printf '%s\n' "$?" > "$cache/vet.exit"
date -u +%FT%TZ > "$cache/end.txt"
exit "$result"