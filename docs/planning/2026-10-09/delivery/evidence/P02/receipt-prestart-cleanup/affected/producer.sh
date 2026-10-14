#!/bin/bash
cd /mnt/c/Users/RyanHelms/GitHub/agentmux/platform || exit 2
d=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-receipt-prestart-affected-XXXXXX) || exit 2
printf '%s\n' "$d"
go=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
"$go" test -race -json ./runtime -run '^Test(BootstrapReceipt|ReceiptHost|HostReceipt|OwnedBootstrap)' -count=1 > "$d/events.jsonl" 2> "$d/stderr.log"
result=$?
printf '%s\n' "$result" > "$d/exit.txt"
"$go" vet ./runtime > "$d/vet.stdout" 2> "$d/vet.stderr"
v=$?
printf '%s\n' "$v" > "$d/vet-exit.txt"
printf 'test=%s vet=%s\n' "$result" "$v"
exit "$((result || v))"
