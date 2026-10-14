# Recorded exact producer shape after execution; no replay was run.
# Each run used its immutable source path recorded in review.json.
GORACE=atexit_sleep_ms=0 GOPROXY=off GOSUMDB=off /home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go test -race -json ./cmd/agentmux-runtime -run '^TestFrontend(Budget|CleanupNever|Status|Earlier)' -count=1
GORACE=atexit_sleep_ms=0 GOPROXY=off GOSUMDB=off /home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go test -race -json ./cmd/agentmux-runtime -run '^TestFrontendNearExpiryOwnedReceiptRetainsUnknownFactsAndCleanup$' -count=1
GORACE=atexit_sleep_ms=0 GOPROXY=off GOSUMDB=off /home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go test -race -json ./cmd/agentmux-runtime -count=1
GOPROXY=off GOSUMDB=off /home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go vet ./cmd/agentmux-runtime
