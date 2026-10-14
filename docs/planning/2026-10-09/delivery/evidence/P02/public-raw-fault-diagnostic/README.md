# Public caller raw cleanup diagnostic

This archive contains test-only fault-instrumented source and its recorded evidence. It does not claim that the unmodified candidate ran these injected failures. The original and instrumented source hashes, exact source bytes, unified diff, diagnostic test, producers, commands, exits and logs are preserved. No runtime binaries, credentials or private broker fixture data are included.

Three genuine public calls use real native NATS fixtures: TeamConnection.Observe receives an authenticated scoped snapshot, Probe performs a real health write and readback, and Observe reads the real existing record under read-only permissions. Test-only instrumentation wraps only the actual dialer-owned TCP socket and records actual facts immediately before cleanup. It neither supplies nor changes those facts. The first actual socket close fails.

The smallest Team check passed two named race-test entries, including its parent. The three caller cases then passed four named entries, including their parent. Each caller cleared its returned facts, retained the exact typed cleanup owner, and completed an idempotent bounded retry. The actual local TCP socket rejected writes with net.ErrClosed and its owner retained no sockets or cancellation hooks afterward. Probe and Observe also returned the broker connection count to zero. Direct remote peer EOF was not measured in these caller fixtures.

Each separate mutant removes one caller's fact reset. Each exits 1 and fails that caller's returned-facts assertion plus its parent. These expected failures show that the controls detect missing fact invalidation; they are not successful candidate runs.

The first observer-mutant producer selected an earlier raw-owner if-failed block. Its structural assertion rejected that location before mutation or test execution. The original producer and a fixed explanation remain archived. A separate repair producer used the exact caller precleanup anchor, after which the observer mutant failed at the expected assertion.

These diagnostics supplement the earlier source review and affected tests. They establish no native macOS, Docker Compose, installed runtime, or phase-gate acceptance. They add no production injection API and make no shared source, index, tracking or review-metadata change. Standard local filesystem and network Close behavior remains the product timing assumption; this API cannot preempt a blocking synchronous platform syscall. Independent review is separate and is not claimed by this archive.
