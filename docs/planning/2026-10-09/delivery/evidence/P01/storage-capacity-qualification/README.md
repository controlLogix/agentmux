# P01 storage capacity qualification evidence

The final folder contains the executed 27-case storage report, its safe summary log, source-bound review and actual default-bypass mutation result. The original twenty case IDs and module AST remain preserved; root independently reviews these claims before acceptance.

The historical-pre-oracle folder preserves the earlier 27-case execution and mutation result before the same explicit capacity invariant was applied to guarded and bypassed states. Its older source hashes are historical evidence, not final candidate proof.

The final run used a disposable, token-protected file-backed NATS Server 2.15.0 on WSL Linux with nats-py 2.16.0 and the independently compiled TypeScript storage client. All 27 cases passed in 21.792 seconds. The mutant fixture call raised the expected threshold assertion; the negative-control driver passed only after observing that failure. No independent mutant process exit1 is claimed.

This is a scaled one-task aggregate with two reserved final/reconciliation records, a 10,000-byte payload budget and conservative physical record slots. All writers must enter the owner admission boundary. Unguarded writers deliberately exhaust a separate real broker stream; final publication then reports unavailable without a false commit. No account-wide, disk-full, multi-task, object-store, R3, power-loss or production owner policy is qualified. Production admission remains P04. Native macOS/Linux candidate execution requires separate evidence.

Raw bytes and their SHA-256 hashes are preserved in manifest.json. No broker configuration/log, credential, signing key, provider prompt or live business data is archived. This bundle does not approve a phase, merge or release.
