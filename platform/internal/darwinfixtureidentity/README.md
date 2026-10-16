# Darwin fixture identity helper

This package supports installed CLI tests. It is internal test code, enabled only by `darwin && cgo && agentmux_bootstrap_docker`. It does not add a production process-control API or a local status channel.

The implementation is under review. Seven pure race controls passed an earlier source candidate. A later verified local snapshot passed 22 top-level controls and 15 subtests with race detection, including the parser, role-owner bookkeeping and interrupted-event repair. No protected-image child control, installed CLI qualification or SDK 27 enrollment has passed through this package. See `docs/planning/2026-10-09/delivery/evidence/P02/local-darwin-identity/` for the bounded review records.

## Ownership and authority

`NewCreator` admits this process's native identity. `Creator.StartProtected` builds and starts its own command. No API accepts a caller PID, audit token, process handle or mutable command.

`Launch.Args` excludes argv[0]. `Proof.LiteralArgs` returns an independent copy including the protected path as argv[0]. Environment entries and arguments remain private test inputs.

Successful protected launch returns an owned handle and records a timestamp. A post-start admission failure is retained for Pin; it is not reported as a failed launch. Fast status, warm or refusal commands can still return their exact joined outcome without gaining descendant authority. Cold creation and receipt binding must explicitly require full Pin. No admission is retried after reaping. While the original child remains unreaped, the helper captures minimal native cleanup authority: PID, version, unique identity, creation-parent unique identity and real/effective user IDs. `Owned.Signal` accepts only TERM or KILL and rechecks that identity before the version-bound native send. This authority cannot discover descendants or provide full proof. If minimal admission fails, the helper retains the original child and sole Wait but grants no cleanup signal authority.

Full proof requires the protected image, digest, literal arguments, native lineage and an exact process watch. The helper observes identity, path and arguments around watch registration. Current PPID is checked for direct-child creation, but it is excluded from later stability comparisons because reparenting changes it. Creation-parent unique identity remains required.

The internal roster engine discovers a complete expected roster through bounded UID enumeration. It reads minimal identity before path or arguments, filters by creation-parent unique identity, rejects missing, extra or ambiguous members, retains a protected descriptor for each child, installs watches and repeats the complete roster and child observations. A parent with an exact exit observation can remain a lineage anchor. A closed or executed parent cannot.

`Proof.PinDirectHost` admits one host with a closed, ordered invocation grammar. Its generated attempt is validated and frozen. `Proof.PinDirectRoles` derives all four paths and digests from verified assembly policy, retains all four runtime-prepared images through a shared owner, and revalidates the complete assembly after watch registration. It never treats a role in `bin/` as a standalone host image. Review found runtime paths that discarded close errors or returned only the first cause. Those paths now have a separately reviewed repair and three local Darwin race controls. Actual deferred caller fault injection and the full affected lifecycle suite remain open; the role adapter does not establish complete rollback qualification.

Exported handles hold shared private state. Copying a handle does not duplicate Wait, descriptor or signal ownership. Watch and image close attempts are consumed once; uncertain close failures stay attached to the retained handle. The helper never retries an uncertain numeric descriptor or falls back to an unbound PID signal.

`Owned.Join` is the sole Wait owner. Completion time follows command Wait and stream-copy completion. Output captures are independent, bounded to 64 KiB per stream, and report overflow and copy errors. `exec.ErrWaitDelay` remains available through `errors.Is` on the safe Wait error; it is a failed output join, not clean completion. There are no caller-provided live output writers. Callers can read copied bounded snapshots after Join.

## SDK 27 qualification proposal

Normal admission still refuses SDK 27. Header declarations and allowed symbol origins alone do not qualify the private ABI.

Before changing normal admission:

1. Review a separate diagnostic-only build tag and an exact candidate tuple: native ARM64, macOS 26.6, Darwin 25.6 and the actual SDK 27 build identifier. Keep this route separate from `NewCreator` and production code.
2. Record compiler structure sizes and field offsets, actual native observation return sizes, runtime library origins and translation state. Match the private selector and layout to reviewed source evidence.
3. Run controls against children created by that diagnostic process only. Check minimal lineage, changed identity and version refusal, the helper's signal-zero policy, exact exit/exec events, TERM/KILL, one Wait and joined output. Do not adopt arbitrary processes.
4. Build a minimal cooperative fixture in private cache. Review source, digest, exact protected release path and installation/cleanup commands before any privileged installation. No privileged installation is currently authorized.
5. After separate approval, install the reviewed immutable root-owned fixture. Run full protected-image, literal-argument, wrong-image, wrong-digest, wrong-argv, extra-child, reparenting, cleanup and descriptor-lifetime controls.
6. Independently review retained evidence. Only then consider exact candidate admission. A pure test pass or compiler success cannot establish native qualification.

There is no actual PID-reuse qualification yet. Wrong-version refusal must never be described as observed PID reuse.

## Diagnostic results retained so far

The first exact-tuple diagnostic passed compiler layout, own-child TERM/KILL and wrong-version refusal, but failed its final exec exit-event read. That read error was not classified. A separate classify-only rerun recorded an actual EINTR failure at the same observation. Both failed runs are retained. Neither run qualifies SDK 27. Signal zero was refused by helper policy; no native signal-zero call was made.

The implemented repair retries only EINTR within the diagnostic control's original three-second deadline. Normal proof zero-time observations allow at most three attempts and then return an explicit failure. Deterministic controls passed for other errors remaining hard failures and interruption not resetting the deadline. The repaired native run also recorded actual interruptions before successful exact exit observations. Both failed runs remain retained. Full protected-image child, roster and installed CLI qualification remain pending.

Private candidate admission is now implemented behind the separate diagnostic tag and shared creator guards. It propagates only through internal opaque state. Normal NewCreator still refuses SDK 27. Protected fast-exit and full host/role controls have not run; a passing primitive diagnostic cannot replace them. Native argv parsing accepts at most 64 arguments within 256 KiB, including the 38 arguments required for 16 workspace roots.
