# Startup reporting before the broker is available

Status: implementation in progress. Runtime receipt handling has independent Linux component evidence. Installed CLI timing, full Compose behavior and native platform qualification remain open.

The installed launcher needs to report progress within ten seconds of invocation, even when its local NATS broker has not started. An authenticated NATS response remains the source of instance details, service readiness, persistence, work and connected hubs.

The newly spawned, verified host receives one private inherited pipe. It sends one bounded lifecycle receipt, bound to the full kernel scope, exact owner enrollment digest, actual cold invocation and held executable digest. The pipe is OS process lifecycle infrastructure. It carries no agent messages, tasks, status snapshots or application communication. All such communication uses NATS.

The bootstrap core sends `accepted` only after complete admission and protected executable preparation, when the real service-lease-owning operation has entered. Opening the pipe or constructing an operation does not establish acceptance. Receipt I/O occurs outside the operation state lock. A frontend closing the pipe must not cancel the owned host startup.

The frontend first seeks authenticated NATS details. After spawning its exact verified child, it reads the receipt and requests NATS details again within its original ten-second budget. If those details remain unavailable, an accepted receipt can produce a separate `bootstrap-progress` document with `requestDisposition: accepted`, `instanceState: unknown` and `detailsAvailable: false`. This records earlier admitted entry, not current in-flight execution: the bootstrap call may have completed or failed while its host is still alive. Only authenticated NATS observations supply current `starting` or readiness. Before the receipt fallback, the frontend checks its original caller cancellation and the exact child's completed wait. A known child exit prevents successful request acceptance output. Authentication, enrollment, malformed replies and cleanup errors remain failures.

An independently launched later terminal cannot recover the earlier pipe or infer another owner's identity from a PID, lock metadata or file age. It must obtain details from authenticated NATS. The current lock API does not prove contention merely by returning `StartingElsewhereError`: that error can also occur before the first lock attempt. Until an actual contention capability is implemented and reviewed, this path reports unconfirmed startup rather than manufacturing an owner or readiness claim.

The receipt requires one strict JSON frame, at most 4096 bytes including its length header, exact binding and EOF. Cancellation closes and joins owned receipt I/O. It does not add another process wait or signal a caller-provided PID. The original installed-host API remains available.

This extends the existing PLAN-04 startup facade. Keeping startup entirely synchronous through NATS is simpler but cannot report admitted progress while the broker is absent. The receipt adds descriptor ownership, framing, correlation and cancellation obligations. It is intentionally limited to newly spawned host lifecycle control and is not a second application bus.

Evidence: [independent runtime review](../evidence/P02/bootstrap-receipt-independent/independent-review.json), [policy binding checks](../evidence/P02/host-receipt-binding/review.json). These records do not accept P02.
