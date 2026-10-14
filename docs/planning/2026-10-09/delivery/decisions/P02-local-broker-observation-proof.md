# One broker inspection within a bootstrap observation

Status: implemented with component review and a passing real WSL Compose flow. Installed CLI and supported-platform acceptance remain open.

## Observed problem

The isolated real Compose timing run `p02-real-tls-timing-PJeFfc` measured a complete present-broker inspection at 2,525 ms. Kernel observation repeated that inspection, taking 2,389 ms and 2,398 ms. Its three-second budget then left little time for a current NATS snapshot. One observation timed out; the retry succeeded, but the genuine cold write proof was 6,022 ms old and correctly failed the freshness check.

This run used fixed timing instrumentation on an isolated source copy. It failed and is diagnostic evidence, not acceptance of the production candidate. The retained raw events and source hashes are under `delivery/evidence/P02/secure-compose-diagnostics/p02-real-tls-timing-PJeFfc/`.

## Decision

Allow the next kernel observation in the same bootstrap operation to consume the complete inspection that just succeeded. Keep the proof private and usable once. Do not put it in a configuration, Session, public API, shared cache or persistent record.

The inspection must reload and compare private enrollment, then verify the selected Docker engine, exact broker roster, container, image, port, volume and all three injected private files. Only that concrete inspection may produce the proof. Bind it to the exact private authority object, original operation context, enrolled scope, endpoint, credentials and immutable TLS trust. Reject mismatches and cancellation before dialing. Bound freshness by the original deadline and a maximum four-second interval after completed inspection. An expired proof requires a real fresh inspection within the remaining caller budget.

The public `ObserveKernel` path continues to inspect authority independently. Consuming a private proof does not replace TLS chain, DNS, validity or leaf-pin checks before NATS CONNECT. It does not establish readiness: the observer must still receive and validate a current scoped kernel snapshot.

Bootstrap holds the proof only between its own inspection and next observation. Discard it before lease waits, mutations and subsequent attempts. Preserve all startup, warm observation, cleanup and evidence freshness limits. If the owning startup needs a new write proof, run the actual health probe again; never refresh a stored timestamp to make old evidence appear current.

## Alternatives and costs

Increasing time limits would conceal the repeated work and delay callers. A global inspection cache would allow evidence to cross invocation boundaries. Both are rejected.

Running the three fixed private-file archive reads concurrently was initially reserved for measurements showing further pressure. A subsequent real warm launch exhausted its four-second budget during the complete authority inspection. The chosen repair uses a separate bounded helper after all ownership checks, validates every archive and joins cancelled siblings. The general parallel Docker read allowlist remains unchanged and rejects private-file reads.

The private proof adds lifecycle and correlation checks. Tests must cover wrong context, authority, scope, endpoint, credentials and trust; cancellation, expiry and repeated consumption; changed private enrollment; and real TLS plus current snapshot validation. The final unchanged candidate must pass real cold, concurrent and warm Compose checks, installed lifecycle checks, independent review and supported-platform verification. This decision does not accept P02 or authorize advancement.

## Verification on October 14

Independent review closed the context identity and mutation-boundary findings. Bootstrap discards the proof before acquiring role leases, provisioning or starting children, then obtains a fresh proof for the next readiness observation. The archive helper preserves the public configuration-only inspection and all earlier identity checks.

The real Compose run `AshKde` passed cold startup, concurrent reuse, warm reuse and normal owner recovery in 68.73 seconds. Six baseline guards remained unchanged. Cleanup stopped only the exact owned container, retained its volume and preserved the original persistence record. This is WSL bootstrap evidence; it does not replace abrupt installed-host crash, native macOS/Linux Docker or terminal frontend checks. See `delivery/evidence/P02/real-compose-current/review.json`, `kernel-operation-proof-independent/independent-review.json` and `fixed-tls-archives-independent/independent-review.json`.
