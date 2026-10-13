# Agentmux version 1 contracts

These contracts are the separate P01 implementation path. The existing hub and federation protocols continue using their own decoders and namespaces. A matching version number does not make legacy v2/v3 traffic compatible with this format.

The JSON Schema identifiers begin with `urn:agentmux:contract:1:`. Every wire object with a schema version declares `1.0.0`. Resolve schema references locally from this package; an incoming message cannot supply a schema URL to download. `common` supplies referenced definitions only; callers must select a concrete message/object schema, never use the definitions document as an admission check. Closed infrastructure objects reject unknown fields. `registry.json` binds each supported contract ID/major to its message kind, payload schema and destination service. Complete-envelope verification rejects unknown contracts and validates their closed payload before returning verified claims. Owner state extension slots still need domain-specific state schemas before production execution.

The initial Python and TypeScript libraries implement strict JSON parsing, schema checks, canonical bytes and Ed25519 attestations independently. The cross-language harness verifies interoperability rather than calling one library from both clients. This package is under implementation; it is not a complete plugin SDK or production domain service.

## Bytes and identity

Decode UTF-8 strictly and reject duplicate object keys, including escaped spellings of the same key. Comments, trailing commas, invalid Unicode and non-finite numbers are invalid. Preserve Unicode without normalization. Canonical bytes follow RFC 8785 JCS; exact large integers and decimals belong in domain-defined strings. Counters and revisions use the safe-integer range in the shared schema.

Hash the canonical domain payload. Sign canonical attestation claims, excluding the signature wrapper. The claims bind the operation, source, contract, message kind and destination. Verify the full envelope as well as the signature: an attacker must not be able to change an unsigned outer caller or destination while retaining valid inner claims.

Verification receives an already trusted public key and expected audience from its caller. It never treats a key in a message as trusted or retrieves caller-selected key URLs. Production owners must resolve the exact enrolled issuer/key revision, authenticate the ingress credential, enforce current grants and use durable operation identities. Signature validity alone supplies none of those permissions. Broker credentials and attestation signing keys are separate.

## Compatibility and remaining work

P00 draft schemas and model evidence remain in the planning package as history. These promoted schemas do not rewrite those records. Incompatible schema changes require a new contract major version and explicit negotiation; producer and consumer fixtures must demonstrate every advertised compatible change.

Ten core payload schemas, five executable lifecycle models, ordered recovery histories and bounded real NATS storage/leaf fixtures are implemented. The signed leaf fixture verifies both independent SDKs over real transport. Native macOS/Linux CI and separate WSL checks passed at checkpoint `a2e9ee6`; their reports identify exact sources and do not qualify later changes automatically. P01 still requires the complete task, failure and preservation review before its gate. See `recovery.md` for fixture semantics and limits. The single-node storage result does not qualify replication. Later phases implement plugin construction, enrollment, domain execution and real runtime authorization. No existing source, stored identity or user action is retired by adding these files.

## Registered payload meanings

| Contract | Meaning |
| --- | --- |
| task-inspect / task-reserve | Inspect a task or request an origin-owned reservation with an explicit executor, assignment epoch and execution grant. |
| delegation-offer / delegation-decision | Offer scoped execution; report a durable accepted reservation, pending approval or rejection. Delivery alone is never acceptance. |
| execution-report | Report an attempt and artifact references. `completion_reported` is not origin acceptance; `effect_uncertain` requires reconciliation. |
| cancellation-request | Request cancellation, optionally targeting an attempt/delegation. This command never proves execution stopped. |
| delivery-receipt | Report receipt/redelivery only. Its schema excludes result, completion and task-acceptance fields. |
| plugin-lifecycle | Report a bounded lifecycle observation. Its source still needs supervisor/plugin authorization. |
| operation-outcome | Reply with committed, rejected, unavailable or unknown. Committed requires an owner record reference; unavailable/unknown cannot invent one. |
| status-query | Request scoped status and optional visible hubs; no request can widen the authenticated scope. |
| startup-status-observation | Return the L04 caller-scoped startup observation, including readiness, persistence, permitted work counts and visible hubs. Unavailable or forbidden information must remain explicit. |

Task and attempt IDs in payloads must match operation context. A delegation ID must match its context reference. An outcome identifies the original operation through the envelope's correlation ID. A reply may target its authenticated recipient rather than a fixed service; its signed audience is still checked. A delegation's execution grant is a distinct reference from the requesting actor's authority grant, so comparing those two for equality would be incorrect.

`retryable` is only advice about repeating the same operation identity and digest after re-authentication. It never permits a new task, executor reassignment or repetition of an uncertain external effect. Unknown/unavailable outcomes retain reservations until the authoritative owner reconciles them. These schemas do not resolve referenced grants, fetch artifact bytes or execute state transitions; those are owner responsibilities.

The startup observation is a wire contract, not evidence that a stack is running. P02 supplies the status service; P06 and P10 qualify terminal integration and live federation state. A signed reply still needs an authorized producer and an authenticated recipient. Schema validation cannot decide which projects or hubs that recipient may see.
