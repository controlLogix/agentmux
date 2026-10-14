# P02 local owner status over NATS

Status: implementation in progress. This decision is not phase acceptance.

The installed launcher must return the owning runtime's actual startup result and keep using the accepted L04 observation for startup, reuse and status refresh. A successful process launch or a ready kernel snapshot cannot, by itself, prove persistence readiness, selected Docker ownership or the outcome of a cold start.

## Decision

Add a separate local `HOST` account with two distinct enrolled principals: `runtime-host` and `runtime-client`. The host subscribes to one request subject and publishes only its scoped reply prefix. The client has the reverse grants. This account has no kernel commands, imports, exports, JetStream, system-account or business permissions.

The fixed namespace is:

```text
amx.v1.h.<hubId>.host.owner.<instanceId>.request
amx.v1.h.<hubId>.host.owner.<instanceId>.reply.<requestNonce>
```

Closed requests identify `ensure` or `status`, a fresh request nonce, the actual invocation, the complete enrolled kernel scope and the send time. Correlated replies carry the unchanged L04 observation. The receiver checks the expected producer, scope, nonce, invocation and freshness. A schema check cannot supply that authority.

The external private host policy selects server and client credential records. Each record binds its role, credential, full scope and expected local owner enrollment. Factory admission compares the complete broker configuration before any Docker command. Arbitrary broker JSON cannot enable the account. The existing factory remains unchanged when the account is not enabled.

Acquire a distinct host-service OS lease before calling `BootstrapForInvocation`. The owning session supplies the actual cold outcome and its qualified write proof. A reused session owns no protected child. If the status service was missing, a host-service lease owner may serve freshly verified read-only observations for that existing runtime; it must never adopt or stop another group's children.

Every successful reuse or refresh still needs the applicable selected broker, private configuration, image, port, current scoped kernel and authenticated FILE-record evidence. Old receipts and records cannot become current observations merely by changing their timestamp. Work and hub inventory remain unavailable until their authenticated owners exist in their respective phases.

OS process handles, detached process creation, EOF and leases are lifecycle infrastructure. Application observations travel over NATS. A broker that never starts cannot produce an authenticated owner reply; the launcher must report bridge unavailability and actual owned process evidence without inventing an owner outcome.

## Alternatives and tradeoffs

A file or startup pipe would be simpler, but would create another application communication path and weaken the stated NATS backbone. A `hostLaunchRequested` flag remains useful metadata; it cannot replace the owner's actual result. A separate diagnostic status envelope may be an additional asset, but cannot replace L04.

The NATS bridge adds credential enrollment, correlation, bounded waiting and a separately owned service lease. It also creates a startup dependency: the frontend must wait within its overall startup deadline while the broker and host service become available. Requests and transport retries must not create duplicate runtime owners.

This initial boundary trusts the enrolled local user and explicitly trusted host code. It is not remote business authorization, federation trust or third-party sandboxing. Those product requirements remain in the implementation plan.

The later local broker review requires [enrolled TLS server authentication](P02-local-broker-authentication.md) before credentials are sent. Advertised server identity and account grants alone do not prove that the connected peer owns the selected broker. That requirement is part of P02 acceptance; the earlier plaintext partial-integration results remain historical evidence.

## Required verification

- Prove the account's exact grants and denied cross-account traffic on a real disposable NATS server.
- Verify complete private policy and credential binding, including otherwise valid mismatches and unchanged default factory behavior.
- Reject duplicate, aliased, unknown, stale, replayed and incorrectly correlated messages.
- Admit emitted replies through both independent SDKs using the unchanged L04 body.
- Demonstrate one owner under concurrent terminals, actual cold results, qualified warm reuse, terminal closure and recovery on the supported candidate.
- Preserve explicit native macOS, Linux and WSL evidence. A cross-build, synthetic status input or isolated transport test cannot replace native boot or the P02 gate.

The independent review that motivated this correction is recorded in `../evidence/P02/installed-launcher-independent/pre-bridge-review.json`.
