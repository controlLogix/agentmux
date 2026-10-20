# Ordinary secret authority API

AMUX-625 supplies public enrollment and current authorization. AMUX-626 owns
secret material, retained custody and delivery to an authenticated consumer.
AMUX-287 owns the plugin receiving path and its native declaration and child
scope checks. A public resolution does not replace those checks.

## Enrollment and rotation

Send `identity-ordinary-secret-set` through the existing signed identity ingress
to `identity-owner`, using a current organization administration grant and any
required exact approval. Its payload is `authorityId`, `record` and
`previousRef`. The identity owner commits enrollment and its authorization audit
in the same owner record, preserving the original operation ID, payload digest
and expected owner version. Use that same operation when reconciling an
uncertain append; a conflict needs a fresh current read and authorization.

The closed `identity-ordinary-secret-reference` schema binds a fresh `ref` and
matching `generationRef`, the profile and project/workspace scope, custody owner,
pinned `ownerAudience`, original caller, service consumer, purpose, status and
validity. `consumerRef` names an enrolled service identity. `purposeRef` is the
exact public purpose approved in this enrollment; it is not a general resolver.
Owner, caller and consumer must have current membership in that enrolled scope.
An authorized service may be both caller and consumer.

A fresh generation uses a fresh reference ID at revision 1. Rotation sets
`previousRef` to the current old reference and supplies a new record with the
same owner, audience, scope, profile, caller, consumer and purpose. One conditional
append revokes the old row and creates the new generation. The old generation
reference remains in its tombstone and is never bound to new material. Changed
bindings require a separate enrollment. Existing administrator and account-issuer
secret records and their resolver remain separate.

## Current use and recovery

The custody service sends a signed `identity-ordinary-secret-resolve` possession
request with its current resolve grant and `expectedVersion: 0`. Its closed
payload contains `authorityId`, `secretRef`, `generationRef`, `profileId`, `scope`,
`consumerRef`, `purposeRef` and `originalEnvelope`.

`originalEnvelope` is the unchanged, signed original `capability-secret-use`
message envelope. It contains public references only. Its original issuer,
transport, caller, grant, approvals, scope, payload digest and audience are
verified independently against current retained identity state. The caller is
derived from that proof, never from the custody service's assertion. The outer
request must come from the enrolled custody owner; its resolve grant cannot stand
in for the original Secret.Use permission. Hard denials defeat either proof.
The inner audience must match the immutable enrollment audience and the existing
Secret.Use owner route.

The original scope must equal the outer requested scope and be the same as or
narrower than enrollment. A narrower workspace still requires its own current
exact caller and custody grants and memberships; a parent grant is not expanded.
Original resource, generation, consumer and purpose must match enrollment.
Revoked identities, memberships, grants, stale generations and expired proofs
refuse, including during recovery.

For a same-process custody owner,
`OrdinarySecretAuthority(actual_identity_service.reader).resolve(envelope_bytes)`
accepts the admitted outer message envelope. It rereads the actual
`LedgerAuthorityReader` and samples time after that read. It returns immutable
`OrdinarySecretResolution` bytes and a deadline bounded by both proofs and the
generation's expiry. It reads no secret material and writes no second authority
store. `resolve_snapshot` is the pure snapshot function used by tests; supplied
snapshot bytes alone are not production enrollment.

The broker route returns `identity-ordinary-secret-resolution` signed by the
identity owner. `verify_resolution(response_bytes, request_bytes, public_key=...,
issuer_ref=..., now=...)` verifies its signature and exact request, original
operation/digest, caller, resource, scope, purpose and generation bindings. The
reply contains public metadata only. It is not a bearer permit: reread current
authority before each actual custody effect, reply disclosure or recovery, and
authenticate delivery to the approved consumer. The custody owner must retain
the original operation and result for replay; a timeout is not permission for
another effect. Expired or revoked proofs cannot authorize new disclosure.

## Limits

This API provides no offline authority, provider provisioning, plaintext lookup,
plugin Secret.Use receiver or execution profile. It does not revoke copies of
material already disclosed outside Agentmux. Public records, operation arguments,
receipts, logs and errors must contain no secret material, storage location or
private reasoning.
