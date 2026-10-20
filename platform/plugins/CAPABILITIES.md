# Capability evaluation

`EvaluateCapabilityGrant` calculates the access allowed by a validated package
manifest, a resolved instance grant, parent delegation and a resolved policy.
It does not issue a grant, authenticate a caller, create a handle or make a
remote call. Its result is not a credential or a cached authorization decision.

The authority owner supplies the inputs. It must resolve current enrolled
identity, exact grant and policy revisions, membership, revocation and applicable
approvals. A policy decision may say `allow` only after those checks succeed.
An unavailable owner must cause refusal; a caller must not manufacture an empty
policy or reuse an earlier allow as a substitute for a current decision.

## Inputs and refusal rules

- Supply an admitted `ValidatedManifest`, the exact instance ID, resolved grant,
  resolved policy and the trusted host's current time.
- Use `independent` for an independent installation, including an independent
  child reference. It receives its own authority. Parent inputs are refused.
- Use `private` for a private child. Supply the exact parent instance, grant and
  current effective `ParentAccess` tuples. The child grant must refer to that
  exact parent grant ID, issuing hub and revision. The authority owner must bind
  these facts to the actual live parent generation and validate its ancestry.
- A private child's scope must equal its parent's scope. Empty project and
  workspace strings represent the wire contract's null dimensions. They never
  act as wildcards. Resource and action sets may narrow; scope containment
  beyond exact equality needs a separately defined and tested contract.
- A child cannot add actions or resource IDs, begin before its parent grant, or
  outlive it. A broader grant is refused in full before intersection.
- Policy decisions name exact action, resource class and resource ID tuples.
  The resource owner supplies the class. No prefix, wildcard or Cartesian
  product matching occurs. Parent tuples are also required for private access.
- `deny` overrides `allow`; `approval_required` also prevents access. Unknown
  outcomes or malformed decisions refuse the evaluation. Missing policy
  decisions and empty resource lists grant no access.
- A required declaration must have at least one allowed exact resource tuple.
  This proves access exists for that declaration; it does not promise access to
  every resource of its class or prove that a service is ready. Missing optional
  access is omitted. The result expires at the earlier grant or policy expiry.

Collections are limited to 256 entries each. Inputs must be owned snapshots and
must not change while evaluation runs. Results contain copied values, and
`Access()` returns a new slice. Generic formatting and JSON encoding of grants,
policies, evaluations and results conceal their contents. Errors use fixed
codes, without resource IDs, private policy text or secret values.

## Authority and context integration

The intended caller is the authority implementation behind `ContextAuthority`.
During `BindInstance`, it resolves the current facts, evaluates the grant, then
uses allowed tuples when selecting declared service/domain bindings. The grant
record and `ContextInstanceAdmission` still belong to that owner. The evaluator
must not become another registry or persistent source of authority.

At `AdmitOperation`, `Recheck` and `PrepareDomainCall`, the authority owner must
resolve current facts again and bind each requested action to the authenticated
principal, exact instance generation, operation scope and actual target
resource. The original signed operation remains unchanged. Any downstream
request needs its own correct audience and payload binding; an intersection
result cannot substitute for either signature verification or the destination
owner's current authorization check.

The current helper accepts no operation principal, signature, generation or
revocation feed. Those are explicit integration responsibilities. It cannot
prove an installed handle is current, safely drain a handle, migrate a stored
record, or enforce NATS permissions. Context and service owners retain those
responsibilities. Trusted native plugins remain unsandboxed.

The implementation uses a direct bounded calculation with no additional
framework or storage. This keeps the established authority and lifetime owners
intact. The exact-scope and parent-grant rules follow the accepted
[contract requirements](../../docs/planning/2026-10-09/delivery/contracts/README.md).

## Typed handles

`OpenCapabilityHandles` creates typed remote clients for one admitted operation.
Pass that operation's original context, the exact `ContextBinding`, instance and
operation admissions, and `CapabilityHandlePorts` borrowing the context's
`Authority`, `Domain` and `Now` dependencies. Do not pass a short admission or
startup context. A canceled operation invalidates its clients and cancels their
calls. Instance or parent shutdown and the earliest operation/grant deadline do
the same. `Close` joins original calls before the context host releases transport;
a timeout reports incomplete cleanup and the same set must remain owned.
Borrowed services are never closed by a handle.

Only declared, admitted routes create clients. Missing routes leave the
corresponding field nil; unsupported methods refuse. Each call checks its exact
resource ID against the instance grant, calls `Recheck`, asks
`PrepareDomainCall` for a payload-bound envelope, dispatches through `Domain`,
and rechecks before returning data. The authority must verify the full resource
reference, current action/class permission, principal, scope and approvals.
`Domain` must authenticate the remote owner reply, not return an arbitrary
broker message. Local shape checks cannot supply those guarantees.

| Client | Implemented client operation | Owner responsibility |
| --- | --- | --- |
| Storage | `Read`, `CompareAndSwap` | Resolve the owned record, preserve IDs and fields, enforce expected revision, commit durably and return conflict/uncertainty accurately. No SQL or database object crosses the handle. |
| Artifact | `Read` with expected SHA-256 digest | Resolve authorized artifact bytes and metadata. The client verifies the returned bytes against the requested digest. |
| Secret | `Use(secret, consumer, purpose)` | Resolve the secret only for the authorized consumer and intended operation. The plugin receives a receipt, never the secret value. |
| Workspace | `ReadFile` with a relative path | Resolve the authorized workspace and enforce filesystem and symlink containment. Client path checks reject traversal; they are not a filesystem sandbox. |
| Process | `Start` with an approved plan reference; `Cancel` with a run reference | Own execution isolation, process identity, durable outcomes and reconciliation. The client accepts no shell command, environment or host path. A pending cancellation is not proof of stop. |
| Policy | `Evaluate` for an exact action/class/resource tuple | Resolve current rules and approvals. An allow receipt is not a grant and cannot replace effect-time authorization. |
| Decision | `Request` with an owned proposal reference | Own pending, approved, rejected and uncertain outcomes. A client cannot accept work or create approval locally. |

Requests and replies are bounded. Returned content and receipts conceal their
contents during ordinary formatting and JSON encoding; explicit accessors
return copies or references. Secret use requires the exact admitted secret reference, including owner and
revision; secret replies reject extra fields. Clients never
retry an uncertain effect automatically. Callers must reconcile the original
owner outcome before requesting another effect.

### Prepare, persist, execute and reconcile

Mutating methods require an explicit `*CapabilityMutation`. First call the
matching `Storage.PrepareCompareAndSwap`, `Secret.PrepareUse`,
`Process.PrepareStart`, `Process.PrepareCancel` or `Decision.PrepareRequest` with
the intended arguments. Preparation rechecks authority and freezes the exact
input, owner generation, downstream operation ID and canonical payload digest.
It does not call `Domain` or send an effect.

Save `mutation.RecoveryBytes()` in the caller's protected recovery storage before
calling the matching effect method with that token and the same arguments.
`RestoreCapabilityMutation` restores that snapshot. It contains the complete
request payload, resource and owner references, request ID, source operation ID
and digest, and downstream operation ID and digest. The handle adds no signature,
broker credentials or resolved secret value. Caller-supplied storage values and
references can still contain sensitive data.
Ordinary formatting and JSON encoding conceal it. Recovery storage and its
retention remain the caller's responsibility; these clients create no ledger.
`NewMutation` alone only allocates an identity and cannot dispatch an effect.

Execution obtains current authority again. It refuses changed payload, contract,
resource reference, source operation bytes, owner generation or approved digest.
The stable downstream ID is `ContextDownstreamOperationID(sourceID, requestID)`.
A retry uses the same prepared token and original operation/owner generation;
retry under a renewed source operation or restarted generation is not supported.
A fresh admitted session may use `Reconcile(ctx, restoredMutation)` to query the
original outcome, subject to its current authority for that resource. This does
not authorize it to retry the old effect. Neither errors nor reconciliation
trigger an automatic retry.

The outcome query carries `{contractId, operationId, payloadDigest}` in `input`
and the original `resourceRef`. Its reply contains exactly
`{operationId, payloadDigest, recordRef, outcome}`. It must echo the exact ID and
digest. `absent` requires a null record; `committed` and `rejected` require a valid
record reference. Absence does not prove an earlier external effect stopped or
that it is safe to submit a new intent.

The remote adapter must resolve the original reference to the same aggregate,
including its trusted enrolled `StreamIdentity`, then use
`state_owner.OwnerLedger.outcome(operation_id, payload_digest)`. The caller may
not select a stream, owner subject, replacement aggregate or creation time.
The original resource revision identifies the attempted operation; an outcome
query must still find its retained outcome after the aggregate has advanced.
Owner-ledger replay does not itself dispatch or reconcile external effects.

### Service contract handoff

The client methods use the following version-1 contract IDs, now present in the
shared registry. Registration does not establish a running owner service:

- `capability-storage-read`, `capability-storage-write`
- `capability-artifact-read`
- `capability-secret-use`
- `capability-workspace-read`
- `capability-process-start`, `capability-process-cancel`
- `capability-policy-evaluate`
- `capability-decision-request`
- `capability-outcome-query`

The shared schemas under `contracts/v1/schemas/capability-*.schema.json` now own
the wire shapes and `contracts/v1/registry.json` fixes their destinations. The
local `capability_contracts.schema.json` records the earlier handoff proposal;
it is not used for runtime validation. Content replies are shared by storage,
artifact and workspace reads; other replies have individual definitions. Every
defined object refuses additional fields.

| Contract suffix | Resource class | Action |
| --- | --- | --- |
| storage-read / storage-write | storage | read / write |
| artifact-read | artifact | read |
| secret-use | secret | use |
| workspace-read | workspace | read |
| process-start / process-cancel | process | start / cancel |
| policy-evaluate | policy | evaluate |
| decision-request | decision | request |
| outcome-query | outcome | inspect |

The outcome adapter must check authorization for the original resource and
contract as well as the declared outcome route. It must not treat `inspect` as
permission to read every service's private outcome.

All payloads have `resourceRef` and `input` fields. `resourceRef` is the existing
`{id, ownerHubId, revision}` reference. Read-storage input is `{}`; write-storage
input is `{value}` with the complete owner-defined JSON value. Artifact input
is `{digest}`. Secret input is `{consumerRef, purposeRef}`. Workspace input is
`{relativePath}`. Process inputs are `{planRef}` and `{runRef}`. Policy input is
`{action, resourceClass, resourceId}`. Decision input is `{proposalRef}`.

Content replies contain exactly `{resourceRef, data}`, where `data` is base64
bytes and the reference must equal the request. Receipt replies contain exactly
`{receiptRef, outcome}`. Allowed outcomes are fixed by the client method:

- Storage write: `applied`, `conflict`, `rejected`, `uncertain`.
- Secret use and process start: `accepted`, `rejected`, `uncertain`.
- Process cancel: `pending`, `stopped`, `rejected`, `uncertain`.
- Policy evaluate: `allow`, `deny`, `approval_required`.
- Decision request: `pending`, `approved`, `rejected`, `uncertain`.

The shared contract owner must register each schema and destination with its
exact action/resource-class pair from `capabilityHandleOperations`. Downstream
storage writes must bind `operation.expectedVersion` to `resourceRef.revision`;
the owner must enforce both and retain the original record identity. A newly
signed downstream operation does not alter the original invocation envelope.

For host-side callers, the native context owner can construct the Go set from
the admitted operation's `op.ctx`, retain it with that operation, and join `Close`
before releasing the original context transport. Process plugins need equivalent
SDK clients using the existing `domainGateway.request` transport and admitted
bindings; these host-local Go objects do not cross that boundary. The identity
owner supplies current checks and approved destinations. The clients expose no
NATS subject selection; exact and wildcard kernel-subject denial still needs
broker qualification.

### Existing service boundaries

The storage migration must retain the existing Python owners rather than copy
live data into a second store. `hub/fed/message_services.py` owns message and
directory access; `work_services.py` retains work transactions;
`board_services.py` retains authoritative `am_board` KV and its SQL projection;
`knowledge_services.py` retains knowledge records, FTS and outbox transactions;
`code_services.py` retains code shares, repository lookup and Git operations.
These services do not yet implement the ten proposed owner operations above.
Their record IDs, revisions, deduplication keys and transaction behavior must
survive any remote adapter. This client change performs no migration or write
to those stores.

`OwnerArtifacts` supplies the retained artifact byte owner used by the receiving
adapter, including the bounded coordinated live artifact-read case. Context secret references do not implement an
intended-operation secret resolver. `RepositoryDirectory` and `GitOperations`
provide existing workspace/Git behavior but are not a general remote workspace
or execution owner. `NativeDriver` supervises plugin lifetime; it does not grant
task execution permission. `hub/fed/policy.py` and `guard.py` preserve existing
federation policy; a guard result or delegation-decision event is not a general
authoritative policy/approval service. Those boundaries need concrete owner
integration before these client methods can serve production calls.

No old runtime path is disabled by these clients. Rollback stops new admissions,
drains active calls and restores the compatible package/configuration set;
it does not erase stored records, revoke an uncertain process effect by
assumption, or silently downgrade storage.

### Receiving adapters

[`capability_owner`](../../capability_owner/README.md) provides a concrete Python
receiver over `AuthorityReader`, `OwnerLedger` and `OwnerArtifacts`, with enrolled
checkout reads. It preserves retained records and original outcome identity.
Identity capability admission and authenticated reply transport are integrated
with the native gateway. Coordinated live checks cover retained storage, artifact,
workspace and historical outcome reads, owner refusal cases and current parent
revocation. Disposable broker checks cover exact kernel publications and
exact/wildcard subscriptions, plus current-authority child narrowing checks. Unavailable effects refuse. The receiver documentation gives exact
construction, request, response, size and cleanup APIs and their current limits.


Storage write replies now include `resourceRef` separately from `receiptRef`.
Call `CapabilityReceipt.ResourceReference()` to obtain the original result's
resource reference and presence flag. Applied, conflict and rejected results
carry a real retained resource version; uncertain results use JSON null and
return no resource reference. Exact replay keeps the original result version,
not a later current version. A receipt's own version must never be used as the
next card or namespace resource version. Other capability receipt wire shapes
are unchanged. The storage decoder validates the raw original reference shapes
before typed decoding, including required receipt revisions.


Storage reconciliation replies also carry the original contract and result
resource reference. `CapabilityOutcome.ResourceReference()` returns that reference
under current recovery authority even after the original write expires. Absent
operations have no result reference. Non-storage outcome reply shapes remain
unchanged. Recovery requires the original declared route, current native original
permission and current caller original permission; an outcome-query route alone
is insufficient. The original operation/digest and result revision remain fixed.
