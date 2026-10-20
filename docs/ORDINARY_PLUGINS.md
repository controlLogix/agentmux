# Ordinary plugin packages

`platform/plugins` admits and supervises ordinary packages outside the protected
kernel. `agentmux-plugins` supplies a foreground owner through an explicit private
composition file. Package admission belongs to
[AMUX-42](https://adag-csai.atlassian.net/browse/AMUX-42); child ownership and
placement belong to [AMUX-43](https://adag-csai.atlassian.net/browse/AMUX-43).

The architecture follows the ADAG Design Patterns 0.5.3
[assessment](https://github.com/csai-bms/marketplace/blob/main/plugins/design-patterns/skills/assess/SKILL.md),
[guidance](https://github.com/csai-bms/marketplace/blob/main/plugins/design-patterns/skills/guide/SKILL.md)
and [refactoring](https://github.com/csai-bms/marketplace/blob/main/plugins/design-patterns/skills/refactor/SKILL.md)
skills. The review applies their enterprise baseline to ownership, security,
failure recovery, compatibility and affected callers. Jira holds findings and
test results. Repository instructions exclude separate pattern registries,
generated diagrams, evidence gates and CI.

The small [Adapter](https://www.dofactory.com/net/adapter-design-pattern) at
`FlatInstanceTopology` preserves the original composition inputs. The existing
NATS lifecycle channel follows the
[Control Bus](https://www.enterpriseintegrationpatterns.com/patterns/messaging/ControlBus.html)
pattern: management commands have their own subjects and permissions. These
patterns address compatibility and lifecycle management. Their names do not prove
delivery guarantees, business authorization or successful cleanup.

[Ordinary secret use](SECRET_USE.md) describes the approved consumer, custody,
original-operation recovery, rotation limits and current qualification boundary.

## Ownership and design choices

Package admission, dependency resolution and contribution registration produce
immutable candidates. The manager owns the active set and publishes it only
after every new process completes readiness. The native driver owns original
process handles, their waits, staged files and lifecycle connections. This keeps
process details out of package resolution and keeps ordinary extensions out of
the protected four-role runtime.

An immutable instance topology sits beside the package plan. A package identifies
reusable bytes; an instance identifies one running process and its lifetime.
Each instance declares its full pin, installation mode and placement. The first
placement is `{"kind":"local-process"}`, meaning the foreground controller's
native macOS ARM64 host. It does not claim an enrolled host identity.

Private children have exactly one parent and bind to that parent's current epoch
and generation. Separate private instances may use the same package pin under
different parents. Independent children have their own lifetime and can be
referenced by several consumers. Root retention is an explicit owner claim,
separate from those references. Releasing one root stops only instances no longer
reachable from another retained root. A shared child survives while another
consumer or its own root claim retains it.

The topology validates every child and dependency against the package manifest.
Required edges must be present; omitted optional edges remain visible. Private
orphans, multiple private parents, cycles, ambiguous bindings, undeclared edges
and unsupported placements fail before startup. This uses an ownership tree plus
explicit references. Treating every reference as ownership would let one consumer
destroy another consumer's shared process.

The existing Python plugins remain behind the
[compatibility adapters](PLUGIN_COMPATIBILITY.md). Those adapters preserve their
original names, verbs, parameters, table prefixes, context, hooks and entry points.

[Selected Work storage](WORK_STORAGE.md) uses the common `StorageHandle`
interface with fixed domain commands, current scoped authority and retained
original outcomes. It also describes the existing Hub and bridge callers and
their recovery boundaries.
They are not silently converted into native executables or given fabricated
package pins. Existing Markdown imports preserve their original path, scope,
bytes and checksum. This command neither changes their stored data nor starts a
second writer against their records.

Go interfaces connect the manager to its local driver. The process contract is
language-neutral JSON over NATS; Go interfaces are not the public plugin ABI.
The registry identifies owners for specific contribution contracts. It does not
replace distinct tool, panel, lifecycle or storage contracts with one generic
handler interface. Resolving a registered contribution checks the current
manager epoch, process generation, connection health and required dependencies.
Its lifecycle acknowledgment does not prove that a business handler is callable.

## Admission and exact versions

The accepted `plugin-manifest` schema retains runtime arguments, installation
modes, platforms, dependencies, children, requested capabilities, configuration
schema references, contributions, lifecycle limits and migrations. Unknown
fields, duplicate JSON keys, invalid Unicode, cycles, missing required versions
and conflicting package selections fail explicitly.

Each selected package has five pin fields:

| Field | Meaning |
| --- | --- |
| `packageId` | Stable package identity. |
| `version` | Three numeric version components. Comparisons do not truncate large components. |
| `manifestChecksum` | SHA-256 of the exact manifest bytes. |
| `packageChecksum` | SHA-256 over framed file paths, modes and bytes in the admitted snapshot. |
| `provenanceChecksum` | SHA-256 over framed source ID, original path, scope and original source checksum. |

The source checksum is separate from the generated manifest and package checksums.
Provenance records what the owner selected; it is not a publisher signature or
installation attestation. Admission holds regular files while reading, checks
their identity and bounds the snapshot. Symlinks and special files are refused.
This does not turn trusted files on the same OS account into a sandbox.

Dependencies use an inclusive minimum and exclusive maximum version. The owner
must select exact pins, even when the catalog has only one matching candidate.
The resolver does not fetch packages or silently choose the newest version.
Unavailable optional dependencies remain explicit in the plan. A selected cycle
fails. Duplicate globally exported `(kind, id)` contributions, unknown contribution
contracts and protected kernel replacements fail before activation. Private
contributions keep their original IDs within their instance scope. `ResolveFor`
checks declared caller visibility and current generations; global lookup exposes
only independent contributions. This lookup is not a business-operation grant.

## Configuration and authority

Configuration is validated against admitted local schema files using JSON Schema
Draft 2020-12. Logical schema references map explicitly to those files; missing
references cannot trigger a network or filesystem fetch. Exact configuration
bytes and values are retained. Defaults, coercion, environment overrides and an
implicit second configuration source are not applied. Format and content remain
standard annotations. Unsupported dialects and required custom vocabularies fail.
Input and regular-expression limits apply; synchronous schema validation is not
a hard CPU sandbox for hostile schemas.

The owner supplies a separate ordinary NATS account, a controller credential and
one distinct credential per instance. The controller may publish only to the
selected control subjects and subscribe only to their event subjects. Each child
may publish only its own events and subscribe only to its own control subject:

```text
amx.v1.h.<hub>.plugins.<instance>.lifecycle.control
amx.v1.h.<hub>.plugins.<instance>.lifecycle.event
```

The initial credential profile supports directly account-signed NATS v2 user
JWTs with the matching user seed and exact subject allowlists. Wildcards, dynamic
response permissions, bearer tokens, delegated signing keys and unsupported
claim fields are refused. The driver verifies the signature, account, identity,
time limits and permissions before connecting. The broker still enforces its
account policy and revocations. The driver does not enroll users, issue grants,
modify the broker or reuse the P02 HOST or application credentials.

TLS with the explicitly selected CA and hostname verification is required,
including on loopback. Plaintext connections and discovered alternate servers
are not accepted. The driver takes a private snapshot of the admitted credentials
and CA. Configuration, credentials and the startup file are staged privately;
the process receives only `AGENTMUX_PLUGIN_BOOTSTRAP` in its environment.
Package arguments remain literal arguments, without shell expansion.

These permissions authorize the lifecycle exchange only. Required business
capabilities fail activation until their real bindings exist. Optional capability
declarations are retained but do not create grants. Scoped context and service
handle authorization belong to AMUX-44 and AMUX-45. Trusted native code runs as
the owner and is unsandboxed; subject permissions do not isolate it from other
files readable by that same OS account.

## Native scoped context

`NewNativeDriverWithContext` requires an explicit `ContextProvider`. The original
`NewNativeDriver` remains a lifecycle-only compatibility constructor; its
readiness does not establish context services. The foreground command uses that
path for lifecycle-only compositions. An explicit version 1.2.0 native context
selection uses the registered host and its scoped service composition.

`ContextProvider.Open` receives the immutable admitted package and configuration,
the exact process owner, and separate owner and parent lifetime signals. It
returns a `ContextLease`, including on a partial failure that still owns work.
The driver reserves the process owner before calling the provider and releases
its mutex during that call. Providers receive the package startup deadline and
must cooperate with cancellation. A late return stays attached to the original
owner until cleanup joins it; a timeout never permits replacement of that owner.

The NATS provider gives each instance seven opaque service handles: logger,
configuration, lifecycle, clock, tracing, metrics and a domain gateway. The child
receives a private descriptor and separate context credentials. Context credentials
have exact request, reply, invocation, result and cancellation subjects under
`amx.v1.h.<hub>.plugins.<instance>`. They do not grant arbitrary NATS access or
expose a raw hub, database, connection or service implementation.

Lifecycle v1.2.0 binds the context descriptor checksum as well as the existing
owner, configuration and contribution fields. Private children also acknowledge
their exact parent owner. Lifecycle-only independent v1.0.0 and private v1.1.0
messages keep their existing closed shapes. A child must read and validate its
descriptor before reporting ready; echoing a checksum alone is insufficient.

`NativeDriver.Dispatch` accepts the original operation envelope for an exact,
ready process owner. The authority's `AdmitOperation` validates that envelope and
returns its operation claims and authority reference. Each call gets a separate
operation handle, cancellation scope and resource lifetime. There is no shared
current user or project. The host assigns logger, trace and metric identity tags
from admitted claims, including separate authenticated identity, effective actor
and delegation references. These references preserve attribution; their presence
does not resolve membership or authorize the actor. Child requests can supply
only declared event, span and metric codes, not arbitrary diagnostic text or
identity tags.

The authority's `BindInstance` supplies the effective grant, scope, configuration
revision, secret references and approved domain bindings. Each binding names an
ID, contract, action and resource class; its action and resource class must appear
in the package's requested capabilities. The gateway checks the selected binding
and contract before asking the authority to prepare a downstream call.
`PrepareDomainCall` must authorize and sign the actual downstream payload for its
registered destination. It cannot reuse a signature for a different payload.
The authority must also resolve the effective actor and delegation, preserve
causation, and keep the downstream deadline within the original call. The
receiving domain owner must still verify the signature and current grants.

The context layer checks that downstream calls preserve the admitted caller,
scope, actor, delegation, trace, task, run, attempt and cancellation references.
Their causation ID must name the original operation, and their deadline cannot
extend it. `ContextDownstreamOperationID` derives the downstream operation ID
from the original operation ID and stable service request ID. A retry uses the
same pair and payload; the receiving owner still provides durable duplicate and
conflict handling. Destination-specific versions, payload digests, grants and
approvals may change, but the authority and receiving owner must verify them.

`Recheck` is required before service work and before returning an operation
result. The context layer bounds concurrent admissions and service work, passes
short deadlines to external owners, and ends calls when their operation, grant,
process or private parent lifetime ends. These owners must honor cancellation.
Invalidation stops new calls; `Close` separately joins existing workers and closes
the original connection. The driver retains staged credentials and the exact
owner until both the process and context cleanup finish. A cancellation notice
does not prove that a remote business effect stopped or rolled back.

The authority interface alone does not authenticate a caller. The registered
composition uses `NativeContextAuthority`, enrolled keys and signed requests to
the selected identity owner. That owner checks credential possession, current
membership, grants and actor/delegation before returning admission. Controlled
test authorities remain useful for focused checks but do not establish those
production guarantees. Concurrent projects use separately admitted instances of
the same package with exact scopes; an absent project is not a wildcard grant.
The enrolled definition-edit route preserves the real human/project attribution
and conflict behavior described in [plugin compatibility](PLUGIN_COMPATIBILITY.md).
A legacy local actor label cannot satisfy that route's identity requirements.
Capability intersection and broader identity-product qualification retain their
separate AMUX-45, AMUX-47 and AMUX-50 scope.

Configuration reads return immutable, validated snapshots from the explicit
`ContextPorts.Configuration` owner. `config.wait-change` waits for a real newer
revision from that owner; it does not poll or use an ambient file as a second
source. The initial snapshot must match startup admission exactly. Later snapshots
must belong to the same package and advance their revision when their values
change. New secret references require fresh admission. The configuration lease
owns its notification resources and must join them on close.

The concrete native owner passes its verified initial read to the constructor
through a private, one-use receipt bound to that opening, admission, owner,
deadline and snapshot. This removes a duplicate startup request without supplying
cached authority to later calls. Public and generic-owner reads remain fresh.
The background watch waits for trusted native readiness or explicit change-wait
demand, then resumes from the verified revision so startup changes are not lost.

Lifecycle status reports the original instance's actual startup, readiness,
health, drain and stop state. Health starts as `unknown`; only that instance can
report `healthy` or `unhealthy` through its scoped service. A health report cannot
mark a process ready or revive a draining instance. Drain refuses new dispatches
and child startups while admitted operations retain their bounded lifetime until
process exit or forced shutdown. The child can wait for the drain signal and
finish its accepted work before leaving. Health reports describe the trusted
plugin's own assessment, not an independent proof of business-service health.

Domain subscriptions require a declared `subscribe` binding and an approved
filter envelope. `ContextPorts.Subscribe` returns an owned subscription;
`SubscriptionAuthority.AdmitDomainEvent` must verify each original signed event,
its audience, filter and current grants before returning a payload. The child
uses an opaque handle for `next` and `unsubscribe`. Each instance has at most 64
subscriptions, with one outstanding receive per subscription. Cancellation keeps
the exact subscription reserved until its original resources join. A child
cannot select raw subjects or reuse another operation's subscription.

Metric names come from the bounded declared code set. Metric requests accept a
bounded number, not child-selected labels. Fixed host tags include instance,
hub, package pin and admitted operation attribution. Payload tracing stays off
in context broker fixtures because their messages carry private data.

The native composition uses `NativeObservability` for local diagnostics. The
host must admit the destination directory and supply an existing private file
opened for append. The owner duplicates that descriptor and keeps one writer,
with at most 64 queued records of 8192 bytes each. The host selects a file size
limit between 64 KiB and 64 MiB. A full or no longer private destination refuses
new diagnostics; the owner never truncates, rotates or deletes it. Closing
cancels queued work and joins the original writer before closing its descriptor.
A successful diagnostic write does not establish durable audit acceptance.
The registered entrypoint admits this destination before constructing the owner;
direct host compositions must supply it explicitly as well.

`clock.elapsed` measures time since this lease opened, using Go's monotonic
clock. It does not subtract UTC timestamps, and changing the UTC source cannot
move it backward. The child cannot supply the origin. Like other methods, it
requires the current instance authority and lifetime.

## Required production context bridge

The following describes the implemented integration boundary and its owner duties.
The existing Python `AuthorityReader.evaluate`
returns an outcome, reason, authority sequence, verified operation and authority
reference. `EnrolledIngress.admit` signs direct enrolled commands. Neither API
supplies the full native instance admission or subscription contract by itself.
`NativeAuthorityProvider` now reads persisted independent-instance facts and
handles operation admission, recheck and downstream capability signing.
Private-child admission also checks the original parent's live lifetime and
evaluated grant against current signed authority facts.

Every bridge request must carry a version, unique request ID, exact owner
(package pin, instance ID, epoch and generation), pinned profile/hub, deadline,
and the method's input. An authenticated response must bind that request ID,
method, owner and input digest; identify its authority and current revision;
and include its validity deadline and outcome. Transport credentials and issuer
trust come from the enrolled host profile, never child request fields. Missing,
expired, mismatched or unverified responses fail closed. Private bytes stay out
of diagnostics. Cancellation must join the original request or subscription.

| Method | Input and required result |
| --- | --- |
| Bind instance | Host-admitted manifest and package digest, relationship, exact parent owner when private, configuration checksum. Return current grant, policy decisions for exact action/resource-class/resource-ID tuples, scope reference, configuration revision, secret references and registered domain bindings. Private children also require the exact current parent grant and effective access tuples. The host independently checks live generations and invokes Go `EvaluateCapabilityGrant`; Python must not duplicate that calculation. |
| Admit operation | Original signed envelope and registered destination. Return verified immutable operation bytes and authority reference only after signature, digest, audience, membership, actor/delegation, approval and current-grant checks. |
| Recheck | Exact instance admission and optional admitted operation. Reload current facts, including generation and revocation state; return a bounded validity deadline. A prior successful response is not a lasting grant. |
| Prepare domain call | Original admitted operation, binding ID, contract ID, stable request ID and actual payload. Return a freshly signed envelope for the registered destination using `ContextDownstreamOperationID`, preserved provenance and a non-extended deadline. Destination version, digest, grant and approvals must be resolved and verified. |
| Admit domain event | Original signed event, approved subscription envelope and admitted operation. Return payload only after source signature, digest, audience, filter and current authority checks. A matching correlation ID is insufficient. |
| Open configuration | Exact owner and admitted revision/checksum. Return a validated same-package snapshot, revision, secret references and an owned change stream. Establish snapshot and watch atomically, or provide a resume cursor that closes the race. Deliver strictly newer revisions; gaps or lost authority require authoritative resynchronization before disclosure. Closing must cancel and join the original stream. |
| Open domain subscription | Approved signed filter envelope and registered destination. Return an owned stream of original signed events, not bare payloads. Bind an opaque lease to the exact owner and operation; close cancels pending receives and acknowledges joined original resources. |

Persisted native authority records carry instance facts and policy inputs. The
host owns live generation checks and Go capability evaluation. The registered
composition connects the native authority, configuration owner, capability
gateway, configuration-event subscriptions and observability through explicit
enrolled routes. Configuration and subscription close paths retain the original
local and remote allocations until joined cleanup is confirmed.

Native macOS ARM64 checks cover the registered foreground route and authenticated
child configuration-event delivery, unread-event revocation and joined cleanup,
alongside the focused service and lifecycle checks. Controlled service fixtures
and actual signed-owner checks have distinct results in
[AMUX-44](https://adag-csai.atlassian.net/browse/AMUX-44). These results do not
qualify arbitrary remote owners, every capability effect, untrusted-code
sandboxing or other platforms.

### Native authority v1 fields

AMUX-47 owns the shared `native-authority-request`, `native-authority-response`
and `native-authority-facts` schemas, all `1.0.0`. The native consumer embeds
exact copies and validates against them. The tables summarize those schemas;
the shared schema files remain the field authority.
Objects are closed (`additionalProperties: false`); all listed fields are
required, with explicit `null` where stated. Reuse `common` definitions for
`identifier`, `reference`, `scope`, `revision`, `timestamp`, `digest` and `grant`,
and the existing ordinary-plugin lifecycle owner shape for `owner`.

Both messages use `{schemaVersion, algorithm, canonicalization, claims,
signature}`. `algorithm` is `Ed25519`, `canonicalization` is
`RFC8785-JCS-UTF8`, and `signature` is the existing 86-character unpadded
base64url form. Sign the complete canonical `claims` object. Each complete
message is at most 65,536 UTF-8 bytes; reject duplicate keys and noncanonical
signature encoding. This reuses the ingress signing format, not its command
purpose or its authority semantics.

| Claims | Exact fields |
| --- | --- |
| Request | `purpose: "agentmux-native-authority-request-v1"`, `requestId: identifier`, `method: "bind-instance" \| "admit-operation" \| "recheck" \| "prepare-domain-call"`, `profileId: identifier`, `hubId: identifier`, `authorityId: identifier`, `owner`, `signingKeyRef: reference`, `issuedAt: timestamp`, `expiresAt: timestamp`, signed `replySubject` using the schema's `_INBOX` pattern, `input` as below. |
| Response | `purpose: "agentmux-native-authority-response-v1"`, exact request `requestId`, `method`, `profileId`, `hubId`, `authorityId`, `owner`; `requestDigest: digest` over JCS request claims; `signingKeyRef: reference`, `authorityRef: reference`, `authoritySequence: revision`, `issuedAt: timestamp`, `validUntil: timestamp`, `outcome: "allowed" \| "denied" \| "approval_required" \| "unavailable"`, `result` as below or `null` for every non-allowed outcome. |

Host requests expire within five seconds and within the original operation's
deadline. Responses cannot extend either bound or the next relevant authority
activation/expiry. `authoritySequence` identifies the read record; it is not the
entity's `authorityRef.revision`. Signing references only select already pinned
or enrolled keys authorized for this purpose and profile. Neither message can
carry a public key, key URL or replacement trust root. Each response is accepted
only for its outstanding request; retaining facts for comparison does not allow
reusing them as authorization on a later call.

| Method | `input` | Allowed `result` |
| --- | --- | --- |
| `bind-instance` | `{manifestDigest, relationship, parentOwner, configurationChecksum}`. Digests use `common.digest`; relationship is `independent` or `private`; parent is exact owner or `null`. The host retains its validated manifest. The provider resolves its admitted declaration by digest, not from child claims. | `{grant, policy, parentGrant, parentAccess, scopeRef, configurationRevision, secretReferences, domainBindings}`. `grant` and nullable `parentGrant` use `common.grant`; `scopeRef` and secret items use `common.reference`; revision uses `common.revision`. `parentAccess` is an array of access tuples. Each domain binding is `{id, contractId, action, resourceClass, resourceIds}`, with identifier fields and exact resource IDs. |
| `admit-operation` | `{envelopeBytes, audience}`. Bytes are canonical base64 encoding of the original signed envelope, without reconstructing it. Audience is `{hubId, serviceId}` using identifiers and must match the host's registered destination. | `{operation, authorityRef}`. Operation validates against `operation-context`; reference uses `common.reference`. Its claims must match the verified original envelope. |
| `recheck` | `{instanceFactsDigest, operation, operationAuthorityRef, originalEnvelopeBytes}`. Digest binds the accepted bind-instance result; the other three fields are all `null` or the admitted operation, reference and unchanged original signed envelope bytes in canonical base64. | The full current bind-instance result, plus `{operationAuthorityRef}` (nullable). Go reruns its capability intersection, verifies owner/admission compatibility and refuses stale or widened access. Returning only `allowed: true` is insufficient. |
| `prepare-domain-call` | `{operation, operationAuthorityRef, bindingId, contractId, serviceRequestId, serviceReplySubject, payload, originalEnvelopeBytes}`. Original signed envelope bytes remain unchanged; service request ID is `request_` followed by 64 lowercase hexadecimal digits. | `{bindingId, envelopeBytes, serviceRequestBytes}` containing the fresh signed destination envelope and issuer-signed capability delivery request. The native consumer applies provenance, payload, downstream-ID and delivery-binding checks before dispatch. |

An access tuple is `{action, resourceClass, resourceId}` with identifiers.
`policy` is `{reference, subjectInstanceId, scope, issuedAt, expiresAt,
decisions}`; each decision is `{access, outcome}`, with outcome `allow`, `deny`
or `approval_required`. These map directly to `CapabilityPolicy` and
`CapabilityAccess`. Grant references map from `(grantId, issuerHubId, revision)`.
All tuple, decision, action, resource, secret and binding arrays have at most 256
items and reject duplicates. Private parent facts must match `parentOwner`;
independent instances use `parentGrant: null` and `parentAccess: []`. Go retains
the only capability intersection evaluator and uses its own current clock and
live owner handles. A domain binding is selectable only for evaluated access;
resource IDs are authority input even though the current public binding omits them.
The current native context has a tighter limit of 64 secret references and domain
bindings; it refuses larger valid responses instead of truncating them.

`NewNativeContextAuthority` implements the four authority methods using this
protocol. It retains original signed operation bytes and original instance facts
for comparison, but obtains a fresh signed response on every recheck. Changed
instance fact digests currently require re-admission. A newer authority record
revision is accepted only after a fresh verified response for the same admitted
operation. The current provider applies the same unchanged-facts rule; allowing
configuration changes through that rule still needs owner alignment.

`NewNativeEnrolledKeys` implements `NativeAuthorityKeySource.Current` and
`NativeCapabilityServiceKeys.CurrentServiceKey` against the existing retained
identity aggregate. Host enrollment supplies the profile, hub, authority,
organization, stream name/domain, trusted stream creation time, recovery sequence
floor, retained-storage limits and exact host/issuer identity and key references.
Each lookup reads the current owner record through the borrowed host transport.
It checks the dedicated stream's retention settings, creation identity, sequence
floor, latest record binding and complete shared schemas, then resolves the
current active key and service identity association for the requested purpose.
It refuses a lower observed revision or changed bytes at an already observed
revision. Each returned key carries the exact read's `AuthoritySequence`. The
native client retains the highest sequence from current key reads and verified
signed authority replies, and refuses an allow below that known sequence. The
capability gateway carries its final recheck sequence through the last service-key
lookup and refuses disclosure if that lookup observes a newer authority revision.
A compatible newer revision can be admitted by a fresh request. These checks fence
state this host has already observed; they do not make a remote revocation atomic
with a read or another owner's operation. Key validity is checked after the awaited read; successful keys do not
replace the next current-state read.

This reader checks the latest owner record and stream continuity metadata. It
does not replay the retained prefix, maintain `OwnerHistory`, or persist a new
recovery checkpoint. It therefore does not provide `LedgerAuthorityReader`'s
verified-prefix recovery guarantees. The host must preserve and supply its
trusted recovery floor; neither a first read nor an observed stream creation time
can establish enrollment.

`NewNativeAuthorityNATSExchange` requires admitted `localtls.ClientTrust`, with
an exact local endpoint, enrolled CA, DNS name and server leaf digest. It uses
TLS 1.3 and TLS-first dialing before presenting JWT/NKey credentials, with no
reconnect or discovered endpoint. It verifies the account-signed credential's
exact publish subjects and single private reply-prefix subscription. The host
broker must isolate every principal's reply prefix and restrict receiving
services to broker-authorized responses. A random inbox is not an authorization
boundary. The signed authority and capability reply subjects use the same
host-selected prefix; key-source JetStream reads use fresh subjects under it.

The transport owns its original connection, dialer and request subscriptions. It
never retries and joins original work on close. A nonnil owner returned with an
error must still be closed. Host shutdown closes it after context and key-source
callers join. The Go TLS/NATS boundary has not yet been live-qualified.

`TestNativeAuthorityPythonProviderIntegration` runs the real Python provider,
signer, enrollment transition and retained-ledger reader through one offline
Python process. It checks native binding, operation admission, fresh recheck,
persisted revocation and refusal of unavailable downstream signing. The broker
responses and pinned test keys are controlled; this does not qualify a live
broker or production key enrollment. Set `AGENTMUX_NATIVE_AUTHORITY_PYTHON` to
the prepared Python runtime containing the SDK and NATS dependencies to run it.
The runtime Go consumer never starts Python.

### Signed capability replies

`NewNativeCapabilityGateway` consumes the registered
`capability-service-request` and `capability-service-response` contracts.
It forwards the issuer-prepared `serviceRequestBytes` unchanged after checking
its signature, current authority, exact owner, registered destination, resource,
scope, original operation and signed reply subject. It does not create a new
request wrapper. `ContextApprovedEnvelope.Clone()` preserves the private host
preparation when a context caller passes the approved envelope to the gateway.

The request limit is 96 KiB and the response limit is 64 KiB. The enclosing
native-authority response still has a 64 KiB limit, including nested base64
bytes; a larger preparation is refused rather than truncated. Both contracts
use closed Ed25519/JCS wrappers. `requestDigest` binds the complete canonical
signed service request. `envelopeDigest` binds the exact decoded envelope bytes,
including whitespace and number spelling. These are distinct checks.

Each host route pins the profile, hub, service ID, service instance, service
identity reference, signing key reference and request/reply contract IDs.
`NativeCapabilityServiceKeys.CurrentServiceKey` verifies that exact enrolled
service association for `agentmux-capability-service-response-v1`; the retained
key reader above implements it. A response cannot replace trust
with its own key or owner label.

The gateway validates the signed response and registered payload schema,
rechecks source authority, then verifies current service trust again before
returning private payload bytes. Deadlines are checked after awaited trust
lookups and signature verification. Replies cannot extend the original request
or operation deadline. Lost replies remain uncertain; the gateway never retries.
Its `Close` cancels and joins original calls. The host closes the borrowed route
transports only after those calls have joined.

`TestNativeCapabilityPythonServiceIntegration` connects the Go consumer to the
actual Python authority provider, `CapabilityReplyService`, capability receiver
and retained resource reader in one offline process. It checks a signed storage
read against the original retained record digest and refuses access after a
persisted enrollment revocation. Controlled broker responses and test key
resolvers mean this test does not qualify production key enrollment or live
NATS delivery. It uses the same `AGENTMUX_NATIVE_AUTHORITY_PYTHON` runtime as the
native authority integration test.

The subsequent stream proposal adds `open-config`, `open-subscription`,
`next` and `close` to separately registered owner contracts. Open returns signed
`{leaseId, owner, operationId, cursor, validUntil}` plus a config snapshot
`{configurationBytes, configurationRevision, checksum, secretReferences}` or
an approved subscription envelope digest. `operationId` is null only for
instance configuration. Signed next replies bind that lease, request and cursor,
and contain a newer snapshot or the original signed event bytes. No bare event
payload is authoritative. Signed close replies bind the original lease and
`joined: true` only after its original worker and subscription resources join.
Local close also joins the Go connection and callbacks. Cursor gaps require
authoritative resynchronization; loss of authority stops disclosure. Exact
stream schema registration follows instance/operation alignment.

## Owner-run command

Run the prepared native macOS ARM64 executable as the owning user:

```sh
agentmux-plugins validate --composition /absolute/owner-private/composition.json
agentmux-plugins plan --composition /absolute/owner-private/composition.json
agentmux-plugins run --composition /absolute/owner-private/composition.json
```

`validate` and `plan` check package, source, configuration, version and registry
declarations. They do not create a state directory, acquire its lock, connect to
NATS or claim execution readiness. `run` additionally validates the local driver
bindings, locks the selected state directory, checks the complete native
executable set and starts the selected processes. An `active` result follows
successful activation. The command remains in the foreground to supervise them.

The private composition shape is defined by `composition` in
`platform/cmd/agentmux-plugins/main.go`:

| Field | Required content |
| --- | --- |
| `schemaVersion` | `1.0.0`. |
| `catalog` | Explicit package directories, manifest paths, source ID/path/scope, source file and checksum, and positive file/count/total limits. |
| `roots`, `selected` | Full five-field pins. `selected` supplies dependency pins; use an empty array when none are needed. |
| `installationMode`, `platform` | `independent` and `{ "os": "darwin", "arch": "arm64" }`. |
| `configurations` | One exact package pin, admitted schema resource bindings and private configuration file per resolved package. |
| `contracts` | Explicit supported contribution kind and contract reference pairs. |
| `instances` | One unique instance ID for each resolved package ID. |
| `driver` | Hub ID, ordinary account public key, TLS URL, CA file, state directory, controller credentials and per-instance pin/credential/workspace bindings. |
| `activationTimeoutMs`, `cleanupTimeoutMs` | Positive limits no greater than 180,000 milliseconds each. |

For the native context host, use `schemaVersion: "1.2.0"` with the same
explicit topology as version 1.1.0 and a `nativeContext` object:

| Field | Required content |
| --- | --- |
| `profileId`, `repositoryRoot` | The registered central profile and an approved repository root. |
| `selectionPath`, `selectionSHA256` | Absolute path and exact SHA-256 digest of the private native host selection. |
| `observability` | An existing private append-only file `path`, explicit `maxBytes` (64 KiB to 64 MiB), and `eventCodes`, `spanCodes`, `metricCodes` arrays. |

`run` retains the original central profile, host policy, selection, credentials,
key files and observability descriptor. The selected lifecycle driver must equal
`driver` in the command composition. Required capabilities can pass declaration
validation only on this native context path. The manager and process driver
require the concrete registered native provider, which checks the manifest,
current grant and policy before starting the process. Lifecycle-only and generic
context drivers continue to refuse required capabilities. Authority, lifecycle and context each use
their explicit TLS trust and credential bindings. `subscriptionRoutes` names each
binding, source, service signer and scope explicitly; the host checks these against
the activation declaration. Configuration routes do not supply subscription routes.
Optional `privateStorageResources` entries pass unchanged from the protected
activation declaration to the native identity owner. The capability owner checks
their binding digests and provides the shared plugin storage interface.

`validate` and `plan` check this command input's shape and package declarations.
They do not admit the selected host files or establish native service readiness.
A failed startup retains the same owner while cleanup is unfinished. The command
reports `cleanup_required` and retries that owner; a historical error remains an
error after cleanup completes. These paths have offline admission and ownership
tests. Live broker delivery and installed startup require separate qualification.

For explicit child ownership, use composition `schemaVersion: "1.1.0"` and replace
the legacy `roots`, `instances` and `configurations` fields with:

| Field | Required content |
| --- | --- |
| `topology.instances` | Explicit `instanceId`, full `pin`, `installationMode` (`independent` or `private-child`) and `placement` (`{"kind":"local-process"}`) per process. |
| `topology.roots` | Instance IDs whose independent owner claims are retained. Package resolution does not invent these claims. |
| `topology.children` | `parentId`, `childId` and manifest `relationship` (`private` or `independent-reference`) per selected child edge. |
| `topology.dependencies` | `consumerId` and `dependencyId` per selected dependency edge. |
| `instanceConfigurations` | One `instanceId`, full `pin`, schema `resources` and private `configurationFile` per instance. |

Keep `selected` as an explicit array of dependency pins, including an empty array
when none are needed. The remaining fields keep the meanings above; the top-level
`installationMode` stays `independent` for compatibility, while each instance's
own mode is authoritative. Mixed legacy and topology bindings fail. The command
accepts at most 64 instances and 256 edges of each kind. Credentials and assigned
workspaces are supplied separately for each instance, including multiple
instances of the same package.

To control root retention, explicitly enable owner input:

```sh
agentmux-plugins run --composition /absolute/owner-private/composition.json --control-stdin
```

This topology-only option accepts one closed JSON command per line. Send
`{"schemaVersion":"1.0.0","action":"snapshot"}` to read current owners. To
release a root, send `schemaVersion`, `action: "release-root"` and `owner` containing
the complete owner reference from that snapshot. Its full package pin, instance
ID, epoch and generation must still match. A stale reference cannot release a
replacement. Commands are bounded to 8 KiB; invalid commands return fixed
diagnostics without echoing input. EOF explicitly ends this foreground owner and
joins all remaining processes. Signals retain the same shutdown behavior.

The input loop is owned by the foreground command and is enabled only by that
option. It adds no broker subject or child permission. It represents the local
OS owner, not authenticated organization identity. Topology-mode snapshots report
failed subtrees while unrelated independent owners continue; ordinary v1.0
compositions retain their existing stop-on-exhausted-restart behavior.

Composition, configuration, CA and credential files must be owner-owned regular
files with mode `0600`, one link and an owner-only `0700` parent. The existing
state directory and any assigned workspace must be owner-owned `0700`
directories. Paths must be absolute and canonical. For these private inputs,
held-descriptor checks reject unsafe ACLs, symlinks, writable ancestors and
unqualified mounts. Original source
files may remain owner-owned `0644` files; their explicit checksum binds the read.
The initial command accepts at most 64 catalog packages, with a declared total
snapshot budget of 512 MiB and a per-file limit of 128 MiB.

Status output contains fixed categories, counts and package pins. Manifest
payloads, source bytes, configuration values, credentials, arbitrary child output
and raw transport errors are not logged. A caller that needs private bytes must
use an explicit private accessor; generic formatting of admitted objects is
redacted.
Counts and pins describe the admitted composition. In topology mode, `snapshot`
describes the current instances and retention claims after any releases.

## Readiness, failure and recovery

The [ordinary lifecycle schema](../contracts/v1/schemas/ordinary-plugin-lifecycle.schema.json)
defines `prepare` and `stop` controls and `registered`, `ready`, `failed` and
`stopped` reports. It is separate from protected kernel control messages. A
private bootstrap binds the selected instance, complete package pin, fresh
manager epoch, generation, configuration and contribution checksums, command ID
and deadline. The controller subscribes before starting the child. The child
subscribes to control, reports registration, receives `prepare`, then reports
readiness. A PID, open port, stderr line or container state is not readiness.

Independent frames retain the closed v1.0.0 shape. Private-child v1.1.0 frames
add the complete `parentOwner`, which the child must acknowledge unchanged.
Reports from a previous parent lifetime fail even if the child pin is unchanged.
These references fence manager lifecycle access; they do not revoke a NATS JWT or
issue an effective business grant.

The manager stages additions in dependency order. Failed additions are stopped
in reverse order while the previous active set remains published. Every actual
attempt consumes a new generation, including failed attempts. Unexpected exits
use the manifest restart limit and the same exact package/configuration pins.
Connection loss immediately invalidates availability and stops the owned process.
Required dependency failure also invalidates dependent contribution references.

Within an ownership group, the manager starts parents before private children,
then waits for readiness in required dependency order. Parent lifetime is checked
separately from readiness, so a parent can wait for its required child without a
false lifecycle cycle. A parent's deadline includes this startup work. Parent
loss immediately invalidates descendant references and stops the original private
processes. Cleanup runs deepest first; replacement begins only after every old
owner joins. Parent recovery advances the subtree's generations and spends the
parent's restart budget. A child's own unexpected failure spends that child's
budget. Shared independent instances remain under their own owners.

Shutdown first asks the child to stop, then uses bounded TERM and KILL portions
of its drain deadline when needed. The driver joins the original process wait and
output readers and finishes its lifecycle callbacks before removing owned staged
files. It never adopts a PID or kills a process group. A `stopped` command result
means manager and driver cleanup completed.

An unjoined process or unresolved staged resource stays with its original owner;
the foreground command reports `cleanup_required` and retries bounded cleanup.
It cannot claim success or start a replacement while ownership is unresolved.
A consumed file-close failure remains attached to the driver after all live work
and staged resources are gone. The command then exits with a fixed failure code,
preserving that failure rather than retrying the consumed descriptor as proof of
success. An uncatchable owner termination is an uncertain outcome; this command
does not adopt an orphan on its next run.

Active package replacement, arbitrary removal, instance changes and configuration changes
are refused with `plugin_upgrade_required`. This preserves the current process
set and configuration until the drain/upgrade owner exists. Keep the last working exact package set and its
compatible configuration. Recovery may reselect those pins after explicit
shutdown; it must not downgrade incompatible storage. This command performs no
storage migration or live-record cutover.

## Current execution limits

The process driver accepts native macOS ARM64 Mach-O executables. It rejects
scripts, managed interpreter entry points, containers and migrations explicitly.
Legacy flat compositions refuse child declarations; explicit topologies validate
and supervise them. Existing trusted Python entry points continue through
their original path. Python and TypeScript SDK execution and upgrade/drain
qualification belong to AMUX-46. The manifest
retains those declarations so later implementation cannot silently lose them.
Linux and macOS AMD64 remain deferred; Windows and WSL remain unsupported.
