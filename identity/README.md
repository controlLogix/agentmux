# Identity authority

`AuthorityReader` reads a pinned NATS owner aggregate and evaluates a signed
operation against its current records. `EnrolledIngress` verifies application-key
possession and prepares signed direct calls. `transition` computes enrollment,
revocation, membership, grant and approval changes. `IdentityCommandOwner` prepares
a complete state and audit record for the shared ledger. These components run
outside the protected kernel; they do not yet form a deployed identity service.

The host supplies an authenticated JetStream context restricted to the intended
retained authority stream, plus its stream, subject, hub, entity, profile and organization IDs.
`current()` uses the ordinary leader-backed stream API, not a direct-read replica
or a derived KV view. Missing, malformed or unavailable state refuses admission.
Cancellation propagates. The read has a two-second default timeout, bounded to ten
seconds. Provisioning must preserve the accepted file-backed Limits retention,
discard-new, no automatic age expiry and owner-only writes. This component does
not provision a stream or prove its broker account permissions.

`await reader.evaluate(envelope_bytes, audience=destination)` returns a private,
immutable `Decision`. Outcomes are `allowed`, `denied` and `review-required`.
An allowed result includes canonical operation bytes, the current authority stream
sequence, an `authority_ref` using the owner entity version, and the verified
effective principal ID for audit. The stream sequence is not the entity version. This is a current
calculation, not a durable audit receipt or reusable credential. Cryptographic or
structural failures raise fixed `ContractError` codes. Logs must not serialize
the envelope, records, private operation bytes or broker errors.

The reader selects enrolled issuer keys, checks the active issuer service and
source instance, then reuses the Python SDK's Ed25519/JCS envelope verification.
It checks exact transport, caller, effective actor, membership and grant references.
The production clock is sampled after the authority read. Hard denial overrides
approval. Review approval must bind the grant, payload digest, audience, operation
ID and expected version, with a current approver identity, membership and explicit
`identity-approve` grant for that grant ID. `identity-approval-set` also verifies that the authenticated actor owns the
explicit approval permission before preparing a change.

The closed `identity-authority-state` schema bounds each collection to 1,024 records;
the identity boundary limits each encoded request, envelope and owner record to
64 KiB. The collection count does not override that byte limit. Public keys and references are
stored, never private keys or bearer credentials. Reference IDs are unique across
collections; principal IDs and external `(issuer, subject)` pairs cannot collide.
`owner-record` adds the `identity-authority` entity kind without changing existing
record fields, versions or meanings. New consumers must explicitly support it;
old consumers must continue refusing unsupported kinds.

This slice supports direct human/device/service/plugin `task-inspect` operations,
direct human definition commands and organization-scoped identity administration. Delegation is explicitly refused. Instance
capability construction is separate: this evaluator does not reproduce the Go
`EvaluateCapabilityGrant` rules or establish a plugin's current live generation.

## Definition commands

`definition-save` and `definition-drop` are new major-1 commands addressed only to
`definition-owner`. They use the existing signed envelope. The payload contains a
stable `definitionId`, logical name, `repo` or `global` scope and `expectedChecksum`.
Save also contains a closed `definition` object using the existing definition
fields. Actor, path and payload-level expectedVersion are rejected. The legacy
adapter combines the outer name with nested fields before calling its encoder.
It must derive paths from admitted scope, never from caller-provided paths.

Grants bind the stable ID, logical name, repo/global target and exact operation
scope. Global edits require an explicit global grant with absent project and
workspace; a project grant never authorizes them. The verified `audit_actor` must
replace request-body authors. A successful evaluation does not make the existing
`EditIdentity` constructor an authentication mechanism.

The definition owner keeps a retained mapping of identity, name/scope, integer
revision, current checksum and deletion tombstone. The integer is never derived
from SHA-256. Check both revision and checksum under the owner lock:

- First creation: no prior record, `expectedVersion=0`, null checksum.
- Update/delete: retained version `N`, exact current file checksum.
- Recreation: retained tombstone version `N`, null checksum.

Each successful change increments the integer, even if bytes repeat. The owner
rejects stale revisions and identity/name mismatches. Deletion must retain its
revision. The definition owner must integrate this retained mapping with its file writer.
A successful authority check alone does not make file replacement and audit one
NATS commit.

The domain owner re-evaluates current authority after acquiring its mutation lock
and immediately before mutation/commit. A read of the authority aggregate and a
write to a separate definition aggregate are not an atomic cross-stream transaction.
Identity-owner changes should serialize within their own aggregate using the
existing conditional-append primitive, rereading and reauthorizing after conflicts.

## Native context boundary

`platform/plugins/ContextAuthority` remains the native integration boundary.
`BindInstance` must resolve current identity, instance/parent generations, package,
grant and policy, then call `EvaluateCapabilityGrant(CapabilityEvaluation)` with
the admitted manifest, relationship, instance, exact parent grant/access, current
grant/policy and host time. Only its resulting action/resource-class/resource-ID
tuples may select service and domain bindings.

The native provider returns persisted independent and private-child inputs.
`validate_native_lineage(state, index, row, now)` checks the current parent chain
in one authority snapshot: exact owner pins, active identities and host recheck
authority, exact current parent grant, delegation bounds and allowed retained
domain tuples. It returns the earliest expiry. Parent access without a matching
retained domain binding is refused; the record alone cannot prove an arbitrary
manifest declaration. Go still checks the actual parent process lifetime,
manifest declarations, effective access and equal parent/child ledger sequences,
and runs its normative grant intersection. Configuration watches and event streams
remain separate integrations. No arbitrary callback stands in for authority.

`AdmitOperation` must return the immutable verified operation and authority
reference. `Recheck` reloads current records. `PrepareDomainCall` resolves an admitted
binding, validates the actual payload and signs a fresh envelope for its registered
destination. `EnrolledIngress` supplies a signer for direct enrolled calls, but no production
`ContextAuthority` implementation yet connects it to native service handles.

## Enrolled ingress and identity changes

`EnrolledIngress.admit` accepts a closed, signed request with a maximum lifetime
of 60 seconds. The configured private signing seed and issuer reference come from
the host. A request cannot supply its own actor or scope: the service derives them
from the current transport and grant records. Proof binds the actual payload,
operation ID, expected version, profile, hub and authority. It supplements broker
credentials; it does not discover a NATS publisher's identity from message data.
The result exposes a dispatch envelope only for allowed calls. Its separate private
audit envelope preserves authenticated refusals for the identity command owner.
`IdentityService` owns a bounded NATS subscription, exact signed inbox binding,
tracked calls and retained shutdown tasks. It returns signed request-bound receipts.
Unconfirmed outcomes require reconciliation under the original operation ID.

Enrollment transitions verify possession of each public application key and retain
revoked records with a new revision. Membership and grant mutations remain within
the aggregate's explicit organization. Existing references are exact: changing a
revision does not silently renew dependent grants. No private key or broker bearer
credential is stored in the aggregate.

`IdentityCommandOwner.execute` reads current authority, checks replay binding and
prepares a complete owner record. Allowed changes put state and authorization audit
in one record; denied and review-required commands preserve state and carry a
separate `authorizationDecision`. Unverified actors cannot enter that audit record.
Replay checks current authority again before returning a private receipt. Conflicts
require a new read and authorization; uncertain writes require reconciliation with
the original operation ID. There is no automatic retry.

The shared ledger now enforces `append(..., valid_until=...)` immediately before
publish. `LedgerAuthorityReader` also uses its retained history and trusted
`StreamIdentity(created, minimum_sequence)` checks. The deadline covers envelope expiry and the next activation
or expiry of a timed authority record, including future hard denials. A check before
calling a ledger that performs more reads is insufficient. Wrong-scope denials also
need an admitted audit destination: the organization ledger correctly refuses an
operation whose original signed scope differs from its pinned scope. Do not rewrite
that operation to make an audit append pass. Wrong-scope and unverified refusals still need an authorized audit destination.
The current organization command service is tested offline through the real ledger
implementation, with a controlled NATS boundary.

An empty authority stream never trusts the first request's actor or key.
`BootstrapOwner` commits a complete initial record only under a host-private
`BootstrapPermit` that pins its exact bytes for at most five minutes and verifies
every issuer and transport possession proof. It reconciles only that exact original
record after uncertainty. The explicit private-profile ceremony, broker credential
provisioning and trusted stream-identity source still need host integration. Local and Keycloak
profiles, delegation, native subscriptions, and live broker revocation tests remain
incomplete. The production Hub path can now resolve retained legacy alias records
through current identity authority and fence delivery by the persisted agent
registration generation. Legacy mode remains available when no enrolled adapter is
selected. Installed Hub, NATS, and broker qualification for this migration still
remains incomplete. Offline tests use public fixture keys and controlled responses;
they do not qualify a running service.

## Record capacity and time validity

Every timed authority record is parsed and checked for an ordered UTC interval,
including revoked records. Invalid proposed dates become an audited rejection;
they cannot poison later reads. No signed timestamp is normalized.

The 64 KiB record cap includes its operation and audit. Admission bounds the state
to 48 KiB after sizing every reference at the maximum integer width and every
status as revoked. There is no separate 8 KiB operation ceiling. The complete
request and resulting record must each fit within 64 KiB. The operation schema
itself has no approval-count maximum; ingress accepts up to 32. Larger direct
operation combinations remain subject to the whole-body cap. Existing records
above the state reserve may still be revoked if the complete result fits; growth
continues to enforce the reserve. Nothing is truncated to make a record fit.

Allowed `Decision.valid_until` comes from the evaluated snapshot and bounds the
signed request deadline, attestation expiry, and every upcoming timed authority
activation or expiry. A receiving mutation owner passes it to
`OwnerLedger.append(valid_until=...)`; it does not replace a fresh authority check.

Network `IdentityService.start()` requires host-supplied `history` and
`checkpoint_path`. It verifies history before subscribing, checks checkpoint
cadence after commands and every 30 seconds, and closes the cache after draining
requests and the timer. The host supplies the private directory and trusted stream
identity. Direct offline `handle()` tests can still omit the cache; this mode
cannot start a network subscription.

`application_lease` optionally installs the application binding provider. Its
signed observation must come from a current enrolled service issuer, with current
membership and an exact `application-attest` grant for the instance and scope.
The host must explicitly provision this purpose-authorized signer and create the
observation from verified runtime, profile, release, policy and workspace state.
A plugin request signing key is not implicitly authorized for this purpose. The
host ends the lease when that runtime lifetime ends. Clients use their existing
approved connection, bind the nonce and reply subject, verify the reply, and
invalidate binding on reconnect. Signer provisioning and startup integration are
still incomplete; broker readiness does not establish application readiness.

## Native authority bridge

`native-authority-request`, `native-authority-response` and
`native-authority-facts` define standalone signed messages, separate from P01
command envelopes. Requests expire within five seconds and sign their exact inbox
reply subject. Recheck and downstream preparation retain `originalEnvelopeBytes`,
so the provider can authenticate the original ingress again instead of trusting a
reconstructed operation object. The response binds the exact request-claims digest,
method, owner, profile, hub and authority, plus current authority revision and
sequence. These two numbers are not interchangeable.

`identity-native-instance-set` persists native owner, plugin identity, host service
identity, declaration/configuration digests and capability/policy facts through the
organization command owner. `NativeAuthorityProvider` reads those facts through the
shared ledger. It requires an enrolled host-service transport, current membership
and an exact `native-authority-<method>` grant for the instance ID. Revoking the
instance row or either identity stops disclosure. Request JSON cannot install facts,
replace a key or select a stream. Bind, direct operation admission and recheck are
implemented for independent instances; private-parent evaluation and downstream
preparation currently refuse. Native live generation checks and Go's
`EvaluateCapabilityGrant` remain mandatory. Configuration watches, signed event
subscriptions, delegation and application-startup binding still need integration.

The capability payload/reply schemas are registered with fixed domain destination
IDs. This defines their wire format only. Direct ingress does not admit those
commands, and registration does not implement a storage, secret, execution or
other receiving owner. Existing record ownership and recovery remain with those
services.

## Checkpoint and application host handoffs

The checkpoint writer runs off the event loop. SQLite stays on the owner loop;
the writer requests pages of at most 32 immutable records. Close joins the writer
before closing history. Each generation has a unique immutable manifest path.
The host supplies async `checkpoint_committed(CheckpointReceipt)` and must retain
its manifest path, digest and cursor durably before returning. A failed callback
leaves files intact and fails service health; cadence is not marked complete.

`ApplicationObservationLease.refresh(signed_observation)` is a host-only in-process
API. It preserves the signed instance, generation, lifetime ID, release, policy,
workspace and scope, and refuses observation-time rollback. Each request still
verifies the observation signature, freshness and current enrollment. Refresh
must follow new runtime verification, never merely retimestamp old evidence.
`IdentityService.replace_application_lease(lease)` requires the previous lifetime
to have ended, a higher generation and a different lifetime ID. The production
Go-host delivery channel and purpose-authorized signer are not implemented here.

## Capability service preparation

`prepare-domain-call` takes `serviceReplySubject` in its signed input and returns
`serviceRequestBytes` as well as the admitted `envelopeBytes`. The native request
and response remain bounded to 64 KiB: base64/framing combinations that do not fit
are refused intact. No 96 KiB transport support is claimed. The capability request
validator accepts at most 96 KiB framing and at most 64 KiB decoded envelope.

`identity.capability_service.evaluate_capability_service_request(snapshot, raw,
service_id=..., now=...)` returns the current allowed `Decision` or raises a fixed
error. It checks the enrolled issuer, host transport and method grant, current
native generation and canonical facts digest, exact wrapper/inner bindings and
fresh downstream authority. Its `valid_until` bounds the receiving mutation.
The service wrapper schemas are standalone signed protocols, like native
authority wrappers, rather than registered P01 payload contracts with one fixed
destination. Existing capability payload contracts retain their fixed routes.

## Explicit application-attestor enrollment and delivery

`provision_application_attestor(path, profile_id=..., authority_id=...,
instance_id=..., identity=..., issuer_ref=..., transport_ref=...,
ingress_issuer_ref=..., issued_at=..., expires_at=...)` creates a distinct Ed25519
seed in a caller-selected private directory. It uses create-only mode 0600,
refuses symlink traversal and never replaces an existing key. The file is the
closed `agentmux-application-attestor-key-v1` JSON format, with a standard base64
32-byte seed and the exact profile/hub/authority/instance and identity/issuer/
transport references. Only the enrolled attestor process may receive this file.
A partial or uncertain write is not silently repaired or rotated.

The returned public `identity-enroll` payload includes possession proofs. It is
not a committed enrollment or grant. An enrolled administrator submits that
payload through the existing signed identity command path, then commits exact
membership and an `application-attest` grant whose caller and actor are the new
service identity, resource is the selected application instance, and scope is
the explicitly selected organization/project/workspace. Client `application-bind`
grants remain separate. `load_application_attestor(path)` only reads an existing
private store; its signer accepts the two application observation purposes and
refuses another profile, hub, instance, issuer or transport binding.

AMUX-61 supplies a separately enrolled application-attestor NATS credential with
permission to publish only the selected identity command subject and use its
bounded reply inboxes. This is not the HOST account; neither its permissions nor
the inherited bootstrap pipe change. This module does not mint broker credentials.
The observation producer must recheck the owned runtime process and verified
kernel scope before each observation. `releaseDigest` is the verified kernel
scope's release-manifest digest. Policy, workspace, scope and signer references
come from explicit application enrollment, never paths or kernel readiness.

Send `application-observation-update` over that connection to
`amx.v1.h.<hub>.o.<organization>.identity.<authority>.command`. Its signed claims
bind action `refresh` or `end`, request/profile/hub/authority IDs, generation,
lifetime ID, attestor transport reference, exact reply subject, a time window no
longer than five seconds, and base64 `application-runtime-observation` bytes.
The inner observation is separately signed by the purpose-authorized issuer.
The service requires both credentials to map to the same enrolled attestor
service identity, checks its current grant and membership, and returns a signed
`application-observation-receipt` bound to the full-wrapper request digest.
The actual NATS reply must equal the signed inbox before dispatch. No unsigned
failure proves that an update was rejected; reconcile the same lifetime.

Refresh preserves the runtime tuple and refuses timestamp rollback. End marks the
exact lifetime done and cannot be undone by replaying a refresh. A higher
generation requires a different lifetime ID and an ended or expired prior lease.
If an end message cannot be delivered, the five-second observation expiry still
refuses later binding. The producer owns original publish/reply work until joined
shutdown; it must not create a replacement anonymous connection after reconnect.
Application clients use `application-binding-request` on their own existing
approved connection and verify the pinned issuer, nonce, exact tuple, generation,
lifetime ID, request digest and validity before treating the app as bound.

The shared integration routes `integration-intent` and `integration-effect-query`
use `integration-owner`. Intent requires a current operation-bound approval even
with an allowed grant. Both require exact project scope, owner hub and expected
version; query additionally checks current authority for the original intent.
These routes retain intents and permit outcome queries, not external dispatch.
`definition-command-receipt` is a closed signed receipt using the identity receipt
wrapper. It contains only operation/effect/attempt identifiers, definition/catalog
versions, receipt sequence, status, replay and observation time; no file content
or paths. These standalone receipt schemas are not P01 payload registry entries.

Key custody also runs the existing Darwin ARM64 native descriptor admission on
ancestors, the private directory and the held key file. That checks ACLs and
ownership-enforcing storage, not only uid/mode bits. The shared utility lives at `native_security.descriptor_admission` and imports
only standard-library/native code. The previous `hub.native_descriptor_admission`
path remains a compatibility alias to that same module; no hub service or business
authority is used. Reads open nonblocking before
checking the held object is a regular file, so a FIFO cannot hang enrollment.
Focused tests cover actual admitted temporary storage, malformed/FIFO refusal and
propagation of native ACL/mount refusal. They do not qualify a production profile
or real application-attestor broker enrollment.


Exact signed client-request replay derives a stable trace ID from the canonical
request claims and preserves the client's signed expiry as the operation deadline.
The receiving host must reuse its cancellation reference for that operation
(the identity and definition services derive it from the operation ID). Caller,
scope and grant references still come from current authority; a revoked or changed
reference cannot bypass admission. Current credential/grant expiry shortens the
ingress attestation and `Decision.valid_until`, never the retained operation.
Fresh message IDs and attestation timestamps do not change operation equality.

Network identity startup also requires an enrolled `backup_host` and
`backup_key_id`. `IdentityService` constructs `OwnerBackupLifecycle` for its exact
history, binding and trusted stream identity. After recovery and before
subscription, it verifies key custody and runs the due backup and fenced restore
sample. `check_health()` and each request surface backup lifecycle failures.
Close joins backup work before closing the shared cache. Identity records own no
external artifacts, so an unexpected artifact reference refuses backup instead
of silently omitting it. No key or protected destination is created by startup.

The shared native guard also exposes `DescriptorPurpose.PROTECTED_FILE` for
root-owned mode-0444 regular data files, including empty Python package files.
It requires the same protected ACL and root-owned APFS policy as executable
admission, with a 128 MiB size limit. `PROTECTED_EXECUTABLE` remains mode 0555;
callers must choose the purpose explicitly rather than accepting either mode.

Before history recovery, identity startup awaits
`OwnerBackupLifecycle.recovery_identity()` and passes its result to
`OwnerLedger.require_recovery_identity()`. Those shared APIs preserve the maximum
trusted floor and reject a stream-creation mismatch. A broker below that floor
is refused during recovery before subscription. The backup lifecycle must also
complete its initial checks; starting its timer alone is not successful recovery.


## Application client handoff

`identity.application_client.provision_application_client(path, selection=...,
identity=..., issued_at=..., expires_at=...)` explicitly creates a separate private
client key and returns public transport enrollment with possession proof. The
administrator must commit enrollment, exact membership and an `application-bind`
grant through the owner. This function does not create broker credentials or
reuse a HOST/attestor key. Loading never provisions or rotates.

`load_application_client(path)` returns an `ApplicationClientKey`. Its closed
`application-client-key` file requires purpose `agentmux-application-client-key-v1`,
a canonical standard-base64 32-byte seed, and these public selection fields:

- `hubId`, `profileId`, `authorityId`, `instanceId`.
- `callerRef`, `scope`, `transportRef`, `grantRef`.
- `replyIssuerRef`, `replyIssuerPublicKey` (canonical unpadded base64url).
- `releaseDigest`, `policyRef`, nullable `workspaceRef`.

`key.selection` returns a copy of those public fields. `key.sign_discovery(claims,
now=...)` and `key.sign_binding(claims, now=...)` return complete signed request
bytes. Claims require purpose, requestId, fresh 64-hex nonce, the nine pinned
request fields (`hubId`, `profileId`, `authorityId`, `instanceId`, `releaseDigest`,
`policyRef`, `workspaceRef`, `transportRef`, `grantRef`), exact replySubject and
issuedAt/expiresAt within five seconds. Binding additionally requires generation
and lifetimeId from authenticated discovery. Do not include callerRef, scope or
reply-issuer fields in requests; the service derives them from current authority.

Discovery uses `application-discovery-request` and `application-discovery-response`
on the existing identity command subject and the consumer's already approved
application NATS connection. It requires the same current application-bind grant,
caller membership and fresh attestor observation as binding. It returns the
current signed generation/lifetime without treating HOST status as authority.
`key.verify_response(raw, request, now=...)` accepts discovery or binding replies,
checks the pinned issuer and all request bindings, and additionally compares
current callerRef and exact scope with enrollment. It returns verified claims.
The returned discovery is not a cached authorization grant: issue a new binding
request for that exact generation/lifetime on the same original connection.
AMUX-67 owns nonce/inbox allocation, borrowed connection ownership, cancellation,
joined close and invalidation on reconnect. Reconnect never silently creates an
anonymous replacement connection. The native protected-file loader is shared
with attestor custody, including ACL/mount checks and nonblocking regular-file
admission; the two purpose tags are mutually incompatible.

The explicit host selection writer is
`identity.application_host_selection.write_application_attestor_host_selection(path, selection)`.
It accepts the closed `application-attestor-host-selection` schema, creates a private
file without replacing an existing file, and returns `ApplicationHostSelectionReceipt`
with `path` and `digest`. Setup must retain the digest separately and pass the pair as
`--application-attestor-selection` and `--application-attestor-selection-sha256`.
The record pins the host policy, owner UID, workspace roots, kernel scope, attestor
key and NATS credential paths, application references and scope, receipt trust,
and initial generation. Required `connection` fields are exactly `endpoint`,
`serverName`, `rootsPEM` and `leafCertificateSHA256`, supplied explicitly for the
enrolled application broker. Missing connection data is refused; the writer never
infers the kernel endpoint. The writer checks loopback TLS inputs, one current CA
and the leaf-pin shape. Native composition checks the actual connection pins,
refuses the infrastructure endpoint, and binds the identity receiver to the same
application connection/account with separate users and inboxes.
The launcher independently checks those pins against the
admitted host and signer. Writing the record does not grant access or provision
credentials. Client enrollment remains a separate selection.

The production identity ledger requires an explicit completion budget. Bootstrap,
inline identity changes and their audit records pass `completion_records=0`.
A retained record with effects, artifacts or a repository obligation is refused;
those obligations cannot be silently treated as inline identity work.

### Explicit application-service activation inputs

`application-service-selection` is the closed setup record for the identity and
definition services. Its design follows accepted [D01, D02 and D04](../docs/planning/2026-10-09/delivery/decisions/runtime-and-deployment.md)
and their [acceptance](../docs/planning/2026-10-09/delivery/decisions/acceptance.md):
Python retains domain behavior, ordinary services stay outside the protected
kernel, and setup explicitly enrolls credentials and local resources.

`identity.application_service_selection` provides these APIs:

- `provision_application_service_issuer(path, ...)` creates a separate private
  service issuer key and returns `(identity_enroll_payload, receipt)`. Setup must
  submit that proof-bearing payload through the authorized identity owner. This
  does not create a broker user, membership, business grant or stream.
- `write_application_service_selection(path, selection)` creates the private
  record once and returns `ApplicationHostSelectionReceipt(path, digest)`.
- `load_application_service_selection(path, expected_digest=..., host_policy=...,
  owner_uid=..., workspaces=..., kernel_scope=..., protected_host_account=...)`
  requires the separately admitted host inputs. It checks the exact file digest,
  host pins and separate service users, and requires the native-admitted
  named-password HOST description.
- The returned selection provides `binding(role)`, `stream_identity(role)`,
  `retention(role)`, `load_signing_seed(role)`, `read_credential_bytes(role)` and
  `tls_options(role)`, where role is `identity` or `definitions`.
- The optional `oidcBrowser` block pins the HTTPS issuer, public client
  audience, EdDSA key ID and public key, maximum token lifetime, and same-provider
  authorization, device authorization and token endpoints.
  `oidc_browser_configuration()` and `oidc_device_configuration()` return those
  admitted public pins. The application-service process applies the browser pins
  before host startup. Browser and terminal requests cannot choose or override
  provider configuration, and omitting the block keeps the existing local-only
  startup behavior.
- The device-authorization owner implements the bounded provider exchange and
  returns only a verified `(issuer, subject)` pair. No installed terminal caller
  consumes that result yet. That integration still needs an enrolled ingress
  contract that maps an already-linked pair to a current human and project
  session. It must not let the terminal link accounts, grant membership or choose
  a local identity from provider or command input.
- `identity_kwargs(history=..., checkpoint_committed=..., signing_seed=...,
  backup_host=...)` supplies `IdentityService(connection, **kwargs)`.
- `definition_kwargs(history=..., checkpoint_committed=..., signing_seed=...,
  authority=..., artifacts=..., scope=...)` supplies
  `DefinitionCommandService.from_enrolled_host(connection, **kwargs)`.

Each service selects its own credential file and digest, account/user public keys,
reply prefix, TLS endpoint, server name, roots and leaf-certificate pin, explicit
JetStream domain (including an explicit null for the default domain), and issuer
key file/digest/reference/public key. Each ledger selects its entity and scope,
stream name and creation/floor identity, retention, bounded private history, and
checkpoint path plus `commitRef`. Identity also selects protected backup,
inventory and key directories, destination and key ID. Definitions also selects
project/home/global directories and the artifact bucket, store reference and size
bound. These fields match existing constructor inputs; there is no executable,
command, environment, fallback configuration or broker permission wildcard field.

The admitted host must resolve `checkpoint.commitRef` to the durable checkpoint
receipt handler. It must verify each credential's JWT, seed and scoped permissions,
enforce the selected TLS leaf pin, and supply the corresponding owned connection,
history, backup and artifact resources. Reading pinned credential bytes or building
TLS options alone does not perform those checks. Constructor adapters check the
selected resource bindings and issuer key; they do not open connections or start
processes. Required broker permissions for the service's replies and storage APIs
must be admitted by the host transport implementation before activation.

Start and await identity recovery before starting definitions with the identity
service's `reader`. Await definition recovery and writer activation before exposing
that route. Close definitions before identity, join their original close tasks,
and only then release connections and key custody. The host process owner retains
startup and shutdown responsibility. No live application-service activation is
qualified by these selection and constructor tests.

The optional `integration` service entry reuses the same connection, issuer,
ledger, history and checkpoint fields. It adds a closed provider choice
(`github`, `jira`, `confluence`), `credentialRef`, `originalOperationId`, artifact
bucket/store reference/size bound, and `credentialEnrollment` file/digest. The
ledger must be project-scoped, with entity ID equal to
`integration_owner.intent.effect_id(scope, originalOperationId)`. Jira and
Confluence require a non-null durable enrollment pin; GitHub may omit that pin
without claiming that its managed provider worker is available.

`integration_kwargs(authority=..., history=..., artifacts=..., credentials=...,
signing_seed=..., checkpoint_committed=...)` supplies
`IntegrationService.from_enrolled_host(connection, **kwargs)`.
`read_integration_enrollment()` checks the selected file digest and returns bytes
for the integration owner's durable pin loader. It never calls
`pin_atlassian_config`, reads a provider account at launch, or infers a replacement
pin. The host must load that retained pin before supplying the credential resolver.

For the service credential validator, the trusted role is the fixed selection key:
`identity`, `definitions` or `integration`. Its exact permission inputs come from
`kernelScope.hubId`, `ledger.scope`, `ledger.entityId`, `ledger.stream`,
`connection.jetstreamDomain`, `credentials.replyPrefix`, and the artifact bucket
where present. The separately admitted `hostPolicy` remains the host policy pin.
There are no caller-selected permission strings. Integration commands remain the
five existing registered commands; this selection adds no provider action.


`load_service_credentials(role, protected_host_account=...)` is the connection
handoff API for validated identity, definition and integration credentials. It checks the exact
private-file digest, calls the shared `service_policy`/`validate_service` API with
selection-derived inputs and verifies the enrolled user public key. JWT-only
credentials cannot authenticate as the admitted local password HOST users.
Application services may share the attestor's application account.
For a selected JetStream domain, service credentials must include both the
domain-qualified and canonical `$JS.API.STREAM.INFO.<stream>` and
`$JS.API.STREAM.MSG.GET.<stream>` subjects for the service's own ledger and any
explicitly selected artifact stream. The broker can check permissions after
rewriting a domain-qualified request to its canonical subject. These are exact
resource permissions, not wildcard API access.

Previously issued JWTs that lack these aliases now fail exact credential
validation. An authorized enrollment owner must explicitly reissue and re-enroll
the credential with the complete selected policy, then update its retained digest
through the existing enrollment procedure. Loading does not broaden permissions,
fall back to another credential, or modify stored JWTs or selection files. This
source change has not changed the user's existing enrollment.

The private start packet supplies `protectedHostAccount` with exactly
`kind: named-password`, `account: HOST`, and `broker` containing `endpoint`,
`serverName` and `configSha256`. Native code derives it only after full local
broker factory admission and the matching-scope OwnerBridge check. It identifies
that local broker, not every account named HOST. Python checks the closed shape;
this does not replace native provenance checks. Neither service selection nor
repository configuration may supply the description. The obsolete
`hostAccountPublicKey` field is rejected rather than converted. No broker is
provisioned by loading these selections.
`service_policy_inputs(role)` exposes those derived inputs to the
host adapter. Definition authority reads use the borrowed identity reader and its separate
connection. Definition credentials grant no identity-stream reads; their storage
permissions use only their own selected JetStream domain. The strict client credential validator is unchanged.
An unsupported service role is refused until the shared validator supports it;
raw credential bytes alone must not authorize a connection.

Integration credential loading now uses the shared `integration` service policy.
It requires project scope, the exact derived effect route and ledger, and only
stream-info/message-get access to its selected artifact bucket. It grants no
identity-stream reads, artifact publication, stream purge or provisioning. The
selection's artifact reference is required by its managed integration constructor;
the lower-level policy's optional no-artifact mode is not inferred from missing
selection fields.

### Explicit client integration query

Native host enrollment has a separate closed selection in
`native-authority-host-selection`. `identity.native_host_selection` provides
`write_native_host_selection(path, selection)` and
`load_native_host_selection(path, expected_digest=..., host_policy=..., owner_uid=...,
workspaces=..., kernel_scope=..., protected_host_account=...)`. The writer creates
only the selection; the loader checks its retained digest and separately admitted
host pins. Neither creates identities, keys, memberships or grants.

The immutable result exposes `key_options()`, `client_options()`, `destinations()`
and `capability_routes()`. Each route includes explicit authorization scope as
well as its enrolled service binding; display Project metadata is not scope.
`requestSigner.ref` must equal `keys.hostTransportRef`, distinct from the identity
issuer reference. `read_signer_material()` reads exactly 32 raw Ed25519 seed bytes,
checks their pinned digest and derived unpadded base64url public key, and rejects
JSON wrappers. It never provisions or copies an attestor key.

`publish_subjects()` derives the exact authority command, scoped capability
commands, and canonical plus selected-domain INFO/MSG.GET subjects for the one
identity stream. `load_credentials()` validates the private file digest, JWT,
account/user pins and exact publication/private-inbox permissions. No caller may
provide permission strings. `transport_options(binding_id=None)` returns pins for
the authority transport; an explicit binding ID selects its capability transport.
The host builds TLS trust from the returned connection pins and re-admits the
credential file when opening each connection. Subject count is bounded by the
existing native transport limit of 16.

Go composition supplies the live `Keys` and `Exchange` objects and retains their
ownership. Its current ledger checks must still establish signer enrollment,
recovery floor, memberships, grants, native-instance facts and revocation. A
selection or successfully read seed is not an authority credential or evidence
that a live provider was constructed.

Ordinary `EnrolledIngress` maps `configuration-read`, `configuration-set` and
`configuration-watch` to `configuration-owner`. Existing current membership,
exact resource grants, approval and denial checks still apply; set requires the
configuration reference revision to match the operation's expected version.
The configuration owner separately verifies its exact owner tuple and scope.
Direct plugin callers remain refused. These routes do not add configuration to
the native capability map or replace configuration's signed reply protocol.

The optional `integrationEffectQuery` field in `application-client-key` enables
only `integration-effect-query`. It requires `subject`, `grantRef`, `transportRef`,
`originalOperationId`, `originalPayloadDigest`, `replyIssuerRef` and
`replyIssuerPublicKey`. The subject must be the exact integration effect route
computed from the client's project scope and original operation ID. Its grant and
transport references must differ from the discovery/binding references.

`provision_application_client` includes a second proof-bearing transport record
when this field is selected. The original transport maps to the identity issuer;
the command transport maps to the selected integration issuer. Authorized setup
must commit these records and the exact scoped query grant through existing owner
commands, and enroll broker publication to the explicit query subject. Provisioning
the key does not create membership, a business grant or broker credentials.

`ApplicationClientKey.command_subject('integration-effect-query')` returns that
subject. `sign_command(claims, subject=..., now=...)` signs the existing
`agentmux-client-possession-v1` request with a maximum 60-second validity window.
It checks the selected command transport/grant, original operation/digest, exact
effect, expected revision and explicit reply inbox. No other command is enabled.
`verify_command_response(raw, request, subject=...)` verifies the client's original
request and delegates receipt authentication to
`integration_owner.receipts.verify_receipt` using the separately selected reply
issuer. A late receipt is an outcome, not renewed authority.

`ClientConnectionOwner.query_integration_effect(operation_id=..., expected_version=...,
deadline=..., cleanup_deadline=...)` uses its current application binding and a fresh
private reply inbox on the same admitted connection. It checks binding validity
before publication and after receipt, verifies the signed receipt, and retains the
exact request in `command_request` for reconciliation. The strict broker credential
validator accepts only the identity subject, or identity plus this explicitly
enrolled query subject, as the complete publication list. The signer does not
select or open a connection and cannot grant
HOST-account access. Existing keys without the optional field keep discovery and
binding behavior and refuse command signing. Current installed package bytes are
unchanged; the new route needs a later explicitly admitted package and caller.

Configuration enrollment is optional in `application-service-selection`. It pins
an exact ordinary plugin owner, `schemaRef`, and 1–64 `schemaResources` entries.
The required `requesterReplyPrefix` admits one caller inbox prefix for command
responses. It must differ from `credentials.replyPrefix`, which is the service’s
own outbound request inbox. Unknown caller prefixes remain refused.
Each resource has an owner-private path and SHA-256 digest; resource names are
relative package paths, and their combined bytes may not exceed 256 KiB.
`load_configuration_schemas()` reads those exact bytes without network retrieval.
`configuration_kwargs()` checks the enrolled authority reader, history,
checkpoint host, backup host and signing seed before supplying the real
`ConfigurationHost.from_enrolled_host()` factory. The calling host still owns
connection setup, startup order and resource release.

The configuration credential permits its scoped command, its own ledger writes
and notification subscription, exact stream INFO/MSG.GET requests, and its
private reply inbox. It permits one response within twelve seconds to cover the
bounded handler and publish/flush. Other service roles retain five seconds.
This broker permission never extends signed authorization or a native request's
original deadline. Existing selections and credentials are not rewritten.

`prepare-configuration-request` is a separate native authority method for reads
and watches. Its signed input contains `configurationRef`, `contractId` and an
owner-allocated `cancellationRef`; watches also require `afterRevision`. The
provider requires both the native host method grant and current ordinary host
configuration authorization. It returns an ordinary signed envelope, preserving
the exact plugin owner and cancellation reference. The deadline and attestation
expiry cannot exceed the original native validity or current authorization.
This method cannot prepare configuration writes and grants no capability access.

`activate-instance` binds the manager's newly allocated owner before native
context admission. The signed input is `{record, previousRef, cancellationRef,
expectedVersion}`. `record` uses the complete existing `identity-native-instance`
schema and must contain exactly the owner in the signed native claims. Initial
activation uses `previousRef: null`; an update supplies the exact prior record
reference. The host must assemble the record from admitted package,
configuration and authority inputs after owner allocation. This path creates no
placeholder owner and does not require a prior native-instance row.

The receiving service requires a current `native-authority-activate-instance`
grant for that instance and scope, plus organization-level
`identity-native-instance-set` authority for the host actor. It uses the existing
identity command owner for authorization, conditional append and durable audit.
A new activation must use the exact authority version that passed its native
method and lineage checks. A different version is accepted only for an exact
previously committed operation, which the identity owner reauthorizes as a retry.
The explicit authority `expectedVersion` stays unchanged on retry. Success
requires a current retained readback of the exact record after the append;
revocation before readback prevents success even when the write committed.
The response returns `{enrollmentRef, facts}` and the retained authority sequence.
A lost or refused response does not undo a committed write or authorize startup.
The caller retains its original cancellation and cleanup obligations, and must
complete ordinary `BindInstance` admission before starting plugin context work.

The optional protected native-host `activationDeclarations` map supplies the
initial activation inputs, keyed by instance ID. Each entry contains
`recordRef`, `previousRef`, `identityRef`, the full package `pin`,
`manifestDigest`, `configurationChecksum` and complete `facts`.
`NativeHostSelection.activation_declarations()` returns a copied map after host
selection admission. The map must cover exactly the selected destinations.
It contains no allocated owner, epoch or generation. The Go composition inserts
the actual `ContextBinding` owner and parent, derives the host identity from
selected keys, and reads the current authority version before making the signed
activation request. These declarations are protected enrollment inputs, not
ownerless authoritative records or a substitute for the authorized retained write.

Protected native host selection can also supply `lifecycle`, `contextTransport`
and `configurationRoutes`. Lifecycle and context each carry their own explicit
connection trust, pinned private CA file, account key, server credential and
per-instance credentials. The lifecycle selection also pins package bindings,
workspace choices and its private state directory. The adapters compare CA file
bytes with the selected roots and validate each signed JWT's exact role subjects
before returning `NativeDriverOptions` or `NATSContextOptions` fields. Go must
still admit the original private files and construct each pinned transport; the
selection does not create credentials, connect, or borrow protected-kernel trust.
Missing production inputs have no fallback to authority transport settings.

`configurationRoutes` maps each selected instance to its configuration and
authority references, current service signer association, authorization scope,
and relative schema resources inside the admitted package. The configuration
command subject is derived from those fields and included in the exact native
client JWT allowlist. Its requester inbox remains the native client's selected
inbox; configuration service credentials keep their separate outbound inbox.

`prepare-configuration-initialization` is distinct from the read/watch preparation
method. Its input is `{payload, cancellationRef}`, where `payload` is a complete
`configuration-set`. It requires the retained activated owner, exact admitted
configuration bytes and secret references, and the revision declared by the
activation. Both its own native method grant and the ordinary host's exact
configuration-set grant must allow preparation. It returns a signed ordinary
envelope with the original bounded validity. The Go activation caller must send
that envelope to the configuration owner and verify its signed committed result
before opening plugin context. Preparation alone does not initialize state.
