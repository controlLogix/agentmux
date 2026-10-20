# Capability receiving adapters

`CapabilityReceiver.handle(envelope_bytes)` is a host-private receiving boundary
for signed capability commands. It uses the concrete `identity.AuthorityReader`,
checks the registered payload, verifies the fixed destination and current
identity/grant decision, and checks the exact enrolled owner scope. It repeats
current authorization after reading and before returning private data. It accepts
no authorization callback, caller-selected NATS subject, stream or filesystem root.

## Host integration

1. Resolve an existing authoritative aggregate from the enrolled host profile.
   Create `RetainedResource.open_existing(jetstream, binding=OwnerBinding(...),
   stream=..., stream_identity=StreamIdentity(...), retention=...)`. The factory
   opens the shared `OwnerLedger` against that exact existing binding; it neither
   provisions a stream nor copies records into another authority. Supply the
   trusted creation identity and retained minimum sequence, never values from
   request JSON. Optional `artifacts=OwnerArtifacts(...)` must refer to the
   enrolled Object Store already used by that owner.
2. Construct `CapabilityReceiver(authority_reader, hub_id=..., resources=[...])`.
   Prefer the existing `LedgerAuthorityReader`, which validates retained stream
   identity, over a reader backed by an unpinned source. Resource IDs must be
   unique within this receiver; they name existing aggregate IDs, not arbitrary
   table names or newly allocated entities.
3. Existing `EnrolledIngress.admit` must first produce the signed command for
   the fixed registered destination. Pass its immutable envelope to `handle`.
   The receiver verifies again; an ingress allow is not a cached permission.
4. `handle` returns private `CapabilityResponse(contract_id, request_digest,
   operation_id, payload)`. `payload` is canonical reply JSON; `request_digest`
   hashes the complete signed request using the shared canonical codec. The host
   must authenticate the reply and bind that digest and operation ID before
   delivering it to the native `Domain` gateway. This module does not install a
   NATS subscription or invent an unsigned wire-reply protocol.
5. Call `await receiver.close(timeout=5)` before releasing borrowed owners,
   checkout roots or transport. It cancels and joins original calls and tracked
   filesystem workers. `capability_cleanup_incomplete` means the closed receiver
   still owns those workers; keep the same resources and retry `close`. Never
   interpret request cancellation as proof a filesystem worker has stopped.

## Reads and limits

- `capability-storage-read` returns the complete canonical retained owner record
  at the requested current entity version. IDs, unknown state fields, provenance,
  artifact references and effect intent remain intact. It does not write a
  projection or reinterpret a domain transition.
- `capability-artifact-read` resolves the digest only from that exact retained
  record's artifact metadata. It requires one matching reference, checks size
  before retrieval and delegates immutable version, Object Store metadata, chunk
  and digest checks to `OwnerArtifacts.retrieve`. A caller cannot name a bucket,
  object key or alternate artifact reference.
- `capability-outcome-query` calls `OwnerLedger.outcome` on the same enrolled
  aggregate with the original operation ID and canonical payload digest. Changed
  digest reuse refuses. The query can use the old resource revision after the
  aggregate advances. It returns the retained record reference and committed or
  rejected outcome, or explicit absence. It never retries an effect. The original
  retained `authorizationDecision` must bind the requested contract, operation ID
  and effective actor. Missing or mismatched provenance refuses the query. Caller
  contract text and effect intents are not substitutes for that original audit.
- `capability-workspace-read` requires a `WorkspaceRoot` constructed from the
  existing `RepositoryDirectory.checkout` result. Supply it as `workspace=` when
  opening the resource. The retained record's repository ID must match the
  checkout. Reads use directory descriptors and refuse symlinks, parent/dot
  segments, absolute paths, control characters, special files and oversized files.
  A changed file is refused. This is a working-tree read, not a promised immutable
  Git snapshot. The host owns checkout enrollment, directory mutation control and
  release after the receiver joins workers.

Every returned content body is limited to 45,000 bytes before base64 encoding.
Requests and canonical replies are limited to 64 KiB. The receiver admits at most
32 outstanding calls/workers with a five-second request timeout. Workers remain
owned after timeout. It never truncates or splits a record or artifact to fit.
Ordinary representations conceal record, request, path and credential contents;
errors crossing `handle` use fixed codes.

## Integration still required

The shared registry fixes capability destinations and reply schemas. Enrolled
capability calls use `AuthorityReader.evaluate` and `EnrolledIngress.admit`,
including owner hub, exact resource/scope, storage version and original-permission
checks for outcome queries. Native calls also check enrolled declarations,
credentials, exact instance generations and current parent lineage. Go performs
the package/grant intersection and retains the original instance lifetimes.
`CapabilityReplyService` and the Go gateway bind signed replies to the complete
request, operation, destination and enrolled service. The coordinated live tests
cover retained storage reads, scoped broker denials and current revocation,
including private children. The live artifact case uses the enrolled Object Store
and refuses a digest absent from retained metadata. The workspace case resolves a
real Git checkout through `RepositoryDirectory`, reads its file and refuses a
symlink. The outcome case queries seeded retained history with its original
operation/digest and refuses changed-digest reuse. Each case also checks parent
revocation before reading and before signing. Seeded history is not proof that a
storage write effect was implemented.

The live boundary case checks exact kernel command/reply publication denials and
exact/wildcard subscription denials with observed broker permission errors. It
also checks that enrolled child resource, secret/NATS tuple and project widening
refuse at current authority. These disposable broker checks do not qualify the
installed credential policy, exported kernel status, secret use or a raw NATS
capability. No protected kernel process runs in this fixture.

Unmapped domain storage writes, secret use, process start/cancel and decision
requests return `capability_service_unavailable`. Policy evaluation is implemented
for an explicitly selected `PolicyResource`, as described below. A generic replacement of an
owner record's state would bypass existing task, board and other domain rules.
The remaining `FederatedWorkOwner`, `KnowledgeOwner` and `CodeShareOwner`
mappings must retain their existing transactions and identities. The message
mapping below supports explicit post/publication commands; it does not accept
arbitrary record replacement. Their adapter must preserve
those rules rather than map arbitrary JSON directly to a ledger append.

The ledger and artifact APIs are AMUX-48 dependencies. A real intended-operation
secret resolver, task executor with durable cancellation/outcomes, and an authoritative
decision-request interface are still required for the remaining effects. Their
later Jira ownership must be confirmed from Jira, not inferred from planning
phase names. No mock success, raw shell execution or secret disclosure is provided
in their place. Existing tables and live data are untouched. The disposable live storage-read
fixture does not qualify migration or the remaining effect boundaries.

## Policy evaluation

`PolicyResource` binds one policy reference and plugin instance to the existing
current identity authority and an owned `policy-evaluations` ledger. It checks
query permission separately from the requested action, resource class and resource
ID. Missing rules deny; parent grants and exact delegated access constrain child
results. A result of `approval_required` leaves approval and execution to their
own authorized flows.

The owner retains the original operation ID, payload digest, policy digest,
authority reference and result before returning `receiptRef`. Identical replay
returns the original result, including after a policy change, only while current
query and disclosure authority remain valid. Changed intent under the same
operation refuses. Lost acknowledgments reconcile against that same ledger;
replay does not create another decision. Revocation before reply signing withholds
the reply while preserving an already committed receipt.

The optional `policy` application-service selection pins the policy reference,
plugin identity and instance, separate credentials and signer, ledger, checkpoint
and backup custody. `ApplicationServiceHost` starts, checks, fences and joins
`PolicyHost` before releasing its borrowed identity source and transport. No
caller can supply those owners or paths through a handle.

Focused tests cover retained outcomes, replay, uncertain append recovery, current
revocation and parent constraints. Selected-host tests cover startup, readiness,
missing signing material and joined cleanup. Live TLS/JWT tests cover all three
outcomes, owner restart, stale policy references, parent revocation and observed
broker denials. The native Go case uses the actual typed `PolicyHandle.Evaluate`,
then refuses reuse after parent revocation and joins the handle and transports.
The live fixture constructs the receiving owner directly; it does not establish
installed application startup. Existing selected production wiring
has focused test and source review coverage.

## Existing message storage

`MessageStorageResource` borrows the existing `LocalMessages`,
`FederationPublisher`, `Store` and federation session. Host enrollment fixes the
resource alias, peer, actor/transport mappings, plugin identity and instance.
A project resource also fixes its local repository and repository ID. An
organization resource uses `repository=None` for operator messages without a
repository. Request JSON cannot choose a database, connection or NATS subject.

The existing storage interface accepts a closed value with exactly
`formatVersion` set to `1`, `command` set to `post` or `publish`, and `envelope`
set to the complete existing federation message or handoff value. The envelope
keeps its original ID, route and body. The receiving owner validates the exact
selected peer/repository and derives recipients and presentation through the
existing message rules. Publication also binds sender attribution to the enrolled
actor and checks the local node. Arbitrary state replacement and unrelated
commands refuse explicitly.

Post keeps `Store.post`, its original message ID, `fed:<envelope_id>` duplicate
key, message/delivery/search-index transaction and current recipient generation
checks. Missing-role fallback and remote-data framing retain the existing message
behavior. An identity failure cannot redirect delivery to another inbox. Peers
that require approval need an exact, already approved quarantine record. Storage
calls cannot create approval; later denial or withdrawn sharing still refuses.

Publish keeps the original federation envelope ID, route, current sharing check,
redaction, outbox and audit transaction. Reusing a publication ID with different
contents refuses and rolls back. Read returns the complete original stored SQL
row, including unknown columns. Original records remain in place after later
commands; no message is renamed or copied to another authority.

`MessageStorageJournal` retains the full original signed envelope and result in
reserved `fed_state` entries within the same owning SQLite transaction. It adds
no database or schema migration. The version describes committed commands for
this enrolled resource, beginning at one; it does not invent a CAS column on
legacy message rows. A conflict retains its own result without posting or
publishing. Identical replay and outcome recovery return the original references
after later writes or owner reopen. Changed intent refuses. The stable metadata
namespace checks the complete binding so a configuration change cannot silently
reset its version or history. Incompatible bindings require reconciliation.

The receiving service checks current signed native authority before dispatch and
again before disclosure. The DB transaction checks its authorization deadline
before and after effects. Cancellation keeps the original SQL worker owned;
receiver close must join it before releasing the borrowed store or session.
Legacy migration fences remain effective. Existing database backup and recovery
must retain the reserved metadata with the original tables; deleting it would
lose operation recovery and is not supported.

Focused tests exercise both shared storage-provider contract cases, original
rows and unknown fields, exact conflicts, replay/reopen, publication redaction,
transaction rollback, sharing withdrawal, recipient generation, migration fences,
operator approval and cancellation. Native TLS/JWT tests use the actual Go
storage handle's prepare/save/execute/replay calls against the actual SQLite
owner, then revoke the parent and join original cleanup. These native fixtures
construct the receiving owner directly.

The optional `storage.messages` selection constructs the message resources in
`SelectedStorageHost` before opening its storage and outcome subscriptions. It
pins an existing database and policy, local peer and node, one repository (or
organization scope), channels and actor/transport mappings. Startup opens the
database without creating or migrating it and checks its existing message
tables. When board and message selections name the same database, they must pin
the same policy, repository and peer; both use the same Store and joined
executor. Source replacement and legacy migration fences refuse further use.
Selected startup and cleanup have focused coverage. A copied-package check also
opens and closes the actual message source without repository access. These
checks do not qualify a protected installation or complete legacy caller routing.

The optional `legacyActors` channel declarations select a separate signed
message bridge on the existing storage-owner subject. They fix the application
principal, transport and exact send, delivery, approval, inspection and outcome
grants. Startup checks current identity, transport, membership and grants.
Possession frames cannot use native admission, and a native receiver without the
explicit bridge refuses them. The application client key's optional
`messageCommands` declaration fixes its subject, channel, caller, repository and
reply signer. The Hub receives a transport possession key, never an ingress
issuer key. Inbound remote sender text remains data attributed to the separately
enrolled federation service.

Legacy messages retain the existing 1,000,000-byte envelope limit. Only the closed
message bridge family accepts frames up to the SDK's 1 MiB ceiling; native and
other owner commands keep their existing limits. Legacy journal format 2 stores
the full signed original in a separate digest-linked `fed_state` entry, in the
same transaction as its compact receipt and original message or outbox write.
Format 1 remains readable. No body is truncated and no separate database is
created. Large SQL rows remain in place, but the native storage read reply still
has its existing 45,000-byte bound.

The enrolled Hub accepts explicit `--message-selection` paths alongside its
repository identity selections. These select separate admitted application
sessions for the local caller and federation service. The Hub borrows them;
bootstrap closes and joins the original sessions after Hub shutdown. Omitting
these paths preserves the existing unqualified runtime. This wiring still needs
full live caller qualification before the message integration is accepted.

`LegacyMessageCommandClient` retains each immutable original intent in reserved
`legacy-message-client:` entries in the existing Hub `fed_state`, before sending
an effect. There are at most 32 pending entries, each bounded to 1 MiB. They are
removed only after a confirmed original outcome; inbound entries remain until
the actual seen or quarantine-state transition is durable. Redelivery recovers
the original saved operation before finishing that transition. A definitive
non-applied CAS conflict is retained; only a fresh authenticated retry of that
same immutable intent may allocate a new attempt at the current revision.
Unknown outcomes never change attempt identity. Backup and recovery must keep
these entries with the Hub database. A changed enrollment cannot replace a
pending intent on the same logical route; it requires reconciliation. The
message-only client exchange can retire a timed-out inbox and join its original
exchange while preserving a healthy connection for a fresh authorized outcome
query. A transport change or incomplete cleanup refuses; other command exchange
behavior is unchanged.

Code-share handoffs keep their existing derived message. The adapter consumes a
fresh proof for the original `fed_code_share` invocation and checks its local
`p_code_shares` record, author, repository and derived note/stat body. Remote,
missing or substituted source records refuse. A share can outlast its first
five-second local proof while Git runs. In that case the actual Hub dispatch
reauthenticates its immutable original request on the same still-live connection,
requiring the same principal, caller and request digest before issuing one new
five-second proof. The private invocation capsule never persists its token or
places it in the ordinary retained request, wire data, logs or representation.
The original connection handler disposes the capsule and all replacement proofs
on success, failure and cancellation. This does not grant Git execution authority
or qualify the remaining code storage mapping.

## Existing federation board storage

`FederationBoardResource(binding, board, repository, repository_id, card_key,
stream_identity)` maps one enrolled handle alias to an existing `am_board` card.
`board` is the actual `SharedBoardStore`; `binding` has owner domain
`federation-board`, entity kind `board-card` and the enrolled project scope.
The host supplies the repository/card mapping and trusted `StreamIdentity` for
`KV_am_board`. Request JSON cannot select a bucket, repository or key.

Pass this resource to the existing `CapabilityReceiver` or
`CapabilityReplyService`. `capability-storage-read` checks current enrolled
authority before and after the actual board-owner read. Its reference revision
is the real KV card revision. The response contains the original card JSON bytes,
including the unchanged key, repository ID, comments, history and unknown fields.
It does not import the card into `OwnerLedger`, rename its stored identity or
write the `p_board_cards` projection. Original session, repository mapping, stream
creation identity and observed sequence are checked on use. The host retains the
borrowed board session and transport until receiver calls join.

The accepted AMUX-45 mapping covers the existing federation owners. The later
user addition also requires private plugin storage through the same interface;
it does not replace these existing mappings. Board mutation
integration must retain the existing card CAS, redaction, history, audit and
projection behavior in the board owner. An explicit move value can describe the
existing `move` command; it cannot replace arbitrary card fields. Before enabling
that adapter, the legacy owner needs one command entry point that binds the
authenticated actor, exact expected KV revision and original operation/digest,
and retains its replay/outcome identity in the same authoritative card CAS.
Calling today's `move` and then appending a receipt elsewhere would create a
second commit and an unresolved crash gap. That is an owner implementation
handoff, not an undecided storage product requirement.

## Required mutation interfaces

A storage mutation adapter needs an existing domain owner that accepts the exact
signed capability envelope, resolves the enrolled resource to its original record,
checks current authority under its mutation lock, and implements the original
domain transition. It must retain the supplied operation ID and canonical digest,
expected resource revision and complete unknown fields. Its result must identify
the retained receipt; conflict or uncertainty cannot allocate another operation.
The client's existing Prepare/save/execute/reconcile flow remains required.

The shared ledger already provides `append(record, expected_sequence=...,
valid_until=...)` and `outcome(operation_id, payload_digest)`. Those are commit and
recovery primitives, not permission to replace arbitrary domain state. A domain
owner must build the complete validated state, provenance, outcome and effect
intent before the append. Keep its existing transaction boundaries; do not add a
second ledger append next to a legacy SQL/KV mutation and claim atomicity.

Concrete compatibility constraints are visible in the current interfaces:

- `SharedBoardStore` delegates to `_BoardOperations._write`, which retries CAS
  races by rereading and reapplying a domain change. It cannot implement exact
  expected-version generic replacement without an owner change.
- `KnowledgeOwner.share` creates a new federation event ID and commits indexing
  and outbox work together. It needs supplied-operation replay and outcome lookup
  without breaking that transaction before accepting a capability write.
- `FederatedWorkOwner.add` creates the work item, reservation metadata and offer
  together. A storage adapter cannot replace those steps with a raw state append.
- The message owner below implements explicit post/publication commands and
  retains their operation identity in the original transaction. Code-share owners
  still need an explicit signed domain operation; a narrow legacy method is not a
  generic record-replacement contract.

For secret use, the required owner operation accepts the original signed envelope
and exact secret/consumer/purpose references, rechecks disclosure authority, and
returns a retained receipt without returning the value. Broker credential loading
is not this interface. Process start/cancel requires an owned execution plan/run,
current execution authority, isolation, and durable reconciliation of the original
effect; plugin lifetime supervision is not a task executor. The policy owner
evaluates enrolled action/class/resource decisions and retains their outcomes.
An `approval_required` result does not create approval or authorize the requested
effect. Decision requests
need an owned proposal and durable pending/approval outcome; the existing
`identity-approval-set` administration command cannot be substituted for a request.

## Existing owner APIs and capability commands

A typed client and a retained append primitive do not establish an effect owner.
The following boundaries determine whether a receiving adapter can enable an
operation without changing domain behavior.

| Capability command | Existing API | Required owner integration |
| --- | --- | --- |
| `capability-storage-write` | `MessageStorageResource.write` maps closed post/publication commands into the existing message owner transaction. `DefinitionCommandOwner.execute(envelope_bytes)` accepts signed `definition-save`, `definition-drop` and their effect commands. Board `_write` retries domain changes after CAS races. `FederatedWorkOwner.add` commits work/reservation/outbox changes together. `KnowledgeOwner.share` commits index/outbox work together. | Choose an explicit domain command and retain its original operation/digest under that owner's mutation lock. The capability payload currently supplies only `input.value`; it does not identify a definition, board, work or knowledge transition. An adapter cannot infer one from arbitrary state. Preserve each domain's revision meaning and transaction. |
| `capability-secret-use` | `AtlassianCredentialResolver.resolve(credential_ref, provider=..., config_version=...)` validates an explicitly pinned private config. `IntegrationOwner.handle` retains approved `integration-intent`, answers `integration-effect-query`, and accepts explicit attempt/reconciliation commands. | Add the intended consumer/purpose operation to a real secret owner. It must authorize the exact `resourceRef`, `consumerRef` and `purposeRef`, pass the value only to that enrolled consumer, and retain a value-free receipt. Config resolution performs no authorization or dispatch; a retained integration intent does not prove secret use. |
| `capability-process-start` and `capability-process-cancel` | `FederatedWorkOwner` manages offers, reservations and results. `hub.store.Store.cancel(work_id, reason)` changes work-item state. Native lifecycle supervision owns plugin processes. | A task execution owner must resolve the exact enrolled `planRef` or run reference, admit execution, own isolation and the original process wait/output, and retain start/cancel outcomes. A cancelled work row or stopped plugin is not proof that the task's effect stopped. |
| `capability-policy-evaluate` | `PolicyResource.evaluate` uses the current enrolled native policy facts and an owned `OwnerLedger`. Optional selected `PolicyHost` supplies the actual identity source, protected signer, scoped connection and recovery custody. | Implemented for the selected policy reference and exact plugin instance. Query permission and requested access are checked separately; parent grants also constrain requested access. The retained receipt reports `allow`, `deny` or `approval_required`. It grants no effect or approval. |
| `capability-decision-request` | `identity-approval-set` records an administrator's approval change. Team proposals prepare roster choices. | A decision owner must resolve the exact `proposalRef`, retain the requester and original operation/digest, and expose durable pending/approved/rejected outcomes. Creating a request must not silently grant approval. |

The concrete source APIs are in
[`dashboard/definition_commands.py`](../dashboard/definition_commands.py),
[`hub/fed/board_services.py`](../hub/fed/board_services.py),
[`hub/fed/work_services.py`](../hub/fed/work_services.py),
[`hub/fed/knowledge_services.py`](../hub/fed/knowledge_services.py),
[`integration_owner/credentials.py`](../integration_owner/credentials.py),
[`integration_owner/receiver.py`](../integration_owner/receiver.py),
[`identity/authority.py`](../identity/authority.py),
[`identity/downstream.py`](../identity/downstream.py), and
[`identity/commands.py`](../identity/commands.py).
These are API compatibility requirements, not permission to replace an owner's
signed contract or add a second state commit beside its current transaction.

Cross-owner API requests are:

- AMUX-47: preserve direct receiving admission and current native declaration,
  generation and credential checks. `evaluate_snapshot` already returns the
  allowed decision's `valid_until` from the same authority snapshot, including
  timed-denial activation and grant/approval expiry. `IntegrationOwner` passes
  that deadline to `OwnerLedger.append(valid_until=...)`. Future adapters must
  preserve this behavior immediately before publish; a separate later read cannot
  establish the earlier decision's deadline.
- AMUX-44: authenticate `CapabilityResponse` against the complete request digest,
  operation ID, expected reply contract and enrolled owner before returning bytes
  from `Domain`; retain the original call and worker ownership during cleanup.
- AMUX-48: retain the current conditional append and original-pair outcome APIs.
  A lost acknowledgment remains uncertain until that same aggregate reconciles it.
  No additional storage authority is requested.

Only AMUX-44, AMUX-47 and AMUX-48 ownership is established in the available Jira
context. Exact later issue IDs for the domain mutation/effect owners still need
confirmation by the orchestrator. AMUX-45 is not reduced to these read adapters:
its mutation, existing-data preservation, all-seven-capability and live isolation
acceptance requirements remain open until their real integrations pass.


## Existing definition owner requirements

A definition edit must use the registered `definition-save` or `definition-drop`
command. Do not reinterpret `capability-storage-write.input.value` as either one.
The existing call is `await DefinitionCommandOwner.execute(envelope_bytes)` with
the complete signed `message-envelope`, destination hub from enrollment and
`destinationServiceId="definition-owner"`. The payload is:

- Save: `{definitionId, scope, name, expectedChecksum, definition}`. `scope` is
  `repo` or `global`; `definition` follows the registered `definition-save` schema.
- Drop: `{definitionId, scope, name, expectedChecksum}`.

`operation.expectedVersion` is the retained version of that definition. Creation
uses zero and a null checksum. Updates use the current version and checksum;
recreation uses the tombstone version and a null checksum. Drop requires the
current version and checksum. The catalog's ledger sequence is separate and is
resolved by the owner during conditional append.

The generic storage wrapper instead carries a `resourceRef`. No accepted mapping
selects a definition transition from `input.value`, or defines how that reference
relates to the definition ID, target version and catalog owner. This does not change the accepted federation storage mapping. Definition
substitution is outside that mapping and is not enabled here.

Definition authorization preserves the authenticated human caller and effective
actor. It requires the exact definition ID and `{scope, name}` target grant,
current membership, required approvals and the existing global/repository scope
rules. The native host's service transport cannot replace that human lineage.

Host composition supplies the existing `DefinitionCommandOwner`, its authority,
artifacts and `OwnerBinding` with `owner_domain="definitions"` and
`entity_kind="definition-catalog"`. The binding scope must match the command
scope and the `DefinitionService` project. Before exposing a write route, the
host calls `await owner.activate_writer()`. Its claim binds hub, domain, catalog
entity and scope to the existing directory fence. Request JSON never selects or
activates a writer. `execute` checks that claim under the owner's lock, retains
the original operation/digest and commits its catalog state and effect intent.

The returned `DefinitionReceipt` preserves `operation_id`, catalog `sequence`,
`definition_version`, `replayed`, `effect_id` and `attempt_operation_id`.
Its initial outcome is `intent-committed`. A local `file_status` observation must
not become a storage `applied` receipt. Durable completion and reconciliation use
the registered `definition-effect-complete`, `definition-effect-query` and
`definition-effect-retry` commands. Any future capability integration must retain
those domain distinctions and
first define its explicit command, resource/version binding and reply schema.
The current capability contract does not supply that mapping.

## Signed service transport

`CapabilityReplyService` owns a concrete receiver and accepts only a
`LedgerAuthorityReader`. Configure the profile, hub, authority, service, existing
resources, enrolled service identity/instance/key, signing seed and trusted
request signing key. Resources must share one exact scope. The service calls
`evaluate_capability_service_request` on the current retained snapshot before
reading and again before signing. It also checks its current enrolled signing key;
a response cannot outlive that key or the admitted permission.

Private-child requests also resolve the exact current parent chain from each
retained snapshot. The receiving gate checks parent owners, current grants,
access decisions and host permission, and bounds the reply by ancestor expiry.
Go still checks package declarations, the original parent process lifetime and
the shared authority sequence. The offline provider/receiver tests cover parent
substitution, widened access, denial and expiry. The coordinated live private-child
case covers the actual Go/Python read path and persisted parent revocation before
reading and before signing, with Go checking revocation before the original
prepared request expires. It does not qualify writes or external effects.

`handle(request_bytes, received_reply_subject=...)` accepts the closed
`capability-service-request` wrapper and returns a signed
`capability-service-response`. The native preparer must sign the wrapper only
after admitting the host and domain operation. Required request bindings include
`hostTransportRef` (the exact host credential), `nativeFactsDigest` (the admitted
native facts), and `replySubject` (allocated before preparation). The inner
correlation ID must equal `requestId`. A changed credential, native facts,
permission or reply destination refuses the call.

Both wrappers use Ed25519 over RFC 8785 canonical claims. The outer bytes must
also be canonical. The inner envelope remains exact decoded bytes; its digest
must not be computed by parsing and reserializing it. Responses bind the complete
request byte digest, inner byte digest, operation, expected reply contract,
profile, scope, native owner, resource, reply destination and enrolled service
identity/instance/key. Their maximum lifetime is five seconds, further reduced
by applicable authority deadlines. `verify_capability_response` verifies those
bindings using trusted enrollment supplied by the host and returns canonical
payload bytes. Reply-provided keys are never trusted.

With a borrowed NATS connection, `start()` subscribes to `subject`, whose form is
`amx.v1.h.<hub>.o.<organization>.p.<project-or-_>.w.<workspace-or-_>.capability.<service>.command`.
The service publishes only to the signed reply subject. Broker enrollment must
also give each principal its own private inbox prefix and deny subscriptions to
other principals' inboxes. Configure responders with a bounded one-response
permission for five seconds rather than wildcard inbox publish rights. TLS alone
does not identify the publisher of a Core NATS message; unsigned JetStream
responses require these broker permissions and the exact enrolled local TLS trust.
The host must use its enrolled prefix for both explicit capability replies and
internal JetStream requests. The decoded envelope
limit is 65,536 bytes, the request wrapper limit is 98,304 bytes, and the response
limit is 65,536 bytes. Startup refuses a negotiated transport frame limit below
98,304 bytes. These are transport limits; owner record limits stay unchanged.
Failures produce no unsigned fallback reply and leave the caller's outcome
unconfirmed.

The NATS callback creates and retains a separate task for each delivery. Shutdown
cancels that request task while the borrowed subscription worker keeps draining
queued callbacks. Closed callbacks discard their messages without starting work.

`close(timeout=5)` cancels calls and joins the original subscription, callbacks,
receiver workers and subscription drain. A timeout raises
`capability_cleanup_incomplete` and retains the same cleanup task; a later close
joins that task. A completed drain failure permits another cleanup attempt on
the original subscription. A running cleanup task is never replaced. The service uses `CapabilityReceiver.close(timeout=None)` only
inside its owned cleanup task so a caller timeout cannot abandon a worker.
It does not close the borrowed connection. Offline transport tests do not qualify
live broker isolation or the native host consumer integration.


## Common storage contract

AMUX-45 AC05 and AC06 add private persistent plugin storage alongside the existing
domain mappings. Both use the existing `StorageHandle` and registered storage
contracts below. The host selects the provider from trusted resource enrollment;
a request cannot select a provider, table, stream, bucket, subject, path or owner.
This is the contract for the receiving implementations. The private provider
implements exact-version writes as described below; domain writes still require
the existing owner integration. Documentation alone does not activate a provider.

| Operation | Same plugin-facing contract for both providers |
| --- | --- |
| Read | `StorageHandle.Read(resourceRef)` sends `capability-storage-read` with empty `input`. `capability-content-reply` returns the exact resource reference and base64 content bytes. The resource's registered format defines those bytes. Existing board cards retain their original bytes and IDs; private storage returns its JSON document. |
| Prepare write | `PrepareCompareAndSwap(resourceRef, value)` freezes `capability-storage-write` with `input.value`, the exact expected revision and original operation/digest. The caller saves `RecoveryBytes` before dispatch. Preparing does not change storage. |
| Write | `CompareAndSwap(mutation, resourceRef, value)` dispatches that exact prepared operation. The provider validates its registered value format and current permissions, then conditionally changes its own authority at that exact revision. A conflict never rereads and reapplies the change automatically. Replies use `capability-storage-write-reply` and a real retained `receiptRef`. |
| Recover | `CapabilityHandles.Reconcile(mutation)` uses `capability-outcome-query` against the same resource with the original operation/digest and original contract. Current permission for both the query and original operation is required. A changed digest refuses; absence or uncertainty never proves rollback or authorizes a new operation. |
| Close | Closing the owning handles/receiver refuses new work and joins the original calls and workers. Cancellation can withhold a reply; it cannot prove that a dispatched write did not commit. Resources remain owned until their original workers and cleanup finish. |

`resourceRef.revision` and `operation.expectedVersion` must agree. The revision
is an opaque, provider-native nonnegative integer: an existing board uses its real
KV revision; private storage uses its retained entity version. Clients must not
compare revisions across resources or reinterpret them as catalog versions.
Revision zero permits an initial private document write only to a namespace the
host has already enrolled; it never provisions storage. A read at a missing or
changed revision refuses instead of returning an invented empty value.

Both providers use the same fixed boundary errors: access refusal, stale resource,
service unavailable, closed owner and incomplete cleanup. Invalid domain values
must not be converted to arbitrary state replacement. `applied`, `conflict`,
`rejected` and `uncertain` retain the registered reply meanings. A provider that
cannot produce the required durable receipt must return an explicit unavailable
error rather than fabricate a reference. Transport failure leaves the result
unconfirmed. No exception includes document contents, paths, credentials or raw
broker diagnostics.

The board adapter currently implements only Read. Its existing domain owner must
add exact-version mutation and original-operation recovery within the same card
CAS before Write and Recover can be enabled. The required receipt reference on a
conflict is a concrete compatibility constraint: the owner must identify a real
retained receipt without changing the card version merely to record a conflict.
If that cannot be represented by the current contract, AMUX-45 and the shared
contract owner must resolve it explicitly before enabling either provider.

## Private storage owner contract

The private provider owns one bounded JSON document per enrolled namespace. Its
owner binding is `owner_domain=plugin-private`, `entity_kind=plugin-storage`, an
opaque resource ID, owner hub and exact organization/project/workspace scope.
It uses the existing `OwnerLedger`; it does not store private values in domain
cards, configuration records, a second SQL authority or plugin-selected files.

The trusted namespace enrollment contains the owner binding, `pluginIdentityRef`,
`instanceId`, `packageId`, namespace format/version, trusted stream creation and
minimum sequence, and retention limits. `instanceId` identifies this installation;
identity, package and scope are part of ownership rather than caller assertions.
Each request must match that ownership tuple against the current enrolled native
row, in addition to the exact current owner pin, epoch and generation. A current
resource grant alone cannot authorize another installation's namespace. A private
child has its own namespace and receives no implicit access to its parent's data.

Read requires the existing `capability-storage-read` binding and `read/storage`
permission for that exact resource. Write requires `capability-storage-write` and
its exact `write/storage` permission. Recovery requires `capability-outcome-query`
with `inspect/outcome` and the original write permission. Existing domain resource
permissions remain distinct. No new wildcard permission or unrestricted broker
credential is introduced by selecting the private provider.

The initial private document limit is 16,384 canonical UTF-8 bytes. Each namespace
uses a dedicated, file-backed retained stream with explicit host-enrolled byte
limit, completion reserve and replica count; the factory requires those limits.
A 64 MiB allocation with 4 MiB reserve and one replica is a bounded local-beta
reference configuration. At the existing 128 KiB admission charge and 85% bulk
limit it allows at most 435 ordinary records, including any retained rejections;
completion/recovery writes can reduce that budget. A 4 MiB allocation would allow
only 27 ordinary records and is not the reference configuration. Storage is not
unlimited and one replica does not provide high availability. The provisioner
must explicitly enroll and validate them through the existing `Retention` policy:
discard new writes at capacity, retain history without automatic age expiry,
forbid delete/purge/rollup, and preserve reserve admission. The owner checks the
complete proposed record against the existing 65,536-byte record limit. Capacity
refusal must leave data and operation identity unchanged; it cannot trim history.
Larger quotas require explicit host enrollment, never a request field.

Private writes have no external effect. Under the namespace's mutation lock, the
owner resolves one current authority snapshot, checks the full signed service
wrapper with `evaluate_capability_service_request`, verifies the exact inner
bytes and current namespace ownership, and checks
`OwnerLedger.outcome(original_operation_id, original_payload_digest)` before
checking the current document revision. A retained matching operation returns
its original result even when the document has advanced; changed content under
the same operation ID refuses. Only an absent operation proceeds to the exact
expected-version check and construction of the complete record with original
operation, provenance and terminal outcome. The owner then calls
`OwnerLedger.append(..., valid_until=decision.valid_until, completion_records=0)`
because the private write has no remaining external effect or completion
obligation. That conditional append is the only state commit. An earlier ingress allow or a callback is not
commit-time authorization. Reads and signed replies repeat current authority and
ownership checks before disclosure. Unknown record formats fail closed.

Restart and compatible upgrades retain a namespace only when its enrolled
identity, installation, package and scope remain the same. Fresh epoch/generation
authorization is still required on every call. Uninstall or grant withdrawal
removes access without deleting retained data or outcomes. A reinstall with a new
identity or installation does not attach automatically. Recovery/rebinding needs
an explicit authorized host operation that preserves the old owner and history;
no plugin-facing rename, reassignment, delete or purge operation is supplied.
Lost acknowledgments reconcile the original retained operation/digest, and close
must join an in-flight append rather than start a replacement. A recreated stream,
rollback below the trusted/observed floor or history gap refuses access.

The shared contract review with AMUX-47 must place the enrollment fields in the
trusted authority/activation record and confirm ownership checks and separate
permissions. AMUX-44 must expose both resources through the same existing storage
handle. These shared changes must be coordinated before implementation. Shared
contract tests must execute both actual providers through the same receiving
interface for reads, CAS success/conflict, invalid values, cancellation, close
and original-pair recovery; private cross-installation/scope denial and domain
invariant/transaction preservation require additional provider-specific tests.


`PrivateStorageResource.open_existing(...)` now implements the host namespace
binding and read path. Supply the existing retained stream/identity/retention,
`plugin_identity_ref`, `instance_id` and `package_id`. The receiver requires the
full signed service request as `service_request_bytes=` for private resources;
an inner domain envelope alone cannot establish the native installation owner.
`CapabilityReplyService` supplies those exact bytes and checks namespace ownership
from each of its current authority snapshots, including the final signing check.
Stored documents have the exact state shape `{formatVersion: 1, owner: {
pluginIdentityRef, instanceId, packageId}, value: ...}`. Ownership metadata must
match enrollment; only canonical `value` bytes are returned to the plugin.

The namespace gate tests cover actual signed native admission, identity,
installation, package and project mismatch, detached inner bytes, current host
credential revocation, direct-inner bypass, and an unwritten namespace that does
not provision or fabricate data. The coordinated `plugin-storage` enum addition
in the shared owner-record schema and its embedded Go copy permits real retained
private records. Offline checks now also read a seeded retained private document
through actual enrollment and a verified signed reply, preserve it across owner
restart, and refuse stored-owner/format/size mismatches. Shared read contract tests
exercise both actual providers with the same request/reply, expiry and close
behavior. Seeded history alone does not qualify private writes; the separate write tests
described below exercise actual capability dispatch. The complete two-provider write/recovery contract tests still require domain
mutation integration.


## Private writes and cancellation

The private receiver now dispatches `capability-storage-write` to the same
`PrivateStorageResource`. It serializes namespace mutations, checks the complete
signed native request, and looks up the original operation/digest before the
current revision check. A replay must also match the exact retained operation
metadata. It returns the existing real receipt without consuming a new revision,
even after a later value has committed. A changed payload or operation metadata
under that identity refuses.

A new write validates the complete private document and current namespace,
requires the exact provider revision, reauthorizes from current retained native
authority under the mutation lock, and appends one complete record through
`OwnerLedger` with `valid_until` and `completion_records=0`. That record contains
the original operation, private value, namespace ownership, authorization audit
and terminal committed outcome, with no external effects. The applied receipt
references that actual retained record. The owner never rereads and reapplies a
conflicted value automatically.

A stale expected version against an existing private value now retains a real
rejected OwnerLedger outcome with unchanged state and a new namespace version.
Its reply is `conflict` with that retained receipt and resource version; replay
returns the original result. A stale write to an unwritten namespace refuses
instead of creating a value. A broker CAS race remains an explicit refusal and
never reapplies the value. Capacity, invalid value and uncertain acknowledgment
do not fabricate a receipt reference.
The signed service converts failures to its existing fixed unavailable error;
the client must keep its saved original mutation and reconcile that exact pair.
A successful retained replay does not consume capacity. Reads and outcome queries
remain subject to current namespace and original-operation permission checks.

The receiver starts and retains one worker for each dispatched write. Cancellation
or a request timeout can withhold a response while that exact worker completes;
it is not proof of rollback. Receiver/service close joins that original worker
before borrowed storage is released. A cleanup timeout retains ownership for the
next close call. No replacement append is started to settle a lost response.
The focused write tests cover actual signed dispatch, original-pair recovery,
lost acknowledgment, replay after later writes, changed content/metadata,
competing/stale revisions, capacity refusal, oversized values, current revocation,
authority deadline/completion budget, and cancellation with an in-flight commit.

## Board recovery integration constraints

Source analysis identifies the authoritative mutation paths in
`hub/fed/board_services.py`: `v_add` creates the counter/card, while move, assign,
comment and claim use `_BoardOperations._write`. Its read/mutate/CAS loop
preserves unknown top-level card fields, but retries a domain change after a
conflict. `_on_entry`, `_mirror` and `on_revoke` update local projections rather
than the authoritative card. Redaction recursively preserves field names and
ordinary values. The provisioned `am_board` bucket keeps only 16 revisions per
key, and card history retains only 50 entries. Neither is an unbounded original
operation outcome history.

The board owner therefore needs a durable operation claim before its one-shot
exact card CAS, followed by a retained terminal receipt. The claim binds the
original operation/digest, resource ID, exact expected card revision and a unique
attempt marker. A pending fence must prevent later capability commands from
replacing unresolved evidence. The successful card CAS must retain that marker
and its original pair; all legacy mutation paths must preserve unresolved markers
or refuse. The receipt has its own identity/revision, separate from card version;
its history contains operation outcome metadata rather than another copy of card
business state. A post-write receipt by itself cannot settle the crash window.

Recovery must prove whether the exact marked CAS committed, even after other
writers or a lost acknowledgment. An absent marker after trimmed history is not
proof of non-commit. Nor does observing the old revision prove an original publish
is no longer in flight: recovery must join or fence that attempt before recording
a terminal non-commit. One possible fence is a conditional metadata-only CAS at
the original revision; either that fence wins and prevents the original CAS, or
it loses and recovery inspects the winning original binding. That is a recovery
fence, not an ordinary conflict receipt or permission to retry the domain effect.
The trusted backend implements this algorithm for existing-card changes, with
focused fault tests. Activation still needs protected broker composition and
every legacy writer routed through the owner, including add/counter allocation.

The documented legacy broker policy allows `$KV.am_board.>` and `$JS.API.>`.
Source policy is not proof of actual current credentials or of a protected
pending fence. Activation must establish which current publishers can change or
remove evidence, including direct publishers and destructive administration.
An unsafe or unverified boundary cannot be treated as qualified merely because
all local wrappers preserve markers. The existing publish grant also permits KV
`delete` and `purge` operation headers; denying stream-delete/purge API subjects
does not stop those writes. `KV.create` can reuse a tombstoned key, so creating a
claim key does not prove that key was never used. Neither a local marker nor a
recreated key is a sufficient recovery boundary.

A marker carried through later writes proves at most that the marked effect
committed. It cannot recover the exact original card revision after that revision
leaves KV history. The broker assigns revisions across all keys, so expected
revision plus one is also invalid. Activation therefore requires either a boundary
that stops every eligible publisher from advancing/deleting unresolved evidence,
or a backend that atomically retains the original operation and actual committed
revision with the card change. Current direct legacy publishers prevent the first
option from being established by changes to `_write` alone. No credential changes
or alternate board authority are implemented here.

The shared write result now has a separate resource reference, as specified
below. A board receipt revision cannot identify the next card revision. Private
and domain callers use the explicit result resource reference, without inferring
it from receipt identity or version.



## Qualified board owner route

This describes the implemented backend and remaining board route composition. The
accepted S01/S02/S05 decisions and federation KV preservation requirement already
choose owner-mediated commands, retained recovery and writer fencing. They do
not authorize an implicit data cutover or production credential rotation.

Keep the existing `SharedBoardStore.add/move/assign/comment/claim` methods and
argument shapes. At `build_board_context`, qualified enrollment supplies an
owner command client in place of direct mutation composition. Unqualified legacy
installations keep their existing path and are not presented as qualified
capability-write installations. A qualified composition must fail closed if its
owner route is absent; it cannot fall back to direct KV writes. The receiving
owner retains the existing domain validation, `_clean`, bounded card history,
`FederationAudit.written` and `_mirror`. Capability CompareAndSwap has one exact
expected-version attempt; the legacy retry policy stays explicit at the legacy
command boundary and cannot silently reapply a prepared capability operation.

Bind commands to the actual admitted operation and resource. `Hub.caller_of`
already authenticates local socket ancestry or TCP token possession before
`Federation.dispatch`; `sender_of` only translates the resulting caller for
legacy display. The qualified adapter needs an enrolled mapping from that
verified local caller to its identity, transport and grants, followed by actual
`EnrolledIngress` admission. NATS peers require their enrolled transport or
agreement proof. Neither a JSON caller string nor an asserted `operator` value
can establish this mapping. Use the complete admitted operation for actor, scope,
resource, original operation/digest and deadline checks on the receiving owner.

Prepare a separate disposable qualification account with distinct owner and
caller credentials. Callers publish only their exact command route and subscribe
to their private reply prefix; they have no `$KV.am_board.>` or general JetStream
API grant. Only the board owner receives its enrolled card/counter writes and
required reads, plus its separate operation-journal subject. Projections receive
read/consume access and their own local projection writes. Account administrators
remain separate. Verify the actual credential signatures and exact permission
sets through the existing credential validator, then prove broker refusal of
normal writes, KV delete/purge headers, stream management and out-of-scope
commands in the bounded qualification. A selected policy document alone does
not prove the broker boundary. Existing production credentials are unchanged.

The retained journal owns command progress, not another copy of card business
state. A per-card pending claim serializes **all** qualified writers, including
legacy commands and owner replicas. Every writer must win the same journal CAS
before dispatch. An in-process lock or a check followed by an unrelated card CAS
is insufficient. Freeze that card until its original result and exact resource
revision are durable; carrying a marker through later card versions is not enough.
Store the original complete operation and payload digest, exact key and stream
identity, expected card revision, prepared candidate digest, and claim identity.
Retain the original authorization and preparation data without changing its
expected version to a receipt sequence. Budget required completion and recovery
records before admitting a claim; exhausted capacity must preserve existing data.

The proposed transitions are:

1. Authorize and validate the exact command against current authority, original
   session, repository mapping, stream identity and current card revision. Resolve
   original-operation replay before proposing a new claim. Changed payload or
   operation metadata under an existing identity refuses.
2. Commit a pending journal claim by conditional append. A claim records intent;
   it does not itself grant execution authority. Concurrent claim loss causes
   authoritative reread and refusal/recovery, never automatic domain reapplication.
3. Freeze the exact prepared card bytes, attribution, timestamps and original
   operation/digest/claim marker before marking dispatch. Retain their digest in
   the pending claim. Obtain current execution authority and durably mark the one
   dispatch attempt, then publish those exact bytes in the card CAS. Recovery
   cannot regenerate timestamps or history. Shield and retain the exact worker
   through cancellation and close.
4. Persist the actual broker-returned card revision and terminal outcome in the
   journal. An exact retained marked card revision can reconcile a lost reply
   while the pending claim prevents a later legitimate writer from replacing it.
   Do not infer the result revision from the receipt sequence or expected plus one.
5. Finish the existing audit/projection work with durable pending completion
   metadata. Record completion idempotently so recovery does not duplicate audit
   rows. Once the terminal result and required completion work are durable, release
   the card for the next claim. Later queries return the original recorded result,
   even after other commands advance the card.

If dispatch ownership is uncertain, observing the old card revision is not proof
of non-commit. Join the original worker or issue a separately authorized exact CAS
fence at the original revision. A winning fence excludes that original CAS; a
losing fence requires inspection of the winner. This recovery fence does not
repeat the business change. Missing or altered evidence, unexpected stream/key
recreation, or unproved writer fencing leaves reconciliation required and the
claim retained. Never convert a timeout into a fresh comment or claim.

`add` also needs a per-prefix allocation claim covering the existing counter CAS
and subsequent card creation. Before incrementing, retain the expected counter
revision/value and proposed next key. Recovery must reconcile or fence that exact
increment before advancing the prefix, then use the same key rather than increment
again. Preserve integer counter
contents and existing ID allocation. Reject a tombstoned/recreated enrolled key
instead of relying on `KV.create`'s recreation behavior. Pin the original stream
creation and observed sequence floor; a replacement stream or counter rollback
requires explicit recovery. These checks must cover all qualified legacy add
calls as well as capability writes.

The shared ledger handoff is narrow: add a reviewed board-operation journal case
for independent `expected_target_version`, with explicit binding and retained
original-operation validation. Do not extend it to arbitrary entity kinds.
Preparation, dispatch and completion have distinct journal transitions; their
internal receipt identities must not masquerade as new signed caller commands or
bypass `OwnerLedger`'s original-operation replay checks. The receiving owner needs
an explicit authorized completion format/API for those transitions, following
existing effect-completion authority patterns. This API and the legacy caller
mapping are concrete dependencies, not an undecided SDK language or storage
architecture. The shared ledger now permits this exact board-operation binding.
The trusted backend can dispatch one existing-card CAS after retaining its claim;
public routing still requires the qualified publisher and all-writer boundary.
The existing
`_BoardOperations.prepare_change` now prepares move/assign/comment/claim changes
with explicit attribution and time, returns immutable encoded bytes, and uses the
same validation, redaction and history rules as the legacy retry loop. The legacy
methods use this shared preparation path. This extraction does not enable native
writes or create a receipt, ingress identity or broker boundary.



### Board journal and ingress interfaces

Keep `OwnerLedger.append(record, *, expected_sequence, admission="bulk",
valid_until=None, expected_target_version=None, completion_records=None)` intact.
Its narrow additional target-version case is the exact owner binding
`("federation-board-operations", "attempt")`. CAS, replay, strict history,
retention and completion reserve enforcement remain unchanged. Domain transition
validation belongs in the receiving board owner. Do not add a generic completion
method that bypasses operation identity, authority or history validation.

The implemented journal interface is:

```python
BoardOperationJournal.prepare(
    caller_envelope: bytes, *, expected_sequence: int,
    candidate: PreparedBoardChange, target_ref: dict, observed_sequence: int,
    service_request_bytes: bytes | None = None,
) -> StoredRecord

BoardOperationJournal.advance(
    owner_envelope: bytes, *, expected_sequence: int,
) -> StoredRecord

BoardOperationJournal.outcome(
    original_operation_id: str, original_payload_digest: str,
) -> BoardOperationOutcome
```

Preparation retains the complete original operation, contract and signed input.
Its expected target version is the caller's exact card revision. The pending
claim includes a stable claim identity that can be put into the prepared candidate
before the card CAS; it must not assume an unknown future broker sequence. The
journal validates that the exact candidate binds that identity and original pair.
The actual committed journal reference is learned from the retained claim, not
predicted from a global sequence.

Protected `BoardTargetBinding` pins the repository, card key, JetStream domain,
stream creation time and minimum sequence. Every claim retains that binding and
the actual observed stream sequence. Later claims cannot roll the observed source
back, even when a caller supplies a stale expected card revision. Native writes
require the complete signed service wrapper and current parent authority.
Preparation also retains the original audit categories and redacted description,
so recovery can finish the existing SQL audit and mirror without rebuilding the
domain change or changing its attribution.

Advance takes a fresh signed `federation-board-dispatch` or
`federation-board-complete` operation. Its operation ID differs from the original
caller and every other phase operation; replay retains the exact phase identity.
The payload binds `originalOperationId`, `originalPayloadDigest`, `claimRef`,
`resourceRef` and `candidateDigest`. Completion also names a private owner-held
observation; caller JSON cannot supply authoritative success or revision fields.
Each phase operation uses the journal version it actually observed. The original
card expected revision remains unchanged in the claim. Match the owner-service
identity and distinct current phase grant to protected enrollment, validate the
whole retained transition history, reauthorize and conditionally append once.
Follow `dashboard/definition_completion.py`'s fresh signed completion pattern,
without reusing its definition contract or actor permissions.

Outcome follows the original claim through the later phase operations and returns
its exact recorded resource revision. `OwnerLedger.outcome(original_id, digest)`
finds the initial claim, not the terminal business result. Never present that
initial claim as a committed board change. The current shared outcome-query reply
schema supports absent and terminal results only; an unresolved result needs a
reviewed schema/SDK addition or a fixed unavailable response, not false absence.

The implemented local authentication handoff is:

```python
Hub.authenticate_caller(req, writer, tcp) -> AuthenticatedLocalCaller

LegacyBoardIngress(hub, ingress: EnrolledIngress,
                   enrollment: LegacyBoardCallerEnrollment)

LegacyBoardIngress.admit_local(
    proof: AuthenticatedLocalCaller, *, operation_id: str,
    expected_version: int, cancellation_ref: dict,
) -> AdmittedCall
```

Only actual socket/token authentication may create the private short-lived proof.
Bind the issuing hub, authenticated caller, requested legacy attribution and exact
request; consume it once and never deserialize it from client JSON. Preserve
`Hub.caller_of` compatibility. For operator `--as`, keep the authenticated operator
separate from requested attribution; do not authenticate the asserted agent.
Protected `LegacyBoardCallerEnrollment` supplies already enrolled identity,
transport, grant and signing material. The bridge signs an ordinary
`identity-ingress-request` and calls `EnrolledIngress.admit`; it cannot enroll,
grant authority or sign caller-supplied operation context.
The bridge derives the command from the authenticated request snapshot and its
protected repository/card route. It does not accept separate command bytes.

Identity routing and authorization register the narrow contracts
`federation-board-command`, `federation-board-dispatch` and
`federation-board-complete` in `identity/ingress.py` and `identity/authority.py`,
with closed payload schemas. The first carries the preserved legacy APIs,
including add/allocation and their explicit retry policy. Native exact-version
writes continue to use `capability-storage-write`. The two phase contracts require
the enrolled board owner's service identity and distinct scoped grants; they are
not ordinary plugin write permissions.

`BoardMutationOwner` uses these interfaces for existing-card changes. It shares
the legacy validation and mutation preparation, commits the exact card CAS once,
retains its actual resource revision separately from the journal receipt, and
finishes the existing audit and SQL mirror. Cancellation retains the original
worker until cleanup joins it. Recovery uses a fresh authorized query and owner
phase operations; it never replays the business change. An original operation
marker proves an applied candidate. At the unchanged expected revision, one
conditional metadata fence can exclude a late original CAS. A missing card or
unsafe observation remains uncertain and cannot recreate the card.

`CapabilityReceiver` accepts this backend only through a host-supplied
`BoardStorageRoute`. The route must be issued by `BoardPublisher.bind(owner)`
after that publisher opens its own connection using the exact enrolled JWT,
account/user pins, verified TLS and required leaf-certificate pin. Both the card
and operation journal must use that exact publisher JetStream context. The
receiving connection and borrowed identity reader stay separate. A raw backend,
unregistered route or legacy KV cache cannot substitute for that connection.

```python
publisher = BoardPublisher(**protected_publisher_inputs)
await publisher.start()
# Construct the existing domain resource and strict journal on publisher.jetstream.
route = publisher.bind(board_owner)
storage = CapabilityReplyService(..., resources=[board_resource], board_routes=[route])
outcomes = CapabilityReplyService(..., resources=[board_resource], board_routes=[route])
```

Use `service_id="storage-owner"` for writes and `"outcome-owner"` for recovery.
The route uses the same `capability-storage-write` and
`capability-outcome-query` request/reply contracts as private storage. No new
public board-specific storage handle is introduced. Every reply still passes the
existing signed service response checks, including current native parents and
the resource's original repository/session binding before disclosure. Pending
results refuse with an unavailable response; they are never reported absent.
Close both receiving services and join their original workers before closing
the publisher, which joins its registered backends before releasing transport.

This registration does not prove that other account users cannot write the card.
Qualification still requires real broker refusals and all legacy writer routing,
including add/counter allocation. Existing production credentials are unchanged.
Controlled transport tests cannot qualify a live broker or production cutover.


## Qualified legacy board command composition

A protected host can select `Federation(qualified_board=True,
board_commands=client)` with an enrolled `LegacyBoardCommandClient`. The existing
five mutation methods then use `LegacyBoardCommandService` and publisher-issued
card and allocation routes. The plugin receives the command client and local
projection. Startup, list and show can use the local mirror before a connection
exists; each mutation checks its current session and refuses a replaced, closing
or disconnected route. Missing qualified routes never select direct KV writes.
This selection does not change production credentials or qualify an installation.

The client consumes the actual Hub socket/token proof. Enrollment selects the
allowed command, resource, actor and signing material. The closed
`federation-board-service-request` wrapper proves current transport possession
and binds the inner operation, scope, deadline and reply inbox. The closed
`federation-board-service-response` binds the pinned owner identity, instance,
issuer, request digest and original result. Both ends recheck current authority
and deadlines after authority reads; the client checks its session again before
returning a result. These wrappers do not grant new business authority.

The protected host must provide `retain_recovery`, which durably saves the
immutable recovery bytes before the first publication, and restore those bytes
when reopening the client. Unconfirmed calls retain the original operation.
A fresh authenticated request for that same intent queries its outcome; it does
not retry the business effect. Restoring a different unresolved original for the
same request is refused. A delayed response can remove only its own saved entry.

New legacy card journal records use `amx-board-operation-v2` to retain the exact
prepared card and retry count before any effect. Recovery returns that original
card, resource revision and attempt count even after a later writer changes the
card. Existing v1 records remain readable but cannot invent an unretained legacy
result. Preparation reserves space for the completion and signed response before
claiming the card; an oversized result refuses before a business mutation.

Command connections use the paired NATS client's `subscribe_owned` method.
Task-local ownership records a subscription before sending `SUB`, including a
send failure, without replacing the borrowed connection's session. Cancellation
retains the original acquisition and cleanup. Close the command client and
receiving service and join their original work before closing publishers and
borrowed connections. Incomplete cleanup remains explicit and can be joined
again. Private transport and storage error text is not returned to plugins.

Controlled I/O tests cover the actual Hub, ingress and owner paths. Installation
qualification still requires the actual native broker checks and all-writer
restrictions; these tests do not prove a production cutover.


## Storage result reference

The storage-only reply schema now requires a `resourceRef` beside
`receiptRef` and `outcome` in `capability-storage-write-reply`. It is a registered
reference for `applied`, `rejected` and `conflict`, and exactly `null` for
`uncertain`. Completed outcomes identify the committed or observed resource
revision retained with that original operation result. Replay returns that
original result reference, never a later current resource version. An uncertain
result cannot invent a committed reference. All other capability receipt schemas
remain unchanged.

The canonical schema and embedded copy enforce the same conditional null rule.
The native storage reply decoder requires the original field and validates its
owner hub and resource ID against the request. Both references stay raw until
schema validation, so missing/null receipt revisions cannot become zero through
typed decoding. `CapabilityReceipt.ResourceReference()` returns
`(ContextReference, bool)`; it is absent for uncertain storage results and
non-storage receipts. Existing receipt accessors and other receipt wire contracts
are unchanged. The decoder does not equate resource and receipt revisions or
assume a global sequence increment.

For private storage, an actual rejected OwnerLedger record may retain unchanged
value at a new namespace revision, with a real receipt and a resource reference
to that retained version. That differs from modifying a board card merely to
record an operation conflict: the board's receipt history has its own version.
Any private conflict record must preserve exact original operation/digest and
state, current authority, retention/reserve admission and terminal replay. No
rejection may fabricate an initial private value merely to create a receipt.


Private namespace construction requires strict `OwnerLedger` completion-budget
composition. The ledger checks that the configured history reader can cover every
record slot admitted by the enrolled quota before the resource is accepted.
The private factory enables `require_completion_budget=True`, and direct resource
construction refuses an otherwise non-strict ledger. The documented 64 MiB
reference allocation fits; unsupported larger allocations fail with
`owner_history_capacity` before any value is stored. Increasing quota is not
permission to outgrow the reader and lose original-operation recovery.


## Trusted namespace activation handoff

The authority handoff uses `nativeInstances[].privateStorageResources`, with
at most 64 entries shaped `{resourceId, scope, bindingDigest}`. It is supplied by
authorized activation/admin enrollment and copied from the matching protected
`activationDeclarations[instanceId]`, following the existing configuration-event
source pin flow. Entries are unique per resource ID, have the exact enrolled
scope, and must have applicable storage read/write or outcome domain bindings.
Omission remains valid for instances with no private storage; a private request
must refuse when the mapping is absent. A parent mapping grants no implicit child
namespace access.

`bindingDigest` pins the host namespace enrollment: owner hub/resource ID,
`plugin-private`/`plugin-storage`, exact scope, plugin identity reference, stable
logical instance ID, package ID, format version and document size limit, retained
stream name/domain, creation identity/minimum floor and explicit retention limits. The host obtains
those fields from protected enrollment, never request assertions. Only the digest
and opaque resource ID need to enter the native row; broker subjects, storage
credentials and values do not enter plugin context. Both receiver admission and
the final reply admission compare that mapping from the same current authority
snapshot against the actual namespace binding. The digest is `sha256:` followed
by lowercase SHA-256 hexadecimal over RFC 8785 canonical UTF-8 JSON. The purpose
is `agentmux-private-storage-binding-v1`; creation time uses UTC with six
fractional digits and `Z`. Epoch and generation are current-call authority
checks, not persistent namespace identity. The existing `instanceId` is a logical
instance ID; the protected model has no separate installed-release ID. A child
must have both a different resource ID and digest from every ancestor.

AMUX-47 owns the closed native-instance/activation declaration schema and
validation handoff; AMUX-44 owns the manager/host-selection producer. Their
activation changes require separate review and qualification. Existing full-owner generation,
plugin identity and storage permissions remain required. Namespace service-host
construction must consume the exact protected pins and separately enrolled owner
credentials; registering a route does not launch or qualify that owner service.


Storage recovery now has explicit branches in `capability-outcome-query-reply`.
They require `contractId: capability-storage-write` and `resourceRef` beside the
original operation/digest, `recordRef` and terminal outcome. An absent operation
has null record and resource references. A committed/rejected operation returns
its original retained result resource reference. The existing non-storage reply
branches remain unchanged. `CapabilityOutcome.ResourceReference()` exposes that
storage reference after `CapabilityHandles.Reconcile`, including when a new
operation context queries after the original write deadline has expired. It does
not replay the old write or infer a resource revision from the receipt version.

The native decoder validates raw reference shapes against the shared schema,
requires the storage contract and matching resource/owner hub for storage results,
and rejects storage-only fields on a non-storage query. It also requires the
original declared capability route. The receiving authority checks the current
native original-operation binding/policy from the same snapshot, alongside the
query binding and the caller's current original grant. Query permission alone
cannot disclose a result after original native or caller permission is withdrawn.
The queued live outcome fixture now declares that original write permission for
its package, parent and child and expects the explicit storage result fields;
it still needs rebuilding and a live slot before qualification.

Knowledge storage uses the same native storage read, write and outcome contracts.
Protected `storage.knowledge` selection pins the original SQLite file and policy,
repository, local peer/node, plugin instance and authenticated actor/transport
pairs. It opens existing tables and the original FTS5 index/insert trigger; it
does not create or repair a database. Identical selected message or board source
custody can be borrowed, with one joined executor and no second database owner.

The write value is a closed object with `formatVersion: 1` and one command:

* `publish` includes the original knowledge `envelope`. The owner checks the
  local author, peer/node and repository, then uses the existing stage/index
  transaction, outbound redaction, outbox and audit behavior.
* `index` includes the original received knowledge `envelope`. Current inbound
  policy/sharing and approved quarantine data are checked before indexing. Peer
  author, trust and untrusted flags remain stored as remote data.
* `withdraw` includes `peer`. Only a denied or removed peer can be withdrawn,
  and only rows in the selected repository change. Rows and search data remain.

New envelope data contains `title`, `body`, `tags`, `ref`, `author` and `source`.
Sources are `explicit`, `auto:work`, `auto:handoff` or `auto:result`; other shapes
and commands fail explicitly. Existing rows, including added columns, remain
readable through a host-pinned initial source or the last committed source.
Reads return the full original row and are bounded to 45,000 canonical bytes.
The native envelope and journal bounds also apply; an oversized result or
receipt fails without committing partial data.

Resource revisions and original-operation outcomes are retained under
`capability-knowledge:` in the existing `fed_state` table, in the same transaction
as the domain effect. No replacement record store is created. A duplicate ID
cannot hide changed row or outbox contents. Replay returns the original result;
conflict retains a result without changing the finding. Recovery needs current
original write permission as well as query permission. Reopening with the same
protected binding preserves these outcomes. Incompatible bindings, source files,
schemas, current identities or stopped sessions refuse access. Rollback must pin
compatible packages/configuration and retain the original database and journal.

Native receiving-route checks do not establish legacy facade migration. Search,
panels, automatic capture, notifications and qualified legacy writers still need
their own remote integration and recovery checks before this domain mapping is
complete. The existing local legacy services remain in place.
