# Internal owner persistence

This package stores complete domain-owner records through NATS. It is an internal
helper for an authenticated receiving service, not a public storage capability.
It does not enroll callers, grant permission, execute effects, migrate legacy
data, or activate a replacement writer. AMUX-48 remains open until those required
integrations and the remaining recovery work pass their checks.

`state_owner.task.TaskOwner` provides host-private `task-inspect` and `task-reserve`
receivers for an already enrolled task ledger. It verifies each signed command
against current retained identity authority, reads the exact task and scope, and
checks authority again after the source read. The returned `StoredRecord` retains
the original task identity, state, provenance, reservations and outgoing intent.
The host still owns transport and signed replies. No query rebuild or inspection
dispatches an effect or changes a reservation.

Task state validation retains unknown imported fields while checking `taskId`,
the accepted task `status`, `assignmentEpoch` and the original reservation payload.
A reserved or cancellation-pending task cannot lose its reservation. Missing
history below the enrolled floor and recreated sources require recovery. This
receiver does not provide import, writer transfer or later task lifecycle commands;
those remain required work in AMUX-48.

For the first reservation of a ready task, the host calls
`reservation_references(operation_id)` before signing the possession request.
It derives prospective delegation and execution-grant IDs from the actual owner
hub, task, scope and operation. The signed payload must contain those exact IDs
and origin references at creation revision 1; the receiver never substitutes
another ID. This namespace separates different tasks, scopes and operations.
The host then calls `prepare_reservation(request_bytes, cancellation_ref)`. Its
opaque `PreparedTaskReservation` binds the original possession request, task head,
scope and cancellation reference. `EnrolledIngress.admit(...,
reservation_context=prepared)` checks current direct authority and validates the
same preparation before signing. The prospective delegation reference uses the
unchanged requested ID, the actual origin hub and embedded creation revision 1.
It is an uncommitted proposal, separate from the task record reference returned
after commit. It neither delegates caller privileges nor proves receiver acceptance.

`handle(envelope, reservation_context=prepared)` rechecks current authority and
conditionally commits the reserved state, provenance, original outcome, embedded
delegation, origin execution grant and immutable `delegation-offer` intent together.
The execution grant records its exact task, attempt, delegation, executor hub,
scope, assignment epoch, repository and input reference, source task head,
requesting actor and authorization grant, operation identity and validity interval.
It is a task-scoped business grant, separate from identity-policy grants. It grants
no caller, broker or local-tool privileges and cannot replace receiver acceptance
or current dispatch authority. A requester authorization grant cannot substitute
for it. Inspection and replay validate the stored grant's bindings against the
same committed reservation and provenance. The intent preserves
the task's existing input reference. The grant validity and offer acceptance
deadline are capped at the earlier of the original operation deadline and the
admitted authority validity. Replay preserves that original bound. Delivery must
independently authorize and claim its own durable work
before I/O. This receiver performs no delivery and owes no later delivery receipt
append, so this completed reserve command has a zero remaining-write budget.
That bound does not free the business reservation or promise execution. A lost
acknowledgment stays unknown until the original operation outcome is read; a
fresh admission after restart returns the original record and delegation reference.

The zero-write bound is refused for prior retained effects, nonempty imported
flags or unknown state fields that could carry delivery, receipt or reconciliation
obligations. Inspection still preserves those records. The supported ready-state
metadata fields are `legacyId`, `parentKey`, `body`, `originPeer` and `audit`, along
with the task identity, status, epoch, reservation, origin and input reference.
Other imported state needs a concrete obligation model before write admission.
Retained delegation identities cannot be reused for a new reservation. No timeout,
presence change or expired execution grant releases an existing reservation.

Run its bounded offline checks with the prepared Python environment and
`PYTHONPATH=sdk/python:.:dashboard:taskmgmt`:

```sh
python -W error::ResourceWarning -m unittest state_owner.test_task -v
```

## Owner API

The trusted host supplies a scoped JetStream context and these inputs:

```python
from agentmux_contracts import canonical_bytes
from state_owner import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention

binding = OwnerBinding(
    hub_id="hub-one", owner_domain="task", entity_id="task-one", entity_kind="task",
    scope=canonical_bytes({"organizationId": "org-one", "projectId": "project-one",
                           "workspaceId": None}),
)
owner = OwnerLedger(
    scoped_jetstream,
    stream="OWNER_TASK_ONE",
    subject=owner_subject(binding),
    binding=binding,
    retention=Retention(max_bytes=approved_quota, reserve_bytes=approved_reserve),
    stream_identity=StreamIdentity(enrolled_creation_time, retained_minimum_revision),
    require_completion_budget=True,
)
snapshot = await owner.current()
prior = await owner.outcome(operation_id, canonical_payload_digest)
stored = await owner.append(validated_complete_record, expected_sequence=snapshot.sequence,
                            completion_records=required_future_records_after_transition)
```

`current()` returns a `Snapshot(records, sequence)` with a `latest` property.
`outcome()` returns a matching `StoredRecord`, or `None` only after checking the
complete available history. `StoredRecord(record, sequence, replayed)` carries
immutable canonical bytes. Operation IDs are unique within the pinned aggregate.
The receiving service must bind each command to that same aggregate on retries;
it must not allocate a different entity to bypass an existing operation outcome.

`append()` validates the owner-record schema, exact owner and scope, effect payload
digests, version chain and 64 KiB body limit. State, provenance, outcome and outgoing
intent are one conditional record. It returns the original matching outcome on
replay and rejects changed-content reuse. It never claims a transaction with a KV
view, artifact upload, another stream or an external action.

Pass the receiving service's trusted decision expiry as `valid_until`. Immediately
before publishing, the helper checks the earlier of that expiry and the recorded
command deadline. It cannot create or extend authority. For `definition-catalog`
only, `expected_target_version` lets the service compare the signed target version
separately from the catalog sequence. The service must derive that target version
from the same authoritative snapshot used to build the proposal. The aggregate
sequence comparison still protects the complete catalog; the signed command is
never rewritten. Other entity kinds cannot use this argument.

The receiving service must authenticate the signed command, check current grants,
validate business state and bind the operation's payload digest before calling
this helper. After `owner_revision_conflict`, reread, reauthorize and rebuild the
proposal. After `owner_commit_uncertain`, reconcile the original operation ID and
digest before deciding whether another append is safe. Cancellation during publish
also leaves the commit uncertain. Storage replay itself never dispatches effects.
Current effect authority and idempotent retry, query-before-retry or human
reconciliation remain the dispatcher's obligations.

## Scope and provisioning

`owner_subject(binding)` returns:

```text
amx.v1.h.<hub>.o.<organization>.p.<project-or-_>.w.<workspace-or-_>.ledger.<domain>.<entity>
```

Each component is a validated opaque ID. `_` represents null scope and cannot be
a v1 ID. The helper refuses any different subject. The host must restrict broker
credentials to that exact subject and its dedicated stream read/info APIs, plus
reply inboxes. Callers receive domain command contracts, never this object or its
JetStream client. Python subject checks do not replace broker permissions.

`Retention.stream_config()` returns configuration for a separately authorized
provisioner. The helper cannot create or delete streams. This first implementation
uses one stream per aggregate so history, operation uniqueness, quota admission
and conditional writes have the same boundary. This is a material restriction:
stream count grows with aggregates, quotas are per aggregate, and a project-wide
backup needs coordinated owner watermarks and artifact inventories. The accepted
10 GiB solo/100 GiB team metadata allowances are deployment totals, not an allowance
to assign that quota independently to every entity. Stream-count capacity and
deployment-wide allocation remain unqualified. A shared-stream implementation
would need a separate proven quota and operation-history design.

The host retains the stream's creation identity from enrollment and a minimum
known revision from trusted recovery history. Never learn these anew from an
arbitrary empty stream. Creation mismatch, a revision below the known floor,
retention gaps and unsafe storage configuration refuse readiness. The helper also
advances its in-process floor after reads and commits. This detects recreation
and known rollback, not every old-origin restore. Persisting trusted enrollment
and watermarks, fencing restored owners and reconciling external reservations
remain host/recovery integrations. A restored checkpoint never authorizes writes.
An administrator can replace a stream between observation and publish; the
creation check does not replace lifecycle fencing at that boundary.

## Retention and recovery

Authoritative streams use file-backed Limits retention, discard-new, no automatic
age or per-message expiry, and no message delete/purge/rollup. Bulk admission stops
at the lower of 85% of the approved quota and the quota minus its fixed reserve.
The warning threshold is 70%. Each append conservatively charges 128 KiB for a
maximum 64 KiB body plus framing. Completion/reconciliation can use the reserve;
broker rejection is never reported as a committed outcome. Fixed aggregate
headroom alone does not cover every accepted obligation. Physical
disk headroom, object quotas and independent-host R3 remain separate qualifications.

Qualified owner composition must set `require_completion_budget=True` and check
`completion_budget_required` when accepting a supplied ledger. Each new append then
requires `completion_records=N`: a conservative bound on every future owner record
still needed after the proposed transition. The capacity check reserves 128 KiB
per required record and requires `(stream_records + 1 + N) * 128 KiB <= max_bytes`,
alongside the ordinary bulk thresholds. Completion and reconciliation also obey
this check, so they cannot spend slots still owed to other work. A retained replay
uses no new record and returns its original outcome without a fresh budget.

The receiving domain computes this bound from complete durable candidate state,
including old outstanding work and required claim, receipt, retry and reconciliation
writes. It must derive the bound again after recovery or a revision conflict.
Neither a client-supplied number, the latest record's effects alone, nor a process
counter can establish it. The state and its capacity decision share the same
conditional stream sequence; competing acceptors cannot both commit from the old
snapshot. No separate reservation table or second storage authority is introduced.

Identity's inline transitions, definition effect states and integration phases
need their own checked mappings. The default constructor retains the earlier
fixed-headroom behavior for existing callers; that mode does not qualify the full
completion-reserve criterion. The criterion remains open until the receiving
owners enable strict composition and exercise their complete obligation bounds.

`OwnerView.apply()` and `rebuild()` copy committed state to KV using a conditional
write. `read(entity_id, expected=stored_record)` requires the authoritative record
and checks exact canonical content and revision. Corruption or missing/stale data
refuses readiness. Delete/recreate only the separately owned projection, then
rebuild from the owner; never discard the ledger. Rebuild has no execution hook.

`OwnerArtifacts.upload()` uses a unique artifact/version name and verifies the
uploaded bytes before returning a digest-bound reference. `retrieve()` checks
store binding, version, digest, size and bounded chunks without creating a
consumer. The receiving service rechecks current access on every retrieval.
Uploads precede commits. There is no deletion API: orphan collection still needs
a grace period and checks across retained records, checkpoints and unresolved
work. Store permissions and retention must prevent other writers from replacing
or removing referenced bytes. A detected mismatch refuses use; a digest does not
establish origin authority or safety.

`build_checkpoint(snapshot, binding)` preserves a complete owner chain in bounded
frames, including all state, reservations, operation outcomes, effects and artifact
references. `write_backup(path, bytes, binding)` publishes private files without
replacement using exclusive creation, fsync and hard linking. `restore_backup()`
requires a digest from a trusted inventory and returns `FencedRecovery`, always
marked `reconciliation_required`. This is record backup and fenced readback, not a
complete encrypted, off-volume application or broker restore. This record-only
format omits artifact bytes. The encrypted bundle below includes them; multi-owner
consistency, hourly scheduling/daily restore sampling and measured RPO/RTO remain
host integration requirements.

For an encrypted owner bundle, use `state_owner.backup.export_backup()` with the
verified history, binding, stream identity, a host-supplied 32-byte key, and an
authorized asynchronous artifact reader. It captures one fixed prefix and includes
every artifact referenced by any retained record. It verifies the bytes before
publishing an encrypted manifest last. Keep the returned manifest name and digest
in a separately trusted inventory. The bundle uses the pinned PyNaCl
[SecretBox API](https://pynacl.readthedocs.io/en/latest/secret/) with generated
random nonces; neither keys nor plaintext are written to the backup destination.

`state_owner.backup.restore_backup()` requires that inventory digest and key. It
verifies all components and exact artifact coverage, then returns a `FencedBackup`
with a history cache and verified local artifact reads. Close it after use. Restore
does not republish artifacts, activate a writer, or run effects. Private local
staging temporarily holds plaintext checkpoint files and needs enough disk space
for the complete checkpoint. The restored cache also contains plaintext and must
live outside the backup destination.
The receiving service must check current access before returning restored artifact
bytes to a caller; possession of a backup key is not a product authorization grant.

Each artifact and checkpoint shard is limited to 64 MiB. The bundle has an explicit
total byte budget, artifact-count limit and 512 KiB manifest bound. Failed exports
may leave encrypted components or, after a publication error, a complete manifest.
Treat the reported outcome as uncertain and reconcile it; no automatic collection
deletes those files. The host
still owns hourly scheduling, daily restore sampling, protected off-volume storage,
key custody and rotation, coordinated owner watermarks, and recovery reconciliation.
A single-owner bundle does not establish an application-wide consistency boundary
or qualify the backup RPO/RTO targets.

`BackupHost` in `state_owner.backup_host` supplies local filesystem key custody and
a durable receipt inventory. The trusted administrator selects three separate
private directories for bundles, inventory and keys, and explicitly calls
`enroll_key(key_id)` once for a new key. Startup only loads enrolled keys. It never
creates a replacement for a missing key. Enrollment does not overwrite an existing
key, and selecting a new key ID leaves old keys available for older backups. This
is filesystem custody; Keychain integration and protection against loss of the
source disk remain deployment qualifications.

Native macOS ARM64 custody uses the shared descriptor admission policy for held
directory ancestors, private roots and private files. It checks ACLs and requires
a local mount with ownership enforcement, in addition to POSIX ownership and
permissions. Unknown native results refuse access. Key reads open nonblocking and
refuse non-regular files before reading. Publication checks the new private file
before writing secret bytes and again before linking its final name. Controlled
ACL and mount-refusal tests do not qualify an actual ownership-disabled volume.

Inventory commit verifies the encrypted manifest's digest, selected key, owner,
stream creation identity and cursor. It publishes an immutable private receipt,
reads it back and syncs its directory before returning success. Inventory lookup
preserves the greatest known cursor; a later backup of an older prefix cannot
lower that watermark. An uncertain inventory publication must pass readback and
directory sync before lookup offers it again.

`OwnerBackupLifecycle` in `state_owner.backup_lifecycle` attaches this host storage
to one recovered owner. Construct it with the shared history, binding, stream
identity, `BackupHost`, selected `key_id` and trusted `retrieve_artifact` callback.
Before history replay, obtain `await backups.recovery_identity()` and pass that
identity to `ledger.require_recovery_identity(identity)`. This raises the ledger's
minimum source revision without lowering any prior floor. The inventory read works
with an empty or partially recovered cache; it does not declare that cache ready.
The ledger then refuses a broker below that minimum before replaying source data.
Await `start()` after history recovery and before admitting commands. Call `check()`
from the owner's health path. Await `close()` before closing history. Shutdown
joins the original startup, timer work and active export or restore sample; caller
cancellation does not abandon those jobs.

Startup and every backup tick compare recovered history with the greatest
inventoried cursor, including when recovered history is empty. A lower cursor
returns `owner_recovery_required` before export or sampling. The lifecycle retains
the strongest floor it has observed and rechecks inventory after publication;
an older backup cannot make a rolled-back owner healthy.

The lifecycle checks every 30 seconds, exports when an hourly backup is due, and
advances its schedule only after durable inventory commit. A changed selected key
or a trusted floor above the last backup also requires a fresh generation. It
restores and verifies the inventoried bundle at startup and at least daily while
running. Samples use disposable fenced storage, close their cache and remove local
staging before reporting success. Restart resamples a recent backup without
creating an early duplicate. Missing keys, corrupt bundles, inventory failures and
backward wall-clock movement surface to owner health. The actual receiving service
and installed host still need to supply this lifecycle and its protected paths;
passing these component tests alone does not complete AMUX-48.

Without a history cache, the ledger scans the complete retained chain, bounded by
100,000 records, 64 MiB and a request deadline. Larger owners must pass an
`OwnerHistory` from `state_owner.history` as the ledger's `history` argument. Its
constructor takes a private SQLite path, the binding, and the trusted
`stream_identity`. Keep the cache open for the owner's lifetime and close it during
shutdown. Its record and byte limits must cover every reserved stream slot,
including completion headroom. SQLite file and index overhead also need a local
disk budget. The cache is disposable; the retained broker records remain authority.
With `require_completion_budget=True`, an owner without a cache must also set scan
limits large enough to cover every stream slot. Construction refuses smaller
limits so accepted work cannot lose its completion capacity to a recovery bound.

Call `prepare_history(batch_size=128)` until its result is `ready` before admitting
commands. Each call verifies a bounded page against the broker. An ordinary cache
reopen starts with no verified prefix. Startup checks all SQLite indexes within a
30-second deadline; incomplete checking refuses use. Later checks detect external
database or file changes. Normal reads do not scan the verified prefix again.
Outcome hits reread the exact authoritative record; absence requires a fully
verified, unchanged cache. A snapshot's records are a lazy fixed-prefix sequence,
so consumers must not assume they are a tuple or remain usable after cache closure.

Checkpoint export is synchronous. Keep SQLite reads on the thread that owns the
cache. For event-loop use, await `export_checkpoint_async()` with the same arguments
and return value. It captures a fixed cursor and metadata, then hands at most 32
immutable `StoredRecord` values per page to an owned file worker. Do not pass the
live SQLite-backed sequence directly to `asyncio.to_thread()`. Cancellation stops
new handoffs and joins the original worker and callback cleanup before returning;
keep the cache alive until then. A blocked disk can delay that return. The async
encrypted-backup exporter uses the same handoff and runs each trusted artifact
reader on the caller's event loop, where the host rechecks current access.

`export_checkpoint()` in `state_owner.checkpoints` writes bounded shards containing
every retained record, then publishes a manifest. `load_checkpoint()` requires a
trusted external manifest digest, checks every shard and the complete chain, and
returns a new cache marked `reconciliation_required`. Creation identity and the
strongest supplied revision floor are preserved. Before adopting that verified
prefix, the ledger checks its head against the live broker and then replays only
the suffix. This does not activate a restored broker or authorize effects.

Give every export a fresh manifest generation path. Preserve the completed path,
digest, cursor, binding and stream identity in the host's trusted recovery inventory
before advancing checkpoint cadence. Never overwrite a previous manifest or infer
a trusted digest from an arbitrary directory listing. If inventory publication is
uncertain, retain the generation and reconcile it before reporting completion.

`CheckpointHost` in `state_owner.checkpoint_host` implements that local recovery
inventory. Construct it with the selected checkpoint prefix, exact stream,
`commit_ref`, binding and trusted `stream_identity`; the prefix's parent must
already be a protected private directory. It uses the shared native descriptor
admission policy for the directory, ancestors, inventory and checkpoint files.
The receipt namespace comes from the exact selected commit reference, not a
callback registry. Use the shared `state_owner.checkpoints.CheckpointReceipt`
and pass `host.committed` as the async service callback. Commit validates every
checkpoint shard and retained record with the existing fenced restore validator,
then publishes an immutable, synced receipt and reads it back. Retrying an uncertain
acknowledgement reconciles the same receipt without replacing a generation.
Custody holds a private filesystem lock across verification, publication and
receipt selection. Separate host instances cannot publish against the same old
inventory; contention refuses promptly and requires an explicit retry. The final
scan also refuses to acknowledge a cursor below the greatest retained receipt.
Restore transfers SQLite ownership only after descriptor cleanup succeeds; a
cleanup failure closes the unreturned cache and reports the fixed restore error.

Before owner replay, apply `await host.recovery_identity()` through
`ledger.require_recovery_identity()`. `await host.resolve()` returns only a fully
verified retained receipt. The inventory keeps the greatest observed cursor and
refuses a lower commit or loss of an observed watermark; it never derives trust
from checkpoint exports without receipts. A fresh host still needs its enrolled
floor and protected inventory: loss of both cannot be detected from export files.
`host.restore(history_path)` synchronously creates a fenced cache on the calling
thread, which owns its SQLite handle and close. Adoption still requires the live
source check and external reconciliation. No service should start with an
arbitrary callable substituted for this selected custody mechanism.

Full verification temporarily needs a disposable SQLite cache and disk headroom
for the checkpoint's complete retained history. Filesystem custody is local and
unencrypted. It does not satisfy the separate encrypted backup, off-volume loss,
application-wide consistency, or measured RPO/RTO requirements. No receipt permits
source deletion, compaction or restored effects. Async custody calls join their
original file worker before returning cancellation.

`CheckpointCadence` reports when 10,000 new records or 15 minutes of dirty history
require a checkpoint. The host must drive its timer and record completion only
after durable manifest publication. Shards hold at most 64 MiB, the manifest at
most 512 KiB, and caches support at most one million records with an explicit byte
limit. Capacity failure refuses admission without deleting outcomes. These finite
limits need deployment sizing; neither checkpoint format enables compaction.

## Compatibility and checks

`ConfigurationOwner` in `state_owner.configuration` authenticates signed
`configuration-read`, `configuration-set` and `configuration-watch` commands for
one enrolled configuration aggregate and admitted package pin and instance. Set validates the
supplied bytes against the host's admitted package schemas, then commits payload,
package pin, revision, secret references, provenance and outcome in one owner
record. Read never falls back to a cached value. Watch uses notifications only
to reread retained authority and drains its subscription before final authorization
and signing. Quiet watch timeout means unavailable, not unchanged.
Once watch cleanup starts, reads and new watches remain unavailable until that
original subscription joins. Failed cleanup retains the same watch for retry;
healthy open watches do not block concurrent reads or watches.
The server bounds watch lifetime by the authenticated request deadline and its
five-second local maximum. Confirmed local commits wake local watches even when
the service connection disables core echo, including exact retries after a
committed write loses its caller. Those watches still reread the ledger.

Native watches also reserve an entry before authorization awaits. The separate
`configuration-watch-close` control binds the complete original signed request
digest, operation, cancellation reference, full owner, configuration reference,
profile, Hub and authority. Only the original admitted host transport key can
close that entry. Close can work after read authority expires or is revoked;
it returns no configuration and cannot allocate another watch. It joins the
original handler, subscription allocation, drain, callback worker and any reply
delivery before signing `joined: true`. Unknown or unadmitted requests cannot
establish a successful join. Repeated original requests never allocate twice.

The host retains the first verified joined response and sends its exact bytes in
`joinedResponseBytes` on a fresh signed close. A fresh reply with
`receiptConfirmed: true` acknowledges that receipt. The owner reclaims only
confirmed, joined entries after the original signed request deadline. Expired
original requests are refused before allocation. This permits continued polling
without a lifetime limit of 1024 watches, while unresolved or unconfirmed entries
remain retained within the bounded table. Cleanup requests have separate bounded
capacity from ordinary reads and their replies.

A lost first reply uses the retained entry. A lost receipt acknowledgement can
be recovered after reclamation using the original signed proof and a fresh
signature from its bound host key. Historical proof expiry is not fresh read
authority. The owner verifies its service signature through the exact trusted
authority record and key validity at issuance, then checks current signing
authority again before replying. Missing trusted history or an unavailable
selected signer refuses acknowledgement; the caller keeps its unresolved owner.
Neither a restart nor request expiry proves that resources joined. The Go caller
pins one service signer and does not follow an arbitrary replacement issuer.

Before allocating a native watch, both receivers check that conservative
canonical cleanup frames fit the wire limits: 12288 raw proof bytes, 16384 base64
proof characters and 65536 control bytes. A schema-valid owner whose full binding
cannot fit is refused before subscription allocation. The shared sizing vector
and offline tests cover that boundary. The coordinated close protocol still
needs its foreground live check; local cleanup alone does not qualify it.

Fresh Manager epochs and generations use an explicit new `configuration-set`
record. The current identity ledger must contain one active native activation for
the admitted package and instance, matching the full new owner, host caller,
scope, checksum, next configuration revision and secret references. Current native
lineage and the explicit initialization method grant bound the write and are
checked again before signing success. Revoking the method after request
preparation refuses the receiving write even if ordinary set authority remains.
Read and
watch require the full owner in the retained configuration record. Prior records
keep their original full owners. An old selected owner cannot overwrite a newer
activation. `ConfigurationHost.prepare_initialization()` validates the host's
supplied bytes and returns a payload with the current revision; it grants no
authority and writes nothing. The host must separately authorize activation and
the ordinary configuration write before starting the driver. A concurrent write
or uncertain outcome requires explicit reconciliation of that operation.
Native activation is required by default, including for the exact selected owner
and an empty native-instance inventory. Before signing any read or watch reply,
the source checks the current native owner, lineage, configuration binding and
`native-authority-prepare-configuration-request` grant. Initialization uses its
separate `native-authority-prepare-configuration-initialization` grant. The lower
generic owner API can explicitly select `require_native_activation=False` for
non-native callers; `ConfigurationHost` always requires native activation.

The production configuration host also requires the explicitly enrolled
`ConfigurationEventProducer`. Each set retains one signed `configuration-change`
message envelope in `effects` in the same append as state and outcome. Its closed
payload contains only the configuration reference, full plugin owner, schema
reference and checksum. It contains no configuration bytes or secret references.
The effect digest covers the complete canonical envelope. Retained validation
checks its signature, producer pins and exact relationship to the state and
original set operation. Exact operation replay reads that intent before any
signing call; it never regenerates the event.

The owner reads back the committed operation before publishing the original
event to its exact scoped configuration event subject. Publication checks current
producer authority and the original expiry. Failed or uncertain publication does
not undo the committed configuration; callers must reconcile that original
operation. Original publication tasks remain owned through cancellation and close.
Close joins handed publications and still drains the command subscription if a
publication fails, then reports the uncertainty. It never treats a core publish
as proof that a subscriber accepted delivery.

`ConfigurationHost.events` is a host-private `ConfigurationEventSource` for the
subscription service. `await events.next(cursor)` returns one immutable original
envelope, its next cursor and current producer validity, or `None` when already
at the verified head. It allocates no broker subscription and keeps no private
delivery cursor. The subscription service must independently check consumer
authority, native lifetime and the approved filter before disclosure.
The trusted native provisioner can call `await events.enrollment_pin()` for the
actual configuration reference, schema reference, source digest and creation
identity. The resulting pin grants no access; it supplies the routing values for
explicit native-instance enrollment rather than accepting them from a request.

Cursors bind the enrolled account, domain, stream, exact aggregate route, stream
creation identity and event coverage start through `sourceDigest`, with the
creation timestamp and last delivered sequence. Zero is the initial position for
a source whose coverage starts at revision one. A source adapter cannot be built
from another ledger's route. Caller-owned cursor values are never changed in
place. A missing record, rollback, changed source or future cursor refuses replay.
The first producer coverage defaults to revision one; an explicitly admitted later
start permits older records without events but cannot synthesize historical events.
Startup refuses a source that has not reached the position before that start.

An expired original event returns `configuration_event_resync_required` without
advancing or renewing it. Recovery requires an authorized configuration read and
an explicit new subscription position. This adapter does not qualify replay of
expired historical envelopes or automatically acknowledge delivery.

`ConfigurationHost.subscriptions` serves the signed subscription control protocol
on the existing exact configuration command subject. The receiver distinguishes
controls by their purpose and validates the full control schema and AMUX47
authorization before acting. Normal requests have 32 worker slots; cleanup has a
separate 32-slot limit so occupied read/reply workers cannot block their own close.
The service permits at most 32 unjoined allocations and retains at most 1024
original allocation proofs for its process lifetime. Capacity exhaustion refuses
new opens; a deadline never erases a cleanup proof or establishes a join.

Open reserves its original job by `openRequestId` before authorization or watch
allocation can yield. An admitted replay rejoins that same job and lease. Canceling
an open response does not cancel or replace its original watch allocation.
Expiry monitoring starts at admission, before watch startup. Failed admitted
startup starts cleanup immediately; pending subscribe and flush work remains
owned until its original allocation and callback resources join.
Next
requires current original subscription and native authority, the actual source
route, and a cursor already held or offered by this allocation. A new signed next
may acknowledge the last offered cursor; admission is checked again against local
cursor and in-flight work after authorization returns. A busy older request cannot
roll back a newer acknowledgment. Preparing a response alone never advances
the consumer's position. The service rechecks subscriber and producer authority
from the final signer snapshot before exposing the original event.

Close authenticates against the original allocation's pinned host key, including
after read authority expires or is revoked. It cannot read events. It echoes the
consumer's supplied verified cursor, cancels and joins the original next job,
drains and joins the exact watch and callback worker, and waits for original
open/next reply workers before signing `joined: true`. Pending cleanup may return
`joined: false`; failed cleanup remains on the same allocation for explicit retry.
Unknown allocations cannot authorize cleanup or report a successful join. The
response uses the current service signer view independently of subscriber grants.

Allocation proofs are process-owned resources, not durable business outcomes.
They survive authority expiry but are not restored across a service restart.
An unknown allocation after restart remains refused until the caller establishes
recovery through its owning transport and lifetime. These offline checks do not
qualify native delivery, long-running capacity or recovery after process loss.

`ConfigurationHost.from_enrolled_host()` attaches indexed recovery, concrete
checkpoint custody and the existing encrypted backup lifecycle. It applies both
trusted recovery floors before replay, validates backup custody before opening
commands, and owns its original timers, requests, subscriptions and file workers
through close. Supply the selected reply prefix without a trailing dot, the exact
plugin owner, admitted schema resources, signer, history and custody objects.
The installed caller retains the borrowed connection and cache until `done` is set.
An unsuccessful close retains the original jobs for another join attempt.
The application service host activates an explicitly selected configuration source
after identity, includes it in health checks, and joins its retained close before
releasing borrowed resources. It does not invent a binding for a fresh Manager
epoch/generation or relabel retained records from a previous owner.

The native host selection now requires explicit `subscriptionRoutes` containing
the binding ID, exact source pin, service signer binding and scope. The launcher
matches that route against one admitted activation declaration and constructs the
Go subscription owner with the selected command transport. The source pin comes
from `events.enrollment_pin()` on the actual selected ledger, account and domain;
the launcher does not infer it from configuration routes. This wiring still needs
live delivery and cleanup qualification with the Python source service. Schema
inputs must come from admitted package resources; accepting caller-selected
schemas would defeat validation.
The current Python validator is not a CPU sandbox for administrator-authored schemas.
These local checks do not qualify every package schema, off-volume backup,
application-wide restore consistency, or recovery-time objectives.

No legacy writer or reader is changed. HUB-03, HUB-14 and DASH-02 integration still
requires exact ID/relationship/audit/quarantine/outbox preservation, repeatable
imports, route parity, explicit writer fencing and tested reverse migration after
new writes. Definition uniqueness belongs in one owner aggregate/key strategy;
KV names must not become another authority. A file projection follows committed
intent and remains recoverable; it is not atomic with the owner append.

Run focused offline checks with the prepared Python environment and
`PYTHONPATH=sdk/python:.`:

```sh
python -m unittest state_owner.test_ledger state_owner.test_retention state_owner.test_completion_reserve state_owner.test_views state_owner.test_artifacts state_owner.test_recovery state_owner.test_history state_owner.test_checkpoints state_owner.test_checkpoint_host state_owner.test_async_checkpoint state_owner.test_indexed_ledger state_owner.test_backup state_owner.test_backup_host state_owner.test_backup_lifecycle
```

Only during a coordinated live slot, set `AMX_STATE_OWNER_LIVE=1` and
`AGENTMUX_STORAGE_SERVER` to the prepared native NATS 2.15.0 executable, then run:

```sh
python -m unittest state_owner.test_live -v
```

The live checks reuse `tests.storage.run.Broker`. They test a real local file-backed
stream, competing commits, suppressed acknowledgment/restart/replay, changed-content
refusal, fixed reserve headroom, scoped storage permission refusals, recreation
refusal, KV corruption/rebuild, artifact bytes and fenced checkpoint readback.
The indexed checks cover checkpoint-prefix adoption, suffix replay after an actual
restart and lost acknowledgment, corrupt cache refusal, stream recreation,
authorization expiry, and separate catalog/target versions. Offline growth tests
also retain more than 64 MiB of history and append a completion beyond that bound.
They do not qualify application enrollment, multi-host durability, the complete
permission matrix, full disk exhaustion, actual legacy migration or route parity.

The implementation uses ordinary Python modules and the existing contract SDK.
The retained outcome check follows the plugin's
[Idempotent Receiver](https://www.enterpriseintegrationpatterns.com/patterns/messaging/IdempotentReceiver.html)
guidance: commit identity and business state together before reporting success.
That does not establish exactly-once external effects. The extra retained history
cost is necessary for retries beyond the broker's deduplication window.

`TaskService` accepts signed `task-inspect` and `task-reserve` requests through the
selected task command subject. Reserve authenticates the possession proof and
current direct authority before reading the task for preparation, then uses the
same admitted identity reader and ingress for the operation. Replies bind the
full signed request, private reply subject, selected service signer and exact
source pin. A committed reservation retains its embedded business grant and
unstarted delegation offer; this service does not deliver or execute the offer.

The 65,536-byte owner record limit remains unchanged. Base64 encoding needs at
most 87,384 bytes; the signed reply allows another 8,192 bytes of metadata, for a
95,576-byte frame limit. Startup checks the negotiated broker limit. The task
credential permits one response within eight seconds, and the original callback
deadline includes handling, publication and flush. Cleanup retains any reply
already handed to the transport until its original work finishes or times out.

`TaskHost` requires an existing enrolled task, indexed history, checkpoint custody
and encrypted backup custody before opening commands. It refreshes committed
history before backup, including a commit whose reply was lost. Imported artifact
references require an explicitly selected retrieval provider; without it the host
refuses such a backup instead of omitting artifact bytes. The optional application host
uses its actual shared identity reader and ingress, includes task health, and
joins task cleanup before closing borrowed history or connections. Offline tests
do not qualify live broker permissions, receiver delivery, legacy migration or
application-wide recovery objectives.

`capture_tasks()` uses the actual legacy Store's online SQLite backup on its
existing writer thread, outside a transaction. It publishes a private, unique
snapshot only after read-only validation, with no replacement or pruning of a
completed capture. `TaskMigrationSnapshot` checks the supplied source identity,
database digest, schema version, integrity and foreign keys. It preserves the
complete captured database, including other owners' tables, while task readback
returns exact work columns, ordered work events and resource claims. JSON text,
null values, original W IDs, parent IDs and federation flags remain unchanged.
Readback does not run migrations, expire leases, stage messages or dispatch effects.
The supplied application version stays in each task's source evidence. Capturing
hub.db does not capture external files, other authoritative stores or the whole
platform; it does not fence the legacy writer.

`prepare_task_import()` binds one actual captured row to an explicit target task
and source repository. Deterministic target and import IDs include the target hub,
task domain, scope, stable source owner and original work ID. Capture revision,
time and digest do not change that logical identity. The nullable `parentTaskId`
maps identity only; it does not assert that a parent has been imported or confer
permission over it. Cross-repository parents require an explicit scope mapping and
currently refuse import. The original parent ID remains in source evidence.

`TaskImporter` requires a current direct `task-import` grant for the exact target.
An inspect, reserve or old source approval cannot supply that permission. The
owner compares the signed payload with its actual selected private capture, then
conditionally appends at target version zero. A retry returns the original record;
a changed capture under the same logical import identity conflicts. The target
retains the full source row, events, claims, schema/application versions, capture
digest and source owner, plus the current import authority reference. It does not
create historical grants, execution attempts or delegation IDs.

An imported task has status `reconciliation_required`, with unknown modern
`assignmentEpoch` and `reservation` represented by null. Only the validated import
record can use that representation. Its original legacy state and unresolved
claims remain intact inside source evidence; null does not release them. Task
inspection may return that record, while reservation explicitly refuses it. No
outgoing effects are created. Reconciliation, writer transfer and reverse migration
remain unimplemented and unqualified. A source or resulting record beyond 64 KiB
requires scoped artifact ownership; import currently refuses it while retaining
the complete private capture. This owner path has offline integration coverage;
it is not exposed by the existing task transport or selected application host.

Before any target append, import applies the existing federation protected-content
patterns from `hub.fed.redact`. If that policy would block or alter a source string,
the entire import refuses with a fixed diagnostic. It never silently redacts the
legacy evidence. JSON stored in text columns is decoded for the same pattern
checks, including escaped and duplicate-key values. The private capture remains
unchanged. This is the accepted pattern policy, with its documented detection
limits; it is not a classifier for arbitrary private model reasoning. The task
source includes work rows, work audit events and claims, not conversation
transcripts, model trace data or reasoning artifacts. Ordinary task text is not
classified as private reasoning merely because it is free text.
JSON inspection includes decoded keys and every duplicate-key value. Numeric
literals stay text during inspection, avoiding integer-conversion limits that
could otherwise skip a protected string. Traversal is iterative and refuses with
a fixed diagnostic beyond 128 inspection levels or 65,536 inspected values.
Parser resource failures also refuse; they do not turn structured data into an
unchecked ordinary string. These limits leave the private capture intact.

`TaskArtifactCustody` supplies the optional read-only task artifact backup path.
The protected `task.artifacts` selection pins `bucket`, `storeRef`, `maxBytes` and
`reader` (`transportRef`, `grantRef`, optional `approvalsByOperation`). The actual
Object Store metadata reader and chunk reader must share the same original
JetStream context, selected task connection and domain. Omitting this selection
keeps the no-artifact behavior; references without a selected resolver refuse
artifact-backed startup rather than disappear from the backup.

The reader needs an explicitly enrolled service identity and a current direct
`task-artifact-backup-read` grant for the exact task and scope. Its transport uses
the shared identity ingress issuer, the selected task service identity and the
selected task signing public key. The task issuer's identity, instance, key and
active status are checked separately. Configuration does not issue these grants
or enroll the transport. `task-inspect`, a historical task actor and possession of
an artifact digest do not supply maintenance permission.

Each maintenance payload binds `taskId`, the complete `artifactRef` and
`sourceRevision`, meaning the verified retained task-history prefix watermark.
Only references actually present in that prefix are eligible. The deterministic
`task_artifact_backup_operation_id(binding, payload)` lets protected selection
name exact approved operations. `approvalsByOperation` maps that ID to explicitly
selected approval references; common current approval rules still apply. Missing
approvals for a review-required grant refuse. No approval is inferred or created.

The provider checks selected signer and read authority against the same actual
current identity snapshot before and after bytes retrieval. The original deadline
and any shorter current authority bound the read. The final check follows the
last source-ledger await; revocation cannot be hidden between those lookups.
The existing Object Store helper verifies version, metadata, size, chunks and
digest. Credentials add only INFO/MSG.GET for the selected object stream, retaining
existing task-ledger and private-inbox permissions. No object publication,
deletions, consumers, management access or public retrieval route is added.

The existing encrypted backup includes all retained artifact versions and its
fenced restore verifies their exact bytes alongside owner history. Missing,
replaced, corrupt or withdrawn-access data refuses completion and readiness;
no partial backup gets an accepted custody receipt. The task-specific lifecycle
retains exact jobs through prefix refresh, export, cancellation and cleanup.
Joined startup/loop failures stay in their original tasks for inspection; closing
resources does not turn those failures into backup success. Borrowed identity,
history and connections remain owned until cleanup joins. These changes do not
activate imported tasks, add large-source import, collect orphan objects or
qualify application-wide restore, independent-host durability or recovery targets.

`FederationArchiveSource` borrows an actual admitted `TaskMigrationSnapshot` and
the source organization selected by the protected host. The host keeps that
snapshot open and serializes its reads until the importer finishes. The wrapper
never opens its pathname again. `federation_archive_identity` derives the archive
and import operation IDs from the stable source owner and exact target scope;
capture revision, digest and time remain provenance rather than new identities.
`prepare_federation_import` reads all five legacy federation tables and constructs
the closed `federation-ledger-import` payload. Rows retain raw columns, JSON text,
nulls and typed primary keys. Outbox and audit rows retain sequence order; other
families use binary primary-key order without inventing historical order.

`FederationArchiveImporter` requires the actual retained identity reader and a
`federation-archive` OwnerLedger with completion budgeting enabled. The signed
command must pass shared enrolled ingress and current direct human or service
authority for the exact archive and organization-only scope. Project and
workspace must be null; null does not grant access to projects. The selected
source organization must match that scope. Task grants, captured actors and
enrollment records grant no archive authority. The operation has no task, run,
attempt or delegation lineage. Authority is checked before private source reads,
again before conditional append and after commit or replay before returning data.

One initial owner record contains the complete source manifest, all five family
counts and rows, member identities, provenance and outcome. Identical retries
return the retained record; changed captures conflict under the same logical
identity. Empty or absent older-schema families remain explicit. No partial
archive is appended. The complete record must fit the existing 65,536-byte limit.
Each family has at most 1,024 rows. The shared synchronous source-read budget is
10,000 SQLite instructions and one second across all families, with bounded
counts before sorting. The wrapper restores the private connection's prior row
length limit and clears its temporary progress callback on success or refusal.
The accepted protected-material checks refuse evidence rather than redact it;
all refusals retain the private capture and use fixed diagnostics.

The archive stays `reconciliation_required` with writer transfer required and no
effects or artifacts. Import never dispatches pending work, revives withdrawn
work, releases quarantine or adopts historical policy or enrollment as current
authority. Historical holding policy absent from the source remains explicitly
unknown and requires revalidation; any raw captured policy evidence stays intact.
The existing SQLite runtime, work v3 subjects and consumers remain unchanged.
Larger artifact imports, runtime activation, writer transfer, reverse migration
and full application recovery remain separate requirements in
[AMUX-48](https://adag-csai.atlassian.net/browse/AMUX-48).
