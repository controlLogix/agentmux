# Isolated task containers

AMUX-690 provides the selected Docker task adapter. It consumes an approved
execution plan and fresh admission from AMUX-689 and an existing committed
physical intent from its retained owner. It does not create that journal,
issue credentials, implement the Process plugin receiver or schedule tasks.

The host selects `DockerSelection`, `DockerEngine`, the actual
`WorkspaceCheckoutHost` and a finite `SelectedNetwork`. Request JSON cannot
choose any of these objects or provide Docker flags, executable arguments,
environment variables, mounts, working directories or credential callbacks.
The broker Compose launcher remains a separate owner.

## Selection and dispatch

The selected local Unix endpoint, context, daemon ID/version and content image
ID are explicit. Commands use the exact endpoint, rather than a mutable named
context. Current context/daemon checks refuse a changed selection. The approved
manifest reference must appear in the image's repository digests; its content
ID is separately checked against the selection. The image must already be
cached and be Linux ARM64. The adapter never pulls an image.

`RetainedContainerIntent` borrows the actual run-scoped `OwnerLedger`, with domain
`execution`, kind `attempt` and entity ID equal to `runRef.id`. The first record
preserves the exact original Process.Start operation, `executionBinding` and
`executionPhase: start-intent`. Its fixed `execution-container-prepare` effect
carries that binding and its digest, with query-before-retry recovery. The
accepted common-ledger target-version form preserves the executor revision
separately from this run history's sequence. D owns all writes and transitions.
A later record must retain that same binding; new dispatch requires phase
`start-intent` or `running`. Recovery can also observe `cancel-intent`, `terminal`
or `unknown`. These are native owner interfaces, not public effect authority.

Before each new physical create, supervisor start, task start or private send,
the adapter completes its selected source/runtime observations and refreshes
current exact admission. Recipe reads retain the existing bounded fd-relative
no-symlink walk and digest check. No refresh extends the original deadline.
Separate source owners make no cross-stream atomicity promise; D must still
serialize its own admission and effects. The private network relay refreshes
before an external request and before disclosing its response.

## Physical constraints

One deterministic owned container runs the pinned Python recipe. It mounts only
the assigned workspace at `/workspace`, plus its own private in-memory channel.
It has no IP network route, host home, Docker socket, host PID/IPC namespace,
privileged mode or added capabilities. Its root filesystem is read-only,
privilege escalation is disabled, and worker UID/GID is positive and non-root.
UID 501 is supported with the selected checkout owner's matching UID. Memory,
swap, CPU, process count and execution/offline time are bounded by the profile.
Standard output, standard error and Docker logging are discarded.

The fixed supervisor checks the script digest again inside the container and
holds a prepared stage before task code starts. The owner starts that task once
through the fixed private marker operation. Task code cannot ask the adapter to
run arbitrary commands. Deadline expiry stops the local task container's
supervised process; business reservation release still requires the retained
owner's reconciliation of actual physical state.

## Network and private delivery

`scoped-egress` uses a fixed Unix socket inside the task's private in-memory
filesystem. A retained Docker exec pipe relays bounded requests to the host.
The only request field is `destinationRef`. The host selects the exact HTTPS
host, address, port, GET path and certificate roots for each approved reference.
There is no URL, method, body or header override. Responses are bounded; invalid,
foreign, expired or revoked requests are denied. The relay admits at most 128
requests per physical run. Mode `none` starts no relay. The task still has no
direct network route in either mode.

The separate fixed private delivery operation is bound to the exact prepared
container, run, worker and consumer. It writes at most 16 KiB through standard
input to one exclusive private file, with mode 0600 on the task's in-memory
filesystem. It prints nothing, sends no credential environment map and never
silently overwrites or repeats an uncertain delivery. C must perform credential
approval, scope, generation, custody, expiry and reconciliation checks before
calling it. B's marker-based tests do not qualify real credential delivery.

## Observation and recovery

Native observations expose only run identity, a closed status, optional exit
code and an exact physical resource reference. The latter binds the full
container ID, selected engine/image, run and binding digest. D must retain it.
Every observation or cleanup verifies the actual container's identity and
isolation projection before acting. Malformed projections refuse; an absent or
unreadable container is unknown, not proof that old work stopped.

`prepared`, `running`, `terminal`, `pending` and `unknown` remain distinct. Lost
create/start replies never cause an implicit second mutation. An already-running
container recovered without trustworthy stage knowledge is pending. Recovery
uses the original retained physical reference when available. If a create reply
was lost before the container ID was retained, `recover(intent)` instead looks
up the original deterministic name and verifies its full binding and isolation
against the selected engine and image. It records an ID only after that exact
observation. Missing or invalid resources do not become new memory owners or
authorize creation; absence remains unknown. This route needs no renewed start
admission and cannot start another task or repeat private delivery. Once an ID
has been verified, a replacement ID or changed owner/profile refuses.
Task-writable files are not lasting authority or trusted recovery receipts.

`stop` and `cleanup` act only on the exact owned resource. Cleanup requires a
confirmed stopped/dead container, or a confirmed never-started created container
with no running process, and joins its original host relay and client work first.
It never prunes the engine or removes unrelated containers, networks or volumes.
`close` joins owned work and performs owned stop/cleanup; unresolved cleanup stays
an error with retained resources. `checkpoint` instead joins host clients and
returns exact pending resources for explicit recovery. D must retain their physical
references before transferring ownership. Closing the checkpointed adapter then
joins host work without independently stopping or deleting the transferred
resource. A new recovery owner must retain that exact container identity. This
does not stop the task or release its reservation or credential custody.

## Verification scope

Offline tests use actual signed identity, plan and task owners, the selected
checkout owner and retained intent, with controlled engine boundaries. Real
subprocess tests check complete bounded readers, overflow, timeout and
cancellation joins. The coordinated native Docker suite exercises two current
users/projects, actual VM workspace/process isolation, non-root and resource
controls, fixed private channel, allowed HTTPS relay, denied direct host routes
and foreign destinations, plus lost-create-reply ownership and exact cleanup.
Its authority fixture uses real owner code over the already qualified offline
ledger boundary; it does not claim fresh broker/Process receiver qualification.
No unavailable or skipped native test counts as a pass. C/D and native Process
integration remain separately required.
