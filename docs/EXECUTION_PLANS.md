# Approved execution plans

`execution_owner.plans.ExecutionPlanOwner` enrolls immutable execution metadata
and checks current permission to start one task. It does not launch a process,
resolve a credential or prove that an old process stopped. The container adapter,
private credential delivery and retained physical execution owner remain separate
owners under AMUX-690, AMUX-691 and AMUX-688. Native plugin routing remains AMUX-288.

The host selects one actual `LedgerAuthorityReader`, `OwnerLedger`, `TaskOwner`,
`EnrolledIngress`, executor reference, enrollment administrator and exact profile.
Request data cannot replace these objects or select a verifier, raw service,
callback, process adapter or credential resolver. The plan ledger uses domain
`execution-plans`, kind `approved-execution-plan`, the selected plan ID and exact
scope, with the existing completion budget and retained stream identity checks.

## Enrollment and immutable revisions

The closed `execution-plan-enroll` request contains a complete plan and the
previous owner revision, or null for the first revision. `execution-plan-read`
and `execution-plan-revoke` take only `planRef`. All three are signed commands
for `process-owner`. Existing current identity, exact grants, scope membership,
hard denial and exact approval semantics apply. A review-required grant needs
its current approval bound to the exact content, operation ID, expected version,
audience and approver authority. Human calls also use the selected terminal gate.

Only the host-selected administrator may enroll or revoke; it must differ from
the reserved task actor. Plugins cannot enroll plans. Enrollment inspects the
actual current task through a signed `task-inspect` request. The reservation,
attempt, assignment epoch, input, repository revision, delegation and execution
grant must match exactly. The original task requester's identity, membership,
reservation grant and any required exact approval must still be current.
Embedded execution-grant metadata alone supplies no continuing permission.

Enrollment appends through the existing conditional retained ledger. It preserves
the original signed operation and verifies its payload digest against the stored
plan and previous revision when reading history. Lost acknowledgment is uncertain;
retry the exact original to discover its retained result. Changing approved
content requires a new revision. Reads can return an immutable older definition
marked `superseded`; revoked definitions remain available to an authorized reader.
A view is observed metadata, never execution authority.

## Approved initial profile

The profile pins a `linux/arm64` image by SHA-256 digest and one
`python-script-v1` recipe: a relative script path and content digest. Dot and
parent path segments refuse. This finite initial recipe has no shell, arbitrary
arguments, environment variables, host working directory or mount requests.

The only working directory is `/workspace`, bound to the selected assigned
workspace reference. Worker and credential-consumer identities are fixed current
service references with exact scoped membership. Credential and network policy
references contain no credential material. Network mode is `none` or
`scoped-egress` with one to eight fixed destination references. The physical
adapter must enforce the selected policy; accepting metadata does not establish
network isolation.

The dedicated task container must have a read-only root filesystem, all
capabilities dropped and no privilege escalation. Host home, Docker socket,
host process namespace and privileged operation are forbidden. The worker UID is
positive and non-root, including UID 501; the adapter owns the actual mapping.
Only the assigned workspace may be mounted. No worktree alone counts as isolation.

Limits are finite: one to 3,600 seconds for execution and offline validity,
100 to 8,000 CPU milliseconds, 32 MiB to 8 GiB memory and eight to 256 processes.
Offline validity cannot exceed the execution limit. Initial output policy is
`discard`: untrusted standard output and error are not public receipts or logs.
Later supported workflow expansion requires its own approved profile and owner
integration; this profile does not qualify general allocation or scheduling.

## Prospective original binding

`admit_start` accepts the original signed `capability-process-start` envelope
and a fresh signed inspection request. Its public payload contains only the
selected executor and existing `planRef`. Current capability permission, latest
approved plan, actual task state and task requester authority must all agree.
Original task, run and attempt fields cannot substitute other work. The original
operation is preserved exactly; task delegation is separate binding provenance,
so the existing rule allowing operation delegation only on `task-reserve` stays
intact.

The prospective `runRef` derives from hub, exact scope, executor ID and original
operation ID. Plan or executor revision and changed content cannot choose a new
run namespace. The binding includes the exact original operation and approved
plan/task/attempt references. It allocates no physical run.

AMUX-688 must retain the first binding with its single durable execution intent
before any effect. On every retry or recovery it must pass that stored value as
`retained_binding`; a mismatch refuses. Omitting it is only for evaluating a new
prospective original. A does not provide a second physical effect journal or
claim cross-process deduplication without D's retained original. Do not treat a
newly evaluated binding as permission to replace an existing one.

The run intent uses an `OwnerLedger` bound to domain `execution`, kind `attempt`,
the exact `runRef` ID and scope. Its history sequence is independent of the
original command's executor version. Append with `expected_sequence` for that
history and `expected_target_version` equal to the unchanged original
`expectedVersion`. This closed compatibility form preserves the signed original,
execution binding, state and effects; it supplies no current permission to run.
The usual conditional append, completion reserve and authority deadline checks
still apply. After a lost acknowledgment, reconcile the same original. A replay
returns the retained record rather than accepting newly proposed state. The
container adapter checks that record against the exact binding and original
before using it; AMUX-688 owns the durable intent and later transitions.

`ExecutionAdmission.recheck` uses the exact original and retained binding with a
fresh signed task inspection. Current permission is checked again; its deadline
never extends. Validity is bounded by current original authority, task execution
grant, plan expiry and the profile's offline limit measured from grant issue.
The adapter and credential owner must refresh permission at their own dispatch
and disclosure boundaries. Cancellation or expiry never proves physical stop or
releases an uncertain reservation. The physical execution owner must reconcile
and join its original work.

The plan owner owns and joins only its admission requests. Observer cancellation
does not abandon an accepted owner request. `close` stops admission and joins
those requests; borrowed identity, task owner and ledger resources remain with
their host.

## Verification

`execution_owner.test_plans` checks signed enrollment and actual ingress approval,
immutable history and replay, current authority and read-time revocation,
namespace and original substitutions, stale task bindings, fixed profile closure
and non-root UID 501. `execution_owner.test_plans_live` uses the existing native
TLS/JWT broker fixture with actual identity, task and plan retained owners. It
requires a coordinated `AMX_TASK_LIVE=1` slot on native macOS ARM64 and prepared
NATS tools. It does not exercise a Process plugin receiver, physical isolation or
private credential delivery; those remain required in their owning issues.
