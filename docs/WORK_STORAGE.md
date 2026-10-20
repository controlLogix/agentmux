# Selected Work storage

An explicitly selected Work owner keeps existing Work records in their original
Hub database. Plugins use the same `StorageHandle` interface as private plugin
storage: read, prepare and compare-and-swap, and reconcile an original mutation.
The Work owner interprets a fixed set of domain commands. This does not give a
plugin a database connection, arbitrary SQL, another plugin's private storage,
or permission to choose an unrestricted callback.

## Selection and authority

The enrolled Hub entry point accepts explicit `--work-selection` paths alongside
its identity selections. Each file selects an enrolled Work client; it does not
create an identity or infer permission from a repository name. The selections
must belong to the same Hub. The entry point retains their original sessions
until the Hub exits and joins their cleanup.

The storage host selects the original database, repository channels, current
identity authority and receiving credentials. The Hub verifies that its opened
database and the owner refer to that same physical source before enabling
maintenance. Separate owned connections to the same selected file are supported.
An unrelated database, replaced file or changed source binding is refused rather
than copied or silently selected.

A named local repository does not need to be shared or have federation enabled.
Federated commands additionally require the repository's configured sharing and
peer policy. A global read channel does not authorize mutations in named
repositories. User, service, project and organization grants remain distinct;
an operator acting for an agent must use the explicit checked target rather than
borrow the agent's credential. Child grants can only narrow the parent's access.

## Preserved callers

| Caller | Selected route and retained behavior |
| --- | --- |
| Local Hub Work verbs | Signed create, claim, heartbeat, release, cancel and path-claim commands; scoped reads retain the actual caller and target generation. |
| Federated Work plugin | Fixed offer, receive, claim, grant, result, staged-result and revoke commands; original protocol hashes, quarantine and privileged approval remain required. |
| Registration and maintenance | Fixed registration, observed-state and global lease-sweep batches; original agent, delivery, team, claim, event and Work changes keep their transaction boundary. |
| Older core-NATS Work/result bridge | Protected authenticated ingress and retained outbox owners; configured mode must prove its current selected transport before activation. |
| Completed Work capture | Knowledge receives the exact committed original Work receipt and raw result evidence; required capture must finish before successful completion is disclosed. |

The selected older bridge excludes its raw Work/result mutation callbacks and
subscriptions. Its ordinary message behavior remains available. Supported
unselected compatibility routes retain their existing handlers. A missing
protected route cannot silently fall back to an unprotected Work mutation.

The Work owner retains existing IDs, result content, relationships and event
provenance. Lifecycle batches preserve global atomicity across their declared
repositories. The original transaction also retains required outbox obligations;
a returned transport response alone does not prove those obligations completed.

## Retry and recovery

The CLI accepts `--operation-id ID` for `claim`, `done`, `fail`, `return`,
`block`, `heartbeat`, `work add` and `work cancel`. It retains one ID for
its retry. If it reports an unresolved operation, repeat the original command
with that ID and the same arguments and caller. Do not use a new ID merely
because a response was lost. Changed input cannot recover the original attempt.

The owner retains the operation ID, payload digest and exact outcome. A fresh
authorized outcome query can recover a completed original after response loss
or client reconstruction. A confirmed conflict may lead to a separately
authorized new attempt. An uncertain effect does not authorize repeating it.
Prepared lifecycle work that was never dispatched stays undispatched during
background recovery.

Recovery requires current source custody and permission. It does not renew an
unfinished caller's deadline. The minimum validity of the original aggregate
remains in force through final result use. Spawn and adopt success require a
current check of their original actions; physical launch also checks the original
caller deadline. An unconfirmed original physical termination is retained and
is not automatically repeated.

Background maintenance uses its own task and current service authority. It can
query a submitted original without clearing or extending an interrupted
caller's retained deadline. Cancellation and shutdown join original effects,
subscriptions and readers before releasing borrowed Store or executor resources.
Keep private recovery records and their owning source intact when an outcome
is still uncertain; deleting those records would remove the basis for safe retry.

## Limits

This development target is native macOS ARM64. These routes do not qualify other
platforms or authorize a release. Component tests, adapter reconstruction and
separate broker checks have different boundaries; none alone establishes an
installed deployment or a complete Hub crash-and-restart result. Current combined
qualification and any remaining limitations are recorded in
[AMUX-286](https://adag-csai.atlassian.net/browse/AMUX-286).

See [federation behavior](FEDERATION.md),
[ordinary plugin ownership](ORDINARY_PLUGINS.md) and
[local testing](LOCAL_TESTING.md) for the surrounding contracts and workflow.
