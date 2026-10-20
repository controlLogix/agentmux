# Selected artifact reads

The optional `artifact` application selection serves `capability-artifact-read`
through a fixed `artifact-owner` receiver. It contains `receiver` and
`resourceRef`. The reference must name the task selected by `task.ledger`.
The task must already select its artifact bucket, store reference, maximum size
and backup reader configuration. Omitting `artifact` preserves the existing
application selection and starts no artifact capability receiver.

`ArtifactReadHost` borrows that actual `TaskHost.ledger` and the `OwnerArtifacts`
instance held by its task artifact custody. It creates no second ledger, store
or writer. The task's backup grant remains a separate maintenance permission;
plugin reads use the caller's current `capability-artifact-read` permission.
`TaskArtifactCustody.retrieve` is not a plugin authorization path.

The artifact receiver has a distinct pinned broker credential, reply inbox and
signing key. Its broker permissions allow only its scoped command and private
reply inbox, with bounded response permission. It cannot publish ledger or
Object Store API requests itself. Retrieval uses the already selected task
connection and JetStream domain. Credentials and signing files stay outside the
project workspace and cannot alias the other selected services' private files.

A caller supplies the current task reference and artifact digest. The owner
requires exactly one matching reference in that task's retained record. Callers
cannot select an arbitrary bucket, object key, store or version. The existing
artifact owner verifies immutable metadata, chunks, byte count and digest.
Content larger than 45,000 bytes is refused before retrieval; a read is never
silently truncated. Larger artifacts need a separately accepted transfer
contract.

Current authority is checked around retrieval. Changed task revisions, revoked
grants, stale native instances, stopped task owners, substituted stores and
changed connection/domain custody refuse disclosure. Read results contain only
the requested reference and encoded content; logs and errors do not expose
credentials or private transport details.

Cancellation ends the caller's wait while retaining the exact original read.
The artifact receiver joins that read before the application releases the
borrowed task, history or connection. A cleanup timeout retains the original
owner for a later join. Restart reconstructs the receiver from protected
selection and current retained owners; it does not upload, delete or replay an
external effect. Existing artifact IDs, versions and task records remain intact.

Qualification covers native macOS ARM64. The selected application composition
tests use the actual task and artifact owners with controlled broker I/O. The
selected-owner native TLS/JWT test constructs `ArtifactReadHost` and `TaskHost`
from validated protected selection and real Object Store custody. The Go handle
reaches that selected host over the isolated broker, with current authority,
reply-only receiver permissions, unchanged retained data and joined cleanup.
Full `ApplicationServiceHost` startup has separate composition coverage. These
checks do not establish installed application supervision, an upload API,
garbage collection or support on other platforms.
