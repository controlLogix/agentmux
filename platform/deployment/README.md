# Local infrastructure health

`BuildLocalConfig` preserves the protected Core NATS accounts and adds file-backed
JetStream plus a separate `HEALTH` account. Its credentials and config bytes are
private. Building bytes does not prove directory ownership, volume ownership,
enrollment, or authorization. The launcher must check those before starting NATS.

`ProvisionAndProbe(ctx, options)` creates only an absent health stream.
`Probe(ctx, options)` requires that stream already exists. Both compare the whole
stream configuration and refuse incompatible state without update or deletion.
They never migrate business stores or restart a broker.

The health stream uses one exact subject, file storage, one replica, limits
retention, discard-old, 128 messages, 64 KiB total, 512 bytes per message, 24-hour
maximum age, and a two-minute duplicate window. Records contain a fixed marker
and a random nonce. This is bounded infrastructure storage, not business storage
policy or a completion reserve. NATS 2.15 adds three known capability/version
metadata fields; comparison accepts only those observed values and rejects other
configuration features. Tests separately deny replica and feature changes.

The caller supplies an explicit local endpoint, health password, logical server
name, exact server version, domain, hub ID and timeout. A single deadline covers
connection, observation, provisioning, write and read, with a maximum of five
seconds and any earlier caller deadline preserved. Each call owns and closes its
connection; reconnect is disabled. Failure codes contain no paths or credentials.

The probe separately checks the logical server name and version from Core NATS
and the domain from `AccountInfo`. The returned `ServerName` is the configured
logical name, not the raw NATS server ID. No ID is silently lowercased. A successful
health probe proves infrastructure access and a persisted write/read; protected
process readiness and application status are separate checks.

NATS maps domain-qualified API subjects to local subjects before checking this
deployment's permissions. The health principal permits both exact spellings of
account INFO and health-stream CREATE/INFO/MSG.GET. It has no update/delete,
wildcard API, system-account or other-stream permission. This behavior was
observed against the prepared NATS 2.15 broker and is also described in the
[upstream issue](https://github.com/nats-io/nats-server/issues/6902).

Tests launch only the explicitly supplied disposable broker binary, in private
temporary directories. They use real NATS for cold/repeated/warm operation,
actual restart retention, incompatible stream refusal, denied access, wrong
identity, partial provisioning, total deadlines and owned connection cleanup.
Test-only loopback monitoring retains only connection counts in assertions.

Native Linux execution in WSL covers that environment only. The current beta
requires actual native macOS ARM64 installed profile and volume checks and
complete launcher lifecycle integration. Business-store obligations remain
with their owning Jira issues; these storage tests do not satisfy them.

## Existing federation layout

`hub.fed.admin.provision` keeps the HUB-15 stream and bucket names and policies
from `hub.fed.conn`. It reads every existing resource before creating missing
resources. A mismatch in stream subjects, retention, storage, replicas, age,
duplicate window or discard policy requires a reviewed migration. KV subjects,
retention, storage, replicas, history, TTL and discard policy are also checked.
Provisioning never updates or deletes existing resources. An authorization or
transport failure does not count as a missing bucket.

The operation has a 30-second deadline and a separate close budget of at most
five seconds. Cancellation still closes its owned connection. A failed close
is reported as `ProvisionCleanupFailure`; it does not count as successful
provisioning. That error retains the exact client, the one pending close task,
the original operation failure or cancellation, and cleanup causes. Python API
callers must keep the event loop and this error alive and await its bounded
`retry_close()` before retrying provisioning. A close timeout leaves the owned
close task running; retry waits for that same attempt. A completed failed close
remains a failure: a second no-op close cannot prove that the original cleanup
completed. Error attributes and causes are private; do not log or serialize them.
The CLI prints only the safe failure message.

The shared federation connection wrapper keeps its call interface and establishes
an initial connection within five seconds, including reconnect-enabled callers.
Established reconnect behavior remains separate. Failed initial connections keep
their actual client until cleanup finishes. The runtime retains that cleanup owner
and cannot reconnect while cleanup is unresolved. Established paired clients also
retain their exact close task through the public close call and runtime shutdown;
a completed failed close cannot become a successful no-op retry.

The pinned nats-py 2.16.0 TCP adapter uses Python's paired stream TLS upgrade so
a rejected certificate still closes the actual writer and its matching protocol.
It keeps the configured CA, hostname and handshake deadline; it does not change
TLS verification or permit plaintext fallback. The adapter is local to each
client. It does not patch the installed dependency or other clients.
Python can repeat the original handshake or network error when waiting for a
closed connection. The adapter accepts that repeated error only after checking
the exact paired protocol and original socket have finished closing. A separate
close error, cancellation or unfinished close remains a cleanup failure. Native
checks cover this behavior with CPython 3.14.8, including plain and TLS resets.
When the endpoint requests TLS or a custom CA is configured, the adapter refuses
a plaintext INFO response that does not require TLS. It sends no credential
CONNECT before a verified handshake, including during reconnect. Before replacing
a failed reconnect transport, it joins that exact prior writer's close task.
If provisioning stops partway through,
keep the created resources and rerun against the same account and store. The
next attempt checks their policies and creates only resources that are absent.
A policy mismatch leaves data in place and requires an administrator to review
migration and recovery before changing it. A final read checks every policy after creation, so a changed policy or a
conflicting create cannot silently count as success. The preflight and final
read are not a transaction or an exclusive administration lock; changes after
those observations remain an operator coordination concern.

`hub.tests.test_fed_provision` covers policy comparison and has disposable live
checks for repeated provisioning, retained messages/consumers/KV revisions,
mismatch refusal and interruption recovery. Those live checks require the
pinned federation Python dependencies and a native broker through `NATS_SERVER`
or `PATH`. Additional checks use NSC 2.15.0 and an owned operator-mode broker
for custom CA acceptance, wrong CA and endpoint refusal, missing credentials,
denied storage creation, system-account updates and revoked provisioners.
They do not qualify team replicas or the installed Compose path.

`hub.fed.admin.push` uses the enrolled system-account credentials to send an
account JWT. Live updates require a writable account resolver; a memory resolver
does not provide that update endpoint. The command bounds the update and owned
connection cleanup, rejects malformed/refused responses and never prints broker
response text or the JWT. Success prints `{"updated": true}`. The Python API
keeps its existing successful response object. Existing deployment scripts stay
available; changing a resolver or storage policy requires explicit administration.
