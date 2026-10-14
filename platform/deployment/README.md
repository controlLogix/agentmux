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

Native Linux execution in WSL qualifies that environment only. Actual native
macOS and Linux gate runs, private installed profile/volume checks, complete
launcher lifecycle integration, and business-store obligations remain required.
