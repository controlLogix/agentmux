# Credentials for one approved task

`execution_owner.task_credentials.TaskCredentialOwner` is a host-owned boundary for the fixed assigned-task read consumer. Plugins do not receive this owner, an account issuer, a broker client, a signing callback or a general secret resolver. The process capability composes it with the approved execution plan and retained container intent.

The host selects the exact account, TLS endpoint, server name, certificate pin, reply prefix, consumer and identity issuer in `TaskCredentialPolicy`. The endpoint is the consumer's host-owned broker connection. It does not give the task container a network route or change the approved HTTPS egress profile. The public destination reference is the approved consumer reference; the approved network and workspace references remain bound independently.

## Preparation and delivery

1. The host supplies a current signed `task-credential-prepare` service command, the exact `ExecutionAdmission`, a fresh signed task inspection and a separately signed application-account resolution request. The selected service owner must differ from the task worker and consumer.
2. Preparation checks the original approval and current account, worker grant, issuer and consumer. It derives one short-lived NATS user credential. Permissions contain one literal command subject and one literal reply subject, with finite subscription, frame and byte limits. Its expiry cannot exceed the original admission, current account and worker authority or the selected maximum of 30 seconds.
3. The derived user seed and JWT are retained in a separate private immutable generation. Account issuer and administrator keys stay in the existing account custody. Preparation returns public metadata and an enrollment possession proof. A current organization administrator must enroll that exact worker transport through the existing identity owner. Preparation cannot grant or enroll itself.
4. The signed `task-credential-deliver` command retains a private original delivery claim and a public delivery intent before invoking B's exact prepared container channel. B writes `/run/agentmux/credential` once, before starting the task recipe. Credential material never enters public state, environment maps or output.
5. A separately signed `task-credential-observe` command records acknowledged delivery or uncertainty. Its service permission can retain an observed outcome after the original human permission expires. It cannot authorize a new delivery or task read.

Each phase command uses a separate operation ID and the current credential ledger version. The credential reference identifies the immutable approved generation at revision 1; it is not the credential ledger's changing version. Public records contain closed references, bounds and public keys only.

## Fixed consumer

`inspect_task` accepts the retained signed delivery command as current service permission. It rechecks the exact original run, account generation, worker enrollment, task grant and consumer before use and disclosure. It opens one selected TLS connection for the fixed consumer and one for its task user. Reconnect is disabled.

The task user authenticates with the derived credential. Its broker nonce and exact assigned-task read proof are signed by the fixed `PROOF` program inside the same verified container. The host passes the worker JWT to its paired connection but does not sign those live challenges with a host copy of the worker seed. The fixed program cannot sign another operation, task, reply, grant, generation or purpose.

The consumer accepts only the exact signed task-inspect request and invokes the real `TaskService`. It checks the signed reply against the selected service identity, issuer, instance, retained task source and revision. The public result contains task/run/generation/consumer references, never the task body or credential.

The consumer uses a separately selected service ingress. The original human's terminal session remains enforced by A's selected ingress; this does not add a terminal-session exemption or widen organization-administrator permissions.

## Rotation, offline use and recovery

Rotation requires a newly approved immutable plan/profile credential reference, a new original run and a newly enrolled worker transport. It does not replace the private file in an existing container. Stop and join users of the old generation, confirm its exact physical container is terminal, revoke its transport through the identity owner, and retire it before transferring ownership to the replacement. A retired owner cannot prepare or use that generation again. Any issued broker credential remains time-limited; local retirement alone is not a claim that the broker revoked it.

New private resolution, connection, proof and task reads require current retained authority. An offline authority source refuses them. Already issued credentials retain their original finite expiry; neither account-service completion nor a refreshed inspection extends it. Container stop and reservation release are separate operations.

Cancellation of an observer does not cancel or replace the owned preparation, delivery, proof or cleanup original. A private delivery claim prevents repetition even when acknowledgement or the public append is uncertain. Recovery may observe and retire the original; it cannot assume a second delivery is safe. A durable acknowledgement confirms only that private delivery was observed, not that the task recipe started, finished or stopped.

A rejected or unconfirmed public intent save can leave public state prepared with an immutable private delivery claim. Current service retirement may validate that exact claim, including its original operation, generation, run and physical resource, then require B to confirm that same resource terminal. Running, pending, unknown, missing or replaced resources and unjoined users still refuse. Retirement preserves the claim and private generation; it does not authorize another delivery.

The owner retains exact handler, subscription, proof and connection handles until cleanup joins them. A failed unsubscribe cannot skip the other joins. Unresolved cleanup returns a fixed pending error and retains ownership. Retirement requires joined users and the exact terminal B resource; it never releases task reservations or removes another generation. Immutable private files remain protected for recovery and retention.

C does not own general scheduling, arbitrary execution, Docker lifecycle, workspace allocation, native settings or the durable task execution journal. A owns approved plan admission, B owns the physical private channel and container lifecycle, and D composes the retained business execution.
