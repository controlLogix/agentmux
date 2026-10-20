# Client startup and protocol output

Automatic startup through native client hooks is not yet qualified. The native runtime provides the startup owner. Explicitly enrolled startup and MCP paths use the selected runtime; bare legacy clients retain their existing connection. Do not substitute the runtime's NATS endpoint for a legacy connection or advertise lazy MCP startup as application-launch automation.

This guide covers startup behavior. For installation and prerequisite recovery, see [platform installation](PLATFORM_INSTALLATION.md) and [bootstrap recovery](BOOTSTRAP_RECOVERY.md).

## Adapter coordinator

`hub/client_launch_coordinator.py` owns one frontend invocation through AMUX-61's `RuntimeInvocation`. The enrolled startup and MCP entrypoints call `startup(selection_path, managed_worker=...)`. Actual client launch hooks remain unqualified.

The adapter passes an explicitly selected private enrollment file outside the approved workspaces. The file has exactly these fields:

```json
{
  "schemaVersion": "1.0.0",
  "hostPolicy": "/absolute/private/enrolled-host-policy.json",
  "workspaces": ["/absolute/approved/workspace"],
  "instanceId": "selected_instance",
  "profileId": "selected_profile",
  "hubId": "selected_application_hub"
}
```

Setup supplies these approved values independently of the runtime policy being checked. The coordinator never discovers a selection from the current directory or environment. It rejects absent selection, extra or duplicate fields, links, broad permissions, oversized files and selection or policy paths within a workspace. The selection file must be user-owned mode `0600` in a user-owned mode `0700` directory. It traverses held directory descriptors without following links and checks ancestor ownership and write permissions.

POSIX modes alone do not establish native macOS trust. Production entrypoints call the fixed `hub.native_descriptor_admission.check_descriptor(fd, purpose=..., deadline=...)` checker. They import its exact `DescriptorPurpose` enum: `private_ancestor`, `private_directory`, `private_file`, `protected_ancestor` and `protected_executable`. Private directories and files have separate type/mode admission. The checker validates ACL, local-mount and ownership rules on a temporary duplicate and closes only that duplicate. The coordinator continues owning the original descriptor. `AdmissionError` becomes a fixed failure without its metadata or exception text. Production entrypoints accept no injected checker; injection exists only in internal test APIs.

The stable executable is checked as root-owned mode `0555` at its fixed protected path. `admit_runtime` returns a `RetainedRuntime` owner with `path`, `closed`, `recheck(deadline=...)` and `close()`. The coordinator keeps its descriptor through invocation and any pending process or stream cleanup. Immediately before process creation it rechecks native admission and compares the held executable with the current protected path, including inode and change metadata. Replacement or an exhausted deadline prevents spawning. This is protected-path execution, not execution by file descriptor: the trusted administrator remains able to change that path. Uncertain closes remain incomplete without retrying a possibly consumed descriptor.

The managed launch owner supplies an actual boolean worker classification. Workers invoke `status`; ordinary clients invoke `ensure` once. The coordinator allows one second for admission, included in the frontend budget: up to six seconds overall for status or eleven for ensure, followed by up to one second of process cleanup. Descriptor checks receive the admission deadline. These deadlines cannot interrupt an operating-system filesystem call that never returns; the native admission boundary must reject unsupported storage.

The coordinator drains both output pipes, caps stdout at 256 KiB and stderr at 16 KiB, and retains the original child handle. Cancellation, output overflow or timeout stops only that frontend, not the shared host. If bounded cleanup cannot finish, the returned result retains the exact child, reader and stream owners. The installed adapter must retain that result and call `finish_cleanup()` before allowing another attempt; it must not replace or abandon it. A consumed failed close is not retried. No automatic retry is added.

`StartupResult.public` contains a safe projection. `human_summary(result)` returns a single line for the adapter's human channel; neither function writes output. The adapter must use a separate status channel for structured output and keep MCP stdout reserved for JSON-RPC. The full runtime observation is schema-checked, compared with the selected instance/profile, and rejected if stale. Caller identity ownership is labeled `callerIdentityOwnerHubId`; it does not establish the selected application hub. Bootstrap receipts remain progress with unknown identity/readiness. Private paths, raw stderr, display strings and arbitrary errors are excluded.

Application access and dashboard remain unavailable in every coordinator result. The remaining application-owner interface must consume the admitted selection's expected hub, instance, profile and approved release binding, establish authenticated caller scope and readiness on the same connection used for commands, and preserve per-operation authorization. The coordinator does not accept an arbitrary successful callback as this proof. Wire that interface only after its owner supplies the real contract and tests.

## Use the enrolled runtime

The installed runtime accepts an explicit private host policy and approved workspace roots:

```sh
"$runtime" ensure --host-policy "$host_policy" --workspace "$workspace"
"$runtime" status --host-policy "$host_policy" --workspace "$workspace"
"$runtime" doctor --host-policy "$host_policy" --workspace "$workspace"
```

Here, `runtime` is the explicitly installed executable, `host_policy` is the enrolled policy, and `workspace` is an approved absolute path. Repeat `--workspace` for additional approved roots. Keep paths quoted. These commands are operator diagnostics, not proof that a client runs a startup hook.

`ensure` owns startup through the existing native launcher. It validates the enrolled profile, selected Docker context, release, ownership and authenticated readiness. Ordinary startup does not install software, pull images or upgrade a running release. `status` observes the owner without starting it. `doctor` checks prerequisites; its unprobed service fields cannot establish readiness.

An authenticated startup observation and a bootstrap receipt are different results. A receipt can confirm that a request was accepted while current instance state remains unknown. Do not turn that receipt, an open port or a running container into a ready summary. Keep unavailable dashboard access, hub inventory and work counts explicit; do not invent a URL or turn an unknown count into zero.

## Keep startup outside protocol traffic

Client integration must invoke startup once at the host's startup boundary. A managed worker must use status or attach only. A worker marker is a recursion guard, not authorization; the native owner must still enforce enrollment and current authority. Tools must not start a second broker or retry startup on every call.

Interactive output needs one concise summary from the authenticated observation: instance, authorized hub, readiness and dashboard access or its unavailability. A protocol client needs the equivalent structured result through its supported status interface. MCP stdout contains JSON-RPC frames only. Neither startup banners nor private failure details belong there.

The current MCP server rejects malformed request envelopes and tool parameters before calling the hub. It reports fixed errors without echoing exception details. A malformed JSON line does not prevent a later valid request. A frame above 1,048,576 characters receives one error and closes the stream instead of draining an unbounded input. Notifications do not invoke request methods. Managed Claude launches encode the MCP argument array as JSON before shell quoting, preserving checkout paths with spaces, quotes and backslashes.

## Native client launch paths still need qualification

Claude Code uses its `SessionStart` command hook for `startup`, `resume` and
`fork`. The adapter reads the event JSON from stdin and returns Claude's
supported hook JSON on stdout. Its visible `systemMessage` gives the concise
startup result. Its `hookSpecificOutput.additionalContext` carries the same safe
structured status and the selected environment and project display values when
the installed registration supplied them. That context is informational and
does not grant authority.

The installed stable frontend accepts one admitted selection literally:

```sh
"/Library/Application Support/Agentmux/Protected/agentmux-runtime" claude-code-hook --client-installation <installation-id> --selection "/absolute/private/client-selection.json"
```

The fixed native route rechecks the installed package before entering the
packaged adapter. It does not run a checkout interpreter or an arbitrary module.
An existing registered-profile handoff preserves its validated environment and
project display context. Hook input never selects enrollment. A top-level
session uses the existing `ensure` operation. Add the closed
`--managed-worker` flag when Agentmux owns a managed top-level Claude process.
That installed-owner fact is combined with Claude's validated `agent_id`, so
both managed top-level processes and Claude-created subagents use status-only
mode and cannot recursively bootstrap. `clear` and `compact` do not start again.

Each installed client manifest pins the exact stable frontend digest. Installing
a new digest-named foundation or client does not update the fixed stable path.
Replacing that path makes registrations for a different frontend digest fail
closed on their next invocation, even though their client directories remain
installed. Before a permanent replacement, identify every registration that
must keep working and move it through an approved client-registration migration.
Do not describe a content-addressed install as a registration migration.

A bounded qualification may use a reviewed compare-and-replace of the stable
frontend only when no intended client operation is active. Keep a separately
verified selection for the previous frontend. Remove or restore any temporary
hook settings before restoring that frontend, then restore it with a digest
comparison against the qualification frontend. Open handles retain their old
bytes, while new invocations use the current stable path. Existing enrollment,
client directories and data stay in place, but registrations are compatible
only while the stable digest matches their installed client manifest.

The adapter flushes exactly one safe JSON response as soon as bounded startup
returns. It then finishes cleanup on the original owner, even when that final
join must wait beyond the response budget. Catchable TERM, HUP and INT signals
remain recorded while the same cleanup owner finishes; they never start a retry
or replace the child. No diagnostic text is written to protocol stdout.

Claude Code runs `startup` and `resume` hooks in the background while delaying
its first response, and `SessionStart` cannot block the session. A reported
Agentmux failure therefore remains a visible startup status; it is not an
authorization gate. Claude continues a running hook if the user withdraws the
first prompt. The adapter still handles Python interruption by joining the same
startup owner without retrying startup.

The setup and settings task must install the command in Claude's supported
settings scope and preserve unrelated hooks. This slice does not modify user
settings. The actual enabled hook still needs native macOS ARM64 testing at
startup and resume before the path is qualified. See Claude Code's official
[hooks reference](https://code.claude.com/docs/en/hooks).

Codex needs a trusted command hook: installing or enabling a plugin alone does not trust its hooks. Its `SessionStart` output can add model context; that alone does not prove that the user saw the instance summary. See the official [plugin hook documentation](https://developers.openai.com/plugins/build/plugins) and [hook behavior](https://learn.chatgpt.com/docs/hooks).

Pi needs its session event integration and both interactive and structured modes tested. Claude Desktop needs an actual app-launch path or a clearly named installed launcher; starting MCP only when the application first needs a tool is insufficient. Other advertised terminal clients need their real installed launcher path tested. No changes in this slice install hooks or modify real client settings.

Before qualifying any path on native macOS ARM64, provide an isolated enrolled profile, its approved local Docker context, installed release, client version and trusted hook or launcher. Use a coordinated live test slot. Test cold, warm and concurrent launch, another project directory, paths with spaces, owner crash, failed prerequisites, wrong context/user/endpoint/release, expired authentication, reconnect and malformed protocol input. Verify callbacks reach only the selected hub and concurrent sessions keep their own identities.

Close the originating terminal while another session has durable work, then observe the same owner and retained state from that other session. Removing the client integration must preserve unrelated client settings and durable data. An explicit stop must use the authorized drain/reservation path; a hook must never stop the shared owner on exit. Disabling only the affected adapter is the rollback boundary, with alternate CLI access and stored state preserved.

## Explicit command hooks and managed Claude

The CLI now supplies a once-only coordinator entrypoint. Configure a trusted client startup hook with literal arguments:

```sh
agentmux hub startup --selection "/absolute/private/client-selection.json" --output human
```

Human output goes to stderr. Use `--output json` for one structured status on stdout. An ordinary client invokes `ensure`; a managed worker must add `--managed-worker` to use `status`. No environment variable or current directory selects enrollment. Missing selection reports setup required.

For a development protocol client, configure `python3` with the absolute `hub/cli.py` path followed by `mcp --enrolled --selection /absolute/private/client-selection.json`. Add `--managed-worker` for managed workers. The MCP session invokes startup once and exposes `agentmux_startup_status`, plus the fixed integration query below when explicitly enrolled. It reports verified connection binding separately. Bare `mcp` retains its legacy behavior. Installed registration uses the admitted stable runtime rather than this checkout path.

Managed Claude can receive this configuration through `agentmux spawn NAME --cli claude --client-selection /absolute/private/client-selection.json`. This path requires unrestricted posture under the existing sandbox rules. The generated MCP arguments explicitly select worker status mode. Other managed clients reject this option before launch; they still need their own startup-hook integration. This does not qualify MCP connection time as application-launch time.

The command retains its startup result through reporting or the MCP session. On normal exit, it finishes cleanup on the original handles. If a killed child remains unreaped after bounded cleanup, final process exit waits for that same child. Thus the startup status has a bounded response budget, but final exit is not guaranteed within that budget. Uncertain descriptor closes remain incomplete and are never retried by descriptor number. Actual native client qualification and interrupted-session cleanup still require review. Retaining an unreaped original child is intentional; it does not establish a separate product requirement for bounded final process exit.

## Repository profile references

Enrolled startup and MCP accept an explicit `--repository-root` when
`--selection` is absent. An explicit selection always wins without reading repo
configuration. Bare legacy MCP and the named Desktop launcher's explicit
selection behavior are unchanged. The current directory never selects a profile.

The installed public commands use literal installation and repository arguments:

```sh
"/Library/Application Support/Agentmux/Protected/agentmux-runtime" startup --client-installation <installation-id> --repository-root "/absolute/approved/repository" --output json
"/Library/Application Support/Agentmux/Protected/agentmux-runtime" mcp --client-installation <installation-id> --repository-root "/absolute/approved/repository"
```

Add `--managed-worker` for status-only worker startup. The installed admission
retains the protected client through `ExecRepository`; its fixed bootstrap then
enters the repository reader. Explicit `--selection` bypasses that reader,
including validation of an unused repository value.

The selected root's `.agentmux/config.json` contains only:

```json
{"schemaVersion":"1.0.0","profileId":"profile_0123456789abcdef0123456789abcdef"}
```

This is an untrusted reference, not enrollment or authority. The strict reader
rejects extra fields, duplicate keys, links and unsafe file ownership. Missing
or malformed references produce setup required. The client passes only the ID
and explicit repository root to the admitted native runtime's `profile-client`
route by direct process replacement. Native resolution checks existing central
registration and workspace membership, then retains that same resolution through
`ExecClient`. It never prints a private selection path for another process to
reinterpret. Unknown or unapproved profiles return a closed setup-required
diagnostic on stderr without starting a new profile or instance.

Worker classification and structured output use six closed internal operations:
`startup`, `startup-json`, `startup-worker`, `startup-worker-json`, `mcp` and
`mcp-worker`. The final installed client receives an admitted explicit selection;
it does not read the repository reference again. No host credentials, paths,
grants or authorization project IDs come from repo configuration. Environment
and project display metadata remain separate from authorization. The installed
bootstrap can pass a private `RegisteredProfileContext` binding through
`hub.cli.main(..., registered_context=...)`. The existing selection reader
checks its SHA-256 digest, profile ID and instance ID against the same bounded
selection read used for startup. A mismatch refuses startup before runtime
admission. It does not reopen the selection for display context. After the
check, the session exposes only immutable `profile_context` display values;
private binding pins do not enter agent metadata or public startup output.

This handoff has staged response bounds: up to one second for the repository
read and frontend admission, up to ten seconds for native central resolution,
then the existing six-second status or eleven-second ensure/client budget.
The first installed-client hop has a separate ten-second total bound over
argument parsing, package admission, exec refusal and any failure diagnostic on
stderr. A full stderr pipe cannot restart that deadline. Successful direct exec
keeps normal signal handling. These are not one
aggregate six- or eleven-second deadline, and final cleanup may wait for its
original owner. Actual installed timing remains unqualified. A missing or
malformed reference can use the existing structured MCP setup status before
handoff; a native central refusal exits with its closed stderr diagnostic and
does not fabricate an MCP readiness response.

## Retain pending cleanup ownership

The [named Claude Desktop launcher](CLAUDE_DESKTOP_LAUNCHER.md) separately handles
SIGTERM, SIGHUP and SIGINT: catchable termination prevents app opening and joins
original startup cleanup despite repeated signals. This does not establish signal
cleanup for every client route, and SIGKILL cannot be handled.

AMUX-67 requires bounded startup progress, failure and readiness checks. FAIL-56 states that “waiting callers get bounded progress or failure”; FAIL-57 requires “bounded, actionable diagnostics.” The accepted startup contract gives the adapter a ten-second interactive launch wait budget and states: “No silently orphaned startup process is an acceptable implementation.” Neither text imposes a separate final-exit deadline after the original child cannot be reaped.

The current `Capture` retains the exact `subprocess.Popen` child, output streams and executable admission when bounded cleanup cannot finish. Its public result reports cleanup pending. `EnrolledSession.exit_code()` then joins that same child before releasing process ownership. The status response remains bounded; final process exit can wait for the original child. This is retained cleanup ownership, not a successful shutdown or permission to start a replacement attempt. No new supervisor or ownership-transfer protocol is required by these criteria.

`InstalledFrontendImage` owns image admission only. The runtime group owns members that it starts. Neither API adopts this Python child, and the client does not attempt adoption. Tests and actual-client qualification must keep bounded status reporting distinct from completed cleanup and must preserve shared work when a client closes.

## Application-binding consumer inputs

`identity.application_binding.verify_response(raw, request_raw, public_key=..., signing_key_ref=..., now=...)` verifies a binding reply against an independently enrolled issuer and the exact signed request. The request binds `hubId`, `profileId`, `authorityId`, `instanceId`, `generation`, the 64-hex `lifetimeId`, `releaseDigest`, `policyRef`, `workspaceRef`, `transportRef` and `grantRef`. It also carries a fresh request ID, nonce, reply subject and an interval of at most five seconds. `generation` is an integer from 1 through 9007199254740991; `lifetimeId` and nonce are lowercase 64-hex strings. Requests, observations and replies use Ed25519 signatures over RFC8785-JCS-UTF8 canonical claims. The provider verifies the request signature. `verify_response` verifies the reply signature, its request digest and echoed claims; it does not independently verify the supplied request signature. A reply is evidence only through its `validUntil` time. Generation and lifetime must come from verified current runtime state; the startup broker endpoint and L04 observation do not supply them.

The production consumer still needs an admitted application transport and its scoped credential/signing reference, the enrolled reply issuer key, the expected caller and scope, and the verified runtime tuple above. It must send and receive through the connection retained for subsequent commands, verify expected caller and scope as well as the signed reply, and refresh binding after expiry or reconnect. Every domain command still requires its own current authority and exact payload binding. A binding reply cannot enable the legacy JSON socket or authorize arbitrary domain commands.

`hub/client_launch_binding.py` implements signed reply verification, expected caller/scope comparisons, connection lifetime invalidation and expiry. The enrolled entrypoint now consumes it through the fixed connection factory. It opens no connection itself and cannot enable domain operations by itself.

`hub/client_launch_connection.py` now retains the original NATS connect and close tasks, enforces one creating event loop, refuses automatic reconnect and invalidates binding on connection loss. Its internal connect entrypoint is not a production admission API. The fixed factory now consumes the shared credential validator and paired pre-CONNECT leaf pin. Neither this owner nor a connected flag grants domain-operation authority or readiness.

The connection owner now performs signed discovery followed by binding with `identity.application_client.ApplicationClientKey`. Discovery omits generation/lifetime in the request and verifies those values in the signed response; binding then names that exact lifetime with a fresh request ID, nonce and private inbox. Both exchanges stay on the same retained connection and use one caller deadline. Reply subscriptions are retained before SUB can fail, and their original unsubscribe tasks remain owned through cancellation or close failure. These paths have offline signed-response checks; they have not qualified a production connection.

The connection owner must invalidate binding on disconnect, reconnect and close. Retaining the same NATS client object is insufficient: a reply started before reconnect must not restore access afterward. Capture the current connection lifetime before sending, require it to remain current when accepting the reply, and check it again when dispatching a command. Use a fresh request ID, nonce and inbox when rebinding; do not reuse an old signed reply within its remaining validity interval. This is local connection ownership, not a missing field that clients can fill with an asserted connection ID.

The signed reply includes `callerRef` and `scope`, but `verify_response` does not compare them with client enrollment. The consumer must make those comparisons using independently admitted expected values before reporting a binding. Preserve the verified issuer, authority revision and sequence, grant reference, runtime generation/lifetime and expiry with that connection's binding. Do not translate a valid binding into blanket application readiness: the binding provider proves its own authenticated current runtime/authority observation, while each domain still requires its own operation authorization and availability check. An application-observation receipt acknowledges the host's update; it is not a client-binding response.

AMUX-47 owns current authority, observer enrollment and the signed observation-update service. AMUX-61 owns fresh host observations, signer provisioning/delivery and the installed production frontend. The checkout command `python3 /absolute/checkout/hub/cli.py ...` is a development entrypoint. Registration needs a release-admitted installed executable and literal startup/MCP arguments, plus supported hook timing, settings preservation and rollback. The stable runtime now defines `mcp` and `startup` with explicit `--client-installation` and `--selection` arguments. Packaged installation, registration and actual native-client qualification remain separate checks. A broker endpoint or checkout path cannot substitute for that installed command.

## Explicit application enrollment

The private startup selection keeps its six required fields. Optional closed objects supply application inputs:

```json
{
  "application": {
    "clientKey": "/absolute/private/application-client-key.json",
    "connection": "/absolute/private/application-connection.json"
  },
  "applicationAttestor": {
    "selection": "/absolute/private/application-attestor.json",
    "sha256": "sha256:<independently trusted 64 lowercase hexadecimal digits>"
  },
  "applicationServices": {
    "installationId": "<64 lowercase hexadecimal digits>",
    "selection": "/absolute/private/application-services.json",
    "sha256": "sha256:<independently trusted 64 lowercase hexadecimal digits>"
  }
}
```

This is an excerpt; retain the required startup selection fields. Replace every
placeholder with independently enrolled values. Each optional object requires all
its shown fields and rejects extra fields. Every path must be absolute and outside
approved workspaces. Omitting these objects preserves the existing infrastructure-only
startup. No ambient variable supplies them.

`applicationAttestor` adds the literal paired flags `--application-attestor-selection` and `--application-attestor-selection-sha256` only to ordinary `ensure`. The native host loader admits the selected record and digest. Managed-worker `status` carries neither flag. Startup does not provision a key, expand HOST broker grants or silently enroll an attestor.

`applicationServices` requires `applicationAttestor`. Ordinary `ensure` forwards
the three literal pins `--application-services-installation`,
`--application-services-selection` and `--application-services-selection-sha256`. Managed-worker `status` carries none of
these flags and cannot start services through this path. The installation ID is
64 lowercase hexadecimal digits; the digest is `sha256:` followed by 64 lowercase
hexadecimal digits. The service selection path is at most 4096 UTF-8
bytes, contains no control characters, and must not resolve inside an approved
workspace. These checks do not grant service authority: the native host separately
admits the protected package, selected private file and digest, and derives the account from admitted host credentials. A stale `hostAccountPublicKey` field or `--application-services-host-account` flag is refused.

The private application connection file has exactly nine fields: `schemaVersion` (`1.0.0`), `endpoint` (explicit `tls://127.0.0.1:PORT`), `serverName`, `rootsPEM` (one explicit CA, at most 16 KiB), `leafCertificateSHA256`, `credentialsFile`, `accountPublicKey`, `userPublicKey` and `replyPrefix`. The reply prefix is `_INBOX.` plus 16–64 letters, digits, underscores or hyphens. Its credential file is private, bounded to 64 KiB and outside approved workspaces. The selected client signing key remains in its separate purpose-bound store.

The shared credential guard verifies the enrolled account signature, exact user key, current time and exact permissions. Publication is limited to the identity command subject and, only when explicitly enrolled, the single integration query subject. Subscription is limited to this principal's private reply prefix. Broader or incomplete credentials are refused. The connection uses a TLS-first handshake, only the explicit CA, TLS 1.3, normal certificate/hostname verification and the exact leaf SHA-256 pin before authentication. The factory never rereads a mutable credential path during CONNECT; it uses the admitted bytes and rechecks them before signing the nonce or returning the JWT.

`ApplicationClientSession` keeps this connection's event loop in one thread inside the existing client process, so synchronous MCP input does not pause heartbeats. It retains opening, status and close work, and joins the original connection before stopping its loop. Startup status uses the remaining original frontend deadline. Interrupted final cleanup keeps its original future and loop. This introduces no separate daemon or supervisor and never stops the shared runtime.

A successful discovery and binding add `applicationBinding: {state: verified, hubId: ...}` to the status projection. Expiry or connection loss changes it to unavailable. `applicationAccess` remains unavailable: binding proves the selected connection and current signed identity, not blanket domain authority or service readiness. Native installed-client qualification remains open.

## Enrolled integration outcome query

The client key may explicitly enroll one `integrationEffectQuery` route, with its
exact subject, original operation ID and payload digest, separate transport and
grant references, and trusted reply issuer/key. Startup does not create this
enrollment or broaden broker permissions. Existing keys without it keep only
startup status.

The enrolled MCP tool `agentmux_integration_effect_query` accepts exactly
`operationId` and `expectedVersion`. It derives the selected hub, effect, original
intent, subject and authority references from enrollment. It uses the same retained
connection and requires a current binding. Its signed request uses the registered
`integration-effect-query` contract; its result is the verified closed
`integration-effect-reply` receipt. This query cannot start or repeat an external
effect, and no legacy socket or general publish route is used.

An expired binding, lost connection, denied authority or unverified reply returns
a fixed unconfirmed result. A caller timeout retains the original command future.
A later call with the same operation ID and revision can consume that result;
another identity cannot replace it while it remains owned. Cleanup joins that
original command before closing the connection and stopping the event loop.
Offline composition tests use the actual signer, connection owner and receiving
integration service. They do not qualify an installed connection or provider.
