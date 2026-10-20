# Client launcher integration

The client startup argument adapter is implemented in `hub/client_startup.py`. It builds an explicit `agentmux-runtime ensure` invocation for an ordinary client, or `status` for a managed worker. It does not launch a process, install a stable dispatcher, select an application transport or authenticate a caller. Existing CLI and MCP entry points remain unchanged.

## Use the runtime invocation contract

The integration supplies three values from its approved installation and setup selection:

- An absolute installer-admitted executable reference.
- An absolute enrolled host-policy path.
- One to sixteen explicit approved workspace roots. Do not derive these roots from the policy being checked.

Construct `RuntimeInvocation(executable, host_policy, tuple(workspaces))` and pass `arguments(managed_worker=...)` directly to the process API with `shell=False`. Preserve the client's working directory. The tuple preserves spaces, quotes and shell characters literally; never convert it to a shell command string. Path checks are syntax checks, not executable admission or proof of user approval.

The owning integration must bound time and output, keep the original process handle through joined cleanup, and send structured status to a separate channel from MCP stdout. Call ensure once; do not add retries or stop the shared runtime when a terminal closes. Managed workers query status instead of recursively ensuring another runtime.

For native descriptor checks, import `DescriptorPurpose` and `check_descriptor` from `hub.native_descriptor_admission`. The fixed function accepts `fd`, keyword-only `purpose` and a monotonic `deadline`; it returns `True` or raises `AdmissionError`. The five purposes are `PRIVATE_ANCESTOR`, `PRIVATE_DIRECTORY`, `PRIVATE_FILE`, `PROTECTED_ANCESTOR` and `PROTECTED_EXECUTABLE`. Do not supply a checker or purpose from user configuration. The integration must map admission failures to its closed public diagnostics.

The checker duplicates the supplied descriptor and closes only that duplicate. It checks native ACLs, ownership-enforcing local mounts, ownership, modes and object type. Protected objects also require a root-owned APFS mount. The selection/coordinator owner retains the original path and descriptors, rewalks without symlinks and compares identities before launch, and closes retained handles during joined cleanup. Descriptor admission does not select an executable, verify its content digest or authorize application access. Each native check limits its admission budget to one second within the caller's remaining budget and refuses success after expiry; an in-progress OS metadata call cannot be safely preempted.

A successful runtime exit is not an application access grant. The runtime can return a `bootstrap-progress` document with unknown state, or a full startup observation whose disposition is `starting`. Preserve unknown and unavailable states. Even ready broker/kernel observations do not prove that the application ingress is ready or authorized for this caller.

## Install the stable entrypoint explicitly

The stable path is `/Library/Application Support/Agentmux/Protected/agentmux-runtime`. The installer publishes the same verified frontend bytes included in a selected release. This frontend already uses `LoadEnrolledHostPolicy` and `PrepareHost`; there is no second startup implementation. The client's invocation path stays the same when the administrator updates that frontend. The enrolled policy continues to select its own pinned host and release.

First verify and install a reviewed package using the existing [installation procedure](PLATFORM_INSTALLATION.md). Then have the installation administrator invoke the same installer with the same independently pinned selection and the ordinary user's numeric owner ID:

```sh
/absolute/path/to/agentmux-install install-launcher \
  --selection /absolute/private/path/selection.json \
  --selection-sha256 sha256:<separately-trusted-selection-digest> \
  --owner-uid <enrolled-user-id>
```

This command verifies that the selected release is already installed. It does not install that release implicitly, elevate privileges, change enrollment or launch a service. The fixed executable is root-owned mode `0555`, with no setuid/setgid bits. Clients invoke it as their ordinary user:

```sh
"/Library/Application Support/Agentmux/Protected/agentmux-runtime" ensure \
  --host-policy /absolute/private/path/enrolled-host-policy.json \
  --workspace /absolute/approved/workspace
```

The frontend also accepts `doctor --client claude`, `doctor --client codex`, `doctor --client pi` or `doctor --client claude-desktop`, with the same explicit policy and workspace arguments. Client checks run only after policy admission, within the original doctor deadline. Omit `--client` to keep the original report. Other operations refuse this flag. Client diagnostics do not establish application readiness or authentication.

Use `status` for managed workers. The Python adapter exports this fixed path as `STABLE_RUNTIME_EXECUTABLE`; setup must still verify trusted installation before invocation. Do not discover the newest release directory or use ambient PATH as installation authority.

Initial installation refuses a different existing executable. An exact admitted copy is reused without changing its inode. Updating requires `--replace-launcher-sha256 sha256:<reviewed-current-launcher-digest>` as an additional installer argument. The current digest must match even if the requested new bytes are already present. This flag is refused on the existing verify, install and check operations.

The installer takes a nonblocking lock on the retained protected directory, verifies the current executable and its identity, writes and syncs a unique staging file, then publishes it by atomic rename. It never truncates the installed file. Open handles to the previous inode keep their original bytes. Root ownership, modes, link counts and access-control checks remain required. No policy, credential, release directory or unrelated file is replaced.

A failure before publication leaves the existing launcher intact. An uncertain failure after publication may mean the new bytes are present. Inspect the stable executable and retained staging entries before retrying; do not infer rollback or delete unrelated files. A changed selection requires explicit review. Installing a frontend does not prove compatibility with every previously enrolled host, application readiness or successful client startup.

The installation and update code has focused private-directory checks. Native macOS ARM64 qualification also covered initial administrator installation, an explicit digest-bound update, and preservation of the original inode and bytes through an open handle. The installed frontend passed cold ensure and warm ensure/status against a separately enrolled release host, with unchanged enrollment and retained data. This does not qualify automatic startup or domain commands in the actual clients.

## Selected application transport still required

`EnrolledHostPolicy.PublicEndpoint` and startup status `instance.endpoint` identify the NATS broker. They cannot be passed to the legacy hub JSON socket client. The legacy hub's ping and whoami responses do not establish the enrolled application instance, profile, hub or release.

Before a client can dispatch a domain command, the application ingress owner must provide a separately enrolled transport contract that:

- Binds the expected instance ID, profile ID, hub ID and release to an explicit supported application protocol and endpoint.
- References a scoped credential through the owning secret facility. It neither copies credentials nor converts a local process identity into human authentication.
- Verifies authenticated application identity, caller scope and readiness within a bounded handshake on the same connection used for the command.
- Refuses mismatched identity, expired authority and unsupported transport without falling back to a default socket, ambient environment endpoint or another hub.
- Preserves per-operation authorization and durable operation identity. A successful handshake cannot authorize every subsequent command or make an ambiguous reply safe to retry.

Proposed handoff: the application owner defines connection admission in `hub/server.py` (or its replacement ingress); the client owner integrates verification in `hub/cli.py` connection/call handling; setup supplies the admitted declaration and credential reference. The identity-contract owner reviews any shared schema. Startup wiring in AMUX-67 can consume these contracts once they exist. No transport declaration, handshake or new authentication grant is implemented by this adapter.

## Verification and remaining scope

Offline tests cover literal invocation arguments, explicit selection refusal and status-only managed-worker calls. The macOS `timeout` helper also waits for its original child after kill escalation; its offline tests verify the ordering and preserve existing exit and signal behavior.

The native stable frontend test also verifies joined process cleanup and removal of its owned container and network while retaining its data volume. These checks do not qualify installed clients, automatic startup hooks or application authentication. Those checks require the application-owner contracts above and an authorized serialized live slot. The remaining AMUX-61 owner migration and preservation requirements remain open, including work that depends on P03/P05. This guide does not replace their Jira acceptance criteria.
