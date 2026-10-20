# Recover the local platform runtime

Use this guide for the opt-in `agentmux-runtime` entrypoint on native macOS ARM64. The existing launcher remains available. This guide does not qualify other platforms or promise that the whole application is ready.

Use the installed runtime executable, private host-policy path and workspace roots supplied during explicit enrollment. Do not copy a profile from another user, generate a second identity or enroll by opening a repository. The commands below use example paths; replace them with your enrolled paths. Repeat `--workspace` for each enrolled workspace root.

```sh
/path/to/agentmux-runtime status --host-policy /private/enrolled/host-policy.json --workspace /path/to/workspace
/path/to/agentmux-runtime doctor --host-policy /private/enrolled/host-policy.json --workspace /path/to/workspace
```

`status` requests an authenticated observation from the enrolled owner. `doctor` validates the private enrollment and release, then reads the selected Docker context, engine and versions. Neither command starts the stack. Doctor has a five-second diagnostic budget and never runs Compose lifecycle commands. Private file admission uses local filesystem operations; an unresponsive filesystem may delay those operations.

The initial doctor command leaves broker, persistence and protected-role checks `unknown` with `not_probed`. These checks need authenticated read-only probes from their owners. A nonzero doctor exit can therefore mean incomplete checks, even when Docker checks pass. Read the report's individual `status` and `code` fields. A diagnostic pass never establishes application readiness.

## Prepare the pinned broker image

Before startup, the already enrolled OS owner can explicitly download the broker image selected by the verified release:

```sh
/path/to/agentmux-runtime prepare --host-policy /private/enrolled/host-policy.json --workspace /path/to/workspace
```

This action checks the current owner, protected installed runtime, release and exact enrolled local Docker context, endpoint, engine and versions. It holds the same process-held bootstrap lease used by startup. It pulls only the release's immutable broker image for Linux ARM64 and then verifies that image on the enrolled engine. It creates no identity and starts no services.

Running `prepare` explicitly permits a registry request even when the image is already cached; Docker may reuse cached layers. Ordinary startup, warm reuse and broker recovery never invoke this download action or pull an image. Preparation has its own maximum of 180 seconds, including admission, lock waiting, the original command and output-reader joins, and final output. It does not extend the host's existing startup budget. The existing lock wait can end earlier if another owner retains the lease.

When the output destination remains writable and the caller has not canceled, output consists of fixed JSON progress records for `checking`, `waiting_for_owner`, `downloading` and `verifying`, followed by a result. `outcome: prepared` confirms the pinned image passed verification. `readiness: not_observed` means application readiness was not checked. Docker's raw output and credentials are never included. The downloading progress record announces the upcoming pull; final authority checks still run before Docker can change the image cache.

For `outcome: failed`, read the result's `stage` and closed `diagnostic`. `docker_image_pull_failed` reports failure of the actual pinned-image pull; it does not identify a registry, network or authentication cause by itself. `docker_image_pull_timeout_outcome_unknown` reports a timed-out pull whose cache outcome is unknown. Correct the owner's registry access or other reported prerequisite, let owned cleanup finish, then repeat the same explicit preparation command. Preserve existing images and configuration. After `prepared`, request startup with the normal `ensure` command below.

Closing the preparation terminal or sending an ordinary interrupt cancels the foreground action and waits for its Docker command. Cancellation, an uncatchable process termination or a machine failure can leave the image-cache outcome unknown. Waiting for the client to exit does not establish what the engine cached. A later explicit `prepare` requests the same immutable image again and verifies it; it never deletes cached images to force a retry.

## Read startup output correctly

- A versioned authenticated status observation reports the selected instance and its current observations. Kernel information alone does not establish application readiness or persistence health.
- `bootstrap-progress` with `requestDisposition: accepted` says the newly launched host accepted that request earlier. `detailsAvailable: false` and `instanceState: unknown` mean current details are unavailable. Run `status` again; do not treat the receipt as a running or ready instance.
- Startup history describes a past attempt. Its timestamps do not make it current status.
- Missing work and connected-hub owners remain unavailable. Unknown counts are not zero. Later service availability must come from those service owners.

An interactive startup request has a ten-second frontend budget. Status and doctor requests have five-second budgets. The host's enrolled startup budget is separate. A request timeout does not prove that startup stopped. Inspect status before retrying.

## Resolve a diagnostic

| Reported problem | Safe next action |
| --- | --- |
| Invalid host policy, profile, enrollment or installed executable | Check the existing enrolled paths, private access, release and identity bindings. Have the installation owner repair the declared installation. Do not relax file permissions or bypass trust checks to make it run. |
| Docker environment conflict | Remove launch-specific `DOCKER_HOST` or `DOCKER_CONTEXT` overrides and use the enrolled selection. Do not change the machine's default context as a workaround. |
| Missing Docker client or execution permission denied | Restore access to the exact enrolled client and its required interpreter. Check executable and ancestor permissions. Ordinary launch does not install software or change account privileges. |
| Compose check failed | Check the qualified Compose plugin for the selected client. This result alone does not prove that the plugin is missing. |
| Engine check failed or inspection unavailable | Check that the selected local Docker service is available and accessible to the enrolled user. The diagnostic may not distinguish a stopped daemon from an access failure. |
| Endpoint, engine identity or version conflict | Compare the selected engine and qualified versions with enrollment. Make an explicit reviewed configuration change if needed; do not attach to a different engine or use an ambient fallback. |
| Enrolled port occupied or resource conflict | Identify the listener or resource owner. Resolve the conflict with that owner. Do not kill an unrelated process, select a second port, start a shadow stack or delete a volume. |
| Runtime authority rejected | Check enrolled credentials, server trust and certificate validity through the installation owner. Renewal is explicit. Do not disable TLS, replace trust during warm launch or fall back to plaintext. |
| Command timeout; outcome unknown | Inspect the selected instance before retrying. A timed-out start may have created partial resources. Do not issue overlapping starts or infer failure from the timeout alone. |
| Owned cleanup incomplete | Preserve the current recovery handles and let the owning operation finish cleanup before retrying. Do not remove locks or protected files to force progress. |

Shared reports contain closed diagnostic codes rather than raw subprocess output. Share only those reports and the relevant timestamps with the installation owner. Keep credential files, broker configuration, private keys, raw logs and private agent reasoning out of tickets and shared output.

## Retry without losing state

1. Read `status` and `doctor` for the existing enrollment. Check any active startup before requesting another.
2. Resolve the reported selection, trust, configuration or service problem. Keep persistent volumes and the existing profile and identity.
3. Request one explicit retry with the same enrolled paths:

   ```sh
   /path/to/agentmux-runtime ensure --host-policy /private/enrolled/host-policy.json --workspace /path/to/workspace
   ```

4. Read the returned disposition and service observations. Run `status` again when current details remain unavailable. A healthy compatible instance is reused; a retry must not recreate it or erase its state.

Concurrent terminals share startup ownership. A lock file's age, a PID or a stale receipt does not authorize taking ownership. Process-held leases release when their owners exit; startup inspects actual resources again before reuse or start. An unreachable owner remains unknown until ownership and current state are established.

Closing a terminal does not stop the shared stack. A broker interruption may make status unavailable while the protected runtime reconnects. If recovery remains unavailable, inspect the selected Docker service and enrolled instance, then use the explicit retry above after resolving the cause. Reconnection does not establish application readiness until fresh authenticated observations arrive.

The owning host can replace an exited protected role after its original process and output readers finish. It checks the same signed release, current enrollment and actual role lease again. Each role has at most two replacement attempts during that host's lifetime. A stop request disables replacement for that role. Replacement does not establish readiness: status needs fresh observations from the current role incarnation, and independently verified sibling observations remain visible.

Loss of the status connection does not immediately stop that owning host. The status service can use at most two reconnection windows of 20 seconds each during the host's lifetime while lifecycle recovery repairs the broker. It checks the original credentials, enrollment, container and TLS identity again before serving requests. An expired window or a changed authority stops this recovery; it never selects another broker or creates another host.

When broker communication stops, the host can make at most two bounded recovery checks. It verifies the enrolled engine, configuration, image, ports, volume and exact original container again. It starts that container only if it is stopped. A running container is left running; an absent, replaced or unverifiable container is refused. This recovery never creates a replacement stack, pulls an image, changes credentials or deletes data. Authentication, permission and server-trust failures stop automatic recovery. Have the installation owner resolve those failures before retrying.

Protected member recovery waits for the authenticated control connection to return. The host does not spend replacement attempts while that connection is reconnecting. A replacement still needs fresh scoped readiness observations before it counts as recovered.

The host stops protected roles in reverse assembly order within one shared shutdown budget. A missed deadline means cleanup is incomplete. Keep the exact owning operation and its recovery handles; another successful check or a repeated no-op close cannot establish that an earlier failed cleanup finished.

Recovery must preserve persistent data. Do not use `down -v`, engine pruning, forced recreation, arbitrary container deletion or lock removal. Stop only resources whose exact current ownership has been verified by the owning operation. This guide does not authorize deleting retained test resources or changing protected helper installations.

## Installation and migration limits

The current product provides enrolled profile, signed release and private configuration admission plus an installed-host entrypoint. Doctor is a basic diagnostic skeleton; it does not install, enroll, upgrade, renew certificates or repair dependencies. Complete native installation and live Compose lifecycle qualification remain required before claiming supported beta behavior.

This opt-in path does not convert legacy business data. Keep the previous launcher and user configuration while migration is incomplete. Do not run old and new writers against the same live task records. If the new entrypoint cannot be recovered, disable that entrypoint and retain the old launcher under its existing ownership rules; preserve the new profile and persistent data for inspection.
