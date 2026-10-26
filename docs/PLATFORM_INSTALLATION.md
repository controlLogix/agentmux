# Install a selected native release

`agentmux-install` provides the basic product installation path for native macOS ARM64. An administrator explicitly installs a selected signed release and a separately pinned runtime. The command does not elevate itself, install dependencies, start services, select a profile, or change existing enrollment, settings, credentials, state or volumes.

Installation and enrollment are separate operations. The final `check` operation requires an existing explicit user enrollment. The installer does not import a profile bundle, create an identity, enroll a certificate authority or grant release authority. Installing a package does not prove operational readiness.

For another developer's Mac, follow [native development setup](DEVELOPMENT_SETUP.md).
The repository's `agentmux-dev-package` command prepares a locally signed dev
package with a fresh ephemeral key. It does not require sharing a private release
key or importing another user's enrollment.

## Select and verify

The release administrator supplies the signed package and an independently trusted release policy: the Ed25519 public key, authority identity and revision, release version, API major and parent manifest digest. A package's own public key or manifest cannot grant that trust. The existing release signature binds the parent manifest and four-role assembly; it does not bind `agentmux-runtime`. The administrator must also approve that executable's separate SHA-256 digest.

Record these choices in an absolute-path JSON selection file. Its direct parent must be private mode `0700`, and the file must be mode `0600`, owned by the installing user, without links. Retain the selection's SHA-256 digest separately. Changing the selection requires explicit review and a new trusted digest.

```json
{
  "schemaVersion": "1.0.0",
  "release": {
    "packageDirectory": "/absolute/path/to/release",
    "publicKeyHex": "<64 lowercase hexadecimal characters>",
    "releaseManifestDigest": "sha256:<64 lowercase hexadecimal characters>",
    "releaseAuthority": {"id": "approved_authority", "ownerHubId": "approved_hub", "revision": 1},
    "releaseVersion": "1.0.0",
    "kernelApiMajor": 1
  },
  "runtime": {
    "path": "/absolute/path/to/agentmux-runtime",
    "digest": "sha256:<64 lowercase hexadecimal characters>"
  }
}
```

As the ordinary user, verify the explicit selection:

```sh
/absolute/path/to/agentmux-install verify \
  --selection /absolute/private/path/selection.json \
  --selection-sha256 sha256:<separately-trusted-selection-digest>
```

A successful result has `outcome: verified`, `enrollment: not_checked` and `readiness: not_observed`. Verification checks real signatures, hashes, fixed role membership and native ARM64 executable headers. The later enrolled image check also uses the protected runtime's full image admission rules.

## Install explicitly

Have the installation administrator invoke the same installer with administrator privileges, operation `install`, the same selection and digest, and `--owner-uid` set to the ordinary user's numeric user ID. The command itself performs no privilege escalation.

The destination is a new digest-named directory beneath `/Library/Application Support/Agentmux/Protected/releases`. The name binds the parent manifest digest, assembly digest and separate runtime digest. Existing system ancestors must already be trusted. The installer may create only the fixed `Agentmux/Protected/releases` directories beneath `/Library/Application Support`. It checks root ownership, permissions, access-control lists, mount identity and no-follow descriptor ancestry. It neither follows links nor repairs an untrusted ancestor.

The installer copies exactly nine files: `release-manifest.json`, `release-authorization.json`, `release-authorization.sig`, `protected-assembly.json`, `agentmux-runtime` and the four fixed files under `bin`: `boot`, `kernel-lifecycle`, `internal-communication` and `exported-status`. Metadata becomes mode `0444`, executables `0555`, and directories `0755`. It retains verified bounded source bytes before writing and checks the complete destination afterward. It never copies unrelated package files.

An existing directory is reused only if its complete file roster, bytes, ownership, permissions and link counts match. A foreign, changed or partial directory is refused without replacement. Concurrent attempts cannot overwrite one another.

## Validate existing enrollment

After the explicit enrollment procedure selects the installed release and externally trusted policy, run this check as that enrolled ordinary user:

```sh
/absolute/path/to/agentmux-install check \
  --host-policy /absolute/private/path/enrolled-host-policy.json \
  --workspace /absolute/approved/workspace
```

Repeat `--workspace` for every explicitly authorized workspace. The check uses the existing enrolled policy, host executable and protected role loaders. It validates the installed images without spawning them or contacting Docker or a broker. Success reports `enrollment_verified` and `readiness: not_observed`. Use the runtime's authenticated status and lifecycle commands for operational readiness.

## Handle a failure

Commands return a nonzero exit code and a bounded diagnostic. A failed copy may leave the exact digest directory partly written; the installer does not select it, delete it or fall back to another release. Keep that directory unselected. The administrator must inspect the reported installation ID before deciding how to recover. Do not remove another release or user data to make a retry succeed.

The library retains concrete cleanup owners and causes in its returned failure. It does not retry a descriptor after a failed consumed close. A deadline bounds cooperative work and rejects late results; it cannot interrupt a filesystem call blocked by the operating system. Use supported local storage.

The focused tests exercise the real signature and copy logic through a private destination policy. Those tests do not qualify root-owned protected installation, installed lifecycle behavior, Compose behavior or release publication. Those checks require the actual reviewed native package, explicit administrator installation and enrolled native environment.

## Explicit selected core Hub commands

This development route targets one user on native macOS ARM64. Before using it, install the reviewed runtime and client, and select an existing central profile that approves the repository. The repository's `.agentmux/config.json` references that profile; it does not grant permission. An explicit `--profile-id` can select an already registered profile instead.

The repository reference accepts exactly these two fields. Replace the example ID with the existing admitted profile's ID:

```json
{
  "schemaVersion": "1.0.0",
  "profileId": "profile_0123456789abcdef0123456789abcdef"
}
```

Keep other profile metadata and credentials in their central settings and enrollment files. Do not add them to this repository reference.

The registered client selection must contain a pinned `coreHub` selection. That private selection supplies the Hub data directory, the approved repository-root-to-local-name mapping, and pinned identity, message and Work application selections. All selections must identify the same profile, instance, Hub and approved workspaces. Each application must already be enrolled with its credentials and current permissions. Infrastructure readiness or a profile display name cannot supply these requirements. Use the existing profile owner to prepare and register these inputs; do not edit a retained registration or invent grants to bypass a setup error.

For a new profile, add this optional field to the explicit `prepare-owner-profile` request before approving its request digest:

```json
"coreHub": {
  "selection": "/absolute/private/core-selection.json",
  "sha256": "sha256:<approved-core-selection-digest>"
}
```

The core selection must already exist outside approved repositories, in a private directory owned by the native user (directory mode `0700`, file mode `0600`). Preparation retains and checks that original file while creating the profile and registering the client selection. Run the usual request preview, then the same request with `--apply`. Explicit recovery uses the same request and core pin; it refuses changed inputs. Omitting `coreHub` creates an infrastructure-only profile whose core commands report setup-required. This create-time option does not update an existing registration or create application enrollments. Successful preparation confirms the mapping and custody; startup still verifies the selected applications and current authority.

From the harness, start the selected Hub in a terminal and keep that foreground process open:

```sh
agentmux hub selected --repository-root /absolute/approved/repository -- start
```

In another terminal, use the same repository selection for each command:

```sh
agentmux hub selected --repository-root /absolute/approved/repository -- ping
agentmux hub selected --repository-root /absolute/approved/repository -- status
agentmux hub selected --repository-root /absolute/approved/repository -- work list
agentmux hub selected --repository-root /absolute/approved/repository -- events --limit 20
```

To name the existing central profile explicitly, set `PROFILE_ID` to its registered ID and put `--profile-id "$PROFILE_ID"` before `--`. The corresponding direct installed entrypoint is:

```sh
"/Library/Application Support/Agentmux/Protected/agentmux-runtime" profile-core \
  --profile-id "$PROFILE_ID" \
  --repository-root /absolute/approved/repository -- ping
```

Use the existing `spawn`, `adopt`, `kill`, message and Work command arguments after `--`. Keep the original operation ID when retrying an uncertain `spawn`, `adopt`, agent `kill` or Work operation. Managed workers use the installed callback from the enrolled repository or its subdirectories; they do not start another shared Hub. A missing or changed registration, endpoint, source, enrollment or permission causes a refusal instead of selecting a default Hub.

For a new profile's first worker, the selected Work channel can include one explicit declaration:

```json
"firstWorker": {
  "caller": "falcon-worker-first",
  "generation": 1,
  "spawnOperationId": "first-spawn"
}
```

The profile owner must also enroll that exact caller in the channel's `legacyActors` and prepare its own client transport and current Work grants before startup. The repository, profile, identity and transport must match the selected application. This declaration grants no authority and creates no agent row. Only one first worker can be declared across the selected Work channels; it cannot update an already retained selection.

Start that worker with the declared original `--operation-id` and matching repository, role and agent arguments. Access becomes available only when the original operator spawn has completed registration and process startup for generation one, with the current matching handle and PID. Until then, its signed route permits only the authorized source inspection needed for startup. Ordinary Work and local `post`, `inbox` and `ack` remain unavailable. Existing native caller checks and current permissions still apply after activation.

If the spawn reply is uncertain, retry the same supported command with the same operation ID and arguments. Keep its records and any uncertain process; do not replace the declaration, generate a new operation ID, or edit the database to force activation. Restarting the owner retains the original declaration and generation. A dead worker or later registration generation cannot inherit this route. General enrollment changes and worker replacement require their own supported preparation workflow.

Status, events and inbox limits apply within the selected repository. Historical status and events retain their original records; shared records without an unambiguous repository are excluded from those aggregate views. Inbox operations refuse ambiguous messages. A message batch with foreign recipients is refused before acknowledgement. Operator peeks do not mark or acknowledge mail. The message `ref` is opaque; a typed Work link is checked through the Work owner. Shared bridge diagnostics, configuration changes and streaming subscriptions are outside this route.

Stop the selected Hub explicitly when finished, then wait for its foreground process to exit:

```sh
agentmux hub selected --repository-root /absolute/approved/repository -- stop
```

Stopping the Hub does not delete profile settings, credentials, retained messages, Work records or storage volumes. Hub `stop` has no operation ID. If its response is lost, check the original foreground process and wait for it to exit before starting a replacement Hub. For an uncertain operation that supports an operation ID, retain that ID for recovery.
