# Native client setup and diagnostics

The beta target is native macOS ARM64. Keep each client's existing installation,
update channel, login and settings. Agentmux resource checks do not install clients,
change profiles, copy credentials or execute the displayed setup commands. Linux,
macOS AMD64 and Windows/WSL are outside this beta qualification.

The Settings → Resources panel reports `configured`, `unavailable` or `unknown`.
A configured check confirms only the named prerequisite. A version check does not
prove an Agentmux workflow works. Unknown means the check could not establish the
answer; it does not mean signed out. Optional plugin failures leave the resource
cards, refresh button and setup hints available.

## Before setup

The default local profile label follows `{User} - {Environment}`, for example
`Ryan - Local Development`. Include a project name only when the user explicitly
chooses a project-specific setup. The label is display text; it grants no access
and does not select an identity, Docker context, workspace or broker. Generate
profile and instance IDs once during explicit enrollment and reuse them when
opening another project. Changing the current directory must not create a new
profile or stack.

New central profiles must explicitly supply Environment, Project, or both.
These are profile context labels, separate from authorization scope and
`projectId`. Agent metadata must omit absent fields rather than fill in null,
empty or guessed values. Existing profiles need an explicit compatibility or
migration path; a missing label cannot silently become new enrollment metadata.

The repository reference format is closed JSON at `.agentmux/config.json`:

```json
{"schemaVersion":"1.0.0","profileId":"profile_0123456789abcdef0123456789abcdef"}
```

The ID above is illustrative, not enrolled. `dashboard/repository_profiles.py`
implements `read_repository_profile()`, `prepare_repository_profile()` and
`publish_repository_profile()` for an explicitly supplied repository root.
Preview writes nothing. Publication creates only a missing reference, preserves
a matching reference's bytes, and refuses malformed or conflicting configuration.
It preserves other `.agentmux` files. Uncertain publication retains exact handles
through `RepositoryProfileError.recovery`; callers must close that owner and
inspect any `cleanup_owners`. A consumed descriptor with uncertain cleanup must
never be retried by number.

The returned profile ID remains untrusted input. This module chooses no central
storage root, creates no central enrollment, starts no services and grants no
permission. Central admission and startup resolution still need their separate
integration. They must use the existing admitted user-scoped Agentmux storage,
verify that the repository is an approved workspace, and refuse unknown profiles.
An explicit `--selection` keeps precedence without reading repository config.
Missing references must not create another profile or instance.

The source launcher now provides `PrepareOwnerProfile()` for an explicit new
enrollment. It creates the profile in the native account home's
`Library/Application Support/Agentmux/profiles/<profileId>` directory. It requires
approved owner references, release pins, installed client and frontend pins,
Docker declarations and repository roots. It derives the display name from the
native account and the supplied project and environment labels. It generates new
local broker credentials and TLS material, checks the complete host policy, then
publishes central registration. It preserves existing profiles and native client
settings. It does not start services or establish application readiness.

Callers must retain a non-nil preparation result even when preparation fails and
must check its `Close()` result. Partial setup remains in place for inspection;
there is no automatic deletion, retry or resume after a process restart. The API
has passed focused source tests using disposable directories and the actual
configuration factories and loaders. Native installed checks are required before
claiming a changed setup or recovery path is qualified.

For an interrupted setup whose original credentials and declarations are intact,
use `recover-owner-profile --request PATH --request-sha256 sha256:HEX [--apply]`
with the original approved request and digest. Without `--apply`, this checks only
the request. With `--apply`, `RecoverOwnerProfile()` admits the installed code,
locks the central store, and compares the retained files against the same
configuration factories used for creation. It can publish a missing `profile.json`
and central registration. A matching completed registration is read back without
replacing it. Existing file contents and identities are preserved.

Recovery refuses missing credentials, conflicting declarations, unknown files,
leftover staging files and changed filesystem bindings. Keep these files for
inspection; do not change the request, generate replacement credentials or
delete files to force recovery. The original request remains the caller's
approved source of intent; an incomplete profile is not proof of its former
display labels or client selection. Recovery does not start services, pull
images or change repository or Desktop settings.

The owner command parser and runner use
`prepare-owner-profile --request PATH --request-sha256 sha256:HEX [--apply]`.
The default checks the private request's pinned bytes and closed format. It
creates no enrollment and does not admit the declared release or installed code.
`--apply` invokes `PrepareOwnerProfile()`. The request must be an owner-held,
single-link regular file with mode `0600`, at an absolute path without symlinks,
and contain at most 64 KiB. Approve its SHA-256 digest independently; the digest
does not authenticate a business identity. The runner retains the original file
and parent directories through preparation and checks them again before success.

The request uses schema version `1.0.0` and these exact fields. Unknown,
duplicate, missing or differently cased keys are refused. Passwords and private
keys have no fields in this format; preparation generates local broker secrets.

| Field | Required content |
| --- | --- |
| `schemaVersion` | `1.0.0` |
| `owner` | Approved `OwnerEnrollment`: `schemaVersion`, `ownerUid`, `principalId`, `authenticatedIdentityRef` (`id`, `ownerHubId`, `revision`), `scope` (`organizationId`, `projectId`, `workspaceId`), `instanceId`, `profileId`, `releaseFingerprint`. Scope `projectId` and `workspaceId` use the existing enrollment format and may be null. |
| `context` | `environment`, `project`, or both. Omit absent display metadata. Present values must be nonempty. |
| `clientInstallationId` | Explicit protected client installation ID. |
| `approvedWorkspaceRoots` | One to sixteen distinct absolute repository roots. |
| `release` | `packageDirectory`, `publicKeyHex` (32-byte release public key as lowercase hex), `releaseManifestDigest`, `releaseAuthority` (`id`, `ownerHubId`, `revision`), `releaseVersion`, `kernelApiMajor`. |
| `runtimeExecutable` | `path` and `digest` for the approved installed frontend. |
| `docker` | `backend` (`native-unix`), `executable`, `context`, `endpoint`, `engineId`, `clientVersion`, `serverVersion`, `composeVersion`. |
| `hostPort`, `composeProject`, `serverName`, `domain` | Explicit local broker declarations. |
| `maxMemoryBytes`, `maxFileBytes` | Positive broker storage limits in bytes. |
| `limits` | Integer `startupMilliseconds` (1–60000), `probeMilliseconds` (1–5000), `roleStartMilliseconds` (1–30000), `stopGraceMilliseconds` (1–10000), `reapMilliseconds` (1–10000). |

The command returns one bounded result with outcome `request_checked`,
`prepared`, `refused` or `review_required`. Results disclose no private request
contents. A preparation error with a retained owner requires inspection before
retry; the runner does not close that owner implicitly or restart the command
budget for diagnostics. A complete stdout result suppresses the duplicate stderr
diagnostic; failed stdout writes retain the bounded stderr fallback.

1. Confirm that the client already installed is the one you intend to use. Use its
   existing stable command or application, including after updates. Do not point
   Agentmux at a versioned executable inside an installation directory.
2. Open the client in your normal native environment. Keep its configuration home
   and project trust settings. Do not create a second configuration directory to
   share a login. Log in through the client if needed.
3. Follow [platform installation](PLATFORM_INSTALLATION.md) for the enrolled
   Agentmux installation and [bootstrap recovery](BOOTSTRAP_RECOVERY.md) for its
   installed doctor. The resource panel currently checks client prerequisites
   separately. The installed doctor also accepts `--client claude`, `--client codex`,
   `--client pi` or `--client claude-desktop`. Keep the usual host policy and
   workspace arguments. Client diagnostics do not replace installed workflow
   qualification.
4. Review any proposed client configuration change before applying it. Add only
   the Agentmux-owned entry. Preserve other MCP servers, hooks, profiles, settings
   and secret references. Installed launch and startup paths require their own
   qualification; this guide does not claim those paths qualified.

## Claude Code

Use the existing `claude` command. `claude --version` identifies its version;
`claude auth status` asks the native client about authentication. Diagnostics retain
only a status, never the account details or raw output. An unavailable command or
unrecognized response remains unknown. `configDirectory` in the native status
response requires version 2.1.268 or later; the plugin prerequisite check reports
that lookup requirement, not a minimum qualified Agentmux version.

The native user settings reference is `$CLAUDE_CONFIG_DIR/settings.json`, defaulting
to `~/.claude/settings.json`. Project and managed settings can also apply. On macOS,
Claude Code owns the Keychain login and its supported credential-file fallback.
Changing `CLAUDE_CONFIG_DIR` can select a different credential namespace. Agentmux
must use the same environment as the intended client; it must not copy credentials
into an isolated worker directory. Use `claude auth login` yourself when needed.

The source now has an offline-qualified planner and durable receipt caller for one
Agentmux-owned `SessionStart` matcher group covering `startup`, `resume` and `fork`.
It preserves unrelated hook arrays and settings, creates a missing `settings.json`
without replacing a file that appears concurrently, and supports install, owned
update, remove, restore and receipt recovery. The command uses Claude's exec form:
the protected Agentmux runtime is the fixed executable and the fixed
`claude-code-hook`, installation and enrollment values are literal arguments.
The settings path is a required protected-owner input. The isolated caller does
not read `CLAUDE_CONFIG_DIR` or silently choose the default namespace.

Ten focused offline tests cover the planner and caller. The installed Go owner,
protected package route and package roster still need their coordinated handoff.
Until then, no installed setup command reaches this caller. Native qualification
must use a disposable configuration directory before any intended-user settings
change is considered.

After a client-side settings change, refresh Resources after its two-second minimum
refresh interval. The check resolves the native reference again. File metadata does
not validate effective settings or establish login. A legacy `agent-config` check
is retained as optional compatibility information; it is not authentication authority.

Source: [Claude authentication](https://code.claude.com/docs/en/authentication),
[settings](https://code.claude.com/docs/en/settings), and
[CLI reference](https://code.claude.com/docs/en/cli-reference).

## Codex CLI

Use the existing `codex` command and update channel. `codex login status` is the
supported authentication query; `codex login` starts the user's login flow.
Codex owns credential storage, which may be a native credential store, a file or
another supported mode. Agentmux never reads `auth.json` or the keychain directly.

`CODEX_HOME` selects the user configuration directory, defaulting to `~/.codex`.
The resource panel observes metadata for `config.toml`; a missing file can be normal
because defaults, project settings and managed settings also apply. The retained
`yolo` profile check is optional. It does not enable unrestricted permissions.
The former `codex doctor` resource command is replaced by this native reference
check; it is not a claim that the configuration has been parsed by Codex.

Keep native settings and credentials in place during install, update and uninstall.
Refresh resolves the reference again without synchronization. Use the client itself
to inspect effective settings. Do not run `codex exec` merely to validate configuration:
it can start provider work. Custom-provider setup creates a new private profile without overwriting an existing
file or symlink. If a profile already exists, setup stops before prompts or settings
writes; review and back up the existing file in your own terminal before deciding
how to change it. The local `--verify` check reads at most 64 KiB of a regular profile
without following a symlink. It checks TOML syntax only: invalid or missing profiles
return 1; valid syntax returns 2 with native acceptance and authentication unknown.
Provider setup still needs its separate compatibility qualification. Native parse
and workflow checks must not be inferred from this syntax check.

Sources: [Codex authentication](https://developers.openai.com/codex/auth) and
[configuration](https://developers.openai.com/codex/config-basic).
The installed CLI version check reported 0.162.1. A disposable native lookup test
observed an invalid file-store setting and recovery after restoring it. This is not
a successful Agentmux workflow or provider authentication test.

## Pi

Use the existing `pi` command. `PI_CODING_AGENT_DIR` selects the native agent directory,
defaulting to `~/.pi/agent`. That directory owns `settings.json`, `models.json`,
`mcp.json` and `auth.json`. Trusted project `.pi` settings can also apply. Use `/login`
in Pi to manage credentials and `/reload` after supported settings changes.

The diagnostic observes metadata only. An `auth.json` file does not prove a working
login; environment credentials, OAuth and credential helpers can also affect the
result. Agentmux does not evaluate secret-helper commands. Automatic provider-auth
qualification remains unknown until a supported lookup is established and tested.

This lookup follows the installed `@earendil-works/pi-coding-agent` 1.3.0 package's
`docs/configuration.md`, `docs/providers.md` and `dist/config.js` (`getAgentDir`,
`getAuthPath`, `getSettingsPath`). See [Pi](https://pi.dev) for the client. The installed version check reported 1.3.0 in a disposable home. It was not run
against the user's login; its version is not an integration pass.

## Claude Desktop

Open the existing Claude application. Use its About and update controls to identify
and update it. Check sign-in in the application. No supported external, non-secret
lookup of its login store has been qualified; diagnostics report that gap as unknown.
Do not infer Desktop authentication from Claude Code credentials.

Use Settings → Developer → Edit Config for the native MCP configuration at
`~/Library/Application Support/Claude/claude_desktop_config.json`. Preserve the
existing document and unrelated server entries. Restart Desktop to load MCP changes.
The metadata check follows that same native file on refresh. Its presence does not
prove a server is trusted, running or connected.

Source: [Connect local MCP servers](https://modelcontextprotocol.io/docs/develop/connect-local-servers).
Agentmux does not use the example's whole-file replacement approach on existing user
configuration.

The Desktop registration planner in `dashboard/resource_registration.py` prepares
an edit to exactly `mcpServers.agentmux`. It preserves unrelated entries and JSON
number values. Replacement and removal require a matching installation ID,
configuration path and previously owned entry. An unowned or edited entry stops
the operation. The returned configuration and command bytes are private and must
not appear in diagnostic output.

The internal publisher in `dashboard/resource_settings.py` follows the installer's
retained-directory approach. Directory and file checks use the shared Darwin
admission policy in `native_security/descriptor_admission.py`, including private
ownership, ACL and mount checks. The staging file is admitted before any settings
bytes are written. All admission calls share the operation's deadline. The
publisher requires an existing private settings file, locks
the retained parent directory, stages a private replacement, and compares the
original file identity and bytes before one rename. It syncs the replacement and
parent directory, then retains the published file handle and ownership record for
the installation owner. A failed staging operation returns only the exact entry it
created. A failure or interruption after rename reports publication as uncertain
and transfers the retained recovery handle; callers must not assume no change or
retry blindly. Uncertain staging files stay in place for exact-owner inspection.

Rollback planning uses the actual before-document. It restores or removes only the
owned Agentmux entry and preserves later unrelated edits. An entry already absent
before a no-op removal stays absent. Changed owned entries stop rollback. Rollback
is a separately reviewed edit, not an automatic whole-file restore after failure.

The `desktop_registration()` composition in `dashboard/resource_settings.py`
accepts only the native-issued installed client owner. It opens the selected
private settings parent through admitted ancestors and derives the new entry's
command and arguments from that owner. A serialized declaration or caller-supplied
command cannot authorize publication. Removal also requires the owned entry to
match the admitted enrollment selection.

The composition retains the application admission and settings-directory lock
through a final check of the exact published file and the receipt commitment.
It then closes its handles. An external replacement reports publication as
uncertain. No Resources HTTP route invokes it.

`dashboard/client_setup.py` provides the explicit terminal caller and private
receipt store. Its fixed arguments are
`--client-installation <id> --selection <absolute-selection-path> --receipt <absolute-receipt-path> --operation install|remove|restore|recover [--apply]`.
Without `--apply`, it checks prerequisites and prepares the change without writing.
Setup resolves the current user's home through the native account database,
requires matching real and effective user IDs, and ignores `HOME` when choosing
the Desktop settings path. A missing or invalid account home stops setup.
The receipt must be outside enrolled workspaces, in an existing private directory
separate from the native settings directory. The native settings file must already
exist. The caller starts no services and reads no client credentials.

Before changing settings, the caller durably records the operation, the complete
owned entry, the previous and proposed ownership states, and before/after settings
digests. Unrelated settings and their secrets are not copied to the receipt.
The pending record remains until the publisher's final native checks succeed.
The caller then commits the receipt under the settings lock with an atomic
replacement and syncs the file and parent directory. A later handle-cleanup
failure reports uncertainty even if the committed receipt is already durable.
Interrupted initial receipt creation can leave an
invalid private file; setup refuses it and leaves native settings unchanged.
It never deletes unknown records or staging files by name prefix.

Recovery compares the current settings digest with the recorded before and after
states, then commits only the matching ownership state. It leaves native settings
unchanged and refuses unrelated edits. A final snapshot failure keeps the pending
record. If receipt replacement succeeded but its directory sync failed, the next
explicit recovery checks the committed native entry and syncs the receipt again.
Removal saves the owned entry for explicit restoration; restoration requires the
same admitted package and enrollment selection. Remove an owned entry before
changing or removing the package that authorizes it.

The installed runtime now implements the closed `client-setup` route. Its
bootstrap calls this module directly, without entering a client session or
starting services. The installed candidate includes the setup caller, settings
publisher, registration planner and retained native admission modules. This
implementation and packaging do not establish successful publication to the
intended user's actual Desktop configuration. That terminal workflow still needs
the intended user's enrollment and install/remove/restore/recovery qualification.
The default command remains a preview; applying a change requires `--apply`.
Directory locks coordinate Agentmux writers; native clients and external editors
must be quiescent because they may ignore the lock. Rename is atomic, but comparison
and rename are separate operations, and receipt persistence is a separate step.
File operations do not have a strict wall-clock bound on an unresponsive filesystem.
Focused offline tests cover shared-checker refusal before writing, refusal after
rename and deadline propagation. These tests substitute the native checker; they
do not qualify real ACL or mount behavior for settings publication.
On October 16, 2026, the production settings composition passed on native macOS
ARM64 with the installed package's real retained admission and the real native
descriptor checker. The test used only its own private directory and disposable
JSON file. It covered add, no-op, remove, restore, receipt-acceptance lock coverage,
preservation of unrelated JSON and number tokens, stale file identity, and
replacement during snapshot or publication. The test passed in 5.580 seconds,
closed its admission and recovery handles, and removed its disposable directory.
On October 17, 2026, the expanded opt-in fixture passed in 19.720 seconds with
the selected installed package and its explicit enrollment selection. It covered
the actual `run_setup()` install, remove and restore flow, a receipt interruption
after settings publication, read-only recovery preview and applied recovery.
Its 120-second functional budget does not qualify the default operation deadline.
The fixture substitutes a disposable settings path. It does not run the installed
terminal command, resolve the intended user's account path, change actual Desktop
settings, start Desktop or test Desktop loading the registration. Those checks
still require the intended user's enrollment and separate qualification.
The stable runtime's `ensure` command and NATS endpoint are not MCP server commands.
Native Desktop install, update,
removal and restore checks remain required. Remove an owned registration before
removing its admitted client package; an absent package cannot authorize an
automatic settings edit.

`hub/installed_client_admission.py` supplies the Python retained admission owner
for that connection. It accepts an explicit installed client ID and private
enrollment selection. It opens only the fixed protected client directory and
stable frontend, verifies the manifest identity, exact file roster, file digests,
native permissions and frontend digest, and rechecks those bindings. The command
declaration contains the stable frontend and exact arguments
`mcp --client-installation <id> --selection <private-enrollment-selection>` with
`stdio` transport. Its fields describe the admitted command; serialized JSON does
not transfer admission ownership. The setup caller must retain the actual owner
and its `hold()` context through publication and ownership-record persistence.

The installer's package selection and the client's enrollment selection are
different artifacts. The installer still requires independent approval of the
package selection digest. Enrollment selects the existing instance, profile and
hub; installed package admission grants no application authority or readiness.
Offline package tests use synthetic files and substitute native descriptor checks.
They do not qualify the pinned Python payload or actual Desktop registration.
Native image checks accept generic ARM64 subtype `0`; other native subtypes and
ambiguous or inconsistent universal-binary slices are refused. Extension library
lookup uses the selected interpreter's actual declared runtime search paths and
the extension's own declared paths. The presence of `python/lib` in the package
does not create a search path. Loader environment commands are refused, and all
supported dylib load commands must resolve to canonical system paths or the
selected package roster.

## Failures and recovery

| Result | Meaning and next action |
| --- | --- |
| Tool missing | The reviewed command is not available on the dashboard's PATH. Check the existing native installation and restart the dashboard with the intended PATH. Install only after an explicit operator choice. |
| Unsupported version | The version is below a named lookup prerequisite. Use the client's existing update channel; retry the check. This does not authorize a duplicate installation. |
| Unknown authentication | The response, lookup or credential source is unsupported or unavailable. Check inside the native client; do not copy or print credentials. |
| Native reference absent | The optional user settings file may not exist yet. Check client defaults and selected configuration home before creating anything. |
| Probe timeout or output limit | The diagnostic stopped at its fixed limit. Inspect the client privately and retry later. Raw output is withheld. |
| Output pipe cleanup incomplete | A wrapper left its output open after exiting. Status remains unknown even if it printed a recognizable login result. Inspect the wrapper privately; the doctor does not claim to stop arbitrary descendants. |
| Missing vendor license or unsupported filesystem | Keep the integration unavailable or unknown until its owner supplies a supported prerequisite check. A client version cannot establish vendor or filesystem readiness. |

Correcting a prerequisite does not require deleting configuration or resetting a
profile. Refresh performs the same reviewed checks again. Requests cannot choose
commands or arguments. Each process has a deadline and output limit; one shared
refresh sweep runs at a time. The normal cache lasts 12 seconds; forced refreshes
have a two-second minimum interval. Client health contributions use version 1 with
`local-read-only` scope. New contribution commands require code review and an
allowlist entry; an HTTP request cannot register one.

For uninstall or rollback, remove only the exact Agentmux-owned registration after
checking it has not been edited. Keep the native client, login, unrelated settings,
enrolled data and durable work. If ownership is uncertain, leave the entry in place
and report the conflict. Restore only a reviewed owned entry; never overwrite the
whole native configuration to recover one integration.

The Atlassian setup command creates a private configuration without replacing a
file that appears while its prompts are open. Updating an existing configuration
still requires the overwrite confirmation and preserves unrelated JSON keys.
Symlinks, invalid configuration and changes detected during the prompts stop the
write with a recovery message. Finish other edits before updating this file:
the confirmed replacement is atomic, but it is not a lock shared with external
editors. No token or existing configuration contents are printed.

Resources keeps existing cards visible when a refresh fails and labels results
that are still being refreshed. Setup notes appear beside the displayed commands;
copying a command does not execute it.

## Qualification still required

Offline fixture checks do not qualify real client behavior. AMUX-65 remains open
for complete native-host setup/change-visibility qualification for all four clients,
authentication expiry, install/update/uninstall/restore preservation, and shared
installed doctor workflow qualification. Grok authentication remains unknown
pending a verified output format; generic word matching can misread negative
results. Stable launchers and installed workflow qualification
belong to AMUX-61/AMUX-63; startup belongs to AMUX-67; provider authentication belongs
to AMUX-66. Missing clients and unsupported lookup mechanisms remain explicit gaps.

A strict parser for `claude plugin list --json` follows
the [documented JSON fields](https://code.claude.com/docs/en/plugins/cli-reference#plugin-list).
The production Resources check uses this fixed command. On native macOS ARM64,
Claude Code 2.1.301 reported empty, disabled and enabled fixture states, then
observed removal and restoration of the fixture contribution. Unrelated settings,
the manifest and Markdown remained unchanged. Unsupported output remains unknown;
plugin IDs, paths, server definitions and raw load errors are withheld. This checks
native discovery and enabled state, not plugin execution or provider usability.

The selected-client doctor adapter accepts only `claude`, `codex`, `pi` and
`claude-desktop`. It preserves policy admission and the caller's deadline, and
reports fixed version checks, native configuration metadata and supported native
sign-in status. Codex and Claude Code can report signed out, signed in or unknown;
signed in does not establish provider usability. Pi and Desktop sign-in remain
unknown. Missing optional user settings stay separate from sign-in status.
The adapter has passed focused offline tests and isolated native signed-out lookup
checks. Its native process tests cover normal output, malformed auth output,
nonzero exit, timeout, output overflow and output pipes held open after exit 0 or
auth exit 1. The fixture retains and joins each pipe holder's original process;
the doctor joins its command and output reader. The focused race run also passed.
No diagnostic result establishes termination of arbitrary descendants.

Version and auth commands share a one-second subprocess budget and reserve time
to close output readers. This is not a strict wall-clock guarantee for executable
lookup or metadata reads on an unresponsive filesystem. An unsupported filesystem
requires separate qualification; do not infer it from a client version.

The focused native checks performed on October 16, 2026 passed: five real process
capture/cleanup checks; the Resources browser flow against an isolated dashboard
with missing clients and an unchanged sentinel file; CLI versions for Codex 0.162.1,
Claude Code 2.1.301 and Pi 1.3.0; Claude native status following two disposable
configuration roots; and Codex seeing an invalid fixture configuration and its
restoration. The last two checks used signed-out fixture homes and printed no
native status contents. They do not establish real-user login, credential expiry,
provider execution, or installed Agentmux workflow qualification.
