# Installed Python client

The ordinary Python client is installed separately from the four protected
kernel roles. Its complete manifest pins the Python 3.14.4 interpreter, standard
library, native libraries, locked dependencies, client modules and contract
schemas. The manifest also binds the foundation installation ID and stable
frontend digest. Installation and broker readiness do not grant application
access or enroll a profile.

The installed layout is:

```text
/Library/Application Support/Agentmux/Protected/clients/<installation-id>/
  client-manifest.json
  bootstrap.py
  python/bin/python3.14
  python/lib/
  site-packages/
  app/hub/
  app/dashboard/
  app/identity/
  app/integration_owner/
  app/native_security/
  app/state_owner/
  app/taskmgmt/
  app/sdk/python/agentmux_contracts/
  app/contracts/v1/registry.json
  app/contracts/v1/models/state-machines.json
  app/contracts/v1/schemas/
```

The installation ID is the SHA-256 digest of the exact manifest bytes, without
the `sha256:` prefix. The manifest lists every other file in sorted path order
with its digest, size and installed mode. Admission rejects unexpected files,
missing files, symbolic links, multiple hard links, changed content, writable
files, unsafe native ACLs and native libraries outside the package or Apple
system directories. It checks root ownership and protected ancestors. Files are
read-only (`0444`), native executable files use `0555`, and directories use `0755`.

Prepare the exact Python 3.14.4 standalone runtime and the complete
`platform/installer/client-requirements.lock` dependency set in an isolated
directory. A virtual environment that points into Homebrew or a build cache is
not an installed runtime. The package builder copies its inputs into independent
regular files and never downloads or installs dependencies itself.

```sh
python platform/installer/package_client.py \
  --python-root /absolute/prepared/python \
  --dependencies /absolute/prepared/dependencies \
  --frontend /absolute/prepared/agentmux-runtime \
  --foundation-installation FOUNDATION_INSTALLATION_ID \
  --output /absolute/private/client-package \
  --selection-output /absolute/private/client-installation-selection.json
```

The output and selection must be new paths. Keep the selection in a user-owned
`0700` directory with mode `0600`. Independently review and retain its printed
`selectionDigest`; reading the digest from the same untrusted source as the
selection does not authorize that source. The selection has exactly
`schemaVersion`, `packageDirectory` and `manifestDigest` fields.

Run `agentmux-install verify-client --selection ABSOLUTE_PATH
--selection-sha256 APPROVED_DIGEST --owner-uid USER_UID` for read-only verification.
After reviewing that candidate, the administrator uses `install-client` with
the same arguments. The matching foundation must already be installed.
The installer does not elevate itself, overwrite an existing package, repair
permissions, select a profile or start services. An interrupted or conflicting
installation remains unavailable for inspection; a retry never replaces it.
An exact existing package is reused without rewriting it.

After the matching frontend is explicitly published, the fixed entrypoint is:

```sh
'/Library/Application Support/Agentmux/Protected/agentmux-runtime' \
  mcp --client-installation CLIENT_INSTALLATION_ID \
  --selection /absolute/private/client-enrollment-selection.json
```

`startup` uses the same arguments for the existing startup report. The client
enrollment selection is the existing private user enrollment document; it is
different from the administrator's installation selection.

The retained central-profile caller can pass six fixed operation values to the
protected client: `startup`, `startup-json`, `startup-worker`,
`startup-worker-json`, `mcp`, and `mcp-worker`. The bootstrap maps the worker
variants to `--managed-worker` and the JSON startup variants to `--output json`.
Both MCP variants include `--enrolled`. Every variant preserves the admitted
selection path and uses the existing session cleanup. The direct public verbs
above keep their existing argument forms.

For a caller with an explicit repository root, `ExecRepository` retains the same
protected admission and starts the private bootstrap form
`repository-client OPERATION REPOSITORY_ROOT`. It accepts only those six
operations and a bounded, canonical absolute repository path. The bootstrap
passes the literal root as `--repository-root` to the existing client. That client
reads the repository's untrusted profile ID, then enters native central-profile
resolution before the final enrollment selection is used. Public imports keep
their usual package roots; this route adds no service or credential imports.

After native central resolution rechecks the registration, profile, host policy
and client selection, `ExecRegistered` duplicates only its retained registration
descriptor. The private bootstrap form is
`registered-client OPERATION SELECTION DESCRIPTOR REGISTRATION_SHA256`.
Environment and project values stay out of arguments and environment variables.
The duplicate is read without changing the original offset, bounded to 16 KiB,
checked against its digest, and closed before entering the client. Failed exec
closes the duplicate while leaving the original with the central owner.

The bootstrap supplies a frozen `RegisteredProfileContext`. The existing
selection reader checks its selection digest, profile ID and instance ID against
the exact bytes used for startup. Only the contained frozen `ProfileContext`
continues into the session, with the supplied environment and project fields.
These are display values. They do not grant application access or authorization
scope. An explicit selection without a registration keeps metadata absent.

`launch-claude-desktop` uses the same installation and selection arguments. Its
bootstrap calls `hub.client_launch_desktop.main` with only that selection. The
named launcher reports the enrolled startup result, joins startup cleanup, and
opens the fixed `/Applications/Claude.app` bundle when infrastructure is ready
or degraded. It accepts no application path or extra launch arguments. See
[the Desktop launcher](CLAUDE_DESKTOP_LAUNCHER.md) for prerequisites and limits.

The installed setup command uses the same protected admission:

```sh
'/Library/Application Support/Agentmux/Protected/agentmux-runtime' \
  client-setup --client-installation CLIENT_INSTALLATION_ID \
  --selection /absolute/private/client-enrollment-selection.json \
  --receipt /absolute/private/desktop-registration-receipt.json \
  --operation install
```

Arguments use the order shown. This checks prerequisites without editing
settings. A final `--apply` explicitly applies the operation. The other fixed
operations are `remove`, `restore` and `recover`; keep the private receipt for
ownership and recovery. The setup command selects Claude Desktop settings under
the native account's home directory, ignoring a caller-supplied `HOME`. It does
not start services. The installed bootstrap calls `dashboard.client_setup.main`
with these exact arguments, and that command retains its own package and
enrollment admission through any settings publication.

An explicitly enrolled application attestor is selected with the paired
`--application-attestor-selection` and
`--application-attestor-selection-sha256` arguments on `ensure` or `host`.
The frontend forwards those exact values only when creating a new host. The
host admits the private record and its independent digest before composing the
application attestor. Reusing an already running host does not restart it or
change its authority. The ordinary client forwards this pair only from its
explicit enrollment; the protected package itself supplies no application key
or broker grant.

An enrolled service process also requires all three explicit `ensure` or `host`
arguments: `--application-services-installation`,
`--application-services-selection` and `--application-services-selection-sha256`.
They must accompany the attestor pair. The host derives its protected named
account and broker description from the admitted local configuration. The
identity service uses the attestor's separately admitted application account
with distinct credentials and a matching pinned connection. A new host
receives these literal pins and retains the original service process through
cleanup; an existing host keeps its current selection. Omitted service pins
preserve the attestor-only route. These arguments neither create enrollment nor
authorize a business command.

The private host service process enters the bootstrap with exactly
`application-services`. This is not a public frontend command. Only that branch
adds the protected `app/dashboard` and `app/taskmgmt` import roots and calls
`application_service_process.main()` without arguments. The native owner sends
the closed start and stop messages on stdin and supplies its retained lease on
descriptor 3. The receiver admits the selected service enrollment before opening
resources; its state messages do not grant business access.
The package includes the receiver's explicit production modules and the fixed
`dashboard/auth.json` definition metadata. Provider credentials, histories,
checkpoints, backup keys and project definitions remain enrolled data outside
the protected package.

The frontend retains protected admission through its final recheck, then
replaces itself with the pinned interpreter using `-I -S`. The current working
directory and standard streams are preserved. Python ignores ambient import
paths and adds only the protected application, SDK and dependency directories.
Startup performs no installation or download. The existing client session owns
startup, MCP handling and cleanup; the MCP session is not subject to the
infrastructure frontend's ten-second lifetime. Protocol stdout stays reserved
for MCP messages.

Settings publication needs a retained admission owner through the write.
`InstalledClientAdmission.Declaration` returns the client ID, stable command,
exact arguments, enrollment reference and `stdio` transport after checking the
package and frontend. Serialized fields alone are not retained admission and do
not authorize settings publication or application operations.

Focused local checks cover installer copy/reuse/refusal, manifest and selection
bounds, library closure, retained file identity, command arguments and the
package builder. Actual installed qualification must also invoke the stable
command outside the checkout, verify package-only imports and MCP stdout, and
join the original client's cleanup. Staging checks alone do not satisfy that
installed behavior requirement. The beta target remains native macOS ARM64.
