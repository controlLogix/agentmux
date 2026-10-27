# Set up the native development checkout

Use this guide when an agent continues work on another developer's Mac. It covers
the native macOS ARM64 development branch. The older harness instructions in the
root README describe a different installation path.

You do **not** need Ryan's private release key. Build the local images and use
`agentmux-dev-package` below. It generates a fresh development signing key in
memory, signs one package and discards the private key. Only public verification
material is saved. The repository distributes the preparation command, not a
shared private key or another user's enrollment.

## Take ownership before changing anything

1. Read `AGENTS.md`, `CLAUDE.md`, `.claude/rules/plain-language.md` and
   `docs/LOCAL_TESTING.md`. Read `handoff.md` if present. Check the actual branch,
   working changes and active agents/processes. Preserve existing work.
2. Use `feat/agentmux-platform-rearchitecture`. Read the current owning Jira issue,
   epic order, prerequisites and latest reviews through Atlassian Rovo MCP.
   Do not infer completion from this guide or an old handoff. Coordinate with the
   current owner before running tests against shared resources.
3. Confirm CodeGraph MCP can explore this checkout. Its generated `.codegraph/`
   stays untracked. If this receiving checkout has no index, initialize it using
   the installed CodeGraph CLI (`codegraph init` from the repository), then check
   `codegraph explore --help` and the MCP connection. Do not create a second index
   or substitute the graph for current source/tests and Jira outcomes.
4. Remove the root `handoff.md` once you have accepted the handoff and actually
   resumed work, as Ryan requested. Keep authoritative task status in Jira.

This setup repair is AMUX-726. Nick's AMUX-725 still owns installed spawn/recovery
qualification. Preparing a package does not finish that task or qualify the MVP.

## Check tools and repair only the missing prerequisites

| Input | Required source or version |
| --- | --- |
| Host | Native macOS ARM64, ordinary user, supported local storage with ownership enforced |
| Go | Exact `go` directive in `platform/go.mod` (currently 1.27.2) and existing `go.sum` |
| Compiler/SDK | A compatible Apple compiler, linker and macOS SDK; build with CGO enabled |
| Packaged Python | Standalone native ARM64 CPython **3.14.4**; see `platform/installer/package_client.py` |
| Client Python dependencies | Complete exact set in `platform/installer/client-requirements.lock` |
| Broker | NATS **2.15.0**, digest-pinned image selected below; Compose **5.5.1** |
| Native worker tools | The exact local tmux and Codex images selected and admitted for this machine |
| Provider login | Developer's own supported Codex/Claude authentication; keep credentials in native stores |

These are compatibility pins, not claims that each is the newest upstream release.
A newer Homebrew Python or Go does not replace a required packaged runtime.
Nick's `.venv` on Python 3.14.8 may remain separate from the packaged 3.14.4 runtime.

First look for prepared tools and cached dependencies. Use the exact toolchain,
`-mod=readonly` and the checked-in locks. If a tool is missing, follow the project's
download/administrator rules and the user's actual authorization; do not silently
download or update the whole machine. For example, a prepared Go 1.27.2 can be
selected by its absolute executable path. An already cached Go toolchain can be
selected with `GOTOOLCHAIN=go1.27.2`; set `GOPROXY=off` to refuse a network fallback.
With `uv`, an existing standalone Python can be located using
`uv python find --no-project --resolve-links --managed-python --no-python-downloads 3.14.4`.

For outdated dependencies, distinguish two cases:

* **The machine is behind the existing pin:** prepare the pinned version in an
  isolated location, then rerun the affected check. Keep other projects' tools.
* **The project pin itself needs an upgrade:** record the reason and compatibility
  impact in the owning Jira issue, update the relevant lock and version checks
  together, run affected tests and review the change. Rebuild/re-enroll affected
  immutable packages and tool selections through their owner workflows. Do not
  edit retained manifests, registrations or grants to make an upgraded binary fit.

Do not run `go get -u`, blanket Homebrew upgrades, unpinned package installs or CI
as part of this bootstrap. Changes to provider clients can also invalidate the
selected executable digest; recheck before a live worker test.

## Build the local native images

Start from the repository root. Set `AMUX_GO` to the actual prepared Go executable
on this Mac, and confirm `"$AMUX_GO" version` reports the version in `go.mod`.
Use separate lines for assignments; do not paste them as command-prefix assignments
whose variables are expanded before they are set.

```sh
AMUX_REPO=$(git rev-parse --show-toplevel)
AMUX_GO=/absolute/path/to/prepared/go/bin/go
export GOTOOLCHAIN=local
export GOPROXY=off
export GOSUMDB=off
export CGO_ENABLED=1
```

Nick observed Command Line Tools 26.6 with a default SDK link pointing to 27.0.
That combination failed during linking. Selecting his already installed 26.5 SDK
worked. On that machine, use this process-local setting before the builds:

```sh
export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk
```

On another Mac, inspect `xcode-select -p`, `xcrun --show-sdk-path` and the installed
SDKs. Select an actually installed SDK compatible with the active compiler/linker,
or update Command Line Tools under the user's authorization. Do not change a
system-wide SDK link or copy Nick's path if it does not exist.

Create a private working directory outside the checkout. Each attempt gets its
own output and log; preserve failures rather than overwriting them.

```sh
mkdir -p "$HOME/.cache"
umask 077
AMUX_DEV_DIR=$(mktemp -d "$HOME/.cache/agentmux-dev.XXXXXXXX")
export AMUX_DEV_DIR
cd "$AMUX_REPO/platform"
"$AMUX_GO" build -mod=readonly -o "$AMUX_DEV_DIR/agentmux-kernel" ./cmd/agentmux-kernel
"$AMUX_GO" build -mod=readonly -o "$AMUX_DEV_DIR/agentmux-runtime" ./cmd/agentmux-runtime
"$AMUX_GO" build -mod=readonly -o "$AMUX_DEV_DIR/agentmux-install" ./cmd/agentmux-install
"$AMUX_GO" build -mod=readonly -o "$AMUX_DEV_DIR/agentmux-dev-package" ./cmd/agentmux-dev-package
"$AMUX_GO" test -mod=readonly ./cmd/agentmux-dev-package ./cmd/agentmux-install ./installer -count=1 >"$AMUX_DEV_DIR/package-tests.log" 2>&1
```

Stop if any command fails. Unit tests do not qualify administrator installation,
enrollment, live Docker behavior or installed spawn/kill/recovery.

## Prepare and verify a development package

The following image digest comes from the signed manifest selected for the
previously installed development foundation. It is a public image pin, not a
credential. Preparation records it; it does not contact Docker or download the image.
Do not replace it with a tag or a guessed digest. Changing the selected broker
requires the affected owner checks and a matching prepared image.

```sh
AMUX_NATS_IMAGE='docker.io/library/nats@sha256:c5385888c04605faecc3379bdaa0cf9862cab97e40d328e0f1d9a505e5c12634'
"$AMUX_DEV_DIR/agentmux-dev-package" --development \
  --kernel "$AMUX_DEV_DIR/agentmux-kernel" \
  --runtime "$AMUX_DEV_DIR/agentmux-runtime" \
  --broker-image "$AMUX_NATS_IMAGE" \
  --output "$AMUX_DEV_DIR/release" >"$AMUX_DEV_DIR/prepared.json"
```

Read `prepared.json`. Success reports `purpose: local-development-only`,
`outcome: verified`, `enrollment: not_checked` and `readiness: not_observed`.
The existing installer verified the exact signature, assembly, native ARM64 images
and runtime pin. This is a format/image check; review the source and intended
local binaries before granting installation authority.

The output contains the nine-member `payload/` and a private
`foundation-selection.json`. The latter contains the **public** verification key,
local development authority, manifest digest and separate runtime pin. Every run
uses a different key and installation identity, even for identical binary inputs.
The signing private key is never saved, so rebuild the package after a change.

After reviewing the local preparation result, retain its `selectionDigest` outside
the package selection. Select the prepared standalone Python explicitly. With
`uv`-managed Python, the following lookup refuses downloads; otherwise set
`AMUX_PYTHON` to the existing absolute Python 3.14.4 executable path.

```sh
AMUX_PYTHON=$(uv python find --no-project --resolve-links --managed-python --no-python-downloads 3.14.4)
AMUX_SELECTION="$AMUX_DEV_DIR/release/foundation-selection.json"
AMUX_SELECTION_SHA=$("$AMUX_PYTHON" -I -c 'import json,os; print(json.load(open(os.environ["AMUX_DEV_DIR"]+"/prepared.json"))["selectionDigest"])')
"$AMUX_DEV_DIR/agentmux-install" verify \
  --selection "$AMUX_SELECTION" --selection-sha256 "$AMUX_SELECTION_SHA"
```

This is an explicit local owner's choice to trust a package built from their
reviewed checkout. It does not make the repository, a package's included public
key or a downloaded package a release authority. Official packages still require
independently trusted administrator policy. Never commit signing keys, private
selections, enrollment credentials, client packages or cache directories.

The command refuses root execution, an existing output directory, output inside
the checkout, non-private/linked output parents, mutable or linked input files,
unpinned images and packages rejected by the existing verifier. A failed attempt
may retain partial files at the requested output. Inspect them and use a fresh
output for a corrected attempt; do not delete other installations or data.

## Install, then initialize this user's enrollment

This is the sequence verified on Nick's Mac for AMUX-728 (profile 7, October 2026):
foundation and launcher install, client install, application runtime, enrollment
ceremony, profile preparation, installer check, startup, selected Hub start and
`ping`. Each step names its owner command. Do not patch registration, enrollment or
database files to get past a refusal; record the refusal in Jira and fix its owner.

### 1. Install the foundation and the stable launcher

Package preparation needs no administrator. To install the reviewed selection on
the developer's own machine, use the existing administrator boundary:

```sh
sudo "$AMUX_DEV_DIR/agentmux-install" install \
  --selection "$AMUX_SELECTION" --selection-sha256 "$AMUX_SELECTION_SHA" \
  --owner-uid "$(id -u)"
```

Use only this specific authorized command. The user types the administrator
password in their own terminal; never request or expose it. Record the returned
`installationId` as `AMUX_FOUNDATION_ID`. This installs a new digest-named
foundation under `/Library/Application Support/Agentmux/Protected/releases/`. It
does not start services, install a Python client or register a profile.

Clients call the stable launcher
`/Library/Application Support/Agentmux/Protected/agentmux-runtime`. On a machine
that has none, install it from the same selection:

```sh
sudo "$AMUX_DEV_DIR/agentmux-install" install-launcher \
  --selection "$AMUX_SELECTION" --selection-sha256 "$AMUX_SELECTION_SHA" \
  --owner-uid "$(id -u)"
```

To replace an existing launcher, add
`--replace-launcher-sha256 sha256:<current launcher digest>` (for example from
`shasum -a 256` of the installed file). An installed client only runs under the
launcher whose digest matches its packaged frontend, so replacing the launcher
stops older clients: build and install a new client afterwards (step 2). See
[client launcher integration](CLIENT_LAUNCHER_INTEGRATION.md).

```sh
AMUX_RUNTIME="/Library/Application Support/Agentmux/Protected/agentmux-runtime"
```

### 2. Build, verify and install the client

Follow [the installed client package guide](INSTALLED_CLIENT_PACKAGE.md). Use the
foundation installation ID, exact standalone Python 3.14.4,
`client-requirements.lock`, the runtime built above and this machine's admitted
native tool selection. If the complete locked dependencies are already cached,
prepare an isolated directory with the command below. A missing cache entry is a
concrete missing prerequisite; follow the user's download authorization before
fetching it.

```sh
AMUX_PYTHON_ROOT=$("$AMUX_PYTHON" -I -c 'import sys; print(sys.prefix)')
uv pip install --offline --python "$AMUX_PYTHON" \
  --target "$AMUX_DEV_DIR/dependencies" --no-deps \
  --requirement "$AMUX_REPO/platform/installer/client-requirements.lock"
```

Set `AMUX_CORE_TOOLS` to this machine's reviewed native core tool selection. Then
build, verify and install from the repository root. Each rebuild needs a fresh
`--output` directory.

```sh
cd "$AMUX_REPO"
"$AMUX_PYTHON" platform/installer/package_client.py \
  --python-root "$AMUX_PYTHON_ROOT" \
  --dependencies "$AMUX_DEV_DIR/dependencies" \
  --frontend "$AMUX_DEV_DIR/agentmux-runtime" \
  --foundation-installation "$AMUX_FOUNDATION_ID" \
  --native-core-tools "$AMUX_CORE_TOOLS" \
  --output "$AMUX_DEV_DIR/client-package" \
  --selection-output "$AMUX_DEV_DIR/client-selection.json" >"$AMUX_DEV_DIR/client-build.json"
AMUX_CLIENT_SHA=$("$AMUX_PYTHON" -I -c 'import json,os; print(json.load(open(os.environ["AMUX_DEV_DIR"]+"/client-build.json"))["selectionDigest"])')
"$AMUX_DEV_DIR/agentmux-install" verify-client \
  --selection "$AMUX_DEV_DIR/client-selection.json" --selection-sha256 "$AMUX_CLIENT_SHA"
sudo "$AMUX_DEV_DIR/agentmux-install" install-client \
  --selection "$AMUX_DEV_DIR/client-selection.json" --selection-sha256 "$AMUX_CLIENT_SHA" \
  --owner-uid "$(id -u)"
```

Success reports `"outcome":"installed"`. Record its `installationId` as
`AMUX_CLIENT_ID`. This package selection is different from the later private
enrollment selections.

### 3. Initialize the application runtime (once per installation)

Each installation owns a separate native `nats-server` 2.15.0 in operator/JWT mode,
apart from the protected infrastructure broker. `init` is create-only and
resumable; it generates the operator, accounts, TLS and JetStream configuration in
the per-user `application-runtime` directory. Pass the absolute path of the
admitted nats-server 2.15.0 executable on this machine.

```sh
"$AMUX_RUNTIME" application-runtime init --nats-server /absolute/path/to/nats-server
"$AMUX_RUNTIME" application-runtime start
"$AMUX_RUNTIME" application-runtime status
```

`status` reports the runtime ID, its `tls://127.0.0.1:<port>` endpoint and
`tlsNotAfter`, when its certificate expires. The port is chosen once from
20000–32767, below the system's temporary port range, and cannot be changed
later. Every enrollment pins the certificate, so it is issued for ten years
instead of being renewed; a runtime initialized before that change keeps its
397-day certificate, and `start` refuses an expired one with
`application_runtime_tls_expired`. Keep the application runtime running for
enrollment and for every profile that uses it. `application-runtime stop` stops it.

### 4. Write the private owner and setup requests

Create a private request directory (mode `0700`) under
`~/Library/Application Support/Agentmux/`, one per profile. Write each request
once, mode `0600`, and never edit it afterwards; a changed request needs a new
digest and a new review.

* `owner-request.json` follows the closed `prepare-owner-profile` format in
  [native client setup](NATIVE_CLIENT_SETUP.md). Use fresh `profileId`,
  `instanceId` and owner Hub ID values, `clientInstallationId` set to
  `AMUX_CLIENT_ID`, the release fields from `foundation-selection.json` with
  `packageDirectory` set to the installed
  `/Library/Application Support/Agentmux/Protected/releases/<AMUX_FOUNDATION_ID>`,
  and `runtimeExecutable` set to that directory's `agentmux-runtime` and the
  selection's runtime digest. `hostPort`, `composeProject`, `serverName` and
  `domain` must not collide with another profile's infrastructure broker on this
  machine.
* `setup-request.json` is the enrollment ceremony's input
  (`identity/local_enrollment.py`). It has exactly these fields:

  ```json
  {
   "schemaVersion": "1.0.0",
   "ownerRequest": {"path": "/abs/path/owner-request.json", "sha256": "sha256:<owner request digest>"},
   "projectId": "agentmux",
   "repositories": [{"root": "/abs/path/to/agentmux", "localName": "agentmux",
                     "normalizedRemote": "github.com/controllogix/agentmux"}],
   "localPeer": "nick", "localNode": "nick_mbp", "messagePeer": "ryan",
   "validityDays": 365
  }
  ```

  `repositories` must cover exactly the owner request's `approvedWorkspaceRoots`.
  `localPeer` and `messagePeer` must differ; `validityDays` is 1 to 397.

Record both digests (`"sha256:$(shasum -a 256 < FILE | cut -d' ' -f1)"`) as
`AMUX_OWNER_SHA` and `AMUX_SETUP_SHA`, with `AMUX_REQUESTS` set to the directory.
Preview the base owner request; it must report `request_checked`:

```sh
"$AMUX_RUNTIME" prepare-owner-profile \
  --request "$AMUX_REQUESTS/owner-request.json" --request-sha256 "$AMUX_OWNER_SHA"
```

### 5. Run the enrollment ceremony

```sh
"$AMUX_RUNTIME" application-enroll --client-installation "$AMUX_CLIENT_ID" \
  --request "$AMUX_REQUESTS/setup-request.json" --request-sha256 "$AMUX_SETUP_SHA" \
  >"$AMUX_REQUESTS/enroll-result.json"
```

The ceremony runs against this installation's application runtime. It writes
`application-enrollment/<profileId>/` (identity, definitions and integration
issuers, least-privilege users, the attestor and five client session selections)
and the profile's Hub home `hubs/<first 12 hex of the profile ID>/hub/`
(`federation.toml`, `config.toml` and `hub.db` with the default plugin schema).
Each profile gets its own reply subjects on the shared runtime. It is
create-only: rerunning with the same request reuses retained material, resumes
an interrupted run (keys from an unfinished first stage were never used and are
replaced) and brings `hub.db` back to a private, complete database. The
result's `coreHub` object (`selection`, `sha256`) pins the core Hub manifest.

### 6. Prepare the profile with its core Hub, recovering if needed

Write `owner-request-core.json`: the base owner request plus the `coreHub` object
from the enrollment result, and nothing else changed. Create it exclusively with
mode `0600`, for example:

```sh
"$AMUX_PYTHON" -I - "$AMUX_REQUESTS" <<'EOF'
import json, os, sys
q = sys.argv[1]
base = json.load(open(q + '/owner-request.json'))
final = dict(base, coreHub=json.load(open(q + '/enroll-result.json'))['coreHub'])
fd = os.open(q + '/owner-request-core.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
os.write(fd, (json.dumps(final, indent=1, sort_keys=True) + '\n').encode()); os.close(fd)
EOF
AMUX_CORE_SHA="sha256:$(shasum -a 256 < "$AMUX_REQUESTS/owner-request-core.json" | cut -d' ' -f1)"
"$AMUX_RUNTIME" prepare-owner-profile \
  --request "$AMUX_REQUESTS/owner-request-core.json" --request-sha256 "$AMUX_CORE_SHA"
"$AMUX_RUNTIME" prepare-owner-profile \
  --request "$AMUX_REQUESTS/owner-request-core.json" --request-sha256 "$AMUX_CORE_SHA" --apply
```

Success reports `prepared` and creates
`~/Library/Application Support/Agentmux/profiles/<profileId>/`. The apply has a
10-second deadline. Launchers built before commit 77ee9f0 took 7.4–8.5 s on
Nick's Mac and sometimes exceeded it; a launcher with that commit took 2.17 s.
If it reports
`review_required`, keep every file and run the supported recovery with the same
request and digest (preview first, then `--apply`):

```sh
"$AMUX_RUNTIME" recover-owner-profile \
  --request "$AMUX_REQUESTS/owner-request-core.json" --request-sha256 "$AMUX_CORE_SHA"
"$AMUX_RUNTIME" recover-owner-profile \
  --request "$AMUX_REQUESTS/owner-request-core.json" --request-sha256 "$AMUX_CORE_SHA" --apply
```

Recovery reported `prepared` in about 1 s. Its refusals and limits are described
in [native client setup](NATIVE_CLIENT_SETUP.md).

### 7. Check, then start the owner

```sh
AMUX_PROFILE=profile_<generated id>
AMUX_PROFILE_DIR="$HOME/Library/Application Support/Agentmux/profiles/$AMUX_PROFILE"
AMUX_ENROLLMENT="$HOME/Library/Application Support/Agentmux/application-enrollment/$AMUX_PROFILE"
"$AMUX_DEV_DIR/agentmux-install" check \
  --host-policy "$AMUX_PROFILE_DIR/host-policy.json" --workspace "$AMUX_REPO"
"$AMUX_RUNTIME" startup --client-installation "$AMUX_CLIENT_ID" \
  --selection "$AMUX_ENROLLMENT/client-selection-identity.json" --output json
```

`check` must report `enrollment_verified`. `startup` brings up the owner host
(`agentmux-runtime host --host-policy …`), its kernel roles, the attestor and the
application services. Its report can still say `progress` /
`observation_unavailable` while everything comes up, so confirm directly: the
services listen on the private browser port in
`$AMUX_ENROLLMENT/service-selection.json` (`localBrowser.port`), and the
repository's `.agentmux/agents/.owner-fence` names this profile's Hub ID.

### 8. Start the selected core Hub, then ping it

Run the Hub in its own terminal and leave it running; it stops when that terminal
or its parent process ends.

```sh
"$AMUX_RUNTIME" profile-core --profile-id "$AMUX_PROFILE" --repository-root "$AMUX_REPO" -- start
```

It logs `hub up <home>/hub/hub.sock` after about 8–12 s. From another terminal:

```sh
"$AMUX_RUNTIME" profile-core --profile-id "$AMUX_PROFILE" --repository-root "$AMUX_REPO" -- ping
```

A working Hub answers with `"caller": "operator"`, `lifecycleOperationIds` and
`workOperationIds` true. Use the other Hub commands (`status`, Work, events) from
[platform installation](PLATFORM_INSTALLATION.md). Do not use an older
`~/.local/bin/agentmux` wrapper; it belongs to the previous harness. Any failure
prints only `Selected core Hub setup or command failed. No default Hub was used.`;
record the profile and step in Jira rather than retrying with changed files.

### 9. Stop and retire a profile

Stop the Hub with Ctrl-C in its terminal. Stop the owner by sending `SIGTERM` to
its `agentmux-runtime host --host-policy …/<profileId>/…` process, then wait until
the host and its child processes have exited. Only one owner can hold the
repository's definitions at a time. Before enrolling a replacement profile, stop
the old owner, confirm `.agentmux/agents/.owner-fence` names the retired profile's
Hub ID and that neither it nor `.writer-lock` is open (`lsof`), then remove those
two files. Keep the retired profile's files for inspection.

### Known limits

* A launcher built before commit 77ee9f0 can exceed the prepare apply deadline;
  recover as in step 6, or install a newer launcher and client.
* `startup` may report `observation_unavailable` for a healthy start (step 7).
* Identity handler errors reach clients only as `identity_outcome_unconfirmed`,
  and the services process's stderr is discarded, so start failures need tracing.
* Retained ports (runtime and browser) cannot be changed after they are chosen.

Track these on AMUX-728. Preparing a package or passing unit tests does not
qualify installed spawn, kill and recovery (AMUX-725). No step here requires
Ryan's private signing key, and none of these private files belong in Git.

## Continue the assigned implementation

Once the required local setup actually passes, return to the earliest eligible
Jira task and its latest review findings. Run the smallest relevant reproduction,
then affected tests and review. Keep failed/uncertain attempts distinct. Record
safe non-blocking improvements under `post-initial-release`; fix demonstrated
required-flow, authorization, data-retention and cleanup blockers before acceptance.
No CI, branch transfer, production release or broad backlog activation is implied.
