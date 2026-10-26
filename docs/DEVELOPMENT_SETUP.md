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

Package preparation needs no administrator. To install the reviewed selection on
the developer's own machine, use the existing administrator boundary:

```sh
sudo -n "$AMUX_DEV_DIR/agentmux-install" install \
  --selection "$AMUX_SELECTION" --selection-sha256 "$AMUX_SELECTION_SHA" \
  --owner-uid "$(id -u)"
```

Use only this specific authorized command. If administrator authentication is
needed, follow the current client's permissions and have the user authenticate
locally; never request or expose a password. This installs a new digest-named
foundation. It does **not** switch the shared launcher, start services, install a
Python client, register a profile or prove readiness. Replacing a shared launcher
requires its exact current digest and consideration of existing registrations;
follow [platform installation](PLATFORM_INSTALLATION.md).

Complete these receiving-machine steps in order, using the existing owners:

1. **Build/install the ordinary client.** Follow
   [the installed client package guide](INSTALLED_CLIENT_PACKAGE.md). Use the
   returned foundation installation ID, exact standalone Python 3.14.4,
   `client-requirements.lock`, this runtime, and this machine's admitted native
   tool selection. The builder is `platform/installer/package_client.py`; inspect
   its `--help`. `agentmux-install verify-client` precedes explicit `install-client`.
   If the complete locked dependencies are already cached, prepare an isolated
   directory with the command below. A missing cache entry is a concrete missing
   prerequisite; follow the user's download authorization before fetching it.

   ```sh
   AMUX_PYTHON_ROOT=$("$AMUX_PYTHON" -I -c 'import sys; print(sys.prefix)')
   uv pip install --offline --python "$AMUX_PYTHON" \
     --target "$AMUX_DEV_DIR/dependencies" --no-deps \
     --requirement "$AMUX_REPO/platform/installer/client-requirements.lock"
   ```

   Set `AMUX_FOUNDATION_ID` to the installation ID returned by this foundation's
   successful `install`, and `AMUX_CORE_TOOLS` to the new machine's reviewed native
   core tool selection. Then run the existing builder from the repository root:

   ```sh
   cd "$AMUX_REPO"
   "$AMUX_PYTHON" platform/installer/package_client.py \
     --python-root "$AMUX_PYTHON_ROOT" \
     --dependencies "$AMUX_DEV_DIR/dependencies" \
     --frontend "$AMUX_DEV_DIR/agentmux-runtime" \
     --foundation-installation "$AMUX_FOUNDATION_ID" \
     --native-core-tools "$AMUX_CORE_TOOLS" \
     --output "$AMUX_DEV_DIR/client-package" \
     --selection-output "$AMUX_DEV_DIR/client-selection.json"
   ```

   Review the builder's returned selection digest and use it with `verify-client`
   and the authorized `install-client`. This selection installs a package; it is
   different from the later client's private enrollment selection.
2. **Prepare local identity and application enrollment.** Use this machine's
   credentials, broker/TLS authority, workspace paths, identity/message/Work
   application selections and current grants. Follow
   [client startup](CLIENT_STARTUP.md) and
   [native client setup](NATIVE_CLIENT_SETUP.md). Ryan's retained test fixture,
   profile registration, release selection and credentials are not portable input.
   Test-only `identity/bootstrap.py` and old `launcher/testdata` scripts are not a
   general production enrollment command. Do not run historical helpers containing
   another user's absolute paths.
3. **Create/register the profile through the owner.** Prepare the complete private
   `prepare-owner-profile` request, including its already enrolled `coreHub`
   selection for core commands. Preview using `--request` and the independently
   reviewed `--request-sha256`; apply that same request with `--apply` only after
   review. Follow the request shape and recovery instructions in the native client
   setup guide. Do not invent grants or patch registration/database files.
   The request's release directory must identify the new installed foundation
   under `/Library/Application Support/Agentmux/Protected/releases/`, and its
   runtime path/digest must identify the admitted installed executable. Do not
   substitute the writable staging paths from `foundation-selection.json` for
   installed host policy. Review and pin the complete new owner request separately.
4. **Select the repository profile.** Its `.agentmux/config.json` references the
   admitted central profile ID. Project and/or environment belong in the profile;
   at least one is required. A display name such as `Nick - agentmux - dev` is a
   label, not authorization. Use the actual generated profile ID, not the example
   ID in a guide. Keep private profile metadata outside version control.
5. **Verify, then run.** Run `agentmux-install check --host-policy PATH --workspace
   REPO` with the actual local private policy. Start the selected Hub in the
   foreground, then check `ping`, `status`, Work and events using the commands in
   the platform installation guide. Keep the original operation ID for uncertain
   spawn/kill/Work retries. Stop and join owned resources after testing.

There is currently no single supported command that invents all fresh-machine
identity, broker and core application grants. If the documented owner inputs or
provisioning route are missing, record the exact remaining setup blocker in Jira
and implement its bounded prerequisite. Do not report that a signing key, successful
package preparation, a passing unit test or an infrastructure-only profile supplies
those grants. No step here requires Ryan's private signing key.

## Continue the assigned implementation

Once the required local setup actually passes, return to the earliest eligible
Jira task and its latest review findings. Run the smallest relevant reproduction,
then affected tests and review. Keep failed/uncertain attempts distinct. Record
safe non-blocking improvements under `post-initial-release`; fix demonstrated
required-flow, authorization, data-retention and cleanup blockers before acceptance.
No CI, branch transfer, production release or broad backlog activation is implied.
