# P01 environment inventory contract

Current delivery scope: the initial beta is native macOS ARM64 only. Linux and Intel Mac qualification are deferred; Windows/WSL examples below are retained historical format documentation, not supported beta targets. Under `DELIVERY-LOCAL-01`, run verification locally and do not run CI until all P00–P14 gates are complete.

Run the standalone synthetic suite on Windows, WSL, Linux or macOS:

```sh
python -m unittest discover -s tests/platform -p "test_*.py" -v
python tests/platform/inventory.py tests/platform/fixtures/wsl-inventory.json
```

This reusable validator reads a caller-selected JSON file and prints its result without modifying the input or machine. It starts no broker, terminal client, model or network connection. The fixture is explicitly synthetic: its commits, hashes, commands and versions are test values, not execution evidence. CI may run it with the commands above. It is separate from SDK wire-contract qualification.

Version 1 is a closed record format defined by `inventory.validate`. Required inventory fields describe the platform, runtime placement, observation time, full candidate commit, record kind, explicit limitations and clients. Each client records search scope, installation/configuration/authentication ownership, a stable target, its runtime launcher, copying/duplicate-install flags, interop limitations and probe observations. Each probe records the surface, command, exit code, version, installation identity and evidence SHA-256. Do not include credential values, private configuration, model reasoning or environment dumps.

Installation identity includes both `executableTarget` and `stableTarget`. For a direct executable they are the same. For an npm client, `executableTarget` is the stable Windows Node path and `stableTarget` is the package's stable script entry point. Both probes must bind both paths through `executable` and `installation`; equal Node paths alone cannot establish the same client. A direct probe command must start with the executable and, for a script client, that package entry point. A WSL probe command starts with the recorded launcher. These are recorded identities requiring evidence review, not an independent inspection of executable contents.

For WSL, the runtime stays Linux and each installed Windows client remains owned by Windows, including authentication and configuration. Both direct Windows and WSL probes must identify the same stable Windows installation; successful observed clients must report the same version. A Windows drive path is required for the installation and an absolute Linux path for its launcher. Explicit version directories are rejected. This syntactic check cannot prove that an arbitrary path or update alias is stable; actual host review remains necessary. Native Linux and macOS records retain native runtime and client ownership and require their own native probe.

A missing client is a valid inventory observation only when it records the search boundary and has no invented installation or probes. An unavailable client retains failed probe results, including a null version for a failed probe. Neither status means client support passed. The `linuxDuplicateInstalled` flag means a duplicate introduced for Windows forwarding, not the mere presence of an unrelated retained Linux installation. All claims and source evidence still require independent review; supplied hashes alone do not authenticate an observation.

Every record retains explicit unverified P06 limitations for authenticated workflows, hub callbacks, concurrent sessions and unchanged-launcher Windows updates. `p06Accepted` must remain false. This P01 format intentionally cannot certify P06; a later qualification format must retain the original observations rather than relabel them. The existing `delivery/evidence/P01/windows-clients` archive provides machine-specific observations, not a completed record in this format. Collect any missing direct-Windows/WSL identity evidence before calling a real inventory complete.

The tests reject mismatched ownership, installations or versions; invented missing-client success; Linux substitution; credential copying; duplicate-install claims; missing evidence or limits; and placement changes. They also verify native placements and a read-only failing CLI invocation. This is a plain validation boundary and data record, not a new product plugin or runtime design-pattern location.

## Native P02 named cohorts

The unlinked-descriptor experiment is opt-in under `agentmux_darwin_descriptor_research`.
`native_go.py --darwin-research` enables that tag and requires the actual named
research result; an empty successful package is refused. The experiment remains
failed and unqualified: historical and fresh SDK26.5 captures report `/dev/fd/3`
permission denial. Its function and assertions are preserved, not converted into
an expected pass. Unlinked-FD execution is not a required P02 product strategy.
Default tests retain the research child marker and the independent product
fail-closed assertion. Protected installed-image and normal host qualification
remain separate requirements; diagnostic relocation does not accept the phase.

`native_go.py --darwin-cohort` routes to the same enrolled, clean-candidate collector as `native_compose.py`. Existing default commands remain unchanged. Each invocation selects one exact set of tests, reports omitted cohorts, and keeps `phaseAccepted` false. A successful cohort is not a complete P02 gate.

| Cohort | Required installed artifact | Scope |
| --- | --- | --- |
| `darwin-frontend-budget` | None | Four original frontend deadline controls |
| `darwin-frontend-receipt` | `frontendReceiptChild` | Actual receipt-child completion and near-expiry behavior |
| `darwin-signed-role-lifecycle` | `signedRelease` | Six owned role/session lifecycle controls with native TLS NATS |
| `darwin-live-role-recovery` | `signedRelease` | Actual four-process degradation, whole-group recovery and TLS broker reconnect/exhaustion |
| `darwin-installed-cli` | `signedRelease` | Six real Docker installed-CLI scenarios |
| `darwin-installed-cli-port` | `signedRelease` | Occupied selected-port failure and recovery |
| `darwin-installed-cli-slow-consumer` | `signedRelease` | Actual stalled subscriber, revision gap and recovery with installed status and same persistence |
| `darwin-creator-history` | `frontendReceiptChild` | Two actual creator-bound history controls |
| `darwin-startup-owner` | `signedRelease` | Owner death before any role starts, followed by retry |
| `darwin-runtime-rollback` | `runtimeFixture` | Three actual protected partial-start rollback controls |
| `darwin-normal-self` | None | Normal SDK 26.5 admission and actual self-identity layout |
| `darwin-normal-identity` | `cooperativeIdentity` | Seven normal-admission protected identity controls |
| `darwin-normal-parent` | `runtimeFixture` | Actual parent EOF, inherited leases and owned reaping |

The normal qualification profile uses the canonical macOS SDK 26.5 with explicit per-command SDK selection; it does not change the machine's default SDK. Historical SDK 27 candidate controls remain separate prequalification work. These cohorts never enable diagnostic ABI tags or treat candidate identity results as normal SDK enrollment. Successful self-admission alone does not qualify protected child processes. The startup-owner scenario uses a preexisting broker and stored record; it does not claim cold broker creation or owner death after partial child spawning.

Live role recovery uses actual public NATS messages, not the cached L04 frames used by the separate session lifecycle controls. Its member-recovery boundary is stopping and re-preparing the whole owned group, not replacing an individual member in place. The installed slow-consumer cohort uses the same real runtime, broker, volume and stored record for its status and preservation assertions; it does not claim internal actor queue-overflow coverage. Source review and compilation alone do not qualify either cohort.

Use the repository-pinned Python 3.14.8 with the exact SDK requirements. Python 3.12 with `--no-deps` is not equivalent: it also needs `referencing`'s conditional dependency, which is absent from the nine-package lock. Do not weaken SDK validation to hide an import failure.

Every run requires an explicit native target, committed candidate, separate disposable workspace/evidence directories, and independently pinned engine selection and tool prerequisites. Installed cohorts additionally require both `--cohort-prerequisites` and `--cohort-prerequisites-sha256`. The prerequisite bundle is a private `0600`, current-user, single-link JSON file with the closed fields `schemaVersion: "2.0.0"`, `target: "darwin-arm64"`, `currentTupleSHA256`, and `groups`.

Groups are purpose-specific: `signedRelease`, `frontendReceiptChild`, `cooperativeIdentity`, and `runtimeFixture` are not interchangeable. Each carries its reviewed plan, installation receipt, current-candidate rebuild-match evidence, exact installed member inventory, and only the applicable policy/CLI plan references. Referenced records have separate byte pins. Runtime fixtures must carry the fixed purpose `native_runtime_five_member_test_artifact_only` and five copies of the same admitted image. The closed record validation and exact test names live in the collector source; the pure controls exercise their permitted shapes.

Create installation and candidate-match attestations only after reviewing actual complete installer receipts plus zero exit and fresh binary correspondence. A hand-written `passed` field, source digest, successful compilation, or historical installation alone is not that evidence. The collector rechecks installed bytes and delegates actual protected admission to the selected tests; it never installs a prerequisite or elevates as a fallback.

Raw Go JSON, stderr, commands and hashes stay in the private capture. Docker cohorts retain the existing exact engine lease and cleanup records. Missing names, skips, unfinished tests, race warnings, timeouts, changed inputs, or uncertain cleanup fail the run and prevent scheduling it as accepted evidence. Recover only through the retained exact owners; do not discover or signal a PID from a diagnostic record.

Subtest names below their top-level owner are opaque: a slash can be part of a sibling's name. The collector checks active top-level ownership and complete observed run/terminal pairs, not a nested tree inferred from prefixes. Reports explicitly set `parentageScope: "top-level-ownership"` and `nestedParentageVerified: false`; actual nesting also relies on the pinned Go harness and its joined successful process. Historical admission failures remain unchanged when a corrected collector produces a separate diagnostic review.
