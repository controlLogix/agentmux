# Private host configuration loader

`launcher.LoadBootstrapConfig(HostPolicy)` combines an enrolled private profile with a separately trusted signed installed release. It reads and validates private configuration; it does not enroll, install, write files, acquire a lease, start a process or contact Docker/NATS. Its returned `BootstrapConfig` contains secrets and belongs only to trusted bootstrap code. Never print or serialize that value for a user.

`HostPolicy` supplies `Profile`, `ExternalRelease`, lifecycle deadlines, startup timeout and probe timeout. Deadline caps match the existing bootstrap: 30-second start, 10-second stop grace, 10-second reap, 60-second total startup and five-second probes. File data cannot supply authority or override those deadlines.

The private canonical profile directory contains `runtime.json`, `broker.json`, and four fixed `<role>.json` files. Runtime metadata has exactly `schemaVersion`, `hubId`, `serverName`, `domain`, `storeDirectory`, `maxMemoryBytes` and `maxFileBytes`. The store is a clean `/data/` container path. Secret-bearing files must be regular, private, owned by the enrolled current user, have one hard link, and satisfy before/opened/after identity and size checks. Reads use the held-root direct nonblocking, no-follow opener and bounded byte limits.

The loader verifies the actual installed release with the external enrolled key/digest/authority/version/API policy. Broker pins come only from that verified release. It checks the enrolled Compose version, exact broker account factory, runtime storage settings and four role credential scopes, passwords and endpoints. Exact-number comparison prevents large integer limits from being rounded together. Exact credential and nested scope keys reject case aliases before typed decoding. The final deterministic Compose bytes include the profile ID, signed release/image and enrolled port; their SHA-256 must equal the profile's enrolled `ConfigDigest`. No partially populated configuration is returned after an error.

The current implementation supports only a local IPv4 plain-NATS profile. Remote/team profiles, local TLS, IPv6 and broader supported-environment qualification remain open; unsupported selections are refused, not silently remapped. Loading the configuration does not establish actual container ownership, network authentication, persistence or protected-role readiness.

## Combined source verification

The preliminary 36 focused checks remain historical. Independent review found a prerequisite profile-open race and role-file case aliases. The loader's exact-key checks fixed the aliases. The coordinator replaced the profile open with the shared direct-handle opener and integrated recursive exact-tag JSON decoding without reducing the private profile limit from 64 KiB to the separate 8 KiB wire limit.

The final frozen source passed 36 host-loader, 365 launcher, 55 protocol and 65 assembly test/subtest checks with race detection, plus clean vet. All 68 copied Go/module files remained unchanged. A protocol attempt initially failed because this worker omitted `AGENTMUX_TEST_NATS` for a new real-broker test. That setup failure is retained in `final/protocol-race.jsonl`. The exact failed test and then the affected protocol suite were rerun with the prepared NATS 2.15 binary on the same unchanged source; passing repair logs are separate. No skip, mock or narrow substitution erased that failure.

Actual signing keys and credentials in these tests are generated disposable fixtures, not user data. Independent review has no remaining findings in this bounded loader/prerequisite scope. Native macOS/Linux, remote/team operation, installed-host setup, full boot/Compose/recovery and phase acceptance remain coordinator-owned requirements.
