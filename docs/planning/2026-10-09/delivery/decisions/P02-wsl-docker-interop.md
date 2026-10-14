# P02 Windows-owned Docker CLI backend

Codex approves this additional backend for P02 implementation on October 13, 2026. This supplements L03; it does not rewrite the accepted P00 decision or claim P02 qualification is complete.

WSL may invoke the explicitly enrolled Windows-owned `docker.exe` and Compose installation against an approved local Docker Desktop Linux engine. Agentmux runtime processes, enrolled profile, credentials and held file locks remain in the selected distro's Linux filesystem. Windows manages the Docker client installation and updates. The launcher must detect a changed client or engine and check compatibility before mutation.

The alternatives remain native Docker Desktop WSL integration or an approved local Linux daemon. Installing another client/daemon would duplicate ownership; changing Desktop settings could disturb existing services. Explicit Windows interoperability fits the user's shared-installation requirement and passed a bounded real fixture. It adds argument, path and transport qualification requirements.

## Evidence reviewed

Root inspected the actual fixture source and result, independently verified all eight archive file hashes, and checked the thirteen original container identities, states and ports across six guards and final cleanup. See `../evidence/P02/docker-interop-preflight/manifest.json` and `actual-fixture-result.json`.

The actual client and engine were 29.8.0, Compose 5.5.1, with explicit `desktop-linux` context and the same recorded local Linux engine identity. Native WSL `nats-py` authenticated through loopback, published and read a probe from a stream requested with FILE storage, and retained that record through same-container Compose reuse. The fixture container is stopped and its named volume remains. No Desktop, networking, firewall or unrelated container changes were made. Mounted native Linux Docker integration remains unavailable.

The pinned fixture image was the official NATS 2.15.0 Linux/amd64 manifest `sha256:fdae708d900cb150ce13f203359719bdd9cefd3dbbbc32a4c6224b23ea3e0b2c`. Registry manifest bytes and exact RepoDigest bound that image. An engine's image ID must not be assumed to equal its OCI configuration digest. Other target architectures require their own reviewed manifest pins and actual runs.

## Required implementation checks

- Enroll the backend, absolute executable, selected distro, context, local endpoint fingerprint and engine identity explicitly. Reject unexpected `DOCKER_HOST`/`DOCKER_CONTEXT`, remote TCP/SSH daemons, changed ownership or endpoint before mutation. Never silently fall back to another backend.
- Use literal argument arrays and bounded calls. Stream Compose configuration through stdin when suitable. Linux paths cannot be passed as Windows host paths without an explicit qualified conversion. The fixture qualifies no host bind mounts.
- Retain L01/L02 ownership, lock, release, resource identity, port and authenticated readiness requirements. Loopback reachability in this fixture is an observation, not a universal WSL networking assumption. Failure returns a clear bounded error; no automatic proxy, firewall, networking or Desktop repair.
- Warm production reuse performs inspection and authenticated readiness only. The fixture's repeated `compose up` establishes retained identity, but does not approve that command for warm production reuse.
- P02 must qualify actual cold/warm/concurrent startup, killed lock owners, wrong context/identity/version, port conflict, partial startup and durable restart. Native macOS/Linux checks remain mandatory. The basic fixture is not kernel boot, account isolation, crash/power-loss durability or production acceptance.

Compose 5.5.1 is the tested WSL implementation candidate; the earlier 5.6.0 recommendation remains historical. Select and lock the actual supported version set during P02 qualification. A Windows-managed update must not silently authorize a new untested Compose version.

P02-T07 owns this backend and its checks. P02-GATE owns final qualification. P06 still owns actual installed terminal hooks. Rollback disables this new opt-in backend and stops only exact-owned new resources while retaining volumes and profile identity. No merge or release is authorized.
