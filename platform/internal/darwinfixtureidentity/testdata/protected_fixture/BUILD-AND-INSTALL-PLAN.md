# Protected helper fixture proposal

This fixture tests the internal process-identity helper. It does not qualify the real installed Agentmux CLI, a signed product release, NATS, Docker Compose or a phase gate.

The user authorized autonomous local macOS ARM64 build and verification. The first build succeeded with digest `sha256:d0113574435bb5472ab607585306adb159add887b835494e822abc7ca49b8c43`. It is retained as historical build evidence and must not be installed for the repaired controls below. No privileged installation has run.

## Minimum build

After review of the fixture and separately tagged candidate controls, build one native ARM64 binary with the already verified Go 1.27.2 toolchain:

```sh
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOTOOLCHAIN=local GOWORK=off \
  /Users/ryan/.cache/agentmux-governance/native-go-1.27.2-darwin-arm64/go/bin/go \
  build -mod=readonly -trimpath -buildvcs=false \
  -o /Users/ryan/.cache/agentmux-governance/darwin-protected-helper-candidate/build/fixture \
  ./internal/darwinfixtureidentity/testdata/protected_fixture
```

Run from the platform module. Create the private cache directory as the ordinary user. Capture source and module hashes before and after, the exact command, toolchain identity, exit status and binary digest. Building does not execute the fixture or grant process-control authority.

The fixture has four modes: a fast completed command, a frontend, a host with the helper's fixed invocation grammar, and a role. It accepts no control PID. Every process in a family shares the same absolute deadline of at most 15 seconds. EOF gates provide cooperative cleanup without an unbound signal.

The frontend waits for a private readiness byte after the host finishes its role-spawn attempt, then emits one fixed readiness marker. Host and role output cannot hold the frontend's output pipes open. A separate frontend gate lets the test join the original frontend and observe the host after reparenting while the family remains alive. A third inherited pipe carries one fixed success byte from the host only after EOF cleanup and successful sole Wait operations for all roles. The frontend closes its copy of that writer after starting the host. The test requires that byte followed by EOF.

## Protected installation, separately reviewed

The actual Go-generated manifest is pinned by `sha256:50fa419183c3e5e343996188d2ae45ed5c53e4aad5c0ef0156e4aa3397033d26`. It binds a fresh release ID independent of the payload digest. This supersedes the initial content-derived directory proposal. Use these manifest-derived paths; do not substitute a directory derived from the binary hash:

- `/Library/Application Support/Agentmux/Protected/releases/63985d14edaa6bcc3c6f7103ce49ecb7f4b2deec213a4c261ca7ec73a48c0f9f/fixture`
- the same release's `bin/boot`
- `bin/kernel-lifecycle`
- `bin/internal-communication`
- `bin/exported-status`

The same binary bytes serve each path. They remain distinct, fixed role paths. The four-member assembly uses exact JSON hashes and separately supplied external `assembly.Trust`. This is not a cryptographic release-signature test.

Coordinate with the reviewed installer owned by Ohm and the main planning session. The installer must consume validated descriptors or stdin bytes; it must not reopen a user-owned staging pathname as root. Do not use an unreviewed `/usr/bin/install` command. Do not overwrite, remove or adopt an existing release based only on its pathname. Required directories and executables must satisfy the existing protected-root, ownership, mode, ACL, mount and digest checks. Preserve exact installation and cleanup ownership and report uncertain failures.

No privileged install or removal is authorized by this document. Inspect and review the actual built digest, exact paths, installer source and bounded setup command first.

## Controls after installation

The separate protected-candidate tag must fail if fixture prerequisites are absent; it must not substitute skips or placeholders. Controls must exercise the actual helper API using its private exact-tuple candidate constructor while proving normal `NewCreator` still refuses SDK 27.

Required cases include joined fast exit without invented proof, rejected prelaunch digest, invalid command arguments, real closed host grammar, frontend exit and immutable creation lineage, all four verified role images, and missing, extra or ambiguous role refusal. Each admitted proof must retain its exact watch and image owner through cleanup. Close gates, join the original frontend once, observe exact host and role exits, and preserve cleanup failures. Observation-only watches cover every role in rejected rosters without granting full proof or signal authority. Start cleanup at least three seconds before the family hard deadline, then use one shared two-second deadline for frontend join, the host success receipt, every exit observation and descriptor release. A forced deadline exit without a success receipt must fail. No per-process timeout reset is permitted.

These controls are prerequisites for review of native SDK qualification. They cannot replace the real installed CLI, signed release, multi-hub or other P02 acceptance tests.

## Review finding and rebuild requirement

Independent review found that the initial controls could accept a forced 15-second exit while waiting up to 17 seconds for cleanup. The receipt and shared deadline repair closes that false-positive path. Rebuild the changed fixture once after source review, then run the bounded pure validators and compile the separately tagged protected controls without executing them. Review the new actual binary digest and descriptor installer before installation. Do not substitute the earlier binary or describe a compile-only result as a protected test pass.

The parent also binds an observation-only host exit-status watch to the full native host proof. It requires NOTE_EXIT and NOTE_EXITSTATUS, no exec or error event, and status zero within that same deadline. The receipt alone does not prove the host's final writer close succeeded. Current Apple source and installed SDK declarations explain the flag; actual same-user registration and status observations remain required controls, not assumed compatibility.

## Ordinary-user verification plan

The exact reviewed environment and argument vectors are captured in `/private/tmp/agentmux-protected-run-plan.json`. Root setup must first succeed under the separately reviewed installer source and manifest. Then run `TestProtectedCandidateLoaderAdmission` alone from a verified source snapshot: the actual runtime loader holds the direct fixture image and all four verified role images together, checks both owner close results, and spawns no process.

Only after loader admission succeeds, run these six protected test cases with both candidate tags and the bootstrap tag: FastCompletion, WrongDigest, InvalidArguments, ReparentedRoles, HostRefusals and RoleRosterRefusals. Require all six top-level tests and five declared subtests. The wrong-digest control first admits the correct installed image; invalid arguments must produce exact exit status 70 and `fixture_mode_invalid` stderr. Any skipped prerequisite, missing named test, unexpected output, failed receipt, missing exit status, nonzero host status or cleanup uncertainty fails verification.

The current payload remains `sha256:ab3e8296d4fe5235e5a1c3fbe2abb6727145290641bf0797a159921fde5ac955` (4,250,978 bytes). Test-source changes require a fresh controller build; they do not require rebuilding that unchanged fixture payload. All protected execution remains pending actual setup and independent review.
