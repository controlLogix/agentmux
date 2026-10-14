# Signed installed protected release

`launcher.LoadInstalledRelease` verifies one fixed installed protected package. It never executes a member, starts Docker, contacts a provider, writes configuration, enrolls a key or manages ordinary plugins. The host separately supplies the enrolled Ed25519 public key, expected parent-manifest digest, authority reference, release version and kernel API major. None of these trust inputs comes from the package being checked.

## Fixed layout and hash bindings

The canonical installed directory contains:

- `release-manifest.json`: exact `schemaVersion`, `releaseVersion`, `kernelApiMajor`, `releaseAuthorityRef` and `broker` fields. The authority has `id`, `ownerHubId` and `revision`. The broker has `image`, `natsVersion` and `composeVersion`.
- `release-authorization.json`: exact `schemaVersion`, `releaseVersion`, `kernelApiMajor`, `releaseAuthorityRef`, `assemblyDigest` and `releaseManifestDigest` fields.
- `release-authorization.sig`: exactly 64 binary bytes, an Ed25519 signature over the exact authorization JSON bytes.
- `protected-assembly.json`: the existing P01 protected-assembly contract and its four contained member files.

The parent manifest contains no assembly digest. Its SHA-256 is therefore calculated first, then referenced by the assembly. The separate signed authorization binds both the parent and assembly hashes. This avoids a hash cycle and prevents treating a self-reported parent reference as authentication.

Signature verification happens before deriving `assembly.Trust`. Both signed hashes must match actual bytes and the separately expected parent digest. Authority, version and API must agree with host policy and with the parent manifest. Broker declarations must use a digest-pinned `docker.io/library/nats` image, NATS `2.15.0` and Compose `5.5.1`. These are authenticated declarations, not evidence that an actual Docker image or running broker has been inspected.

The new metadata format requires integer-typed API and revision values. The protected assembly retains its existing validator and integer semantics. Metadata rejects missing, unknown, duplicate and null fields, invalid UTF-8, lone escaped surrogates, excessive nesting and trailing data. A package-supplied public key is an unknown field, never an authority source.

## Files and execution boundaries

The loader requires a canonical absolute, non-symlink installed directory and reads through its opened `os.Root`. Metadata is limited to 64 KiB per file; the signature must be exactly 64 bytes. Member preflight uses the same 128 MiB per-member and 256 MiB total limits as assembly verification. The assembly verifier also bounds actual bytes read and checks final size/hash, not just initial file size.

Metadata uses the shared direct directory-handle `assembly.OpenMember` operation. It refuses symlinks and special files without waiting on a substituted FIFO. The final `assembly.VerifyRoot` uses the same already-open directory root; it does not resolve and open a possibly replaced pathname again. This follows an observed negative test: Go's `os.Root.OpenFile` can resolve a symlink before applying the open flag, so that call alone was insufficient.

The result has private fields and returns copies of trust, assembly bytes and broker pins, plus the checked assembly. Failed verification exposes no partial trusted result. Paths and signatures do not establish race-free execution: the runtime must still stage, seal and verify the actual executable bytes. Size limits cannot interrupt a filesystem call that is already blocked. This implementation follows the supported Linux/WSL and native macOS source boundaries; Windows-native runtime support is not introduced.

## Verification and remaining scope

The final retained WSL run passed 68 release, 283 launcher and 65 assembly test/subtest checks with race detection, followed by clean vet. All 64 copied Go/module files remained unchanged. Test keys were generated in ephemeral memory only; no private key was stored in package fixtures, repository files or evidence. Tests exercise real Ed25519 signatures and actual contained files, malformed signed data, policy mismatch, byte tampering, unsigned whitespace changes, wrong keys, signature lengths, broker pins, fixed membership, traversal, symlinks, metadata/file size bounds and sparse oversized binaries. A controlled owned subprocess substitutes a FIFO or a symlink after the metadata check; it must return within its bound.

The earlier full-package build failed because the in-progress bootstrap referenced kernel-status APIs that had not yet landed. Its raw failure remains in `historical-missing-status-api/`; no release test executed in that attempt. A temporary explicit-file debug pass was not substituted for package qualification. The final run includes the landed APIs and actual updated rooted assembly implementation.

The coordinator owns installation-policy enrollment, bootstrap/CLI integration, source registration, the final candidate commit/push and phase acceptance. Real installed-host release/signing policy, native macOS/Linux boot, Docker qualification and complete supported-environment checks remain required. This verifier does not implement P04 identity/JWT or P03 ordinary-plugin installation and cannot authorize general kernel replacement.
