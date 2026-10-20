# TypeScript contract primitives

This independent Node 22 implementation validates the version 1 schemas, parses strict JSON, emits RFC 8785 canonical bytes and verifies Ed25519 ingress attestations and complete envelopes. It does not grant permission, resolve trusted signing keys, enroll clients or enforce durable operation replay. The caller must resolve the supplied key from an enrolled issuer and check current grants, transport mappings and business ownership.

The API exports `strictLoads`, `canonicalBytes`, `payloadDigest`, `validate`, `signClaims`, `verifyAttestation` and `verifyEnvelope`. Attestation verification checks signature, audience, issuer/reference ownership, UTC validity interval, deadline and payload digest. Envelope verification additionally binds the outer message fields to the signed claims. Signing is only a primitive; the ingress must first authenticate its caller and construct the claims.

Schema validation retains one compiled bundle for fast repeated checks. Each call reads the trusted schema directory once and fingerprints its absolute path, sorted filenames and exact bytes. Any change replaces the compiled bundle; the cache does not trust file timestamps or grow with arbitrary schema roots. Callers must control schema files and changes during deployment.

Raw JSON rejects invalid UTF-8, duplicate decoded property names, comments, trailing commas, lone surrogates, nonfinite numbers and integer tokens outside the safe integer range. Finite exponent/decimal values use the JCS binary64 number model. Parsing and canonical output are limited to 1 MiB and 64 nested containers. CLI frame limits exclude the newline; an oversized frame produces one error and is discarded until the next newline. Inputs must be plain JSON values without getters, custom serializers, sparse arrays or cycles.

## Isolated build and tests

Copy this directory to a disposable cache directory, then run `npm ci --ignore-scripts`, `npm run build` and `npm test`. Do not put installed dependencies or build output in the repository. Set these absolute paths for the tests:

- `AGENTMUX_SCHEMA_DIR`: repository `contracts/v1/schemas`.
- `AGENTMUX_CONTRACT_EXAMPLES`: repository `sdk/typescript/test-examples.json`.

The fixture is a promoted copy of the P00 example shape; its sample signature is replaced during tests. Passing tests qualifies these primitives, not the live ingress or broker authorization.

## Newline JSON CLI

Run the built `dist/cli.js` with Node. Requests use `op`:

- `parse`: `raw` JSON text.
- `canonical`: `value`; returns `{canonical, sha256}` with a `sha256:` prefix.
- `sign`: `claims`, `seedHex` (exactly 32 bytes); returns an unpadded base64url signature.
- `verify`: `attestation`, `publicKeyHex`, `expectedAudience`, `now`, `payload`.
- `verifyEnvelope`: `envelope`, `publicKeyHex`, `expectedAudience`, `now`.
- `validate`: `schema` and `value`.

Every response is `{ok:true,result:...}` or `{ok:false,error:...}`. Errors omit source payloads and credentials. Error names are implementation diagnostics, not cross-language protocol enums. The CLI is a conformance tool; never pass real signing seeds in routine task records or logs.

Exact dependency versions and integrity hashes are in `package-lock.json`. Parser visitor/error handling follows [jsonc-parser](https://github.com/microsoft/node-jsonc-parser); schema validation uses [Ajv Draft 2020-12](https://ajv.js.org/json-schema.html); canonicalization uses [canonicalize](https://github.com/erdtman/canonicalize).

## Registered domain payloads

Complete-envelope verification also checks the trusted `contracts/v1/registry.json`: known contract/version, message kind, destination, closed payload shape and task/attempt/delegation correlation. The CLI `validatePayload` operation accepts an `envelope` and performs these structural checks without signature verification. It does not resolve grants or authorize execution. Production owners still check current authority and durable operation history.


## Native child connections

`loadNativeBootstrap(path, schemaDir?)` reads the Go host's private bootstrap and
snapshots its configuration, optional context, CA and credentials. Use the path
supplied through `AGENTMUX_PLUGIN_BOOTSTRAP`. The new child path requires separate
DNS and leaf pins for lifecycle and context, a selected loopback TLS endpoint,
and TLS 1.3 before broker INFO or credentials. It has no unpinned fallback,
reconnect or server discovery. Existing lifecycle frame shapes remain unchanged.

Create `new NativeChild(bootstrap)` and await `connect()`. It authenticates the NATS
nonce, subscribes and flushes, then reports `registered`. Await `nextControl()`;
prepare must match the bootstrap, while stop must bind the same owner and
checksums with a fresh command ID and valid deadline. Call `report('ready')` after
application preparation and `report('stopped')` after cleanup. `failed` is also
supported. Always await `close()` to join the original sockets and pending reads.

`bootstrap.context` is frozen, and `bootstrap.configuration` returns a copy.
Display profile values grant no authority. The optional `contextConnection`
provides `publish(subject, bytes)` and `receive(subject)` for only the exact
bootstrap subjects. Business-envelope admission and operation handles remain the
host's responsibility. This is a bounded NATS core client; it has no wildcard
subscriptions or JetStream API.

The Python controlled socket suite in `sdk/python/tests/test_native_child.py`
executes the built TypeScript client against the same TLS peer. Its README lists
the prepared Node and build paths required by that test. No new dependency is
needed, and these tests do not qualify an installed candidate or live broker.
