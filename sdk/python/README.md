# Python contract library

This P01 library validates local versioned schemas and supplies strict JSON, RFC 8785 canonical bytes and Ed25519 attestation verification. It is not a complete plugin SDK or an authorization service.

Use the exact packages in `requirements.lock` inside an isolated environment. Add `sdk/python` to `PYTHONPATH`. The default schema directory is the repository's `contracts/v1/schemas`; `validate` also accepts a trusted local `schema_dir`. This source package does not bundle schemas into an independently installable product release yet.

## API

- `strict_loads(raw: bytes | str)`: parse JSON, rejecting duplicate decoded keys, invalid UTF-8/surrogates, nonfinite numbers, oversized input and excessive depth.
- `canonical_bytes(value)`: produce RFC 8785 UTF-8 bytes from JSON values.
- `payload_digest(value)`: return `sha256:<hex>` of those bytes.
- `validate(schema_name, value, schema_dir=None)`: return `None` or raise `ContractError`; resolve schema references locally only. This checks schema shape, not every cross-record relationship.
- `sign_claims(claims, seed32bytes)`: sign canonical claims with an explicit 32-byte Ed25519 seed; return canonical unpadded base64url.
- `verify_attestation(attestation, public_key32bytes, expected_audience, now, payload)`: verify schema, signature, audience, issuer references, UTC validity interval and actual payload digest; return claims.
- `verify_envelope(envelope, public_key32bytes, expected_audience, now)`: additionally bind every duplicated envelope claim and destination to the attestation.

`now` must be a timezone-aware UTC `datetime`. Expiry is exclusive. No clock-skew grace is implied. Input and canonical output are limited to 1 MiB and nested values to depth 64. Raw integer tokens and Python integers outside the interoperable safe-integer range are rejected; finite binary64 floating-point values follow JCS. Domain schemas must enforce exact decimal or large integer strings where required. Valid Unicode is not normalized.

A missing configured `schema_dir` now raises `schema_configuration_error`; earlier versions returned `unknown_schema` for that condition. An unknown schema name in an available catalog still raises `unknown_schema`. Callers that handle a missing directory must use the configuration error code.

The caller must resolve the supplied public key from its enrolled issuer/key revision, authenticate the ingress credential mapping, verify current grants and revocation, choose the registered domain payload schema, bind broker subjects, and enforce durable replay/idempotency rules. A supplied public key that validates a signature is not evidence that its signer is trusted. Use `verify_envelope` for received envelopes; verifying only their embedded attestation does not bind unsigned outer fields.

## Test CLI

`python -m agentmux_contracts` reads one JSON request per line and writes one JSON response per line. Operations are `parse` (`raw`), `canonical` (`value`), `sign` (`claims`, `seedHex`), `verify` (`attestation`, `publicKeyHex`, `expectedAudience`, `now`, `payload`), `verifyEnvelope` (`envelope`, `publicKeyHex`, `expectedAudience`, `now`), and `validate` (`schema`, `value`).

Responses contain `ok` and either `result` or a stable error code. Errors never echo payloads, secrets or stack traces. The CLI is a conformance harness; do not pass production seeds through shell arguments or retain its input in logs.

Run `python -m unittest discover -s sdk/python/tests -v` with `PYTHONPATH=sdk/python`. Cross-language and real-broker tests live separately under `tests/contracts`.

## Registered domain payloads

Complete-envelope verification also checks the trusted `contracts/v1/registry.json`: known contract/version, message kind, destination, closed payload shape and task/attempt/delegation correlation. The CLI `validatePayload` operation accepts an `envelope` and performs these structural checks without signature verification. It does not resolve grants or authorize execution. Production owners still check current authority and durable operation history.


## Native child connections

`load_native_bootstrap(path, schema_dir=None)` reads the Go host's private
`NativeBootstrap`, including configuration, optional context, CA and credential
snapshots. Pass the path supplied through `AGENTMUX_PLUGIN_BOOTSTRAP`. The new
client requires separate `serverName` and `leafCertificateSha256` pins for each
connection, the selected loopback TLS endpoint and private files. It supports the
existing 1.0.0, 1.1.0 and 1.2.0 lifecycle frame shapes; it does not add fields to
those frames or provide an unpinned fallback.

Create `NativeChild(bootstrap)` and await `connect()`. This opens TLS 1.3 before
reading broker INFO, verifies the DNS name and leaf pin before sending credentials,
authenticates the NATS nonce, subscribes and flushes, then reports `registered`.
`next_control()` accepts the matching prepare or a fresh stop command. Call
`report("ready")` only after application preparation and `report("stopped")` only
after application cleanup. Failed preparation can report `failed`.

`bootstrap.context` is an immutable descriptor snapshot. Profile environment and
project values are display context; they grant no access. The optional
`context_connection` exposes `publish(subject, bytes)` and `receive(subject)` on
only the bootstrap's exact subjects. It does not authenticate business envelopes
or create operation handles. The host remains responsible for those checks.

Always await `close()` in a `finally` block. It closes both original connections
and joins their readers. Cancellation of a close caller preserves the original
close task. A `NativeChildCleanupError` retains `.owner`; keep that owner and retry
its `close()` before treating cleanup as complete. The client does not reconnect,
follow discovered servers, subscribe to wildcards or implement JetStream.

The controlled TLS socket tests are in `tests/test_native_child.py`. For the
TypeScript cases, set `AGENTMUX_NATIVE_CHILD_NODE` to the prepared Node binary and
`AGENTMUX_NATIVE_CHILD_TS_MODULE` to the disposable build's `native-child.js`.
Set `AGENTMUX_SCHEMA_DIR` to the repository schema directory for those Node tests.
These tests do not qualify a live broker or installed native candidate.
