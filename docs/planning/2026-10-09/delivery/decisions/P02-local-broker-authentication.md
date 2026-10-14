# P02 local broker authentication

Status: approved implementation direction; implementation and qualification are incomplete.

The installed runtime must authenticate the broker before sending a NATS credential. A server's advertised name and version are claims. Inspecting Docker proves deployment ownership at that moment; it does not authenticate the socket used by a later connection.

## Evidence and trust boundary

An isolated TCP diagnostic used synthetic credentials and an owned malicious peer. The peer advertised the expected name and version, received the synthetic password, and passed the client's identity comparisons. No production credential, Docker resource or provider was involved. This proves the authentication ordering problem. It does not replace a supported-environment attack test.

The enrolled local user and explicitly trusted host code remain trusted. Other local OS users are not included in that boundary. P02 must address local broker impersonation; P04 still owns human identity, organization membership, JWT policy and revocation. P10 still owns federation trust.

## Decision

Each new installed local profile requires explicit TLS enrollment. Use a profile-specific offline certificate authority and an ECDSA P-256 server certificate. The certificate DNS name is `profile-<32hex>.agentmux.invalid`, derived from the enrolled `profile_<32hex>` ID. The certificate authority lasts two years and the server certificate lasts 90 days. Discard the authority's private signing key after issuing the server certificate. Renewal requires explicit enrollment and an authorized configuration change; warm launch never generates keys or replaces a running configuration.

A new private server-trust record binds the complete kernel scope, selected TLS endpoint, expected DNS name, enrolled public roots and exact server-certificate DER digest. Its bytes are also bound by the profile's trust-record digest. Keep the existing role credential and L04 schemas unchanged. Protected roles receive one fixed `AGENTMUX_NATS_SERVER_TRUST_FILE` reference through the supervisor's exact environment contract.

The shared client trust implementation accepts only the enrolled endpoint and public trust material. It performs TLS 1.3, normal chain, hostname and validity checks, and the exact leaf-certificate digest check before returning a socket to NATS. It uses no system-root discovery, insecure verification, alternate address, plaintext downgrade or caller-supplied TLS options. Cancellation and cleanup retain the existing total budgets and join owned sockets and hooks.

Every installed local credential-bearing connection uses this trust: the owner bridge, kernel observer, health writer and reader, and all four protected actors, including reconnects. Team connections retain their separately enrolled TLS policy. Historical plaintext helper APIs and isolated fixtures remain compatibility evidence; the installed loader exposes no plaintext option.

The secure broker factory preserves all existing accounts, permissions, storage policy and domain. It adds strict TLS-first operation with no timed plaintext fallback. Deterministic Compose input provides three private inline config objects: `broker_config`, `server_cert` and `server_key`. Their fixed targets are `/etc/nats/private.conf`, `/etc/nats/server-cert.pem` and `/etc/nats/server-key.pem`, owned by root with mode `0400`. No CA private key enters the container, data volume or evidence.

Before an owner bridge connects, it also verifies the selected Docker context, engine, versions and exact owned broker image, labels, port, private configuration and certificate/key bytes. This remains a separate ownership check. Only a proved absent or stopped broker allows the startup path. Unknown ownership and TLS identity rejection are hard failures; they cannot start a shadow host or trigger a different-broker fallback.

Docker administrators and container root can access injected key material, as they can access the existing password configuration. They remain trusted infrastructure. All certificate and key comparisons use bounded memory; keys and passwords must not enter arguments, logs, status messages or task evidence.

## Alternatives and costs

Server name/version checks and Docker inspection alone leave an inspection-to-connection race. A system certificate store would add machine-wide trust that this per-profile enrollment does not grant. The selected approach adds certificate generation, private artifact validation, Compose binding, expiry diagnostics and explicit renewal. Those costs are needed before accepting the installed bridge as authenticated.

## Required verification

- A real strict TLS-first NATS server accepts all installed local clients with the enrolled trust and preserves the existing account denials.
- Malicious plaintext and TLS peers cannot receive authentication or application messages when roots, DNS name, validity, scope or leaf pin differ. Matching advertised name/version cannot change that result.
- Missing or altered trust, certificate or key artifacts fail before connection or Docker mutation. Check private file ownership, ancestry, links, closed fields, bounds and full scope.
- An inspection-to-dial swap is rejected before credential disclosure. Authentication failure cannot enter the launch fallback.
- Existing deadlines, cancellation, reconnect restrictions, owned cleanup and secret hygiene pass real process and socket checks.
- Native Linux, macOS and WSL-to-Windows-Docker tests prove actual behavior. A synthetic peer or a cross-build cannot replace those environments or a genuine different-user attack demonstration.
- Actual TLS Compose cold start, concurrent launch, warm reuse, terminal exit, recovery and volume retention pass on the exact reviewed candidate before P02 acceptance.

P02-T03-AC06 records this requirement. No passing plaintext fixture, worker handoff or schema test closes it.
