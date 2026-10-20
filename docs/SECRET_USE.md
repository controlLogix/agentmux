# Ordinary secret use

An ordinary plugin names an enrolled secret reference, approved consumer and
purpose. The trusted owner delivers the credential to that consumer and returns
only a receipt. The supported consumer checks the selected Atlassian account
over HTTPS. Enrollment fixes the destination, expected account and trust roots;
an operation cannot choose another URL, callback or credential resolver.

The native `SecretHandle` path is qualified for this fixed consumer, including
receipt-only results, fresh outcome queries, parent revocation and joined
cleanup. This qualification does not establish an installed release.

## Authority and custody

Public identity records contain exact references and scope, not credentials.
Private custody binds the credential to its enrolled generation. Each use
requires both the original caller's current permission and the custody service's
separate current permission. Knowing a reference or retaining an earlier
resolution does not authorize use.

The operation retains its exact organization, project and optional workspace.
A project enrollment can serve an explicitly authorized narrower workspace.
The separate administrator request that prepares its journal uses the containing
project's account authority. It does not widen the plugin's workspace permission.
Consumer, purpose, generation and current grant substitutions are refused.

When terminal sign-in is required, the owner refreshes the original user's
session at use and disclosure boundaries. Internal service requests use their
own enrolled authority. A service's permission does not replace the user's
current session, and refreshing a session does not extend an old use deadline.
Journal connections use separately bounded service authority so they can retain
completion after a user request expires. That connection cannot authorize another
secret use or disclose an outcome; recovery still requires a fresh authorized query.

The host selects this capability through the application's `ordinarySecret`
selection. It names the existing public enrollment, plugin identity and instance,
private custody locations, approved consumer, journal policy and pinned signer
material. Separate use and outcome receivers have their own credentials and
signing keys. Providing this selection does not create an identity, enroll a
credential or grant permission. Plugins cannot supply or change it.

The fixed consumer sends authorization through its process input, not command
arguments. Its response becomes a bounded private observation and a public
receipt with an `accepted`, `rejected` or `uncertain` outcome. The plugin receives
neither the credential nor the remote response body. Trusted native code is
unsandboxed; private immutable Python bytes do not guarantee memory zeroization.

## Original operations and recovery

Keep the original operation ID, payload digest and retained records after an
interrupted call. An uncertain response does not authorize a new attempt under
another ID. The original journal records preparation, dispatch and outcome;
completion reservations preserve space for the outcome before an effect starts.
Missing acknowledgments do not prove that an external request never happened.

A fresh authorized outcome query can read or reconcile the retained original.
It does not create an absent journal, renew the historical use proof or start
the consumer again. Current disclosure permission remains required, including
the original-use permission or the explicitly supported recovery authority.
Without a retained physical observation, a dispatched effect can remain
uncertain. Keep its records and custody intact; do not delete or recreate them
to obtain another attempt.

Each fresh admitted original gets its own exact-subject journal under a finite
host-selected policy. Private selection files retain assignment, creation and
recovery pins; business state remains in the NATS ledger. An unknown existing
stream is not trusted enrollment. Capacity exhaustion, replaced sources and
missing uncertain creations refuse rather than silently resetting the original.
The policy does not automatically reclaim old journals or promise unlimited use.

Closing a consumer owner joins its work before releasing its custody. Reopening
that original can construct fresh local journal resources over the same retained
stream and recovery floor. Failed source cleanup retains the original connection
for an explicit retry. Host shutdown joins consumers first, then journal
admission, then its borrowed verification custody and identity transports.

## Rotation and availability limits

Current authority must remain available. Offline, expired, revoked or changed
bindings refuse new credential delivery; an old resolution is not an offline
permit. The fixed consumer has a bounded deadline and does not extend the
original authority's validity.

Generation custody is immutable. A replacement credential needs its own signed
enrollment and matching consumer selection; the owner does not overwrite an
existing generation or redirect an uncertain original to a replacement. Local
revocation cannot recall bytes already delivered. Revoke the credential at its
external provider when that is required.

The development target is native macOS ARM64. This capability provides the
approved account check, not arbitrary authenticated HTTP or a general secret
retrieval API. It does not qualify other platforms or authorize a release.
