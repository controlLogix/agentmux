# Read-only infrastructure observation

`deployment.Observe` supplies the read-only boundary needed by doctor integration. It authenticates to the explicit local endpoint and issues only account INFO, exact health-stream INFO and optional existing MSG.GET requests. It never calls the writing `Probe`, publishes a health record, provisions, creates, updates or deletes a stream. Read requests can update broker request counters; they do not change the health stream or its records.

The existing `Probe` remains a separate write/read health qualification operation. Its successful result cannot be substituted for a read-only doctor call.

## What the result proves

The observer compares the actual connected server name/version and actual `AccountInfo.Domain` with the explicit selection. Only then does it return validated identity fields. It uses the existing health configuration comparison, including the approved NATS 2.15 metadata rules.

`configuration-observed` means the expected stream configuration was read. `existing-record-observed` additionally means an already stored, correctly shaped health marker was retrieved, with its sequence, timestamp and digest. Neither proves current write permission, restart retention, protected-role readiness or application readiness. Missing streams or requested records remain `unknown`, without an attempted repair. Configuration and record observations are separate reads, not an atomic readiness snapshot.

The report excludes credentials, endpoints, private paths, raw record bytes, headers and underlying errors. Errors use fixed safe codes. Wrong authentication, domain, server identity, version and unavailable endpoints cannot become successful identity observations.

## Deadlines and resource ownership

One context with a maximum five-second budget covers dialing, the NATS greeting/TLS handshake, account observation, stream observation and record retrieval. An earlier caller deadline or cancellation still applies. The custom dialer accepts only the configured local address and preserves the SDK's TLS handshake and certificate checks.

Every actual socket returned by the context-aware dialer has an owned cancellation hook. Cancellation closes that socket, including during a withheld greeting. Teardown stops or joins each hook and refuses later dialing by a released owner. No unrelated connection is discovered, adopted or closed. Reconnect is disabled, and the observer closes its own SDK connection on every return path.

## Verification

The final immutable-copy run in `final/` passed 21 observer and 74 total deployment test/subtest checks with race detection, followed by clean package vet. It combines the observer with the current frozen health profile/probe and Compose renderer. All 48 copied Go/module files remained unchanged through execution, and artifacts were copied before the owned command returned.

Tests use real disposable NATS 2.15 processes with private temporary configurations and stores. A restricted health principal allows only the three read APIs. Actual publication and creation denial controls prove the restriction; observation succeeds under that identity. Repeated observation preserves configuration, creation identity, record counts and sequence state. Missing and malformed persistence is not provisioned or repaired. Test-only loopback monitoring verifies owned connections return to zero. Separate controlled TCP peers prove earlier deadlines and cancellation after acceptance; failure-safe fixture cleanup closes the accepted socket and joins the accept goroutine.

The coordinator owns bootstrap integration, source registration, the candidate commit/push and full P02 review. These results are not native macOS/Linux qualification, real Compose startup, application readiness, complete recovery, task acceptance or phase advancement. No actual Docker operation or CI dispatch was performed by this worker.
