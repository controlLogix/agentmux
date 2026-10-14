# Startup failure history display

Decision owner and reviewer: Codex. Decision date: October 14, 2026. Implementation and acceptance remain open.

The terminal may display a separately tagged record of a past startup failure when the authenticated NATS status is unavailable. NATS remains the current-status authority. A history record cannot establish readiness, current instance details, ownership, or permission to start work.

The public document has these exact fields:

- `schemaVersion`: `1.0.0`.
- `kind`: `bootstrap-terminal-history`.
- `meaning`: `previous_recorded_terminal_failure`.
- `invocationId`: the validated actual attempt identifier.
- `completedAt`: the validated historical completion timestamp.
- `diagnostic`: one complete, fixed `RequestDiagnostic` representation.
- `recordedCleanup`: `unknown` or `incomplete`; never infer completed cleanup from a historical startup error.

Do not include private binding objects, paths, descriptors, process identifiers, credentials or underlying error text. Conversion must refuse unknown diagnostic codes rather than silently turn them into a generic known code.

The installed policy readers derive current owner, scope, runtime and enrollment internally. Their callers cannot supply a binding, history path, generation or receipt nonce. General status history requires an actual momentarily free service lease. The creator exception requires the exact original factory-created process and its successfully validated receipt for this invocation, checked again after reading. It records provenance even if the original child has exited; it never adopts a child or proves liveness.

A valid authenticated NATS reply takes priority. Authentication, enrollment, malformed-reply and concrete transport-cleanup failures do not invoke a historical fallback. An initial ensure lookup still proceeds through genuine admission and startup; prior history cannot suppress a new attempt. After a newly accepted startup request, creator history may explain that exact attempt's terminal failure when current status cannot be obtained.

The CLI should emit this separate document and retain a nonzero result when it explains a failed startup or an unavailable status request. Preserve the normal fixed stderr diagnostic. A historical document is not a successful L04 response and must never replace one in SDK validation.

The proposed CLI read allowance is at most 200 milliseconds from the existing 500-millisecond response allowance, leaving 300 milliseconds for output and ordinary exit. The original ten-second ensure and five-second status deadlines, existing work budgets and one-second receipt cleanup allowance remain unchanged. All reads use the original total deadline; no background deadline or asynchronous unjoined filesystem reader is introduced. This budget requires actual qualification before acceptance.

The private store, reader facade, host integration, CLI output and real installed lifecycle each require their own meaningful checks. Component passes do not qualify an installed runtime or a supported native environment.
