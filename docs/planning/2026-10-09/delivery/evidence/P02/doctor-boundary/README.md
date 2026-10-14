# Read-only doctor boundary

`launcher.RunDoctor` inspects an explicitly selected Docker setup without starting, pulling, restarting, stopping, installing or changing anything. It does not open legacy Hub or SQLite state. This is a P02-T04 implementation slice, not task or phase acceptance.

The integration caller supplies the backend, context, local endpoint, expected engine and exact client/server/Compose versions through the existing `DockerConfig`. It must set the internal `ProfileValidated` assertion only after private profile loading and separately trusted release checks. External JSON cannot set that assertion or supply probe functions.

## Results and limits

The report contains six fixed checks: profile, client, Docker, broker, persistence and protected roles. Each has a fixed status/code and measured elapsed time. Actual backend, engine identity and versions appear only after the existing driver's complete validated inspection. Reports omit the executable, endpoint, private paths, raw errors, command bodies and subprocess output.

| Result | Meaning and next step |
| --- | --- |
| `profile_not_validated` | The caller has not supplied trusted profile validation. Complete that check before inspection. |
| `client_missing` or `client_permission_denied` | Local executable inspection observed the named problem. Check the selected installation without automatic repair. |
| `environment_conflict` or `endpoint_conflict` | The selected environment or observed endpoint differs from policy. Resolve the selection; do not attach to another setup. |
| `identity_or_version_conflict` | The existing driver observed an engine, operating-system or version mismatch. Its API does not distinguish these further. |
| `inspection_unavailable` | Inspection failed without enough evidence to identify daemon availability, permission denial or another command failure. Do not invent a narrower cause. |
| `not_probed` | No authenticated integration probe was supplied. The service is unknown, not healthy. |
| `deadline_exceeded` or `cancelled` | Inspection or a cooperative probe could not finish within the remaining caller budget. No lifecycle retry or mutation follows. |

The total context is at most five seconds, reduced by an earlier caller deadline. Docker inspection reserves one second inside that budget for the existing driver's output-pipe cleanup. A smaller remaining budget refuses inspection. All integration probes share the same context; none gets a fresh independent timeout. Probes are trusted read-only callbacks that must honor cancellation. The doctor does not launch unowned goroutines to pretend it can terminate arbitrary Go code. Local filesystem inspection likewise cannot promise to interrupt a blocked operating-system filesystem call.

Authenticated broker, persistence and protected-role probes remain integration responsibilities. Missing probes stay unknown. `diagnosticsPassed` never grants application readiness, L04 visibility, implementation approval or phase advancement, even when all supplied probes return verified observations.

## Verification scope

Tests reuse the existing controlled Docker subprocess fixture without editing its `TestMain`. An additional disposable Go helper returns three valid observations before a fourth-read timeout. Its second mode holds an inherited output pipe after CLI cancellation, exercising the driver's one-second cleanup reserve. The bounded holder finishes on its own; a registered test cleanup waits for its marker even after assertion failure. No PID is adopted or signaled. Fixture teardown occurs outside the measured doctor call and does not prove descendant supervision.

The isolated WSL runs use prepared Go 1.27.2, offline dependency resolution, readonly modules and fresh race-test results. `GORACE=atexit_sleep_ms=0` removes only the race runtime's synthetic post-exit delay for the controlled executable. Race instrumentation, assertions and the doctor's real deadline remain enabled. All copied Go sources and module files are hashed before execution and checked afterward.

The original raw run files retain historical evidence from before the timing-coverage refinement. A later successful temporary-workspace run lost its raw files before copying; it is not used as acceptance evidence. Final repaired-source execution is preserved in `final-verified/` with its separate source list and report. That run used persistent Linux home-cache state and copied artifacts in the same owned execution before returning. Neither run is real Docker, native macOS, authenticated service readiness, full boot or phase acceptance. The coordinator owns source registration, integration, candidate commit/push and the remaining phase checks.
