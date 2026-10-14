# Cleanup-cause repair: source controls

Date: 2026-10-14. Root assigned only the three existing probe files. This repair
changes `main_darwin.go` and its README; the native bridge is unchanged. No build,
native control, Docker operation or shared metadata write was performed.

## Findings before repair

1. `newControl` discarded `image.Close()` on pipe failure and reader, gate and
   image close results on nonce or Start failure. The caller already returned
   `cleanupVerified=false`, so this was not a demonstrated false pass. However,
   returning `nil, setupError` bypassed the later owned-control cleanup and lost
   which acquired resources had failed to close.
2. `ownedControl.close` started with retained cleanup errors but assigned a new
   gate-close error, replacing earlier cleanup causes in its result. The result
   remained a failure; its cause chain was incomplete.

Before SHA256: main `455febb1b76fb2395bb8bcfd8783eb8adf9743c2916f98dbd0c36ca6c4d85bf4`,
native `a120f2ce87b049852941efc3e38c9de013173e7998d842ed510eddadb2c6b972`,
README `fc2c08846cea4b3b00c74f8799e9a20990101c5ad1aaa9faac4330f30cbaea63`.
These observations qualify the earlier narrow source-review closure. The
earlier records remain unchanged; no native failure or PID reuse is claimed.

## Source reasoning and repair

All three pre-return constructor branches now call `closeSetupFailure`. It
attempts each acquired reader, gate and image close without short-circuiting.
`closeOwned` returns the earlier error unchanged when a close succeeds; on failure
it joins that error with a `probeCloseFailure`. That wrapper prints a fixed stage
label and retains the original cause through `Unwrap`. Gate cleanup uses the same
join operation, preserving earlier uncertainty. A failed image close consumes
the product image reference; the repair does not promise retryable ownership.

## Minimal control matrix for a coordinated test

This is a source-backed expected-outcome table, not executed tests. A future
focused test should use distinct sentinel causes and counting closers to assert
the real helper's `errors.Is`/`errors.As` behavior and every close attempt.

| Primary branch | Close outcomes | Required result |
| --- | --- | --- |
| Pipe failure | Image close succeeds | Original pipe error retained; one image close; no child assumed. |
| Pipe failure | Image close fails | Original pipe and image cause both discoverable; fixed image stage text. |
| Nonce failure | All closes succeed | Original nonce error; reader, gate and image each attempted once. |
| Nonce failure | Each single close fails, then all fail together | Original nonce plus every failed cause retained; later closes still attempted. |
| Start failure | All closes succeed | Original Start failure; all acquired resources attempted once. |
| Start failure | Each single close fails, then all fail together | Original Start failure plus every failed cause retained; no raw native message or path in diagnostic. |
| Later gate cleanup | Earlier cleanup and gate both fail | `close()` retains earlier causes and new gate cause; cleanup cannot become successful. |
| Later gate cleanup | Earlier cleanup failed; gate closes | Earlier failure remains unchanged; later success cannot erase uncertainty. |

The existing caller still fails the control when construction fails. No source
reasoning substitutes for native descriptor behavior or the real CLI. The sole
Wait/deferred-reaping safety, exact signal/exit checks, private ABI admission and
all unexecuted native/PID-reuse/CLI limits remain unchanged.

## Verification boundary

`gofmt` parsing and formatting ran; no Go typecheck or C compilation ran. An
independent reviewer checks the exact repaired source and the two error paths.
Actual counting-closer tests and native behavior must be coordinated by root.
Root owns updating the registered function lines and evidence. All four native
targets and the complete phase gate remain required.
