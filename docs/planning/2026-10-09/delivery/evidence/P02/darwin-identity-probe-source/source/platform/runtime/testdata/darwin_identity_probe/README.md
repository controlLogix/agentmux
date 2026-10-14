# Darwin identity probe: test source, not qualification

This standalone program is test-only. Normal `go test ./...` does not discover
`testdata`. Do not import it into the runtime or expose its controls through the
product. It currently launches its own disposable probe children, not the real
installed Agentmux CLI. No native execution is claimed from these source files.

## Admission

The program requires native Darwin with CGO, an ordinary user, an independently
supplied `sha256:` image pin and an already prepared immutable root-owned copy of
the probe in the product's protected release tree. The program does not install
or elevate itself. It uses the existing `PrepareProtectedInstalledHost` reader
and retains its protected image descriptors. Active protected releases must not
be replaced by an updater while the probe runs.

`--run-controls sha256:<independently-recorded-image-hash>` is the only controller
command. There is no PID, token, image path or process-name signal input. Child
modes receive only a private inherited pipe and a random correlation value.
Those modes are not a product control channel.

The bridge currently admits macOS major versions 15 or 26 and SDK families 15 or
26, and rejects translated execution. These are candidate boundaries, not proven
SDK support. Symbol lookup must resolve the selected functions to an allowed
system library. A missing symbol, unknown image location, unsupported ABI, short
identity result or denied operation fails closed. No raw syscall or `kill(pid)`
fallback exists.

## Source and ABI assumptions

The private combined BSD/unique identity layout, selector 18, version-bound path
lookup and identity-bound signal calls were reviewed against Apple's
`xnu-11215.81.4`, commit
`d4514f0bc1d3f944c22d92e68b646ac3fb40d452`:

- [Private identity declarations](https://github.com/apple-oss-distributions/xnu/blob/d4514f0bc1d3f944c22d92e68b646ac3fb40d452/bsd/sys/proc_info_private.h).
- [Process query and signal implementation](https://github.com/apple-oss-distributions/xnu/blob/d4514f0bc1d3f944c22d92e68b646ac3fb40d452/bsd/kern/proc_info.c).
- [libproc wrappers](https://github.com/apple-oss-distributions/xnu/blob/d4514f0bc1d3f944c22d92e68b646ac3fb40d452/libsyscall/wrappers/libproc/libproc.c).

SDK headers supply the public BSD structure. Static size/offset checks cover the
private suffix, and every query must return the complete expected structure.
Actual SDK/export/ABI and OS behavior still require native controls. Source
presence cannot prove availability or compatibility.

The signal identifier contains kernel-observed PID/version data; it is not a
kernel-authenticated credential. The pinned kernel checks the real caller's
permission and matching target version while holding its process reference.
Only the private proof constructor establishes the additional lineage, UID,
protected-image and literal-argument assertions. Identity is checked again after
all image/argument reads and watcher registration. The original parent unique
ID records creation lineage and does not change on reparenting; it must not be
confused with the current PPID. Kqueue observes events, not signal authority.

## Controls and limits

Implemented source controls cover exact owned-child SIGTERM/SIGKILL, signal-zero
refusal, deliberately wrong-version refusal and refusal of a pre-exec identity.
Each signal control must observe that exact signal through the creator's sole
Wait and the registered exact exit event within one deadline. The creator defers
Wait until its signal decisions finish, so unexpected exit cannot free the
child's PID for reuse during the deliberately wrong-version control. Raw argv,
environment, tokens, PIDs and native error text are not printed.
Argument buffers are bounded and cleared after parsing.

Actual PID reuse is explicitly reported as **unexecuted**. Wrong-version and
exec tests do not replace observed reuse. The source does not yet exercise real
frontend-to-host-to-role discovery, different-user attacks, all admission races,
or the installed CLI. A zero exit code means only the implemented component
controls passed; the report always denies installed-CLI and native product
qualification.

Cleanup closes the creator-owned pipe and joins each disposable control child.
Admission failure never permits guessed-PID signalling. Unknown cleanup is a
failure, not permission to kill by name or prune processes. The bounded child
lifetime is a probe fixture safeguard, not actual host-shutdown evidence.

No builds or native runs should start until coordinated with the root delivery
session. Before any shared CLI extraction, review this source and the cache-only
control plan, then qualify both native Mac architectures with the selected
SDK/OS, positive controls and all required refusal and cleanup cases. All Linux
and macOS amd64/arm64 targets and the full P02 gate remain required.
