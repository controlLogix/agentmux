# Disposable native ownership-mount fixture

Source-only candidate. Human approval, independent review, build checks and
execution windows remain required. Nothing here qualifies a mount until actual
setup, inspection, tests and matched normal teardown have completed.

## Fixed scope

The current nonce is 20261015-7c4e92b1. Setup exclusively creates
/private/tmp/agentmux-c05-apfs-20261015-7c4e92b1 as root-owned 0711.
It never reuses an existing directory. The names carry no secrets.
The two blank read/write UDIF APFS images have a fixed 128 MiB logical size each and remain
root-owned 0600. Mountpoints are owners and noowners. Each mounted root is
0700, and its sole fresh control file is empty 0600. Only these two held
objects per mounted volume receive fchown to UID501.

The root programs use only isolated system Python, its standard library and
the literal /usr/bin/hdiutil commands. There are no caller paths, environment
configuration, shell expansion, checkout imports, Go execution, diskutil
database changes, system-volume changes, forced detaches or file deletion.
Subprocesses receive a fixed environment and have one original wait.
Captured results and the root receipt are root-owned 0600.

The proposed execution policy is one original 120-second monotonic budget.
SIGINT/SIGTERM are sticky and non-raising before process creation through
finalization. Cancellation, expiry, overflow or capture failure stops further
fixture mutations and requests TERM only on the original hdiutil object,
then KILL after two seconds if its original waiter remains unjoined.
This shutdown policy requires independent review before execution.
Each pipe is drained with nonblocking reads into a separately bounded 1 MiB
capture; stderr is bounded too. Overflow stays a failure even after zero exit.
After child exit, pipe draining has a one-second limit, so inherited writers
cannot hold output copying forever. The original wait and thread join have a
two-second post-KILL confirmation window. If terminal status remains unknown,
the program retains the owner/session/captures for separate recovery; it does
not retry wait, close captures, detach, adopt processes or claim completion.
The keeper continues observing that same original wait record. If it later
confirms terminal status and its waiter joins, pipe/descriptor closeout resumes
but the historical uncertainty remains a failure. Thread exit or a wait error
alone never supplies terminal authority.

Primary and all descriptor-close exceptions remain attached to the final
failure. Each descriptor is consumed before its sole close attempt. Completion
output is selected only after waits, pipe cleanup and every owned close pass;
zero program exit is also required. No pre-close Complete record is emitted.
The sibling lifecycle_controls.py contains unprivileged fake-process controls
for both copies, including capture bounds, cancellation, expiry, late zero,
inherited writers, pre-creation refusal, short writes and final close failures.
It never invokes hdiutil or a root entrypoint.

Popen is deliberately outside filesystem/FD signal-mask windows. Entry and
pre-creation checks query the calling thread's mask and refuse an already
blocked INT or TERM without changing it. Non-raising sticky handlers are
installed first; a gate runs immediately before Popen, whose returned object
goes directly to run_owned before any post-creation refusal. A racing cancel
can therefore create an owned child that must be stopped/joined: this is not
an atomic no-side-effects guarantee. Filesystem and FD windows remain masked.
The controlled-child regression launches only a literal unprivileged isolated
system Python child, observes its actual mask/readiness, signals the parent
test process, and requires that exact child to join on TERM within two seconds
with one wait, zero KILL calls and closed pipes. Fake cancel-at-creation cases
remain in the controls; blocked inherited masks refuse before Popen.

## Reviewed-byte execution boundary

Do not run these files directly as root from the mutable checkout.
After approval, the unprivileged execution driver must read each approved
program once, hash those exact bytes against the independently reviewed pin,
and pass that same byte buffer as the literal -c argument to root-owned
/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9
with -I -S. Do not reread the path after hashing, use a shell
evaluation, or import a checkout module. The driver and exact sudo invocation
still require review and human authorization; this directory does not install
or authorize one. The programs require isolated/no-site mode and argv ["-c"].

`driver.py` implements this boundary using the pinned trusted interpreter above.
Its default only records plans; it starts no process. The explicit setup action
still needs human approval. Teardown refuses before process creation while its
reviewed setup, inspector and joined-test evidence bindings are unset. Its
150-second initial parent observation budget does not turn a late or uncertain
root exit into success. Four-release installation remains a separate action.

Setup outputs its receipt and the hash of its canonical stored receipt bytes
to the private job capture. The stored receipt remains root-owned 0600.
The receipt binds parent and held image identities, attach-result hashes,
exact complete device/mountpoint maps, held mount/control identities, the
physical GUID-partition image device, and independent hdiutil-info hashes.
Backing-image contents can change while attached: inode/device bindings are
live identity checks, not a claim that an initial disk-image content hash stays
unchanged. No arbitrary device is inferred from a prefix or process ID.

## Unprivileged inspection and test handoff

Build inspect/main.go separately under native ARM64, canonical SDK26.5 and the
agentmux_darwin_ownership_mount tag in a granted Go window. Never execute it
from a root program. It accepts no arguments or fixture environment and must
run with real/effective UID501. All fixture paths are fixed and opened through
no-follow descriptor-relative traversal.

The inspector requires actual held Fstatfs results: root mount owner, local
APFS, exact fixed mountpoint, distinct device/volume FSIDs, and flags differing
only by MNT_IGNORE_OWNERSHIP. It also requires explicit native ACL-property
absence, UID501, exact modes and object types, and the empty file's single
link. Failure retains everything; no alternative metadata or mount is used.

It exclusively creates a private UID501 directory at
/private/tmp/agentmux-c05-inspector-20261015-7c4e92b1 and a 0600 manifest.json.
It prints the manifest path and exact byte digest only after all held
descriptors have closed successfully. The independent reviewer must compare
the manifest device/mount/inode identities with setup's captured root receipt
before authorizing the existing explicit-manifest tests. The inspector alone
does not establish the backing-image binding.

Tests receive the existing AMX_OWNERSHIP_AUTHORIZED, AMX_OWNERSHIP_MANIFEST and
AMX_OWNERSHIP_MANIFEST_SHA256 values only in their unprivileged execution
window. These values never configure either root program.

## Explicit teardown

Only after the inspector and every test process have joined and all descriptor
cleanup has completed may the reviewer authorize teardown. Its stdin must be
the exact operator attestation "JOINED 20261015-7c4e92b1" plus a newline.
This attestation is not machine proof of joins; the reviewer must inspect
the original runner evidence first. It supplies no path or device authority.

Teardown reads the held private root receipt, checks it did not change while
read, validates both attachments and image identities before the first detach,
then consumes all held mount/device descriptors. Next to each normal detach
it rechecks the image identity and hdiutil-info map. It never uses -force.
Any failure stops further mutations and retains remaining attachments/files.
An earlier successful detach is not undone. Missing/incomplete receipts,
unexpected topology or busy volumes require separately reviewed recovery;
there is no automatic adoption, cleanup scan, retry or deletion.

All images, mountpoint directories, receipts and captures remain after teardown.
Their later deletion needs separate explicit approval.

The fresh pair cannot execute until main binds a closed, hash-pinned review of
successful normal partial detach and exact-image absence for nonce
20261015-4d927ca8. A sudo authentication failure is not that confirmation.
Historical command-wait proof remains absent and descendant completion unknown.

Four-release provisioning is separate and is not imported or invoked here.
This fixture tests mount-policy refusal, not the complete protected loader.

## Retained first setup failure

The approved first attempt, nonce `20261015-6e8a31d4`, exited 1 before
creating or attaching an image. Its root-private `owners-create.stderr`
reported that `-format` requires a source folder or device. Main checked the
installed `hdiutil create -help`; blank read/write images use `-type UDIF`.
The first directory and captures remain untouched. The corrected command uses
the same two-image, 128 MiB/APFS scope with a fresh nonce, paired program pins
and an unprivileged AST command regression. This correction does not qualify
either mount or authorize teardown; actual setup, inspection and tests remain
required. The earlier inspector binary targets only the failed nonce and must
not be used for the corrected fixture.

The earlier 20261015-4d927ca8 root, partial owners image, and saved captures
remain retained. Its partial normal-detach review is separate from this fresh pair.

Setup and teardown inspect device-node metadata without opening device nodes. The protected version 2 receipt records dynamic mountPolicy, devfs and deviceNodeMetadata observations. The ordinary-user inspector does not read the root-only receipt; compare its independently reported FSID, flags, device and inode identities with the setup output. Root and ordinary-user UID observations on a noowners mount are context-specific and must not be equated. The repository now has 24 metadata and safe failure-reporting controls. All 24, the 12 lifecycle checks and seven fake driver scenarios passed locally after the reporting patch. This source update does not change any installed root payload or authorize setup replay. Live fixture qualification and joined-evidence-bound teardown remain separate requirements; see the P02 evidence records for the actual retained pair and mount-test results.

