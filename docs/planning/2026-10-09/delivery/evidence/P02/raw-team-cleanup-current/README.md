# Raw transport cleanup and team credential reader evidence

This archive preserves the reviewed P02 repair evidence. All nine current source files matched the worker and independent review hashes when this archive was created. Original review records, public logs, producers, commands and exits are copied without changing their bytes.

The worker recorded 6 focused and 106 affected named race-test passes, with no failures or skips, and a successful vet exit. The independent reviewer recorded 5 focused named race-test passes, with no failures or skips. These counts include parent and child test entries; they do not describe that many distinct end-to-end scenarios. The historical negative deliberately discards cleanup ownership and fails the three socket-origin controls plus their parent. Its failure is expected evidence that the controls detect the bug.

The repair retains and rechecks the actual credential-reader ancestor, directory and file descriptors. Raw transport cleanup retains its exact owned sockets, joins cancellation hooks, reports observed close failures, allows a bounded retry, and clears successful result facts on cleanup failure. Error formatting uses fixed public codes.

Native macOS ACL, mount and no-CGO refusal execution remains unverified here. The recorded Darwin ARM64 no-CGO build is compilation only. Full Team/Probe/Observe caller forced-cleanup-failure execution is not claimed: caller fact invalidation was source-reviewed with existing affected success evidence. Blocking synchronous platform Close or filesystem calls are not preemptible by this API; product timing assumes standard local filesystem and network operations.

This archive does not establish real Docker Compose qualification, phase acceptance, permission to refresh source review metadata, or permission to advance phases. No tests were run while packaging it. Runtime/source trees, private fixtures, credentials, and the crosscompiled executable are excluded. The original record retains the excluded executable's hash; that hash does not mean its bytes are present in this archive. Earlier superseded candidates remain identified in the original worker review.
