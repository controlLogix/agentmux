# P02 history cleanup and retry ownership

Decision date: October 14, 2026. Reviewer and decision owner: Codex.

This amends the cache-only terminal-history foundation before integration. It is not phase acceptance. The history record is a bounded private startup diagnostic; it does not establish current readiness or replace NATS communication.

The earlier cleanup interpretation retained the history store's directory and duplicate service lease until a failed staging-file removal succeeded. Independent review correctly required retaining the exact temporary-file cleanup owner. Retaining the service lease indefinitely, however, would let an optional history failure prevent a later genuine startup attempt. That conflicts with the history contract.

After all publication work has finished and joined, the history store must release its own duplicate of the service lease. If staging-file removal remains unresolved, a safe typed cleanup owner retains the private directory handle, the exact minted staging filename and its inode identity. Its later cleanup may remove only that exact unpublished staging object. It must refuse a replacement object and preserve its cleanup capability while removal remains unresolved.

This cleanup owner cannot publish, rename, compare-and-swap the history slot, adopt another lease or delete a newer attempt's history. Each new attempt still acquires its actual service lease and follows normal admission and generation checks. Unjoined publication work must retain the lease until it joins.

Core runtime ownership is separate: incomplete worker or process cleanup retains the existing core service lease and concrete cleanup owner. This decision does not release that ownership or turn incomplete cleanup into a successful startup.

The simpler alternative is to retain the extra service lease with the temporary file. It simplifies exclusion but blocks unrelated startup retries. Releasing the extra lease after publication finishes requires a narrower cleanup object and explicit tests that old cleanup cannot affect a newer generation.

Required verification before integration:

- Cause a real staging-file removal failure and retain its exact cleanup owner.
- Prove a subsequent attempt can acquire the real flock after publication has finished, while temporary-file cleanup is still unresolved.
- Publish a newer generation, then clean the old staging object without changing that generation.
- Refuse deletion when the staging pathname identifies a different object.
- Keep the lease while publication work remains unjoined, and preserve core worker cleanup ownership.

H01 directory identity, H02 mutation deadlines and H03 staging cleanup findings remain open until their repaired source and evidence pass independent review. Preserve the original foundation candidate, findings and earlier interpretation in delivery evidence.

## Foundation review and owner integration budget

Codex reviewed the promoted foundation and its current-dependency checks on October 14, 2026. H01, H02 and H03 source findings are closed for this foundation. The original open-findings statement above is historical. Thirty named race-test cases and launcher vet passed; actual host/CLI integration and native qualification remain open.

Normal history reads and publication use the remaining original startup budget, capped at 500 milliseconds. They must never extend startup or change the authenticated status contract. If that budget expires, normal publication is skipped.

After startup publication and the actual Bootstrap worker have joined, final diagnostic publication and exact history cleanup may use a portion of the existing core cleanup envelope, capped at 500 milliseconds. Integration must create one shared StopGrace plus ReapTimeout envelope and pass its remaining context to core cleanup; history cannot add a separate cleanup period. This records a completed failure after startup has ended; it does not resume startup or establish readiness. Tests must demonstrate that slow or failed history work does not extend this envelope.

History warnings remain separate from core failures and successful NATS replies. The concrete server retains unresolved history cleanup ownership beyond Run return through a narrow method that accepts only a bounded caller context. It does not accept paths, handles, callbacks or replacement owners. Incomplete core cleanup retains its existing service lease and recovery capability. The implementation and these budget and ownership boundaries require independent review before acceptance.

## Joined finalization after an expired startup budget

Review of the untested owner integration draft refined the ordering. A successful actual Bootstrap publishes within the remaining startup budget and retires the optional history lease duplicate immediately. An optional history failure cannot start the core cleanup envelope while a healthy runtime continues serving.

If actual Bootstrap fails and its terminal record cannot be published within the startup budget, retain a private pending-finalization state until actual Run teardown. The original core service lease is already held during that interval. After the publication worker joins, a finalizer may use at most 500 milliseconds of the one existing shared cleanup envelope, publish the actual terminal result, retire history publication, close its exact duplicate lease, and preserve unresolved root/staging cleanup ownership. Core cleanup receives the remaining same envelope. Nothing publishes after retirement.

A private quiescent retirement operation may close only history's exact lease duplicate even when the I/O context has expired. It cannot mutate the history slot or perform staging-file deletion. It must refuse while publication is active; unresolved exact cleanup ownership remains attached to the server. Public cleanup must refuse until all publication producers have joined and retired.

Failures before protected operation entry also need truthful chronology. Capture the actual operation creation timestamp in its factory and use it for the history attempt start. Opening a store after completion must not invent a later start timestamp or reject a genuine earlier terminal failure for that reason. Meaningful tests and independent review must verify these revised boundaries before promotion.
