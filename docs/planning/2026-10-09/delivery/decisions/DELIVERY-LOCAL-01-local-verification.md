# DELIVERY-LOCAL-01: Local builds and verification

Approved by Ryan Helms on October 14, 2026.

Use local resources for implementation, tests, image builds and phase qualification on native Linux/macOS. Do not use CI to build images or verify work until every P00–P14 phase gate is complete. This changes where verification runs, not what must pass.

- Keep AMD64/ARM64 coverage, exact candidate/source pins, actual-host identity and all security, recovery, persistence and preservation assertions.
- Reuse prepared local tools and caches. Do not silently substitute mocks, cross-builds, WSL, a container client, or old CI artifacts for required native execution.
- Existing CI results remain historical diagnostic evidence. They do not qualify a changed candidate or remove current local evidence gaps.
- Defer feature-branch CI jobs behind an explicit, default-off all-phases-complete switch. It must not be enabled before all local gates pass. Do not dispatch CI, change hosted runner settings or use CI as a fallback for missing local capacity.
- Keep workflow source, pinned tools and test assertions for eventual final verification. Other branches' existing generic checks are outside this feature-delivery deferral.
- Serialize jobs sharing a local Docker engine or timing-sensitive fixture. Parallelize independent source work, pure tests and read-only review through bounded subagents.
- Missing local platform capacity remains an explicit evidence gap. Report the actual available environments; do not infer a passing platform from an available executable.

Codex still reviews each phase, commits and pushes the feature-branch candidate, verifies the remote commit and records the gate before advancement. A Git push is not CI qualification. No merge or release is authorized.
