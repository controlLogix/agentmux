# PLATFORM-SCOPE-03: macOS ARM64 initial beta

Ryan approved this scope on October 14, 2026: focus the initial beta on macOS ARM64, coordinate both Codex sessions, and expand to other platforms afterward.

## Current target

The initial beta has one supported host target: native macOS on ARM64. Linux and macOS AMD64 implementation qualification are deferred expansion work, not beta blockers and not passing results. Windows/WSL remain outside the current delivery scope.

This supersedes PLATFORM-SCOPE-02's Linux/macOS, AMD64/ARM64 target matrix. Preserve that decision, existing source, assertions, prior failures and evidence. Historical results retain their original environment and candidate limits. Linux containers used by the macOS Docker Desktop stack remain infrastructure; they do not add Linux as a supported beta host.

## Checks that remain required

- Complete the product scope and sequential P00–P14 gates on the beta target. A beta label does not waive features, security, permissions, recovery, persistence, preservation or real-hub evidence.
- Port required behavior checks to native macOS ARM64 where their current fixtures are Linux-only. Do not skip the behavior or count an unexecuted fixture as passed.
- Qualify actual protected installation, the supported SDK tuple, installed CLI and client workflows. A cross-build, source review or primitive diagnostic cannot replace these checks.
- Follow DELIVERY-LOCAL-01: local builds, images and tests only; no CI builds or verification until every phase gate is complete.
- Keep one active phase, Codex review, the feature-branch commit/push and remote verification requirements. No merge, release or beta publication is authorized by this scope decision.

## P02 qualification build profile

On October 15, local inspection found an installed, root-owned SDK 26.5 alongside the default SDK 27. The unchanged normal identity guard already permits SDK 26. An explicit native ARM64 self probe passed with SDK intrinsic `260500`, macOS `26.6` and Darwin `25.6.0`; see [the bounded evidence](../evidence/P02/local-darwin-identity/normal-sdk265-self-review.json).

Use the explicit canonical `/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk` for the next clean beta qualification build profile. Do not change the system SDK selector, widen the SDK 27 guard, or silently fall back between profiles. Rebuild required executables, retain exact toolchain provenance and execute every required normal protected/installed control. This self probe is not SDK lifecycle qualification. Earlier SDK 27 artifacts and diagnostics remain historical and unqualified for this new candidate; no mixed-profile result can stand in for the complete checks.

## Expansion backlog

Linux ARM64/AMD64 and macOS AMD64 remain deferred qualification targets. Revisit their runner capacity, platform-specific implementations and complete evidence matrices after the macOS ARM64 beta, with a separate scope decision. Their existing code and tests stay in the repository.

The main session owns task and gate reconciliation. Both Codex sessions and subagents use this same target; they must stop starting new Linux qualification jobs. Already started local jobs retain exact process/resource ownership and their evidence during safe shutdown.
