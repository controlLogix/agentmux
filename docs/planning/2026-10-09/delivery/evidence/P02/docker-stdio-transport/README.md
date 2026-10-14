# Read-only Docker engine transport diagnostic

Three actual WSL reads through the installed Windows CLI returned the pinned Linux engine and server version. The tunnel query took 0.27–0.36 seconds; selected-context verification plus query took 0.58–0.75 seconds. The production four-second deadline was not changed. [Proposal and source bindings](proposal.json) identify the safe result fields and remaining verification.

The pinned [Docker info source](https://raw.githubusercontent.com/docker/cli/v29.8.0/cli/command/system/info.go) gathers plugin metadata before server data. Its [dial-stdio helper](https://raw.githubusercontent.com/docker/cli/v29.8.0/cli/command/system/dial_stdio.go) opens a raw selected-daemon connection. The helper is hidden and version-sensitive; this is not a claim of a stable public CLI interface.

The first attempt closed stdin immediately and failed; its precise cause was not retained. Keeping stdin open with a literal `GET /info` and `Connection: close` passed all three later trials. Both records are preserved. No full info, credentials, configuration or stderr were saved; no Docker resource was mutated. Root owns any production adapter change and its acceptance checks.

## Private transport implementation

The new private helper and its tests now have independent source review and 16 passing focused race-test entries. Static checks also pass. [The implementation record](implementation-results.json) binds these results to the exact source hashes and frozen candidate. The fixtures use a disposable CLI process on Linux; this is separate from the earlier actual Windows diagnostic.

The first wider launcher run failed in other owned slices. An intermediate framing repair also failed compilation; both records remain intact. The final helper rejects mixed line endings before HTTP parsing, keeps its input pipe open until the owned process exits, and refuses unqualified versions without fallback. Root owns adapter integration, actual Windows verification, the stable affected-suite run and phase acceptance.
