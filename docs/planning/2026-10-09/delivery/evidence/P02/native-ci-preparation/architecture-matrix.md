# Explicit native architecture coverage

The foundation workflow now selects four native runner targets: Linux amd64 (`ubuntu-24.04`), Linux arm64 (`ubuntu-24.04-arm`), macOS amd64 (`macos-15-intel`) and macOS arm64 (`macos-15`). The Darwin research and protected-install jobs run on both macOS targets. Artifact names include the runner label so their evidence remains distinct.

These labels follow the current [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), checked October 14, 2026. The foundation job also checks the actual machine architecture against its matrix target before collecting evidence.

Local verification: `python tests/platform/native_go.py --self-test` passed all 39 synthetic collector controls. This checks the collector, not execution of the new hosted jobs. No hosted job has been dispatched or accepted by this update.

The workflow still collects foundation, Darwin research and protected-install evidence only. It does not qualify full native Compose startup, the installed CLI matrix or WSL. Those acceptance requirements remain open. This update does not narrow either architecture out of the supported release scope.
