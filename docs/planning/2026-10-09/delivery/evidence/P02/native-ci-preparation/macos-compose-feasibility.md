# Native macOS Compose verification

Research date: October 14, 2026. Status: a possible test environment; not executed or accepted for Agentmux.

The declared qualification scope includes macOS amd64 and arm64, and Linux amd64 and arm64. An Intel runner experiment covers only its actual architecture. Keep the other native architecture checks open; do not reduce support requirements to the environment easiest to provision. See [runtime and deployment requirements](../../../decisions/runtime-and-deployment.md).

The current Agentmux foundation workflow does not establish complete native macOS Compose boot. GitHub documents a nested-virtualization limitation for macOS runners. Do not assume an Apple Silicon runner can start Docker Desktop or a Virtualization Framework VM. [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

Colima's current upstream macOS integration workflow selects `macos-15-intel`. Its reusable Docker workflow installs Docker and Lima, starts a local Colima Docker runtime, and checks container execution and persistence across restart. This is a concrete environment to investigate before treating physical Mac access as the only option. The workflow source alone does not prove that a particular run passed or that Agentmux meets its deadlines there. [Colima macOS workflow](https://github.com/abiosoft/colima/blob/main/.github/workflows/macos-integration.yml), [reusable Docker workflow](https://github.com/abiosoft/colima/blob/main/.github/workflows/_docker.yml)

The next bounded experiment should keep Agentmux's CLI, protected roles and private enrollment on native macOS, with the local NATS Compose service in the local Linux VM. Capture the real Docker executable, context, endpoint, engine identity and versions. Adapt the existing fixture's Windows-only selection through platform-specific fixture code; do not point the Mac host at the Windows test engine or change production assertions. Pin the qualified tools before collecting acceptance evidence.

Require real cold, concurrent and warm installed launches, frontend survival, owner recovery, unchanged unrelated resources, retained volume identity and TLS refusal checks. Keep the existing startup and cleanup limits. If the environment fails its preflight or timing checks, retain the failed evidence and leave native acceptance open. No cloud purchase, runner dispatch, installation or product support declaration occurred during this research.
