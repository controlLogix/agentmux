# Bootstrap lock review

The isolated WSL lock-only race run passed on the exact recorded sources. The tests cover killed process recovery on the same inode, symlink/hardlink refusal, deadline/cancellation, owner metadata and the actual 30-second contention limit. This is scoped evidence, not phase acceptance or macOS qualification.

The full package run under historical-draft-docker-package failed three unfinished concurrent Docker wrapper tests; all lock cases passed. Those original bytes remain historical and are not labeled a successful package run. The Docker owner received the diagnostics.

The fixture used no broker, credentials, providers or real Docker commands. Logs were reviewed for secret assignments before copying. Source paths and disposable process diagnostics remain for provenance. Runtime parent paths must be enrolled/canonicalized; advisory locking cannot prevent a hostile same-user inode removal or interrupt blocking filesystem operations.
