"""Read a bounded regular file beneath a host-resolved existing checkout."""
import os
import stat
import threading

from agentmux_contracts import ContractError
from hub.fed.code_services import Checkout


class WorkspaceRoot:
    def __init__(self, checkout):
        # RepositoryDirectory.checkout resolves this host-private value. Request
        # JSON never supplies the root, remote, repository ID or an absolute path.
        if not isinstance(checkout, Checkout) or not os.path.isabs(checkout.path):
            raise ContractError('capability_workspace_configuration')
        try:
            self._fd = os.open(checkout.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise ContractError('capability_workspace_unavailable') from None
        self._repository_id = checkout.rid
        self._lock = threading.Lock()

    def __repr__(self):
        return '<WorkspaceRoot private>'

    def check_files(self):
        with self._lock:
            if self._fd is None:
                raise ContractError('capability_workspace_stale')

    async def check_current(self):
        self.check_files()

    def close(self):
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def read(self, relative, *, repository_id):
        if (not isinstance(relative, str) or not 0 < len(relative) <= 1024
                or relative.startswith('/') or any(c in relative for c in '\\\x00\r\n')
                or any(part in ('', '.', '..') for part in relative.split('/'))
                or repository_id != self._repository_id):
            raise ContractError('capability_workspace_refused')
        with self._lock:
            if self._fd is None:
                raise ContractError('capability_workspace_stale')
            fd = os.dup(self._fd)
        try:
            parts = relative.split('/')
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                before = os.fstat(file_fd)
                if not stat.S_ISREG(before.st_mode) or before.st_size > 45000:
                    raise ContractError('capability_workspace_refused')
                data = bytearray()
                while len(data) <= 45000:
                    chunk = os.read(file_fd, min(8192, 45001 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                after = os.fstat(file_fd)
                if (len(data) > 45000 or len(data) != before.st_size
                        or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise ContractError('capability_workspace_changed')
                return bytes(data)
            finally:
                os.close(file_fd)
        except OSError:
            raise ContractError('capability_workspace_unavailable') from None
        finally:
            os.close(fd)
