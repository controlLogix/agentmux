"""Build explicit runtime invocations for client startup integrations.

The caller supplies an installer-admitted executable reference. This module does
not discover releases, admit executables, run commands, or grant application access.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass


STABLE_RUNTIME_EXECUTABLE = "/Library/Application Support/Agentmux/Protected/agentmux-runtime"


class StartupSelectionError(ValueError):
    """The caller did not supply a complete explicit startup selection."""


def _absolute(value: str) -> bool:
    return (isinstance(value, str) and bool(value) and "\x00" not in value
            and os.path.isabs(value) and os.path.normpath(value) == value)


def _service_path(value):
    if (type(value) is not str or not _absolute(value) or value.startswith('//')
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        return False
    try:
        return len(value.encode('utf-8')) <= 4096
    except UnicodeError:
        return False


@dataclass(frozen=True)
class RuntimeInvocation:
    """Arguments only; the caller supplies an already admitted executable.

    The runtime admits the selected policy and host after invocation.

    Workspace roots must come from the caller's approved selection, never from
    the policy being checked. Construct a new value after an approved selection
    change. Neither environment variables nor the current directory select one.
    """

    executable: str
    host_policy: str
    workspaces: tuple[str, ...]
    application_attestor_selection: str | None = None
    application_attestor_digest: str | None = None
    application_services_installation: str | None = None
    application_services_selection: str | None = None
    application_services_digest: str | None = None

    def __post_init__(self):
        if (not _absolute(self.executable) or not _absolute(self.host_policy)
                or type(self.workspaces) is not tuple
                or not 1 <= len(self.workspaces) <= 16
                or any(not _absolute(root) for root in self.workspaces)):
            raise StartupSelectionError("Explicit launcher, policy and workspace paths are required.")

        if (self.application_attestor_selection is not None or self.application_attestor_digest is not None):
            if (not _absolute(self.application_attestor_selection)
                    or not isinstance(self.application_attestor_digest, str)
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.application_attestor_digest)):
                raise StartupSelectionError("Application attestor selection and digest must be supplied together.")

        services = (self.application_services_installation, self.application_services_selection,
                    self.application_services_digest)
        if any(value is not None for value in services):
            if (self.application_attestor_selection is None
                    or type(self.application_services_installation) is not str
                    or not re.fullmatch(r'[0-9a-f]{64}', self.application_services_installation)
                    or not _service_path(self.application_services_selection)
                    or type(self.application_services_digest) is not str
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.application_services_digest)):
                raise StartupSelectionError('Application services require complete pins and an application attestor.')

    def arguments(self, *, managed_worker: bool = False) -> tuple[str, ...]:
        """Ordinary launch requests ensure once; a managed worker only queries.

        Pass this tuple directly to a process API with shell=False. The caller
        owns managed-worker detection, the process, its deadline, bounded output
        and joined cleanup. Keep
        its working directory unchanged and keep protocol stdout separate.
        """
        if type(managed_worker) is not bool:
            raise StartupSelectionError("Managed-worker selection must be explicit.")
        operation = "status" if managed_worker else "ensure"
        args = [self.executable, operation, "--host-policy", self.host_policy]
        for root in self.workspaces:
            args.extend(("--workspace", root))
        if not managed_worker and self.application_attestor_selection is not None:
            args.extend(('--application-attestor-selection', self.application_attestor_selection,
                         '--application-attestor-selection-sha256', self.application_attestor_digest))
        if not managed_worker and self.application_services_installation is not None:
            args.extend(('--application-services-installation', self.application_services_installation,
                         '--application-services-selection', self.application_services_selection,
                         '--application-services-selection-sha256', self.application_services_digest))
        return tuple(args)
