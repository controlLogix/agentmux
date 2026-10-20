"""Read the client adapter's explicit, private enrollment selection."""
from dataclasses import dataclass
import hashlib
import os
import re
import stat
import time
from typing import Protocol

from hub.client_startup import RuntimeInvocation, STABLE_RUNTIME_EXECUTABLE
from hub.profile_context import ProfileContext, RegisteredProfileContext
from hub import native_descriptor_admission
from hub.native_descriptor_admission import AdmissionError, DescriptorPurpose
from sdk.python.agentmux_contracts.wire import strict_loads


class SelectionError(ValueError):
    """Fixed diagnostics only; private paths never enter public output."""
    def __init__(self, code, *, cleanup=None):
        super().__init__(code)
        self.cleanup = cleanup


class DescriptorCleanup:
    """Retain consumed-close uncertainty; never retry these descriptor numbers."""
    def __init__(self):
        self.uncertain = []

    def close(self, fd):
        try:
            os.close(fd)
        except BaseException:
            self.uncertain.append(fd)
            raise SelectionError("selection_cleanup_pending", cleanup=self) from None

    def finish_cleanup(self):
        return not self.uncertain


class DescriptorAdmission(Protocol):
    def __call__(self, fd: int, *, purpose: DescriptorPurpose, deadline: float) -> bool: ...


def _open_checked(path, *, purpose: DescriptorPurpose,
                 descriptor_admission: DescriptorAdmission | None, deadline: float):
    """Open through held, non-symlink ancestors; the caller owns the returned fd."""
    if (not isinstance(path, str) or not os.path.isabs(path) or
            os.path.normpath(path) != path or "\x00" in path or len(path) > 4096):
        raise SelectionError("selection_invalid")
    if descriptor_admission is None:
        raise SelectionError("native_admission_required")
    if purpose not in (DescriptorPurpose.PRIVATE_FILE, DescriptorPurpose.PROTECTED_EXECUTABLE):
        raise SelectionError("selection_invalid")
    private = purpose == DescriptorPurpose.PRIVATE_FILE
    parts = path.split("/")[1:]
    if not parts or len(parts) > 128 or any(not part for part in parts):
        raise SelectionError("selection_invalid")
    def admit(fd, role):
        if time.monotonic() >= deadline:
            raise SelectionError("selection_deadline")
        try:
            accepted = descriptor_admission(fd, purpose=role, deadline=deadline)
        except AdmissionError:
            raise SelectionError("native_admission_failed") from None
        if accepted is not True:
            raise SelectionError("selection_permissions")
        if time.monotonic() >= deadline:
            raise SelectionError("selection_deadline")
    uid = os.geteuid()
    cleanup = DescriptorCleanup()
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    output = None
    try:
        ancestor = DescriptorPurpose.PRIVATE_ANCESTOR if private else DescriptorPurpose.PROTECTED_ANCESTOR
        admit(parent, ancestor)
        for index, part in enumerate(parts[:-1]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            try:
                admit(child, DescriptorPurpose.PRIVATE_DIRECTORY
                      if private and index == len(parts) - 2 else ancestor)
                info = os.fstat(child)
                if info.st_uid not in ((0, uid) if private else (0,)) or info.st_mode & 0o022:
                    raise SelectionError("selection_permissions")
            except BaseException:
                cleanup.close(child)
                raise
            previous, parent = parent, child
            cleanup.close(previous)
        info = os.fstat(parent)
        if private and (info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700):
            raise SelectionError("selection_permissions")
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            admit(fd, purpose)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != (uid if private else 0) or
                    stat.S_IMODE(info.st_mode) != (0o600 if private else 0o555)):
                raise SelectionError("selection_permissions")
        except BaseException:
            cleanup.close(fd)
            raise
        output = fd
        return fd
    finally:
        try:
            cleanup.close(parent)
        except BaseException:
            if output is not None:
                cleanup.close(output)
            raise


@dataclass(frozen=True)
class ClientSelection:
    invocation: RuntimeInvocation
    instance_id: str
    profile_id: str
    hub_id: str
    application_client: str | None = None
    application_connection: str | None = None
    profile_context: ProfileContext | None = None
    application_repositories: tuple[str, ...] = ()
    core_hub: dict | None = None


def load_authority_switch_configuration(selected, *, deadline):
    """Read the public cutover binding from the exact pinned service selection."""
    invocation = getattr(selected, 'invocation', None)
    if invocation is None:
        return None
    path = getattr(invocation, 'application_services_selection', None)
    digest = getattr(invocation, 'application_services_digest', None)
    if path is None and digest is None:
        try:
            from identity.application_service_selection import retained_authority_switch_exists
            if retained_authority_switch_exists(
                    os.path.join(os.path.dirname(os.path.realpath(invocation.host_policy)),
                                 'authority-switch')):
                raise SelectionError('selection_invalid')
        except SelectionError:
            raise
        except Exception:
            raise SelectionError('selection_invalid') from None
        return None
    if path is None or digest is None or time.monotonic() >= deadline:
        raise SelectionError('selection_invalid')
    fd = _open_checked(path, purpose=DescriptorPurpose.PRIVATE_FILE,
        descriptor_admission=native_descriptor_admission.check_descriptor, deadline=deadline)
    try:
        before = os.fstat(fd)
        raw = os.read(fd, 65537)
        after = os.fstat(fd)
        if (time.monotonic() >= deadline or len(raw) > 65536
                or before.st_size != len(raw)
                or _identity(fd) != _identity_from_stat(before)
                or (before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_mtime_ns, after.st_ctime_ns)
                or 'sha256:' + hashlib.sha256(raw).hexdigest() != digest):
            raise SelectionError('selection_invalid')
    finally:
        DescriptorCleanup().close(fd)
    try:
        from identity.application_service_selection import ApplicationServiceSelection
        service = ApplicationServiceSelection(raw)
        value = service.policy
        kernel = value['kernelScope']
        if (value['hostPolicy'] != invocation.host_policy
                or tuple(value['workspaces']) != invocation.workspaces
                or value['ownerUid'] != os.getuid()
                or (kernel['hubId'], kernel['profileId'], kernel['instanceId'])
                    != (selected.hub_id, selected.profile_id, selected.instance_id)):
            raise ValueError()
        return service.authority_switch_configuration()
    except SelectionError:
        raise
    except Exception:
        raise SelectionError('selection_invalid') from None


def load_selection(path, *, deadline=None, registered_context=None):
    """Load enrollment using only the fixed production native checker."""
    return _load_selection(path, descriptor_admission=native_descriptor_admission.check_descriptor, deadline=deadline,
                           registered_context=registered_context)


def _load_selection(path, *, descriptor_admission, deadline=None, registered_context=None):
    """No discovery, default profile, environment selection or policy-derived grants."""
    if registered_context is not None and type(registered_context) is not RegisteredProfileContext:
        raise SelectionError("selection_invalid")
    if path is None:
        raise SelectionError("setup_required")
    if deadline is None:
        deadline = time.monotonic() + 1
    try:
        fd = _open_checked(path, purpose=DescriptorPurpose.PRIVATE_FILE,
                          descriptor_admission=descriptor_admission, deadline=deadline)
        try:
            before = os.fstat(fd)
            raw = os.read(fd, 16385)
            after = os.fstat(fd)
            if time.monotonic() >= deadline:
                raise SelectionError("selection_deadline")
            if len(raw) > 16384 or before.st_size != len(raw) or (
                    before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
                raise SelectionError("selection_invalid")
        finally:
            DescriptorCleanup().close(fd)
        data = strict_loads(raw)
        required = {"schemaVersion", "hostPolicy", "workspaces", "instanceId", "profileId", "hubId"}
        if (type(data) is not dict or not required <= set(data) <= required | {
                'application', 'applicationAttestor', 'applicationServices', 'coreHub'}
                or data["schemaVersion"] != "1.0.0" or type(data["workspaces"]) is not list):
            raise SelectionError("selection_invalid")
        for key in ("instanceId", "profileId", "hubId"):
            if not isinstance(data[key], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", data[key]):
                raise SelectionError("selection_invalid")
        if registered_context is not None and not registered_context.matches_selection(
                raw, profile_id=data['profileId'], instance_id=data['instanceId']):
            raise SelectionError('selection_invalid')
        core = data.get('coreHub')
        if 'coreHub' in data and (type(core) is not dict or set(core) != {'selection', 'sha256'}
                or type(core['selection']) is not str or not os.path.isabs(core['selection'])
                or os.path.normpath(core['selection']) != core['selection']
                or type(core['sha256']) is not str or re.fullmatch(r'sha256:[0-9a-f]{64}', core['sha256']) is None):
            raise SelectionError('selection_invalid')
        attestor = data.get('applicationAttestor')
        if 'applicationAttestor' in data and (type(attestor) is not dict or set(attestor) != {'selection', 'sha256'}
                or any(type(value) is not str for value in attestor.values())):
            raise SelectionError('selection_invalid')
        services = data.get('applicationServices')
        if 'applicationServices' in data and (
                attestor is None or type(services) is not dict
                or set(services) != {'installationId', 'selection', 'sha256'}
                or any(type(value) is not str for value in services.values())):
            raise SelectionError('selection_invalid')
        invocation = RuntimeInvocation(STABLE_RUNTIME_EXECUTABLE, data["hostPolicy"], tuple(data["workspaces"]),
                                       None if attestor is None else attestor['selection'],
                                       None if attestor is None else attestor['sha256'],
                                       application_services_installation=None if services is None else services['installationId'],
                                       application_services_selection=None if services is None else services['selection'],
                                       application_services_digest=None if services is None else services['sha256'])
        application = data.get('application')
        repositories = ()
        if application is not None:
            if (type(application) is not dict
                    or set(application) not in ({'clientKey', 'connection'},
                                                {'clientKey', 'connection', 'repositories'})):
                raise SelectionError('selection_invalid')
            for value in (application['clientKey'], application['connection']):
                if (not isinstance(value, str) or not os.path.isabs(value)
                        or os.path.normpath(value) != value or '\x00' in value or len(value) > 4096):
                    raise SelectionError('selection_invalid')
            selected_repositories = application.get('repositories', [])
            if (type(selected_repositories) is not list or
                    'repositories' in application and not selected_repositories
                    or any(type(name) is not str or re.fullmatch(r'[a-z0-9_]{1,32}', name) is None
                           for name in selected_repositories)
                    or len(set(selected_repositories)) != len(selected_repositories)):
                raise SelectionError('selection_invalid')
            repositories = tuple(selected_repositories)
        elif 'application' in data:
            raise SelectionError('selection_invalid')
        external_paths = ((path, invocation.host_policy)
                          + (() if application is None else
                             (application['clientKey'], application['connection']))
                          + (() if attestor is None else (attestor['selection'],))
                          + (() if services is None else (services['selection'],))
                          + (() if core is None else (core['selection'],)))
        for root in invocation.workspaces:
            approved = os.path.realpath(root)
            for external in external_paths:
                if os.path.commonpath((approved, os.path.realpath(external))) == approved:
                    raise SelectionError("selection_inside_workspace")
        return ClientSelection(invocation=invocation, instance_id=data["instanceId"],
                               profile_id=data["profileId"], hub_id=data["hubId"],
                               application_client=None if application is None else application['clientKey'],
                               application_connection=None if application is None else application['connection'],
                               application_repositories=repositories, core_hub=core,
                               profile_context=None if registered_context is None else registered_context.context)
    except SelectionError:
        raise
    except (OSError, ValueError, TypeError, KeyError):
        raise SelectionError("selection_invalid") from None


def _identity(fd):
    info = os.fstat(fd)
    return _identity_from_stat(info)


def _identity_from_stat(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class RetainedRuntime(Protocol):
    """One admitted executable owner passed from admission to process cleanup."""
    @property
    def path(self) -> str: ...
    @property
    def closed(self) -> bool: ...
    def recheck(self, *, deadline: float) -> None: ...
    def close(self) -> None: ...


class RuntimeAdmission:
    """Retain the opened executable and reject substitution before invocation.

    This is a protected-path launch, not fd-based execution. A trusted system
    administrator still controls the path. An ordinary client cannot replace it.
    """
    def __init__(self, fd: int, path: str, admission: DescriptorAdmission):
        self._fd = fd
        self._path = path
        self._admission = admission
        self._identity = _identity(fd)
        self._uncertain_closes = []
        self._walk_cleanup = None

    @property
    def path(self):
        return self._path

    @property
    def closed(self):
        return (self._fd is None and not self._uncertain_closes
                and (self._walk_cleanup is None or self._walk_cleanup.finish_cleanup()))

    def recheck(self, *, deadline):
        if (self._fd is None or self._uncertain_closes or self._walk_cleanup is not None
                or time.monotonic() >= deadline):
            raise SelectionError("launcher_unavailable")
        try:
            accepted = self._admission(self._fd, purpose=DescriptorPurpose.PROTECTED_EXECUTABLE, deadline=deadline)
        except AdmissionError:
            raise SelectionError("native_admission_failed") from None
        if accepted is not True or _identity(self._fd) != self._identity:
            raise SelectionError("launcher_unavailable")
        try:
            current = _open_checked(self.path, purpose=DescriptorPurpose.PROTECTED_EXECUTABLE,
                                    descriptor_admission=self._admission, deadline=deadline)
        except SelectionError as exc:
            self._walk_cleanup = exc.cleanup
            raise
        try:
            if _identity(current) != self._identity or time.monotonic() >= deadline:
                raise SelectionError("launcher_unavailable")
        finally:
            try:
                os.close(current)
            except BaseException:
                self._uncertain_closes.append(current)
                raise

    def close(self):
        if self._fd is not None:
            fd, self._fd = self._fd, None
            try:
                os.close(fd)
            except BaseException:
                self._uncertain_closes.append(fd)
                raise  # Retain uncertainty; never retry a possibly consumed fd.


def admit_runtime(*, deadline=None) -> RetainedRuntime:
    """Admit the protected frontend with the fixed production native checker."""
    return _admit_runtime(descriptor_admission=native_descriptor_admission.check_descriptor, deadline=deadline)


def _admit_runtime(*, descriptor_admission, deadline=None) -> RetainedRuntime:
    """Return ownership of the fixed protected executable; do not close early."""
    try:
        fd = _open_checked(STABLE_RUNTIME_EXECUTABLE, purpose=DescriptorPurpose.PROTECTED_EXECUTABLE,
                          descriptor_admission=descriptor_admission,
                          deadline=deadline if deadline is not None else time.monotonic() + 1)
        try:
            return RuntimeAdmission(fd, STABLE_RUNTIME_EXECUTABLE, descriptor_admission)
        except BaseException:
            DescriptorCleanup().close(fd)
            raise
    except SelectionError as exc:
        if exc.cleanup is not None:
            raise
        raise SelectionError("launcher_unavailable") from None
    except OSError:
        raise SelectionError("launcher_unavailable") from None
