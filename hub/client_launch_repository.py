"""Carry an untrusted repo profile ID into retained native resolution and exec."""
import os
import time

from hub.client_launch_coordinator import result
from hub.client_launch_selection import admit_runtime


class _RepositoryCleanup:
    """Keep original failed cleanup owners; never retry consumed descriptors."""
    def __init__(self, owners):
        self.owners = tuple(owners)

    def finish_cleanup(self):
        return False


class _HandoffFailure(ValueError):
    def __init__(self, owner, *causes):
        super().__init__('repository_profile_cleanup_pending')
        self.cleanup_owners = (owner,) + tuple(item for item in _cleanup_owners(*causes) if item is not owner)
        self._causes = causes


def _cleanup_owners(*errors):
    owners = []
    for error in errors:
        for owner in (*getattr(error, 'cleanup_owners', ()),
                getattr(error, 'recovery', None), getattr(error, 'cleanup', None)):
            if owner is not None and all(owner is not item for item in owners):
                owners.append(owner)
    return tuple(owners)


def _close_handoff(owner, failure):
    try:
        owner.close()
        closed = owner.closed
    except BaseException as cleanup:
        raise _HandoffFailure(owner, failure, cleanup) from None
    if closed is not True:
        raise _HandoffFailure(owner, failure) from None


def profile_operation(options, *, mcp):
    if mcp:
        return 'mcp-worker' if options.managed_worker else 'mcp'
    operation = 'startup-worker' if options.managed_worker else 'startup'
    return operation + '-json' if options.output == 'json' else operation


def _handoff(profile_id, repository, operation, *, deadline, admit, replace):
    owner = None
    try:
        owner = admit(deadline=deadline)
        owner.recheck(deadline=deadline)
        if time.monotonic() >= deadline:
            raise ValueError('repository_profile_deadline')
        # No resolved path crosses stdout or an environment variable. Native
        # resolution retains its own central owner through ExecClient.
        replace(owner.path, [owner.path, 'profile-client', '--profile-id', profile_id,
            '--repository-root', repository, '--operation', operation])
        raise ValueError('repository_profile_exec_failed')
    except BaseException as failure:
        if owner is not None:
            _close_handoff(owner, failure)
        raise


def repository_startup(options, *, mcp, deadline):
    """Return setup required on refusal; successful native exec never returns."""
    from dashboard.repository_profiles import read_repository_profile
    return _repository_startup(options, mcp=mcp, deadline=deadline,
        read=read_repository_profile, admit=admit_runtime, replace=os.execv)


def _repository_startup(options, *, mcp, deadline, read, admit, replace):
    operation = 'status' if options.managed_worker else 'ensure'
    out = result(operation, 'setup_required', 'setup_required')
    try:
        reference = read(options.repository_root, deadline=deadline)
        if reference is None:
            return out
        _handoff(reference.profile_id, options.repository_root, profile_operation(options, mcp=mcp),
                 deadline=deadline, admit=admit, replace=replace)
    except Exception as error:
        owners = list(getattr(error, 'cleanup_owners', ()))
        recovery = getattr(error, 'recovery', None)
        if recovery is not None and all(owner is not recovery for owner in owners):
            owners.append(recovery)
        cleanup = getattr(error, 'cleanup', None)
        if cleanup is not None and all(owner is not cleanup for owner in owners):
            owners.append(cleanup)
        if owners:
            out.selection_cleanup = _RepositoryCleanup(owners)
            out.public.update(outcome='failed', code='selection_cleanup_pending')
        return out
    return out


def core_handoff(repository, arguments, *, profile_id=None):
    """Use the same admitted native resolver; never select a socket in this caller."""
    from dashboard.repository_profiles import read_repository_profile
    deadline = time.monotonic() + 1
    if profile_id is None:
        reference = read_repository_profile(repository, deadline=deadline)
        if reference is None:
            raise ValueError('selected_core_setup_required')
        profile_id = reference.profile_id
    return _core_handoff(repository, arguments, profile_id=profile_id, deadline=deadline)


def _core_handoff(repository, arguments, *, profile_id, deadline, discovery=None):
    owner = None
    try:
        owner = admit_runtime(deadline=deadline)
        owner.recheck(deadline=deadline)
        if discovery is not None:
            discovery.recheck()
        if time.monotonic() >= deadline:
            raise ValueError('repository_profile_deadline')
        os.execv(owner.path, [owner.path, 'profile-core', '--profile-id', profile_id,
            '--repository-root', repository, '--', *arguments])
        raise ValueError('repository_profile_exec_failed')
    except BaseException as failure:
        if owner is not None:
            _close_handoff(owner, failure)
        raise


class RepositoryCoreCallback:
    """Resolve the real current repository again; its reference grants no authority."""
    def invoke(self, arguments):
        from hub.core_profile import core_arguments, CoreSetupRequired
        from dashboard.repository_profiles import discover_repository_profile, RepositoryProfileError
        command = core_arguments(list(arguments))
        if command == ['start']:
            raise CoreSetupRequired()
        deadline = time.monotonic() + 1
        with discover_repository_profile(os.getcwd(), deadline=deadline) as selected:
            try:
                return _core_handoff(selected.repository, command,
                    profile_id=selected.reference.profile_id, deadline=deadline, discovery=selected)
            except BaseException as failure:
                owners = _cleanup_owners(failure)
                if owners:
                    raise RepositoryProfileError('repository_profile_cleanup_pending',
                        recovery=getattr(failure, 'recovery', None), cleanup_owners=owners) from failure
                raise
