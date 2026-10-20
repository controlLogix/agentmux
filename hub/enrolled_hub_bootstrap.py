"""Start one Hub only after every explicit repository identity route is enrolled."""
from __future__ import annotations

import os
import math
import signal
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
APPLICATION_SESSION_START_SECONDS = 5


class EnrolledHubBootstrapFailure(ValueError):
    def __init__(self):
        super().__init__('enrolled_hub_startup_failed')


def _finish_sessions(sessions):
    """Join each original session; never replace or retry its connection."""
    for session in reversed(sessions):
        try:
            session.close(deadline=time.monotonic() + 1)
        except BaseException:
            pass
    complete = True
    for session in reversed(sessions):
        try:
            complete = session.join_final() and complete
        except BaseException:
            complete = False
    return complete


def _run_enrolled_hub(paths, *, startup_deadline=None, loader=None, session_factory=None,
                      resolver_factory=None, server_main=None,
                      authority_switch_loader=None, authority_switch_client_factory=None, message_paths=(), knowledge_paths=(),
                      peer_control_paths=(), policy_paths=(), code_paths=(), work_paths=(), native_core=None):
    """Own admitted sessions around exactly one Hub server invocation."""
    if loader is None:
        from hub.client_launch_selection import load_selection
        loader = load_selection
    if session_factory is None:
        from hub.client_launch_session import ApplicationClientSession
        session_factory = ApplicationClientSession
    if resolver_factory is None:
        from hub.legacy_identity_client import EnrolledLegacyIdentityResolver
        resolver_factory = EnrolledLegacyIdentityResolver
    if server_main is None:
        from hub.server import main
        server_main = main
    if authority_switch_loader is None:
        from hub.client_launch_selection import load_authority_switch_configuration
        authority_switch_loader = load_authority_switch_configuration
    if authority_switch_client_factory is None:
        from hub.authority_switch_recovery_client import EnrolledAuthoritySwitchRecovery
        authority_switch_client_factory = EnrolledAuthoritySwitchRecovery.from_sessions
    sessions = []
    try:
        if type(paths) not in (tuple, list) or not paths:
            raise EnrolledHubBootstrapFailure()
        if type(message_paths) not in (tuple, list) or len(message_paths) > 64:
            raise EnrolledHubBootstrapFailure()
        if type(knowledge_paths) not in (tuple, list) or len(knowledge_paths) > 64:
            raise EnrolledHubBootstrapFailure()
        if type(code_paths) not in (tuple, list) or len(code_paths) > 64:
            raise EnrolledHubBootstrapFailure()
        if type(work_paths) not in (tuple, list) or len(work_paths) > 64:
            raise EnrolledHubBootstrapFailure()
        if type(peer_control_paths) not in (tuple, list) or len(peer_control_paths) > 64:
            raise EnrolledHubBootstrapFailure()
        if type(policy_paths) not in (tuple, list) or len(policy_paths) > 64:
            raise EnrolledHubBootstrapFailure()
        if startup_deadline is None:
            startup_deadline = time.monotonic() + 30
        if (type(startup_deadline) not in (int, float) or not math.isfinite(startup_deadline)
                or not 0 < startup_deadline - time.monotonic() <= 30):
            raise EnrolledHubBootstrapFailure()
        if native_core is not None:
            from hub.native_core_context import NativeCoreContext
            if type(native_core) is not NativeCoreContext:
                raise EnrolledHubBootstrapFailure()
            native_core.require_operator(deadline=startup_deadline)
        selections = [loader(path, deadline=startup_deadline) for path in paths]
        message_selections = [loader(path, deadline=startup_deadline) for path in message_paths]
        knowledge_selections = [loader(path, deadline=startup_deadline) for path in knowledge_paths]
        code_selections = [loader(path, deadline=startup_deadline) for path in code_paths]
        peer_control_selections = [loader(path, deadline=startup_deadline) for path in peer_control_paths]
        policy_selections = [loader(path, deadline=startup_deadline) for path in policy_paths]
        work_selections = [loader(path, deadline=startup_deadline) for path in work_paths]
        if time.monotonic() >= startup_deadline:
            raise EnrolledHubBootstrapFailure()
        hub_ids = {selected.hub_id for selected in
            (*selections, *message_selections, *knowledge_selections, *code_selections,
             *peer_control_selections, *policy_selections, *work_selections)}
        if len(hub_ids) != 1:
            raise EnrolledHubBootstrapFailure()
        hub_id = next(iter(hub_ids))
        recovery = [authority_switch_loader(selected, deadline=startup_deadline)
                    for selected in selections]
        configured = [item for item in recovery if item is not None]
        if configured and (len(configured) != len(recovery)
                or any(item[0] != configured[0][0] for item in configured[1:])):
            raise EnrolledHubBootstrapFailure()
        owners = {}
        for selection_index, selected in enumerate(selections):
            if (selected.application_client is None or selected.application_connection is None
                    or not selected.application_repositories):
                raise EnrolledHubBootstrapFailure()
            for repository in selected.application_repositories:
                if repository in owners:
                    raise EnrolledHubBootstrapFailure()
                owners[repository] = selection_index
        for selected in (*selections, *message_selections, *knowledge_selections, *code_selections,
                         *peer_control_selections, *policy_selections, *work_selections):
            now = time.monotonic()
            if now >= startup_deadline:
                raise EnrolledHubBootstrapFailure()
            session = session_factory(selected)
            sessions.append(session)
            session.start(deadline=min(startup_deadline,
                                       now + APPLICATION_SESSION_START_SECONDS))
        message_sessions = tuple(sessions[len(selections):len(selections) + len(message_selections)])
        for session in message_sessions:
            session.message_enrollment()
        knowledge_start = len(selections) + len(message_selections)
        knowledge_sessions = tuple(sessions[knowledge_start:knowledge_start + len(knowledge_selections)])
        for session in knowledge_sessions:
            session.knowledge_enrollment()
        code_start = knowledge_start + len(knowledge_selections)
        code_sessions = tuple(sessions[code_start:code_start + len(code_selections)])
        for session in code_sessions:
            session.code_enrollment()
        peer_start = code_start + len(code_selections)
        peer_control_sessions = tuple(sessions[peer_start:peer_start + len(peer_control_selections)])
        for session in peer_control_sessions:
            session.peer_control_enrollment()
        policy_start = peer_start + len(peer_control_selections)
        policy_sessions = tuple(sessions[policy_start:policy_start + len(policy_selections)])
        for session in policy_sessions:
            session.federation_policy_enrollment()
        work_sessions = tuple(sessions[policy_start + len(policy_selections):])
        for session in work_sessions:
            session.work_enrollment()
        if time.monotonic() >= startup_deadline:
            raise EnrolledHubBootstrapFailure()
        routed = {repository: sessions[selection_index]
                  for repository, selection_index in owners.items()}
        resolver = resolver_factory(routed, local_source_hub_id=hub_id)
        if time.monotonic() >= startup_deadline:
            raise EnrolledHubBootstrapFailure()
        inputs = {'legacy_identity': resolver}
        if native_core is not None:
            inputs['native_core'] = native_core
        if message_sessions:
            inputs['message_sessions'] = message_sessions
        if knowledge_sessions:
            inputs['knowledge_sessions'] = knowledge_sessions
        if code_sessions:
            inputs['code_sessions'] = code_sessions
        if work_sessions:
            inputs['work_sessions'] = work_sessions
        if peer_control_sessions:
            inputs['peer_control_sessions'] = peer_control_sessions
        if policy_sessions:
            inputs['policy_sessions'] = policy_sessions
        if configured:
            public, closed = configured[0]
            caller = authority_switch_client_factory(sessions, public=public)
            inputs['authority_switch_recovery'] = closed.with_enrolled_recovery(caller)
        result = server_main(**inputs)
    except BaseException as failure:
        from hub.server import HubCleanupFailure
        if (type(failure) is HubCleanupFailure
                and getattr(failure.owner, '_hub_borrowers_joined', False) is not True):
            failure.sessions = tuple(sessions)
            raise
        _finish_sessions(sessions)
        raise
    if not _finish_sessions(sessions):
        raise EnrolledHubBootstrapFailure()
    return result


def _selection_paths(argv):
    paths = []
    index = 0
    while index < len(argv):
        if argv[index] != '--selection' or index + 1 >= len(argv):
            raise EnrolledHubBootstrapFailure()
        paths.append(argv[index + 1])
        index += 2
    if not paths:
        raise EnrolledHubBootstrapFailure()
    return tuple(paths)


def _startup_arguments(argv):
    if len(argv) < 3 or argv[0] != '--startup-deadline':
        raise EnrolledHubBootstrapFailure()
    try:
        deadline = float(argv[1])
    except (TypeError, ValueError):
        raise EnrolledHubBootstrapFailure() from None
    return _selection_paths(argv[2:]), deadline


def _interrupt(_signum, _frame):
    raise KeyboardInterrupt


def _message_paths(argv):
    """Separate explicit protected message selections; never discover defaults."""
    ordinary, messages, index = [], [], 0
    while index < len(argv):
        if argv[index] == '--message-selection':
            if index + 1 >= len(argv) or not argv[index + 1] or argv[index + 1].startswith('--'):
                raise EnrolledHubBootstrapFailure()
            messages.append(argv[index + 1])
            index += 2
        else:
            ordinary.append(argv[index])
            index += 1
    if len(messages) > 64:
        raise EnrolledHubBootstrapFailure()
    return ordinary, tuple(messages)


def _knowledge_paths(argv):
    ordinary, paths, index = [], [], 0
    while index < len(argv):
        if argv[index] == '--knowledge-selection':
            if index + 1 >= len(argv) or not argv[index + 1] or argv[index + 1].startswith('--'):
                raise EnrolledHubBootstrapFailure()
            paths.append(argv[index + 1])
            index += 2
        else:
            ordinary.append(argv[index])
            index += 1
    if len(paths) > 64:
        raise EnrolledHubBootstrapFailure()
    return ordinary, tuple(paths)


def _code_paths(argv):
    """Use only explicitly selected protected code clients."""
    ordinary, paths, index = [], [], 0
    while index < len(argv):
        if argv[index] == '--code-selection':
            if index + 1 >= len(argv) or not argv[index + 1] or argv[index + 1].startswith('--'):
                raise EnrolledHubBootstrapFailure()
            paths.append(argv[index + 1])
            index += 2
        else:
            ordinary.append(argv[index])
            index += 1
    if len(paths) > 64:
        raise EnrolledHubBootstrapFailure()
    return ordinary, tuple(paths)


def _peer_control_paths(argv):
    """Use only explicitly selected protected peer-control clients."""
    ordinary, paths, index = [], [], 0
    while index < len(argv):
        if argv[index] == '--peer-control-selection':
            if index + 1 >= len(argv) or not argv[index + 1] or argv[index + 1].startswith('--'):
                raise EnrolledHubBootstrapFailure()
            paths.append(argv[index + 1])
            index += 2
        else:
            ordinary.append(argv[index])
            index += 1
    if len(paths) > 64:
        raise EnrolledHubBootstrapFailure()
    return ordinary, tuple(paths)


def _policy_paths(argv):
    """Separate explicitly enrolled policy owners from identity defaults."""
    ordinary, paths, index = [], [], 0
    while index < len(argv):
        if argv[index] == '--policy-selection':
            if index + 1 >= len(argv) or not argv[index + 1] or argv[index + 1].startswith('--'):
                raise EnrolledHubBootstrapFailure()
            paths.append(argv[index + 1])
            index += 2
        else:
            ordinary.append(argv[index])
            index += 1
    if len(paths) > 64:
        raise EnrolledHubBootstrapFailure()
    return ordinary, tuple(paths)


def _work_paths(argv):
    """Use only explicitly selected protected work clients."""
    ordinary, paths, index = [], [], 0
    while index < len(argv):
        if argv[index] == '--work-selection':
            if index + 1 >= len(argv) or not argv[index + 1] or argv[index + 1].startswith('--'):
                raise EnrolledHubBootstrapFailure()
            paths.append(argv[index + 1])
            index += 2
        else:
            ordinary.append(argv[index])
            index += 1
    if len(paths) > 64:
        raise EnrolledHubBootstrapFailure()
    return ordinary, tuple(paths)


def main(argv=None):
    previous = signal.signal(signal.SIGTERM, _interrupt)
    try:
        try:
            ordinary, policy_paths = _policy_paths(sys.argv[1:] if argv is None else argv)
            ordinary, work_paths = _work_paths(ordinary)
            ordinary, peer_control_paths = _peer_control_paths(ordinary)
            ordinary, code_paths = _code_paths(ordinary)
            ordinary, knowledge_paths = _knowledge_paths(ordinary)
            ordinary, message_paths = _message_paths(ordinary)
            paths, deadline = _startup_arguments(ordinary)
            return _run_enrolled_hub(paths, startup_deadline=deadline, message_paths=message_paths,
                knowledge_paths=knowledge_paths, code_paths=code_paths, work_paths=work_paths,
                peer_control_paths=peer_control_paths, policy_paths=policy_paths)
        except KeyboardInterrupt:
            return 130
        except BaseException:
            print('enrolled hub startup failed', file=sys.stderr)
            return 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
