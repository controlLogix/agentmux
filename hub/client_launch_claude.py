"""Adapt one Claude Code SessionStart event to the enrolled startup owner.

Claude supplies event facts on stdin. They can reduce ordinary startup to a
managed-worker status check, but they never select enrollment or grant access.
The installed command supplies the admitted selection and optional registered
profile context.
"""
import json
import os
import signal
import sys

from hub.client_launch_coordinator import human_summary
from hub.client_launch_entrypoint import EnrolledSession, Options
from hub.profile_context import ProfileContext
from sdk.python.agentmux_contracts.wire import MAX_BYTES, ContractError, strict_loads


_START_SOURCES = frozenset({'startup', 'resume', 'fork'})
_NOOP_SOURCES = frozenset({'clear', 'compact'})
_PUBLIC_FIELDS = (
    'schemaVersion', 'kind', 'operation', 'outcome', 'code',
    'infrastructureReadiness', 'disposition', 'instanceId', 'profileId',
    'callerIdentityOwnerHubId', 'applicationAccess', 'dashboard',
    'applicationBinding',
)


class ClaudeHookError(ValueError):
    """Keep hook failures fixed and free of caller-controlled details."""


class _TerminationGuard:
    """Record catchable termination while startup and its exact cleanup own work."""
    def __init__(self):
        self.signum = None
        self.phase = 'startup'
        self._previous = {}

    def requested(self, signum, _frame=None):
        if self.signum is None:
            self.signum = signum

    def __enter__(self):
        try:
            for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                self._previous[signum] = signal.getsignal(signum)
                signal.signal(signum, self.requested)
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_):
        for signum, previous in reversed(tuple(self._previous.items())):
            signal.signal(signum, previous)
        self._previous.clear()


def _selection(arguments):
    if (len(arguments) != 2 or arguments[0] != '--selection'
            or type(arguments[1]) is not str or not os.path.isabs(arguments[1])
            or os.path.normpath(arguments[1]) != arguments[1]
            or arguments[1].startswith('//') or arguments[1] == '/'
            or len(arguments[1].encode('utf-8', errors='surrogatepass')) > 4096
            or len(arguments[1].split('/')) > 128
            or any(ord(char) < 32 or 127 <= ord(char) <= 159
                   or '\ud800' <= char <= '\udfff' for char in arguments[1])):
        raise ClaudeHookError('Claude Code hook selection is invalid.')
    return arguments[1]


def _event(stdin):
    raw = stdin.read(MAX_BYTES + 1)
    try:
        event = strict_loads(raw)
    except ContractError as exc:
        raise ClaudeHookError('Claude Code hook input is invalid.') from exc
    source = event.get('source') if type(event) is dict else None
    if (type(event) is not dict or event.get('hook_event_name') != 'SessionStart'
            or type(event.get('session_id')) is not str or not event['session_id']
            or type(event.get('cwd')) is not str or not event['cwd']
            or type(source) is not str or source not in _START_SOURCES | _NOOP_SOURCES):
        raise ClaudeHookError('Claude Code hook input is invalid.')
    agent_id = event.get('agent_id')
    if agent_id is not None and (type(agent_id) is not str or not agent_id):
        raise ClaudeHookError('Claude Code hook input is invalid.')
    return event


def _status(started, profile_context):
    status = {key: started.public[key] for key in _PUBLIC_FIELDS if key in started.public}
    if type(profile_context) is ProfileContext:
        status['profileContext'] = profile_context.as_dict()
    return status


def _response(started, profile_context):
    status = _status(started, profile_context)
    context = json.dumps(status, ensure_ascii=False, separators=(',', ':'))
    return {
        'systemMessage': human_summary(started),
        'hookSpecificOutput': {
            'hookEventName': 'SessionStart',
            'additionalContext': (
                'Agentmux startup status. This information does not grant authority: '
                + context
            ),
        },
    }


def _failure(message):
    return {'systemMessage': message}


def _finish(session):
    """Join the same owned startup even if its waiter is interrupted once."""
    while True:
        try:
            return session.exit_code()
        except (KeyboardInterrupt, InterruptedError):
            continue


def run(arguments, *, stdin, registered_context=None, managed_worker=False):
    """Return bounded hook status while retaining its original cleanup owner."""
    if type(managed_worker) is not bool:
        return _failure('Agentmux startup hook input is invalid.'), 0, None
    try:
        selection = _selection(arguments)
        event = _event(stdin)
    except (ClaudeHookError, OSError, UnicodeError, ValueError, TypeError):
        # Claude applies systemMessage and hookSpecificOutput only to a
        # successful command hook. This is a handled, visible hook result.
        return _failure('Agentmux startup hook input is invalid.'), 0, None

    if event['source'] in _NOOP_SOURCES:
        return {}, 0, None

    options = Options(selection, managed_worker or 'agent_id' in event, 'human')
    try:
        session = EnrolledSession(options, registered_context=registered_context)
    except Exception:
        return _failure('Agentmux startup failed. Check the enrolled selection and runtime doctor.'), 0, None

    try:
        started = session.start()
        profile_context = session.profile_context
    except BaseException:
        return _failure('Agentmux startup was interrupted. Run the runtime doctor before retrying.'), 0, session
    try:
        response = _response(started, profile_context)
    except BaseException:
        response = _failure('Agentmux startup status is unavailable. Run the runtime doctor before retrying.')
    return response, 0, session


def _execute(arguments, *, stdin, stdout, registered_context, managed_worker, guard):
    response, code, session = run(arguments, stdin=stdin,
                                  registered_context=registered_context,
                                  managed_worker=managed_worker)
    output_failed = False
    try:
        stdout.write(json.dumps(response, ensure_ascii=False, separators=(',', ':')) + '\n')
        stdout.flush()
    except (OSError, UnicodeError, ValueError, TypeError):
        output_failed = True
    guard.phase = 'cleanup'
    if session is not None:
        try:
            _finish(session)
        except BaseException:
            code = 1
    if output_failed:
        code = 1
    return code


def main(arguments=None, *, stdin=None, stdout=None, registered_context=None, managed_worker=False):
    """Write exactly one Claude hook JSON value and no diagnostic stream text."""
    with _TerminationGuard() as guard:
        code = _execute(
            sys.argv[1:] if arguments is None else arguments,
            stdin=sys.stdin if stdin is None else stdin,
            stdout=sys.stdout if stdout is None else stdout,
            registered_context=registered_context,
            managed_worker=managed_worker,
            guard=guard,
        )
    return 128 + guard.signum if guard.signum is not None else code


if __name__ == '__main__':
    raise SystemExit(main())
