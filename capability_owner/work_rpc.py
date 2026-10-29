"""Actual Hub work requests with durable, explicit-operation recovery.

Raw callers may omit an ID for a one-shot request. The Hub supplies an ID in
its response; recovery after losing that entire response requires a caller ID.
Identical request content never implies that two calls are the same operation.
"""
import asyncio
from datetime import datetime, timedelta, timezone
import json
import time
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub import names
from hub.native_check_timing import request_sample as _request_sample
from hub.store import HubError
from .legacy_work_client import LegacyWorkCommandClient
from .local_work_client import LocalWorkClient
from .work_completion import WorkCompletionStore

WORK_RPC_VERBS = frozenset(('work_add', 'claim', 'heartbeat', 'release',
    'work_cancel', 'claim_path', 'fed_work_add'))
_COMMANDS = {'work_add': 'create', 'fed_work_add': 'offer', 'claim': 'claim',
    'heartbeat': 'heartbeat', 'release': 'release', 'work_cancel': 'cancel', 'claim_path': 'claim-path'}


class WorkRpc:
    """Host-private caller adapter; only signed owners supply work results."""

    def __init__(self, hub, commands, local_client):
        if (type(commands) is not LegacyWorkCommandClient or type(local_client) is not LocalWorkClient
                or commands._hub is not hub or local_client._hub is not hub
                or local_client._commands is not commands):
            raise ContractError('work_rpc_configuration')
        self._hub, self._commands, self._local = hub, commands, local_client
        profiles = {tuple(strict_loads(raw)[key] for key in ('hubId', 'profileId', 'authorityId'))
            for _, raw in commands._routes}
        if len(profiles) != 1:
            raise ContractError('work_rpc_configuration')
        self._completion = WorkCompletionStore(hub,
            profile=dict(zip(('hubId', 'profileId', 'authorityId'), next(iter(profiles)))))
        self._lock = asyncio.Lock()
        self._requests = weakref.WeakKeyDictionary()
        self._closed, self._closing = False, None

    def __repr__(self):
        return '<WorkRpc private>'

    @property
    def operation_id(self):
        state = self._requests.get(asyncio.current_task())
        return None if state is None else state['identity']['operation_id']

    def replayed(self):
        state = self._state()
        return state['record']['state'] == 'completed'

    def _state(self):
        state = self._requests.get(asyncio.current_task())
        if state is None:
            raise ContractError('work_rpc_unavailable')
        return state

    def _expires(self, state):
        remaining = state['admitted'].expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise HubError('authenticated work request expired')
        return min(state['expires'], datetime.now(timezone.utc) + timedelta(seconds=remaining))

    def check_response(self, value=None, *, finish=False):
        state = self._state()
        self._expires(state)
        self._commands.check(self._commands._federation)
        for session, enrollment in state['routes']:
            if session.work_enrollment() != enrollment:
                raise ContractError('work_rpc_binding')
        if state.get('federated'):
            self._hub.fed._work_commands.check(self._hub.fed)
        if finish:
            if state['record']['state'] != 'completed':
                raise ContractError('work_rpc_completion_pending')
            return self._commands.finish_disclosure(value)
        return self._commands.confirm_disclosure(value)

    async def execute(self, proof, verb, arguments, caller, *, repository=None):
        if (self._closed or verb not in WORK_RPC_VERBS or type(arguments) is not dict
                or proof is not self._hub.current_authenticated_caller()
                or asyncio.current_task() in self._requests):
            raise HubError('authenticated work request does not match')
        if repository is not None and (type(repository) is not str or not repository):
            raise ContractError('legacy_work_route_unavailable')
        admitted = self._hub._admit_local_work(verb, arguments, caller)
        request = json.loads(admitted.request)
        arguments = strict_loads(canonical_bytes(request.get('args', {})))
        # The Hub resolves this descriptor from the actual registered target;
        # request data and caller labels cannot supply a target generation.
        on_behalf_of = await self._hub._work_on_behalf(admitted)
        _request_sample('rpc-on-behalf-return')
        if self._closed:
            raise ContractError('work_rpc_unavailable')
        identity = dict(operation_id=request.get('operationId'), request_digest=admitted.request_digest,
            principal={'authenticatedCaller': admitted.authenticated_caller, 'caller': admitted.caller},
            verb=verb, arguments=strict_loads(canonical_bytes(arguments)))
        if verb in ('claim', 'heartbeat', 'release', 'claim_path'):
            self._hub.need_agent(caller)
        elif verb == 'work_cancel':
            self._hub.need_operator(caller)
        command = _COMMANDS[verb]
        if verb == 'work_add' and arguments.get('federate') and self._hub.fed.enabled:
            command = 'offer'
        routes = self._commands._select(admitted.authenticated_caller, command, repository)
        bindings = [self._commands._binding(enrollment) for _, enrollment in routes]
        state = {'identity': identity, 'admitted': admitted, 'routes': routes,
            'bindings': bindings, 'expires': datetime.now(timezone.utc) + timedelta(
                seconds=max(0, admitted.expires_monotonic - time.monotonic())), 'locked': False,
            'record': None, 'completions': None}
        self._requests[asyncio.current_task()] = state
        try:
            await self._lock.acquire()
            _request_sample('rpc-lock')
            state['locked'] = True
            self._expires(state)
            if command == 'offer':
                self._hub.fed._work_commands._begin()
                state['federated'] = True
            record = await self._commands._owned_db(self._completion.reserve, **identity, bindings=bindings)
            _request_sample('rpc-reserve-return')
            state['record'] = record
            self._expires(state)
            if record['state'] == 'completed':
                for source in record['workSources']:
                    await self._commands.verify_completed_source(source, self._expires(state))
                return self.check_response(record['result'])
            intent = record['intentDigest']
            if command == 'offer':
                federation = self._hub.fed
                target = names.parse_address(arguments['to'])
                if target.kind != 'role' or target.scope == '*' or target.scope.startswith(('group:', 'team:')):
                    raise HubError('a federated item targets role:<repo>/<role>')
                if repository is not None and target.scope != repository:
                    raise ContractError('legacy_work_route_unavailable')
                route = self._commands._select(admitted.authenticated_caller, 'offer', target.scope)[0]
                value = {'target': arguments['to'], 'title': arguments['title'], 'body': arguments.get('body'),
                    'taskKey': arguments.get('task_key'), 'requirements':
                        {'capabilities': arguments['require']} if arguments.get('require') else arguments.get('requirements'),
                    'priority': int(arguments.get('priority') or 100)}
                if on_behalf_of is not None:
                    value['onBehalfOf'] = on_behalf_of
                result = await federation.guarded(self._commands._execute(*route, 'offer', intent, value,
                    admitted.authenticated_caller, self._expires(state)))
                state['completions'] = [(*route, 'offer', intent, result)]
            else:
                method = {'work_add': self._local.add, 'claim': self._local.claim,
                    'heartbeat': self._local.heartbeat, 'release': self._local.release,
                    'work_cancel': self._local.cancel, 'claim_path': self._local.claim_path}[verb]
                kwargs = ({} if verb == 'work_cancel' else {
                    'authenticated_caller': admitted.authenticated_caller, 'on_behalf_of': on_behalf_of})
                result = await method(caller, arguments, intent_digest=intent, repository=repository, **kwargs)
                state['completions'] = list(self._local._completions.get(asyncio.current_task(), ()))
            return self.check_response(result)
        except BaseException:
            try:
                await self._commands._owned_db(self._completion.abandon_unsubmitted, **identity, bindings=bindings)
            finally:
                self.abort()
            raise

    async def capture_source(self, row):
        """Bind capture to this task's exact verified release result."""
        state = self._state()
        self.check_response(row)
        completions = state['completions']
        if (state['identity']['verb'] != 'release' or self.replayed()
                or type(row) is not dict or not completions or len(completions) != 1
                or completions[0][2] != 'release'
                or canonical_bytes(completions[0][4]) != canonical_bytes(row)):
            raise ContractError('work_rpc_capture_binding')
        pending = self._commands._disclosures[asyncio.current_task()]
        source = await self._commands.capture_source(completions[0], 'work-released', row,
            min(self._expires(state), pending[1]))
        self.check_response(row)
        return source

    async def complete(self, result):
        """Seal finished obligations, then separately authorize their disclosure."""
        state = self._state()
        if state['record']['state'] == 'completed':
            if canonical_bytes(result) != canonical_bytes(state['record']['result']):
                raise ContractError('work_rpc_binding')
            return self.check_response(result)
        completions = state['completions']
        if self._local._completions.get(asyncio.current_task(), []) not in ([], completions):
            raise ContractError('work_rpc_binding')
        def commit():
            # Only the fixed Hub dispatcher calls this after every durable
            # follow-on. This receipt grants no new effect or disclosure; seal
            # it even if the reply deadline elapsed while obligations finished.
            with self._hub.store.tx():
                return self._completion.complete(**state['identity'], bindings=state['bindings'],
                    result=result, completions=completions)
        record = await self._commands._owned_db(commit)
        state['record'] = record
        self._local._completions.pop(asyncio.current_task(), None)
        self.check_response(result)
        return result

    async def delivered(self):
        state = self._state()
        if state['record']['state'] != 'completed':
            raise ContractError('work_rpc_completion_pending')
        await self._commands._owned_db(self._completion.delivered, state['record'])

    def abort(self):
        """Release this request's lock; leave original durable records untouched."""
        state = self._requests.pop(asyncio.current_task(), None)
        if state is not None and state['locked']:
            state['locked'] = False
            self._lock.release()
        if state is not None and state.get('federated'):
            self._hub.fed._work_commands._sessions.pop(asyncio.current_task(), None)

    async def close(self, *, timeout=5):
        """Join original invocation tasks before closing shared commands or Store."""
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('work_rpc_cleanup_invalid')
        if asyncio.current_task() in self._requests:
            raise ContractError('work_rpc_cleanup_invalid')
        self._closed = True
        if self._closing is None:
            retained = tuple(self._requests)
            async def finish():
                if retained:
                    await asyncio.gather(*retained, return_exceptions=True)
            self._closing = asyncio.create_task(finish())
        try:
            _, pending = await asyncio.wait({self._closing}, timeout=timeout)
            if pending:
                raise ContractError('work_rpc_cleanup_incomplete')
        except asyncio.CancelledError:
            while not self._closing.done():
                try:
                    await asyncio.wait({self._closing})
                except asyncio.CancelledError:
                    continue
            self._closing.result()
            raise
        self._closing.result()
