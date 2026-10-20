"""Bind one device login to the already enrolled terminal caller.

The provider result may confirm the caller already selected by the signed
application binding. It cannot select, enroll or link a local identity. The
returned session refreshes that same binding and current authority on every use.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from agentmux_contracts import ContractError, strict_loads
from identity.application_binding import _LocalBrowserApplicationBinding
from identity.authority import _active, _indexes, _key
from identity.local_browser_session import LocalBrowserSession
from identity.oidc_device_authorization import (
    OIDCDeviceAuthorizationFlow, OIDCDeviceAuthorizationProvider)
from identity.service import IdentityService

_MAX_PENDING = 4


class OIDCTerminalAttempt:
    """Public instructions around a private device request and owned poller."""
    __slots__ = ('_owner', '_binding', '_request', '_task', '_status_task',
                 '_cancel_task', '_used')

    def __init__(self, owner, binding, request, task, brand):
        if brand is not _ATTEMPT:
            raise ContractError('oidc_terminal_unavailable')
        self._owner, self._binding, self._request = owner, binding, request
        self._task, self._status_task, self._cancel_task = task, None, None
        self._used = False

    @property
    def user_code(self):
        return self._request.user_code

    @property
    def verification_uri(self):
        return self._request.verification_uri

    @property
    def interval(self):
        return self._request.interval

    @property
    def expires_at(self):
        return self._request.expires_at

    def __repr__(self):
        return '<OIDCTerminalAttempt private>'


_ATTEMPT = object()


class OIDCTerminalSession:
    """A finite confirmation of one enrolled human and project binding."""
    __slots__ = ('_owner', '_session', '_closed')

    def __init__(self, owner, session, brand):
        if brand is not _SESSION or not isinstance(session, LocalBrowserSession):
            raise ContractError('oidc_terminal_unavailable')
        self._owner, self._session, self._closed = owner, session, False

    @property
    def expires_at(self):
        return self._session.expires_at

    async def authorize(self):
        """Refresh current caller, membership, grant and runtime authority."""
        if self._closed:
            raise ContractError('oidc_terminal_session_closed')
        return await self._session.verify_identity()

    def close(self):
        """Log out locally and make every later use fail closed."""
        if not self._closed:
            self._closed = True
            self._session.close()
            self._owner._sessions.discard(self)

    def __repr__(self):
        return '<OIDCTerminalSession private>'


_SESSION = object()


class OIDCTerminalLoginOwner:
    """Own device polling and bind its result to a trusted application binding."""
    __slots__ = ('_flow', '_identity', '_begins', '_pending', '_sessions',
                 '_begin_owners', '_operations', '_close_task', '_closed')

    def __init__(self, configuration, identity, *, _flow=None):
        if (type(configuration) is not OIDCDeviceAuthorizationProvider
                or not isinstance(identity, IdentityService)
                or _flow is not None and type(_flow) is not OIDCDeviceAuthorizationFlow):
            raise ContractError('oidc_terminal_configuration_invalid')
        self._flow = _flow or OIDCDeviceAuthorizationFlow(configuration)
        self._identity = identity
        self._begins, self._pending = set(), set()
        self._sessions, self._operations = set(), set()
        self._begin_owners, self._close_task = {}, None
        self._closed = False

    def __repr__(self):
        return '<OIDCTerminalLoginOwner private>'

    def fence(self):
        """Stop admission and wake provider polling before the async join."""
        self._closed = True
        for attempt in tuple(self._pending):
            attempt._request.cancel()

    async def begin(self, binding):
        if self._closed or not isinstance(binding, _LocalBrowserApplicationBinding):
            raise ContractError('oidc_terminal_unavailable')
        self._prune_abandoned_begins()
        if len(self._begins) + len(self._pending) >= _MAX_PENDING:
            raise ContractError('oidc_terminal_unavailable')
        operation = asyncio.current_task()
        if operation is None:
            raise ContractError('oidc_terminal_unavailable')
        started = asyncio.create_task(asyncio.to_thread(self._flow.begin),
                                      name='oidc-terminal-device-begin')
        self._begins.add(started)
        self._begin_owners[started] = operation
        self._operations.add(operation)
        claimed = False
        try:
            # wait does not cancel the retained thread owner when this caller is
            # cancelled. Close or a later begin consumes its exact result.
            await asyncio.wait({started})
            request = started.result()
            claimed = True
            self._begins.discard(started)
            self._begin_owners.pop(started, None)
            if self._closed:
                request.cancel()
                raise ContractError('oidc_terminal_unavailable')
            task = asyncio.create_task(asyncio.to_thread(
                self._flow.complete, request), name='oidc-terminal-device-poll')
            attempt = OIDCTerminalAttempt(self, binding, request, task, _ATTEMPT)
            self._pending.add(attempt)
            return attempt
        finally:
            self._operations.discard(operation)
            if claimed:
                self._begins.discard(started)
                self._begin_owners.pop(started, None)

    async def status(self, attempt):
        if (self._closed or type(attempt) is not OIDCTerminalAttempt
                or attempt._owner is not self
                or attempt._status_task is None
                and (attempt._used or attempt not in self._pending)):
            raise ContractError('oidc_terminal_unavailable')
        if attempt._status_task is None and not attempt._task.done():
            return None
        if attempt._status_task is None:
            attempt._status_task = asyncio.create_task(
                self._complete_status(attempt), name='oidc-terminal-status-complete')
        return await asyncio.shield(attempt._status_task)

    async def _complete_status(self, attempt):
        operation = asyncio.current_task()
        self._operations.add(operation)
        try:
            verified = attempt._task.result()
            if self._closed:
                raise ContractError('oidc_terminal_unavailable')
            session = await self._linked_session(verified.external_identity,
                                                 attempt._binding)
            if self._closed:
                session.close()
                raise ContractError('oidc_terminal_unavailable')
            wrapped = OIDCTerminalSession(self, session, _SESSION)
            self._sessions.add(wrapped)
            return wrapped
        finally:
            attempt._used = True
            self._pending.discard(attempt)
            self._operations.discard(operation)

    async def cancel(self, attempt):
        if (type(attempt) is not OIDCTerminalAttempt or attempt._owner is not self
                or attempt._cancel_task is None
                and (attempt._used or attempt not in self._pending)):
            raise ContractError('oidc_terminal_unavailable')
        if attempt._cancel_task is None:
            attempt._cancel_task = asyncio.create_task(
                self._cancel_attempt(attempt), name='oidc-terminal-attempt-cancel')
        return await asyncio.shield(attempt._cancel_task)

    async def _cancel_attempt(self, attempt):
        operation = asyncio.current_task()
        self._operations.add(operation)
        attempt._used = True
        attempt._request.cancel()
        try:
            await asyncio.gather(asyncio.shield(attempt._task), return_exceptions=True)
        finally:
            self._pending.discard(attempt)
            self._operations.discard(operation)

    async def _linked_session(self, external_identity, binding):
        current = await binding.current()
        snapshot = await self._identity.reader.current()
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], record['ownerHubId'])
        now = datetime.now(timezone.utc)
        matches = [item for item in index['identities'].values()
            if item['kind'] == 'human' and _active(item, now)
            and item['externalIdentity'] == external_identity]
        caller = index['identities'].get(_key(current['callerRef']))
        if (len(matches) != 1 or caller is None
                or matches[0]['ref'] != caller['ref']):
            raise ContractError('oidc_account_not_linked')
        return await LocalBrowserSession.open_server_binding(binding,
                                                              self._identity.reader)

    def _prune_abandoned_begins(self):
        """Consume completed begin calls whose original caller left."""
        for started in tuple(self._begins):
            owner = self._begin_owners.get(started)
            if not started.done() or owner in self._operations:
                continue
            self._begins.discard(started)
            self._begin_owners.pop(started, None)
            try:
                started.result().cancel()
            except BaseException:
                pass

    async def close(self):
        """Retain one cleanup owner so caller cancellation cannot detach it."""
        if self._close_task is None:
            self._close_task = asyncio.create_task(
                self._close(), name='oidc-terminal-close')
        return await asyncio.shield(self._close_task)

    async def _close(self):
        self._closed = True
        current = asyncio.current_task()
        while True:
            beginnings = tuple(self._begins)
            pending = tuple(self._pending)
            operations = tuple(item for item in self._operations
                               if item is not current and not item.done())
            for attempt in pending:
                attempt._used = True
                attempt._request.cancel()
            retained = beginnings + tuple(item._task for item in pending) + operations
            if not retained:
                break
            await asyncio.gather(*(asyncio.shield(item) for item in retained),
                                 return_exceptions=True)
            for started in beginnings:
                if started.done():
                    self._begins.discard(started)
                    self._begin_owners.pop(started, None)
                    try:
                        started.result().cancel()
                    except BaseException:
                        pass
            for attempt in pending:
                if attempt._task.done():
                    self._pending.discard(attempt)
        for session in tuple(self._sessions):
            session.close()
