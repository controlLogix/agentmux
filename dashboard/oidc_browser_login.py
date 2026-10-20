"""Bridge one configured OIDC login into the existing local browser session.

The external provider authenticates only the stable issuer and subject.  This
owner maps that pair to an already linked, active local human, then asks the
current application binding and local browser session to recheck membership and
authority.  It cannot enroll, link, grant, or choose a project from browser data.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import hmac
import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.authority import _active, _indexes
from identity.local_browser_session import LocalBrowserSession
from identity.oidc_authorization_code import (
    OIDCAuthorizationCodeFlow, OIDCAuthorizationCodeProvider)
from identity.service import IdentityService
from local_browser_auth import LocalBrowserAuth

_START_PATH = '/api/local-auth/oidc/start'
_CALLBACK_PATH = '/api/local-auth/oidc/callback'
_BOOTSTRAP_PATH = '/api/local-auth/bootstrap'
_MAX_PENDING = 8
_COOKIE = 'agentmux_oidc_login'
_TOKEN = re.compile(r'[A-Za-z0-9_-]{43}\Z')


def oidc_browser_cookie(value, max_age):
    return (f'{_COOKIE}={value}; Path={_CALLBACK_PATH}; HttpOnly; '
            f'SameSite=Lax; Max-Age={max_age}')


class OIDCBrowserLogin:
    """Own pending browser redirects and convert a linked identity into a login."""
    __slots__ = ('_flow', '_identity', '_auth', '_scope', '_origin', '_host',
                 '_pending', '_exchanges', '_operations', '_monotonic', '_closed')

    def __init__(self, configuration, identity, auth, scope, origin, *, _flow=None,
                 _monotonic=None):
        if (type(configuration) is not OIDCAuthorizationCodeProvider
                or not isinstance(identity, IdentityService)
                or not isinstance(auth, LocalBrowserAuth)
                or type(scope) is not dict or scope.get('projectId') is None
                or not isinstance(origin, str)):
            raise ContractError('oidc_browser_configuration_invalid')
        parsed = urlsplit(origin)
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1'
                or parsed.port is None or parsed.path or parsed.query or parsed.fragment
                or configuration.redirect_uri != origin + _CALLBACK_PATH):
            raise ContractError('oidc_browser_configuration_invalid')
        if _flow is not None and type(_flow) is not OIDCAuthorizationCodeFlow:
            raise ContractError('oidc_browser_configuration_invalid')
        self._flow = _flow or OIDCAuthorizationCodeFlow(configuration)
        self._identity, self._auth = identity, auth
        self._scope = strict_loads(canonical_bytes(scope))
        self._origin, self._host = origin, parsed.netloc
        self._pending, self._exchanges, self._operations = {}, set(), set()
        self._monotonic = _monotonic or time.monotonic
        self._closed = False

    def __repr__(self):
        return '<OIDCBrowserLogin private>'

    def begin(self, *, method, target, host, origin):
        self._request(method, target, host, origin, _START_PATH)
        self._prune()
        if self._closed or len(self._pending) >= _MAX_PENDING:
            raise ContractError('oidc_browser_unavailable')
        request = self._flow.begin()
        try:
            state = parse_qs(urlsplit(request.authorization_url).query,
                             strict_parsing=True)['state']
        except (KeyError, ValueError, TypeError):
            raise ContractError('oidc_browser_unavailable') from None
        if len(state) != 1:
            raise ContractError('oidc_browser_unavailable')
        digest = hashlib.sha256(state[0].encode('ascii')).digest()
        if digest in self._pending:
            raise ContractError('oidc_browser_unavailable')
        browser_secret = secrets.token_urlsafe(32)
        self._pending[digest] = (request, self._monotonic() + 300,
                                 hashlib.sha256(browser_secret.encode('ascii')).digest())
        return ({'Set-Cookie': oidc_browser_cookie(browser_secret, 300),
                 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'},
                {'authorizationUrl': request.authorization_url})

    async def complete(self, target, cookie_header, *, method, host):
        if (self._closed or method != 'GET' or host != self._host
                or not isinstance(target, str) or len(target) > 8192):
            raise ContractError('oidc_browser_unavailable')
        self._prune()
        parsed = urlsplit(target)
        if parsed.path != _CALLBACK_PATH or parsed.fragment:
            raise ContractError('oidc_browser_unavailable')
        try:
            state = parse_qs(parsed.query, keep_blank_values=True,
                             strict_parsing=True, max_num_fields=6)['state']
        except (KeyError, ValueError, TypeError):
            raise ContractError('oidc_browser_unavailable') from None
        if len(state) != 1:
            raise ContractError('oidc_browser_unavailable')
        try:
            digest = hashlib.sha256(state[0].encode('ascii')).digest()
        except UnicodeEncodeError:
            raise ContractError('oidc_browser_unavailable') from None
        retained = self._pending.get(digest)
        if retained is None:
            raise ContractError('oidc_browser_unavailable')
        browser_secret = self._cookie(cookie_header)
        if not hmac.compare_digest(retained[2], hashlib.sha256(
                browser_secret.encode('ascii')).digest()):
            raise ContractError('oidc_browser_unavailable')
        self._pending.pop(digest, None)
        request = retained[0]
        operation = asyncio.current_task()
        if operation is None:
            raise ContractError('oidc_browser_unavailable')
        self._operations.add(operation)
        try:
            exchange = asyncio.create_task(asyncio.to_thread(
                self._flow.complete, request, self._origin + target))
            self._exchanges.add(exchange)
            exchange.add_done_callback(self._exchange_done)
            verified = await asyncio.shield(exchange)
            if self._closed:
                raise ContractError('oidc_browser_unavailable')
            session = await self._linked_session(verified.external_identity)
            if self._closed:
                session.close()
                raise ContractError('oidc_browser_unavailable')
            try:
                bootstrap = self._auth.issue_bootstrap(session)
            except BaseException:
                session.close()
                raise
            credential = bootstrap.take_for_post_body()
            try:
                return await self._auth.redeem(credential, method='POST',
                    target=_BOOTSTRAP_PATH, host=self._host, origin=self._origin)
            finally:
                credential = None
        finally:
            self._operations.discard(operation)

    async def _linked_session(self, external_identity):
        snapshot = await self._identity.reader.current()
        now = datetime.now(timezone.utc)
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], record['ownerHubId'])
        matches = [item for item in index['identities'].values()
            if item['kind'] == 'human' and _active(item, now)
            and item['externalIdentity'] == external_identity]
        if len(matches) != 1:
            raise ContractError('oidc_account_not_linked')
        application = self._identity.application
        if application is None:
            raise ContractError('oidc_browser_unavailable')
        binding = await application.open_local_browser_binding(
            matches[0]['ref'], self._scope)
        return await LocalBrowserSession.open_server_binding(
            binding, self._identity.reader)

    def _request(self, method, target, host, origin, expected):
        if (method != 'POST' or target != expected or host != self._host
                or origin != self._origin):
            raise ContractError('oidc_browser_unavailable')

    def _cookie(self, header):
        if not isinstance(header, str) or not 1 <= len(header) <= 4096:
            raise ContractError('oidc_browser_unavailable')
        found = []
        for part in header.split(';'):
            name, separator, value = part.strip().partition('=')
            if separator and name == _COOKIE:
                found.append(value)
        if len(found) != 1 or not _TOKEN.fullmatch(found[0]):
            raise ContractError('oidc_browser_unavailable')
        return found[0]

    def _prune(self):
        now = self._monotonic()
        for digest, (_request, expires, _cookie) in list(self._pending.items()):
            if now >= expires:
                self._pending.pop(digest, None)

    def _exchange_done(self, task):
        self._exchanges.discard(task)
        if not task.cancelled():
            try:
                task.exception()
            except BaseException:
                pass

    def fence(self):
        self._closed = True
        self._pending.clear()

    async def close(self):
        self.fence()
        current = asyncio.current_task()
        while True:
            retained = tuple(task for task in self._operations | self._exchanges
                             if task is not current and not task.done())
            if not retained:
                return
            await asyncio.gather(*(asyncio.shield(task) for task in retained),
                                 return_exceptions=True)
