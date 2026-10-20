"""One-time local browser credential handoff for an enrolled human session.

The owner-run host creates the already authenticated LocalBrowserSession and
delivers the one-time bootstrap only in a POST body. This module does not enroll
an identity, open a repository, accept an actor from JSON, launch a browser or
own HTTP routing. The future handler must keep the bootstrap, cookie and CSRF
value out of URLs and logs.
"""
from datetime import datetime, timedelta, timezone
import asyncio
import hashlib
import hmac
import re
import secrets

from agentmux_contracts import ContractError
from identity.local_browser_session import LocalBrowserPairingAuthority, LocalBrowserSession


_BOOTSTRAP_PATH = '/api/local-auth/bootstrap'
_LOGOUT_PATH = '/api/local-auth/logout'
_ACTION_PATHS = frozenset({'/api/board/agentdef', '/api/board/agentdrop'})
_DASHBOARD_PATH = re.compile(r'/api/board/(?:create|update|status|move|delete|acceptance|label|dep|evidence|commit|touch|comment|link|triage|state|config|override|recruit|approve|retire|hire|plcstate|bootapp|chatsend)\Z')
_RUN_REVIEW_PATH = re.compile(r'/api/runs/[0-9a-f]{6}/review\Z')
_COOKIE = 'agentmux_local_session'
_TOKEN = re.compile(r'[A-Za-z0-9_-]{43}\Z')
_PAIRING_CODE = re.compile(r'[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){4}\Z')
_PAIRING_PATH = '/api/local-auth/pair'
_BOOTSTRAP_LIFETIME = timedelta(seconds=30)
_SESSION_LIFETIME = timedelta(minutes=15)
_MAX_SESSIONS = 8


def _now(clock):
    value = datetime.now(timezone.utc) if clock is None else clock()
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise ContractError('local_browser_auth_time_invalid')
    return value


def _digest(value):
    return hashlib.sha256(value.encode('ascii')).digest()


def _token():
    return secrets.token_urlsafe(32)


class _OneTimeSecret:
    def __init__(self, value):
        self._value = bytearray(value.encode('ascii'))
        self._taken = False

    def _take(self):
        if self._taken:
            raise ContractError('local_browser_auth_unavailable')
        self._taken = True
        try:
            return bytes(self._value).decode('ascii')
        finally:
            for index in range(len(self._value)):
                self._value[index] = 0

    def __repr__(self):
        return '<local browser secret private>'


class LocalBrowserBootstrap(_OneTimeSecret):
    """Host-only one-time bootstrap, never a URL value."""
    def take_for_post_body(self):
        return self._take()


class LocalBrowserLogin:
    """One-time response material for the bootstrap handler."""
    def __init__(self, session_token, csrf_token, max_age):
        self._session = _OneTimeSecret(session_token)
        self._csrf = _OneTimeSecret(csrf_token)
        self._max_age = max_age
        self._taken = False

    def take_response(self):
        if self._taken:
            raise ContractError('local_browser_auth_unavailable')
        self._taken = True
        session_token = self._session._take()
        csrf_token = self._csrf._take()
        return ({'Set-Cookie': _cookie(session_token, self._max_age),
                 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'},
                {'csrfToken': csrf_token})

    def __repr__(self):
        return '<LocalBrowserLogin private>'


def _cookie(value, max_age):
    return (f'{_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; '
            f'Max-Age={max_age}')


class LocalBrowserAuth:
    """Own opaque browser credentials while authority stays in LocalBrowserSession."""
    def __init__(self, port, *, clock=None):
        if (type(port) is not int or not 1 <= port <= 65535
                or clock is not None and not callable(clock)):
            raise ContractError('local_browser_auth_configuration')
        self._clock = clock
        self._hosts = frozenset({f'127.0.0.1:{port}', f'localhost:{port}'})
        self._origins = frozenset('http://' + host for host in self._hosts)
        self._bootstraps = {}
        self._redeeming = {}
        self._pairings = {}
        self._approving = {}
        self._sessions = {}
        self._owned = {}
        self._closed = False

    def __repr__(self):
        return '<LocalBrowserAuth private>'

    def _cleanup(self, now):
        for digest, row in list(self._pairings.items()):
            if now >= row['expires']:
                self._pairings.pop(digest, None)
                if not row['future'].done():
                    row['future'].set_exception(
                        ContractError('local_browser_auth_unavailable'))
        for rows in (self._bootstraps, self._redeeming, self._approving,
                     self._sessions):
            for digest, row in list(rows.items()):
                if now >= row['expires']:
                    rows.pop(digest, None)
                    self._owned.pop(id(row['session']), None)
                    row['session'].close()
                    if rows is self._approving and not row['future'].done():
                        row['future'].set_exception(
                            ContractError('local_browser_auth_unavailable'))

    async def pair(self, challenge, *, method, target, host, origin):
        """Wait for the enrolled owner to approve one browser-created challenge."""
        self._request(method, target, host, origin, _PAIRING_PATH)
        if not isinstance(challenge, str) or not _PAIRING_CODE.fullmatch(challenge):
            raise ContractError('local_browser_auth_unavailable')
        now = _now(self._clock)
        self._cleanup(now)
        digest = _digest(challenge)
        if (self._closed or digest in self._pairings or digest in self._approving
                or len(self._pairings) + len(self._approving) >= _MAX_SESSIONS):
            raise ContractError('local_browser_auth_unavailable')
        loop = asyncio.get_running_loop()
        row = {'future': loop.create_future(),
               'expires': now + _BOOTSTRAP_LIFETIME, 'origin': origin}
        self._pairings[digest] = row
        try:
            # The monotonic timer wakes an idle request. The UTC check in
            # approve_pairing is authoritative and supports the injected clock.
            async with asyncio.timeout(_BOOTSTRAP_LIFETIME.total_seconds()):
                return await asyncio.shield(row['future'])
        except TimeoutError:
            raise ContractError('local_browser_auth_unavailable') from None
        finally:
            if self._pairings.get(digest) is row:
                self._pairings.pop(digest, None)
            if not row['future'].done():
                row['future'].cancel()

    async def approve_pairing(self, challenge, session, authority, *, origin):
        """Attach one actually verified enrolled session to a pending browser."""
        if (not isinstance(challenge, str) or not _PAIRING_CODE.fullmatch(challenge)
                or not isinstance(session, LocalBrowserSession)
                or not isinstance(authority, LocalBrowserPairingAuthority)
                or origin not in self._origins):
            raise ContractError('local_browser_auth_unavailable')
        now = _now(self._clock)
        self._cleanup(now)
        digest = _digest(challenge)
        row = self._pairings.get(digest)
        if (self._closed or row is None or row['future'].done()
                or now >= row['expires'] or row['origin'] != origin
                or id(session) in self._owned):
            raise ContractError('local_browser_auth_unavailable')
        self._pairings.pop(digest, None)
        row['session'] = session
        self._approving[digest] = row
        self._owned[id(session)] = digest
        try:
            context = await session.verify_identity()
            await authority.recheck(context)
            completed = _now(self._clock)
            if (self._approving.get(digest) is not row or self._closed
                    or row['future'].done() or completed >= row['expires']):
                raise ContractError('local_browser_auth_unavailable')
            login = self._new_login(row, completed)
            self._approving.pop(digest, None)
            row['future'].set_result(login)
            return None
        except BaseException:
            self._approving.pop(digest, None)
            self._owned.pop(id(session), None)
            session.close()
            if not row['future'].done():
                row['future'].set_exception(
                    ContractError('local_browser_auth_unavailable'))
            raise

    def _new_login(self, row, completed):
        session_token, csrf_token = _token(), _token()
        session_digest = _digest(session_token)
        expires = min(completed + _SESSION_LIFETIME, row['session'].expires_at)
        if completed >= expires:
            raise ContractError('local_browser_auth_unavailable')
        self._sessions[session_digest] = {'session': row['session'],
            'csrf': _digest(csrf_token), 'expires': expires}
        self._owned[id(row['session'])] = session_digest
        return LocalBrowserLogin(session_token, csrf_token,
            int((expires - completed).total_seconds()))

    def _request(self, method, target, host, origin, expected):
        if (self._closed or method != 'POST' or target != expected or host not in self._hosts
                or origin not in self._origins or origin != 'http://' + host):
            raise ContractError('local_browser_auth_unavailable')

    def issue_bootstrap(self, session):
        """Called only by an owner-run action after explicit local enrollment."""
        if not isinstance(session, LocalBrowserSession):
            raise ContractError('local_browser_auth_configuration')
        now = _now(self._clock)
        self._cleanup(now)
        if self._closed or id(session) in self._owned or len(self._owned) >= _MAX_SESSIONS:
            raise ContractError('local_browser_auth_unavailable')
        value = _token()
        digest = _digest(value)
        self._bootstraps[digest] = {'session': session,
            'expires': now + _BOOTSTRAP_LIFETIME}
        self._owned[id(session)] = digest
        return LocalBrowserBootstrap(value)

    async def redeem(self, credential, *, method, target, host, origin):
        """Consume one bootstrap from a same-origin POST body."""
        self._request(method, target, host, origin, _BOOTSTRAP_PATH)
        if not isinstance(credential, str) or not _TOKEN.fullmatch(credential):
            raise ContractError('local_browser_auth_unavailable')
        now = _now(self._clock)
        self._cleanup(now)
        digest = _digest(credential)
        row = self._bootstraps.pop(digest, None)
        if row is None or now >= row['expires']:
            raise ContractError('local_browser_auth_unavailable')
        self._redeeming[digest] = row
        try:
            await row['session'].verify_identity()
        except BaseException:
            self._redeeming.pop(digest, None)
            self._owned.pop(id(row['session']), None)
            row['session'].close()
            raise
        completed = _now(self._clock)
        retained = self._redeeming.pop(digest, None)
        if retained is not row or self._closed or completed >= row['expires']:
            self._owned.pop(id(row['session']), None)
            row['session'].close()
            raise ContractError('local_browser_auth_unavailable')
        try:
            return self._new_login(row, completed)
        except BaseException:
            self._owned.pop(id(row['session']), None)
            row['session'].close()
            raise

    def _cookie_token(self, header):
        if not isinstance(header, str) or not 1 <= len(header) <= 4096:
            raise ContractError('local_browser_auth_unavailable')
        found = []
        for part in header.split(';'):
            name, separator, value = part.strip().partition('=')
            if separator and name == _COOKIE:
                found.append(value)
        if len(found) != 1 or not _TOKEN.fullmatch(found[0]):
            raise ContractError('local_browser_auth_unavailable')
        return found[0]

    def _current(self, cookie_header, csrf_header, *, method, target, host, origin,
                 expected):
        self._request(method, target, host, origin, expected)
        if (not isinstance(csrf_header, str) or not _TOKEN.fullmatch(csrf_header)):
            raise ContractError('local_browser_auth_unavailable')
        now = _now(self._clock)
        self._cleanup(now)
        token = self._cookie_token(cookie_header)
        digest = _digest(token)
        row = self._sessions.get(digest)
        if (row is None or now >= row['expires']
                or not hmac.compare_digest(row['csrf'], _digest(csrf_header))):
            raise ContractError('local_browser_auth_unavailable')
        return digest, row

    async def authorize(self, cookie_header, csrf_header, *, method, target,
                        host, origin, body):
        """Authenticate HTTP state, then recheck enrolled authority for this action."""
        if target not in _ACTION_PATHS:
            raise ContractError('local_browser_auth_unavailable')
        _digest_value, row = self._current(cookie_header, csrf_header,
            method=method, target=target, host=host, origin=origin, expected=target)
        proof = await row['session'].authorize(method, target, body)
        return row['session'].consume(proof, method, target, body)

    async def authenticate_dashboard(self, cookie_header, csrf_header, *, method,
                                     target, host, origin):
        """Refresh browser identity; the dashboard owner authorizes the exact effect."""
        if not (_DASHBOARD_PATH.fullmatch(target) or _RUN_REVIEW_PATH.fullmatch(target)):
            raise ContractError('local_browser_auth_unavailable')
        _digest_value, row = self._current(cookie_header, csrf_header,
            method=method, target=target, host=host, origin=origin, expected=target)
        return await row['session'].verify_identity()

    def logout(self, cookie_header, csrf_header, *, method, target, host, origin):
        digest, row = self._current(cookie_header, csrf_header,
            method=method, target=target, host=host, origin=origin,
            expected=_LOGOUT_PATH)
        self._sessions.pop(digest, None)
        self._owned.pop(id(row['session']), None)
        row['session'].close()
        return {'Set-Cookie': _cookie('', 0), 'Cache-Control': 'no-store',
                'Referrer-Policy': 'no-referrer'}

    def close(self):
        """Close every bootstrap/session exactly once during host shutdown."""
        if self._closed:
            return
        self._closed = True
        sessions = {}
        for row in self._pairings.values():
            if not row['future'].done():
                row['future'].set_exception(
                    ContractError('local_browser_auth_unavailable'))
        self._pairings.clear()
        for rows in (self._bootstraps, self._redeeming, self._approving,
                     self._sessions):
            for row in rows.values():
                sessions[id(row['session'])] = row['session']
            rows.clear()
        self._owned.clear()
        for session in sessions.values():
            session.close()
