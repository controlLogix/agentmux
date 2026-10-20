"""Run one pinned OpenID Connect authorization-code login with PKCE.

The flow authenticates an external account.  It never enrolls a local human,
selects a project, grants access, or links the account.  A verified result must
still pass through the identity owner's explicit account-link command.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import re
import secrets
import subprocess
import tempfile
import threading
import time
import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from agentmux_contracts import ContractError, strict_loads
from identity.oidc_adapter import OIDCIdentityAdapter, OIDCProvider

_OPAQUE = re.compile(r'[\x21-\x7e]{1,4096}\Z')
_STATE = re.compile(r'[A-Za-z0-9_-]{32,512}\Z')
_SESSION_STATE = re.compile(r'[\x21-\x7e]{1,512}\Z')
_MAX_RESPONSE = 65536
_TIMEOUT_SECONDS = 5


def _now():
    return datetime.now(timezone.utc)


def _valid_time(value):
    return (isinstance(value, datetime) and value.tzinfo is not None
            and value.utcoffset() == timedelta(0))


def _endpoint(value, *, issuer):
    if not isinstance(value, str) or len(value) > 2048:
        raise ContractError('oidc_authorization_code_configuration_invalid')
    try:
        parsed, authority = urlsplit(value), urlsplit(issuer)
        port, authority_port = parsed.port, authority.port
    except ValueError:
        raise ContractError('oidc_authorization_code_configuration_invalid') from None
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or not parsed.path or parsed.hostname != authority.hostname
            or port != authority_port
            or not parsed.path.startswith(authority.path + '/')):
        raise ContractError('oidc_authorization_code_configuration_invalid')
    return parsed


def _redirect(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ContractError('oidc_authorization_code_configuration_invalid')
    try:
        parsed, port = urlsplit(value), urlsplit(value).port
    except ValueError:
        raise ContractError('oidc_authorization_code_configuration_invalid') from None
    loopback = (parsed.scheme == 'http' and parsed.hostname == '127.0.0.1'
                and port is not None and 1024 <= port <= 65535)
    secure = parsed.scheme == 'https' and parsed.hostname is not None
    if (not (loopback or secure) or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or not parsed.path):
        raise ContractError('oidc_authorization_code_configuration_invalid')
    return parsed


@dataclass(frozen=True, repr=False)
class OIDCAuthorizationCodeProvider:
    """Exact public endpoints for one registered public OIDC client."""
    provider: OIDCProvider
    authorization_endpoint: str
    token_endpoint: str
    redirect_uri: str

    def __post_init__(self):
        if type(self.provider) is not OIDCProvider:
            raise ContractError('oidc_authorization_code_configuration_invalid')
        authorization = _endpoint(self.authorization_endpoint, issuer=self.provider.issuer)
        token = _endpoint(self.token_endpoint, issuer=self.provider.issuer)
        _redirect(self.redirect_uri)
        if authorization == token:
            raise ContractError('oidc_authorization_code_configuration_invalid')

    def __repr__(self):
        return '<OIDCAuthorizationCodeProvider configured>'


class OIDCTokenRequest:
    """A private form request whose representation never exposes credentials."""
    __slots__ = ('_endpoint', '_body')

    def __init__(self, endpoint, fields, brand):
        if brand is not _TOKEN_REQUEST:
            raise ContractError('oidc_token_exchange_refused')
        self._endpoint = endpoint
        self._body = urlencode(fields).encode('ascii')

    def __repr__(self):
        return '<OIDCTokenRequest private>'


_TOKEN_REQUEST = object()


class BoundedOIDCTokenHTTP:
    """POST one bounded form with one deadline covering DNS through body."""
    __slots__ = ('_runner', '_monotonic', '_roots_pem')

    def __init__(self, *, roots_pem=None, _runner=None, _monotonic=None):
        self._runner = _runner or subprocess.run
        self._monotonic = _monotonic or time.monotonic
        self._roots_pem = roots_pem

    def __repr__(self):
        return '<BoundedOIDCTokenHTTP configured>'

    def exchange(self, request):
        if type(request) is not OIDCTokenRequest:
            raise ContractError('oidc_token_exchange_refused')
        deadline = self._monotonic() + _TIMEOUT_SECONDS
        marker = '\nagentmux-oidc-response:'
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            raise ContractError('oidc_token_exchange_refused')
        command = ['/usr/bin/curl', '--disable', '--silent', '--request', 'POST',
            '--proto', '=https', '--max-redirs', '0', '--connect-timeout', f'{remaining:.6f}',
            '--max-time', f'{remaining:.6f}', '--max-filesize', str(_MAX_RESPONSE),
            '--header', 'Accept: application/json',
            '--header', 'Content-Type: application/x-www-form-urlencoded',
            '--data-binary', '@-', '--write-out', marker + '%{http_code}\n%{content_type}',
            request._endpoint]
        roots_path = None
        try:
            if self._roots_pem is not None:
                roots = tempfile.NamedTemporaryFile('w', prefix='agentmux-oidc-ca-',
                                                     delete=False)
                roots_path = roots.name
                try:
                    roots.write(self._roots_pem)
                finally:
                    roots.close()
                os.chmod(roots_path, 0o600)
                command[3:3] = ['--cacert', roots_path]
            completed = self._runner(command, input=request._body, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=max(0.001, remaining), check=False)
        except (subprocess.TimeoutExpired, TimeoutError, OSError, ValueError):
            raise ContractError('oidc_token_exchange_refused') from None
        finally:
            if roots_path is not None:
                try:
                    os.unlink(roots_path)
                except OSError:
                    pass
        if (self._monotonic() >= deadline or completed.returncode != 0
                or not isinstance(completed.stdout, bytes)
                or len(completed.stdout) > _MAX_RESPONSE + len(marker) + 4096):
            raise ContractError('oidc_token_exchange_refused')
        separator = marker.encode('ascii')
        if separator not in completed.stdout:
            raise ContractError('oidc_token_exchange_refused')
        body, metadata = completed.stdout.rsplit(separator, 1)
        if len(metadata) > 4096:
            raise ContractError('oidc_token_exchange_refused')
        try:
            status, content_type = metadata.decode('ascii').split('\n', 1)
        except (UnicodeDecodeError, ValueError):
            raise ContractError('oidc_token_exchange_refused') from None
        if (len(body) > _MAX_RESPONSE or status != '200'
                or content_type.split(';', 1)[0].strip().lower() != 'application/json'):
            raise ContractError('oidc_token_exchange_refused')
        try:
            document = strict_loads(body)
        except (ContractError, UnicodeDecodeError, ValueError, TypeError):
            raise ContractError('oidc_token_exchange_refused') from None
        token = document.get('id_token') if type(document) is dict else None
        if not isinstance(token, str) or not 0 < len(token) <= _MAX_RESPONSE:
            raise ContractError('oidc_token_exchange_refused')
        return token


class OIDCAuthorizationRequest:
    """One private login attempt containing its one-use PKCE verifier."""
    __slots__ = ('_flow', '_login', '_verifier', '_expires_at', '_authorization_url',
                 '_used', '_lock')

    def __init__(self, flow, login, verifier, expires_at, authorization_url, brand):
        if brand is not _AUTHORIZATION_REQUEST:
            raise ContractError('oidc_authorization_request_invalid')
        self._flow, self._login, self._verifier = flow, login, verifier
        self._expires_at, self._authorization_url = expires_at, authorization_url
        self._used, self._lock = False, threading.Lock()

    def __repr__(self):
        return '<OIDCAuthorizationRequest private>'

    @property
    def authorization_url(self):
        return self._authorization_url

    def _take(self, flow, state, now):
        with self._lock:
            if (self._used or self._flow is not flow or not _valid_time(now)
                    or not isinstance(state, str) or not _STATE.fullmatch(state)
                    or not secrets.compare_digest(state, self._login.state)
                    or now >= self._expires_at):
                self._used = True
                raise ContractError('oidc_authorization_request_invalid')
            self._used = True
            return self._login, self._verifier


_AUTHORIZATION_REQUEST = object()


class OIDCAuthorizationCodeFlow:
    """Create and complete one-use browser authorization-code logins."""
    __slots__ = ('_configuration', '_adapter', '_transport', '_clock')

    def __init__(self, configuration, *, transport=None, _clock=None):
        if type(configuration) is not OIDCAuthorizationCodeProvider:
            raise ContractError('oidc_authorization_code_configuration_invalid')
        if transport is not None and type(transport) is not BoundedOIDCTokenHTTP:
            raise ContractError('oidc_authorization_code_configuration_invalid')
        self._configuration = configuration
        self._adapter = OIDCIdentityAdapter(configuration.provider)
        self._transport = transport or BoundedOIDCTokenHTTP(
            roots_pem=configuration.provider.roots_pem)
        self._clock = _clock or _now

    def __repr__(self):
        return '<OIDCAuthorizationCodeFlow configured>'

    def begin(self, *, lifetime_seconds=300):
        now = self._clock()
        if (not _valid_time(now) or type(lifetime_seconds) is not int
                or not 1 <= lifetime_seconds <= 300):
            raise ContractError('oidc_authorization_request_invalid')
        login = self._adapter.begin_login(now=now, lifetime_seconds=lifetime_seconds)
        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('ascii')).digest()).decode('ascii').rstrip('=')
        query = urlencode({
            'response_type': 'code',
            'client_id': self._configuration.provider.audience,
            'redirect_uri': self._configuration.redirect_uri,
            'scope': 'openid',
            'state': login.state,
            'nonce': login.nonce,
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        })
        endpoint = urlsplit(self._configuration.authorization_endpoint)
        authorization_url = urlunsplit((endpoint.scheme, endpoint.netloc, endpoint.path,
                                        query, ''))
        return OIDCAuthorizationRequest(self, login, verifier,
            now + timedelta(seconds=lifetime_seconds), authorization_url,
            _AUTHORIZATION_REQUEST)

    def complete(self, request, callback_url):
        if type(request) is not OIDCAuthorizationRequest or not isinstance(callback_url, str):
            raise ContractError('oidc_authorization_request_invalid')
        state, code = self._callback(callback_url)
        login, verifier = request._take(self, state, self._clock())
        if code is None:
            raise ContractError('oidc_authorization_refused')
        token_request = OIDCTokenRequest(self._configuration.token_endpoint, {
            'grant_type': 'authorization_code',
            'client_id': self._configuration.provider.audience,
            'code': code,
            'redirect_uri': self._configuration.redirect_uri,
            'code_verifier': verifier,
        }, _TOKEN_REQUEST)
        token = self._transport.exchange(token_request)
        now = self._clock()
        if not _valid_time(now):
            raise ContractError('oidc_authorization_request_invalid')
        return self._adapter.verify(token, login=login, returned_state=state, now=now)

    def _callback(self, callback_url):
        if len(callback_url) > 8192:
            raise ContractError('oidc_authorization_request_invalid')
        try:
            callback, expected = urlsplit(callback_url), urlsplit(
                self._configuration.redirect_uri)
            pairs = parse_qsl(callback.query, keep_blank_values=True,
                              strict_parsing=True, max_num_fields=6)
        except (ValueError, TypeError):
            raise ContractError('oidc_authorization_request_invalid') from None
        if ((callback.scheme, callback.netloc, callback.path, callback.fragment)
                != (expected.scheme, expected.netloc, expected.path, '')
                or len({key for key, _ in pairs}) != len(pairs)):
            raise ContractError('oidc_authorization_request_invalid')
        values = dict(pairs)
        allowed = {'state', 'code', 'session_state', 'iss'}
        error_allowed = {'state', 'error', 'error_description', 'error_uri', 'session_state', 'iss'}
        error = values.get('error')
        if error is None:
            if set(values) - allowed or not {'state', 'code'} <= set(values):
                raise ContractError('oidc_authorization_request_invalid')
            code = values['code']
            if not _OPAQUE.fullmatch(code):
                raise ContractError('oidc_authorization_request_invalid')
        else:
            if set(values) - error_allowed or 'state' not in values or not _OPAQUE.fullmatch(error):
                raise ContractError('oidc_authorization_request_invalid')
            code = None
        if ('iss' in values and values['iss'] != self._configuration.provider.issuer):
            raise ContractError('oidc_authorization_request_invalid')
        if ('session_state' in values
                and not _SESSION_STATE.fullmatch(values['session_state'])):
            raise ContractError('oidc_authorization_request_invalid')
        return values['state'], code
