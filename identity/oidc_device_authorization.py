"""Bounded OpenID Connect device authorization for a public client.

The provider receives the client ID, openid scope and a fresh nonce. The
device code stays inside this owner and request bodies. A successful ID token
still authenticates only a stable external identity; local linking, membership
and grants remain separate identity-owner operations.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import base64
import hashlib
import re
import os
import secrets
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlencode, urlsplit

from agentmux_contracts import ContractError, strict_loads
from identity.oidc_adapter import OIDCIdentityAdapter, OIDCProvider
from identity.oidc_authorization_code import _endpoint, _valid_time

_MAX_RESPONSE = 65536
_REQUEST_TIMEOUT = 5
_DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'
_OPAQUE = re.compile(r'[\x21-\x7e]{1,4096}\Z')
_USER_CODE = re.compile(r'[\x21-\x7e]{1,128}\Z')


@dataclass(frozen=True, repr=False)
class OIDCDeviceAuthorizationProvider:
    provider: OIDCProvider
    device_authorization_endpoint: str
    token_endpoint: str

    def __post_init__(self):
        if type(self.provider) is not OIDCProvider:
            raise ContractError('oidc_device_configuration_invalid')
        try:
            device = _endpoint(self.device_authorization_endpoint,
                               issuer=self.provider.issuer)
            token = _endpoint(self.token_endpoint, issuer=self.provider.issuer)
        except ContractError:
            raise ContractError('oidc_device_configuration_invalid') from None
        if device == token:
            raise ContractError('oidc_device_configuration_invalid')

    def __repr__(self):
        return '<OIDCDeviceAuthorizationProvider configured>'


class BoundedOIDCDeviceHTTP:
    """POST a form with a bounded body and one total per-request deadline."""
    __slots__ = ('_runner', '_monotonic', '_roots_pem')

    def __init__(self, *, roots_pem=None, _runner=None, _monotonic=None):
        self._runner = _runner or subprocess.run
        self._monotonic = _monotonic or time.monotonic
        self._roots_pem = roots_pem

    def __repr__(self):
        return '<BoundedOIDCDeviceHTTP configured>'

    def post(self, endpoint, fields, *, deadline):
        if (not isinstance(endpoint, str) or type(fields) is not dict
                or not isinstance(deadline, (int, float))):
            raise ContractError('oidc_device_exchange_refused')
        remaining = min(_REQUEST_TIMEOUT, deadline - self._monotonic())
        if remaining <= 0:
            raise ContractError('oidc_device_exchange_refused')
        marker = '\nagentmux-oidc-device-response:'
        command = ['/usr/bin/curl', '--disable', '--silent', '--request', 'POST',
            '--proto', '=https', '--max-redirs', '0',
            '--connect-timeout', f'{remaining:.6f}', '--max-time', f'{remaining:.6f}',
            '--max-filesize', str(_MAX_RESPONSE), '--header', 'Accept: application/json',
            '--header', 'Content-Type: application/x-www-form-urlencoded',
            '--data-binary', '@-', '--write-out', marker + '%{http_code}\n%{content_type}',
            endpoint]
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
            body = urlencode(fields).encode('ascii')
            completed = self._runner(command, input=body, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=max(0.001, remaining), check=False)
        except (UnicodeError, subprocess.TimeoutExpired, TimeoutError, OSError, ValueError):
            raise ContractError('oidc_device_exchange_refused') from None
        finally:
            if roots_path is not None:
                try:
                    os.unlink(roots_path)
                except OSError:
                    pass
        separator = marker.encode('ascii')
        if (self._monotonic() >= deadline or completed.returncode != 0
                or not isinstance(completed.stdout, bytes)
                or len(completed.stdout) > _MAX_RESPONSE + len(separator) + 4096
                or separator not in completed.stdout):
            raise ContractError('oidc_device_exchange_refused')
        raw, metadata = completed.stdout.rsplit(separator, 1)
        try:
            status_raw, content_type = metadata.decode('ascii').split('\n', 1)
            status = int(status_raw)
            document = strict_loads(raw)
        except (ContractError, UnicodeDecodeError, ValueError, TypeError):
            raise ContractError('oidc_device_exchange_refused') from None
        if (len(raw) > _MAX_RESPONSE or status not in (200, 400)
                or content_type.split(';', 1)[0].strip().lower() != 'application/json'
                or type(document) is not dict):
            raise ContractError('oidc_device_exchange_refused')
        return status, document


class OIDCDeviceAuthorizationRequest:
    """One private device code with public instructions and a one-use poller."""
    __slots__ = ('_flow', '_login', '_device_code', '_user_code',
                 '_verification_uri', '_verifier', '_deadline', '_interval', '_cancel',
                 '_expires_at', '_used', '_lock')

    def __init__(self, flow, login, device_code, user_code, verification_uri, verifier,
                 deadline, interval, expires_at, brand):
        if brand is not _DEVICE_REQUEST:
            raise ContractError('oidc_device_request_invalid')
        self._flow, self._login, self._device_code = flow, login, device_code
        self._user_code, self._verification_uri = user_code, verification_uri
        self._verifier = verifier
        self._deadline, self._interval = deadline, interval
        self._expires_at = expires_at
        self._cancel = threading.Event()
        self._used, self._lock = False, threading.Lock()

    def __repr__(self):
        return '<OIDCDeviceAuthorizationRequest private>'

    @property
    def user_code(self):
        return self._user_code

    @property
    def verification_uri(self):
        return self._verification_uri

    @property
    def interval(self):
        return self._interval

    @property
    def expires_at(self):
        return self._expires_at

    def cancel(self):
        """Wake and refuse this request without exposing its device code."""
        self._cancel.set()

    def _take(self, flow):
        with self._lock:
            if self._used or self._flow is not flow:
                self._used = True
                raise ContractError('oidc_device_request_invalid')
            self._used = True
            return (self._login, self._device_code, self._verifier, self._deadline,
                    self._interval, self._cancel)


_DEVICE_REQUEST = object()


class OIDCDeviceAuthorizationFlow:
    """Begin and complete one RFC 8628 login with Keycloak nonce binding."""
    __slots__ = ('_configuration', '_adapter', '_transport', '_clock',
                 '_monotonic', '_sleep')

    def __init__(self, configuration, *, transport=None, _clock=None,
                 _monotonic=None, _sleep=None):
        if (type(configuration) is not OIDCDeviceAuthorizationProvider
                or transport is not None and type(transport) is not BoundedOIDCDeviceHTTP):
            raise ContractError('oidc_device_configuration_invalid')
        self._configuration = configuration
        self._adapter = OIDCIdentityAdapter(configuration.provider)
        self._transport = transport or BoundedOIDCDeviceHTTP(
            roots_pem=configuration.provider.roots_pem)
        self._clock = _clock or (lambda: datetime.now(timezone.utc))
        self._monotonic, self._sleep = _monotonic or time.monotonic, _sleep

    def __repr__(self):
        return '<OIDCDeviceAuthorizationFlow configured>'

    def begin(self):
        now, started = self._clock(), self._monotonic()
        if not _valid_time(now):
            raise ContractError('oidc_device_request_invalid')
        login = self._adapter.begin_login(now=now, lifetime_seconds=900)
        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('ascii')).digest()).decode('ascii').rstrip('=')
        status, document = self._transport.post(
            self._configuration.device_authorization_endpoint,
            {'client_id': self._configuration.provider.audience,
             'scope': 'openid', 'nonce': login.nonce,
             'code_challenge': challenge, 'code_challenge_method': 'S256'},
            deadline=started + 5)
        allowed = {'device_code', 'user_code', 'verification_uri',
                   'verification_uri_complete', 'expires_in', 'interval'}
        if status != 200 or set(document) - allowed:
            raise ContractError('oidc_device_request_invalid')
        device_code, user_code = document.get('device_code'), document.get('user_code')
        verification_uri = document.get('verification_uri')
        expires, interval = document.get('expires_in'), document.get('interval', 5)
        if (not isinstance(device_code, str) or not _OPAQUE.fullmatch(device_code)
                or not isinstance(user_code, str) or not _USER_CODE.fullmatch(user_code)
                or type(expires) is not int or not 1 <= expires <= 900
                or type(interval) is not int or not 1 <= interval <= 60
                or expires <= interval or not self._verification_uri(verification_uri)):
            raise ContractError('oidc_device_request_invalid')
        complete = document.get('verification_uri_complete')
        if complete is not None and not self._verification_uri(complete, allow_query=True):
            raise ContractError('oidc_device_request_invalid')
        return OIDCDeviceAuthorizationRequest(self, login, device_code, user_code,
            verification_uri, verifier, started + expires, interval,
            now + timedelta(seconds=expires), _DEVICE_REQUEST)

    def complete(self, request):
        if type(request) is not OIDCDeviceAuthorizationRequest:
            raise ContractError('oidc_device_request_invalid')
        login, device_code, verifier, deadline, interval, cancel = request._take(self)
        next_poll = self._monotonic() + interval
        while True:
            current = self._monotonic()
            remaining = min(next_poll, deadline) - current
            if remaining > 0:
                if self._sleep is None:
                    cancel.wait(remaining)
                else:
                    self._sleep(remaining)
            if cancel.is_set():
                raise ContractError('oidc_device_authorization_refused')
            if self._monotonic() >= deadline:
                raise ContractError('oidc_device_authorization_expired')
            status, document = self._transport.post(self._configuration.token_endpoint,
                {'grant_type': _DEVICE_GRANT, 'device_code': device_code,
                 'client_id': self._configuration.provider.audience,
                 'code_verifier': verifier}, deadline=deadline)
            if status == 200:
                token = document.get('id_token')
                if not isinstance(token, str) or not 0 < len(token) <= _MAX_RESPONSE:
                    raise ContractError('oidc_device_exchange_refused')
                now = self._clock()
                if not _valid_time(now):
                    raise ContractError('oidc_device_request_invalid')
                return self._adapter.verify_device(token, login=login, now=now)
            if set(document) - {'error', 'error_description', 'error_uri'}:
                raise ContractError('oidc_device_exchange_refused')
            error = document.get('error')
            if error == 'authorization_pending':
                pass
            elif error == 'slow_down':
                interval += 5
            elif error == 'access_denied':
                raise ContractError('oidc_device_authorization_refused')
            elif error == 'expired_token':
                raise ContractError('oidc_device_authorization_expired')
            else:
                raise ContractError('oidc_device_exchange_refused')
            next_poll = self._monotonic() + interval

    def _verification_uri(self, value, *, allow_query=False):
        if not isinstance(value, str) or len(value) > 2048:
            return False
        try:
            parsed, issuer = urlsplit(value), urlsplit(
                self._configuration.provider.issuer)
            port, issuer_port = parsed.port, issuer.port
        except ValueError:
            return False
        return (parsed.scheme == 'https' and parsed.hostname == issuer.hostname
            and port == issuer_port and parsed.username is None
            and parsed.password is None and not parsed.fragment and bool(parsed.path)
            and parsed.path.startswith(issuer.path + '/')
            and (allow_query or not parsed.query))
