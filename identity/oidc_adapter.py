"""Verify one configured external OpenID Connect identity.

This adapter authenticates an external account. It does not grant membership,
project access, or command authority. Those decisions remain with the retained
identity owner through an explicit account-link operation and current grants.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import re
import secrets
import ssl
import threading
from urllib.parse import urlsplit

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate

_B64 = re.compile(r'[A-Za-z0-9_-]+\Z')
_STATE = re.compile(r'[A-Za-z0-9_-]{32,512}\Z')
_SUBJECT = re.compile(r'[\x20-\x7e]{1,255}\Z')


def _decode(segment, *, limit):
    if not isinstance(segment, str) or len(segment) > limit or not _B64.fullmatch(segment):
        raise ContractError('oidc_token_invalid')
    try:
        raw = base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))
    except (ValueError, TypeError):
        raise ContractError('oidc_token_invalid') from None
    if base64.urlsafe_b64encode(raw).decode().rstrip('=') != segment:
        raise ContractError('oidc_token_invalid')
    return raw


def _document(segment, *, limit):
    try:
        value = strict_loads(_decode(segment, limit=limit))
    except (ContractError, UnicodeDecodeError, ValueError, TypeError):
        raise ContractError('oidc_token_invalid') from None
    if type(value) is not dict:
        raise ContractError('oidc_token_invalid')
    return value


@dataclass(frozen=True, repr=False)
class OIDCProvider:
    """Pinned public configuration for one external provider client."""
    issuer: str
    audience: str
    key_id: str
    public_key: str
    max_token_seconds: int = 300
    roots_pem: str | None = None

    def __post_init__(self):
        if not isinstance(self.issuer, str):
            raise ContractError('oidc_provider_invalid')
        try:
            parsed = urlsplit(self.issuer)
            key = _decode(self.public_key, limit=64)
            if self.roots_pem is not None:
                if (not isinstance(self.roots_pem, str)
                        or not 1 <= len(self.roots_pem.encode()) <= 16384):
                    raise ValueError()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(cadata=self.roots_pem)
        except (ContractError, ValueError, ssl.SSLError):
            raise ContractError('oidc_provider_invalid') from None
        if (not isinstance(self.issuer, str) or len(self.issuer) > 2048
                or parsed.scheme != 'https' or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or self.issuer.endswith('/')
                or not isinstance(self.audience, str) or not 0 < len(self.audience) <= 512
                or not isinstance(self.key_id, str) or not 0 < len(self.key_id) <= 512
                or len(key) != 32 or type(self.max_token_seconds) is not int
                or not 1 <= self.max_token_seconds <= 900):
            raise ContractError('oidc_provider_invalid')

    def __repr__(self):
        return '<OIDCProvider configured>'


class VerifiedOIDCIdentity:
    """A private result that contains only the stable external identity key."""
    __slots__ = ('_issuer', '_subject')

    def __init__(self, issuer, subject, brand):
        if brand is not _VERIFIED:
            raise ContractError('oidc_identity_unverified')
        self._issuer, self._subject = issuer, subject

    def __repr__(self):
        return '<VerifiedOIDCIdentity private>'

    @property
    def external_identity(self):
        return {'issuer': self._issuer, 'subject': self._subject}


_VERIFIED = object()


class OIDCLoginBinding:
    """One private, short-lived state and nonce allocation."""
    __slots__ = ('_adapter', '_state', '_nonce', '_expires_at', '_used', '_lock')

    def __init__(self, adapter, state, nonce, expires_at, brand):
        if brand is not _LOGIN:
            raise ContractError('oidc_login_binding_invalid')
        self._adapter, self._state, self._nonce = adapter, state, nonce
        self._expires_at, self._used = expires_at, False
        self._lock = threading.Lock()

    def __repr__(self):
        return '<OIDCLoginBinding private>'

    @property
    def state(self):
        return self._state

    @property
    def nonce(self):
        return self._nonce

    def _take(self, adapter, returned_state, now):
        with self._lock:
            if (self._used or self._adapter is not adapter
                    or not _STATE.fullmatch(returned_state)
                    or not secrets.compare_digest(returned_state, self._state)
                    or now >= self._expires_at):
                self._used = True
                raise ContractError('oidc_login_binding_invalid')
            self._used = True
            return self._nonce


_LOGIN = object()


class OIDCIdentityAdapter:
    """Validate a signed ID token against one exact login attempt."""
    __slots__ = ('_provider',)

    def __init__(self, provider):
        if type(provider) is not OIDCProvider:
            raise ContractError('oidc_provider_invalid')
        self._provider = provider

    def __repr__(self):
        return '<OIDCIdentityAdapter configured>'

    def begin_login(self, *, now=None, lifetime_seconds=300):
        now = now if now is not None else datetime.now(timezone.utc)
        if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0)
                or type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 900):
            raise ContractError('oidc_login_binding_invalid')
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        return OIDCLoginBinding(self, state, nonce,
                                now + timedelta(seconds=lifetime_seconds), _LOGIN)

    def verify(self, token, *, login, returned_state, now=None):
        now = now if now is not None else datetime.now(timezone.utc)
        if (type(login) is not OIDCLoginBinding or not isinstance(returned_state, str)
                or len(returned_state) > 512 or not isinstance(now, datetime)
                or now.tzinfo is None or now.utcoffset() != timedelta(0)):
            raise ContractError('oidc_login_binding_invalid')
        expected_nonce = login._take(self, returned_state, now)
        return self._verify(token, expected_nonce=expected_nonce, now=now)

    def verify_device(self, token, *, login, now=None):
        """Verify a device-flow token against the nonce retained by Keycloak."""
        now = now if now is not None else datetime.now(timezone.utc)
        if (type(login) is not OIDCLoginBinding or not isinstance(now, datetime)
                or now.tzinfo is None or now.utcoffset() != timedelta(0)):
            raise ContractError('oidc_login_binding_invalid')
        expected_nonce = login._take(self, login.state, now)
        return self._verify(token, expected_nonce=expected_nonce, now=now)

    def _verify(self, token, *, expected_nonce, now):
        if not isinstance(token, str) or len(token) > 65536:
            raise ContractError('oidc_token_invalid')
        parts = token.split('.')
        if len(parts) != 3:
            raise ContractError('oidc_token_invalid')
        header = _document(parts[0], limit=8192)
        claims = _document(parts[1], limit=49152)
        if (set(header) - {'alg', 'kid', 'typ'} or header.get('alg') != 'EdDSA'
                or header.get('kid') != self._provider.key_id
                or header.get('typ', 'JWT') != 'JWT'):
            raise ContractError('oidc_signing_key_mismatch')
        signature = _decode(parts[2], limit=128)
        try:
            VerifyKey(_decode(self._provider.public_key, limit=64)).verify(
                (parts[0] + '.' + parts[1]).encode('ascii'), signature)
        except (BadSignatureError, ValueError, TypeError):
            raise ContractError('oidc_signature_invalid') from None

        timestamp = now.timestamp()
        issued, expires = claims.get('iat'), claims.get('exp')
        if (type(issued) is not int or type(expires) is not int or issued > timestamp
                or timestamp >= expires or expires <= issued
                or expires - issued > self._provider.max_token_seconds):
            raise ContractError('oidc_time_invalid')
        not_before = claims.get('nbf')
        if not_before is not None and (type(not_before) is not int or timestamp < not_before):
            raise ContractError('oidc_time_invalid')

        audience = claims.get('aud')
        if isinstance(audience, str):
            audiences = [audience]
        elif (type(audience) is list and audience
                and all(isinstance(item, str) and item for item in audience)
                and len(set(audience)) == len(audience)):
            audiences = audience
        else:
            raise ContractError('oidc_audience_invalid')
        if self._provider.audience not in audiences:
            raise ContractError('oidc_audience_invalid')
        if ((len(audiences) > 1 and claims.get('azp') != self._provider.audience)
                or ('azp' in claims and claims['azp'] != self._provider.audience)):
            raise ContractError('oidc_audience_invalid')

        subject = claims.get('sub')
        token_nonce = claims.get('nonce')
        if (claims.get('iss') != self._provider.issuer
                or not isinstance(token_nonce, str)
                or not _STATE.fullmatch(token_nonce)
                or not secrets.compare_digest(token_nonce, expected_nonce)
                or not isinstance(subject, str) or not _SUBJECT.fullmatch(subject)):
            raise ContractError('oidc_identity_invalid')
        return VerifiedOIDCIdentity(self._provider.issuer, subject, _VERIFIED)


def external_account_link_payload(*, authority_id, identity_ref, verified_identity):
    """Build the owner command payload without copying mutable profile claims."""
    if type(verified_identity) is not VerifiedOIDCIdentity:
        raise ContractError('oidc_identity_unverified')
    payload = {'authorityId': authority_id, 'identityRef': identity_ref,
               'externalIdentity': verified_identity.external_identity}
    validate('identity-external-account-link', payload)
    return strict_loads(canonical_bytes(payload))
