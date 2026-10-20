"""Short-lived local browser identity from an enrolled application binding.

This module owns no login, enrollment, HTTP cookie or definition permission. The
host supplies an explicitly provisioned application client and current enrolled
authority reader. Production uses the retained client connection owner, which
owns its reply prefix, deadlines and cleanup. A direct identity-service exchange
is retained only for in-process composition and focused tests.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import asyncio
import secrets
import time
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from .application_binding import _permission
from .application_client import ApplicationClientKey
from .authority import LedgerAuthorityReader, _active, _indexes, _key


_ROUTES = frozenset({('POST', '/api/board/agentdef'), ('POST', '/api/board/agentdrop')})
_FORGED_IDENTITY_FIELDS = frozenset({'actor', 'identity', 'projectId', 'project_id', 'userId', 'user_id'})
_MAX_REQUESTS = 32
_SESSION_LIFETIME = timedelta(minutes=15)
_EXCHANGE_LIFETIME = 5
_CLEANUP_LIFETIME = 10
_CONTEXT_BRAND = object()
_PAIRING_AUTHORITY_BRAND = object()


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _now(clock):
    value = datetime.now(timezone.utc) if clock is None else clock()
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise ContractError('local_browser_time_invalid')
    return value


def _has_identity_field(value):
    if isinstance(value, dict):
        return bool(_FORGED_IDENTITY_FIELDS.intersection(value)) or any(
            _has_identity_field(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_identity_field(item) for item in value)
    return False


class LocalBrowserPairingAuthority:
    """One exact signed pairing command, rechecked at cookie publication."""
    def __init__(self, ingress, request, cancellation_ref, operation, caller, scope, brand):
        if brand is not _PAIRING_AUTHORITY_BRAND:
            raise ContractError('local_browser_pairing_authority_invalid')
        self._ingress, self._request = ingress, bytes(request)
        self._cancellation = canonical_bytes(cancellation_ref)
        self._operation = bytes(operation)
        self._caller, self._scope = canonical_bytes(caller), canonical_bytes(scope)
        self._used = False

    @classmethod
    def _create(cls, ingress, request, cancellation_ref, operation, caller, scope):
        from .ingress import EnrolledIngress
        if (not isinstance(ingress, EnrolledIngress) or type(request) is not bytes
                or type(operation) is not bytes):
            raise ContractError('local_browser_pairing_authority_invalid')
        return cls(ingress, request, cancellation_ref, operation, caller, scope,
                   _PAIRING_AUTHORITY_BRAND)

    async def recheck(self, context):
        if self._used or not verified_local_browser_context(context):
            raise ContractError('local_browser_not_authorized')
        self._used = True
        admitted = await self._ingress.admit(self._request,
            cancellation_ref=strict_loads(self._cancellation))
        if (admitted.envelope is None or admitted.decision.outcome != 'allowed'
                or admitted.decision.operation != self._operation
                or canonical_bytes(context.caller_ref) != self._caller
                or canonical_bytes(context.scope) != self._scope):
            raise ContractError('local_browser_not_authorized')

    def __repr__(self):
        return '<LocalBrowserPairingAuthority private>'


@dataclass(frozen=True, repr=False)
class LocalBrowserContext:
    """Verified identity and scope; it is not a reusable authorization grant."""
    _caller_ref: bytes
    _scope: bytes
    _authority_ref: bytes
    _authority_sequence: int
    _valid_until: str
    _brand: object

    @property
    def caller_ref(self):
        return strict_loads(self._caller_ref)

    @property
    def scope(self):
        return strict_loads(self._scope)

    @property
    def authority_ref(self):
        return strict_loads(self._authority_ref)

    @property
    def authority_sequence(self):
        return self._authority_sequence

    @property
    def valid_until(self):
        return self._valid_until

    def __repr__(self):
        return '<LocalBrowserContext private>'


def verified_local_browser_context(value):
    """Recognize only context minted after this module's authority checks."""
    return type(value) is LocalBrowserContext and value._brand is _CONTEXT_BRAND


class LocalBrowserRequestProof:
    """Opaque one-use handle created only by LocalBrowserSession."""
    def __new__(cls):
        raise TypeError('local browser request proofs are private')

    def __repr__(self):
        return '<LocalBrowserRequestProof private>'


class LocalBrowserSession:
    """Bind exact local definition requests to current enrolled human identity."""
    def __init__(self, key, authority, exchange=None, *, binder=None, server_binding=None,
                 clock=None, max_requests=_MAX_REQUESTS):
        from .application_binding import _LocalBrowserApplicationBinding
        client_mode = isinstance(key, ApplicationClientKey) and server_binding is None
        server_mode = key is None and isinstance(server_binding, _LocalBrowserApplicationBinding)
        if (not (client_mode or server_mode)
                or not isinstance(authority, LedgerAuthorityReader)
                or (client_mode and callable(exchange) == callable(binder))
                or (server_mode and (exchange is not None or binder is not None))
                or (clock is not None and not callable(clock))
                or type(max_requests) is not int or not 1 <= max_requests <= _MAX_REQUESTS):
            raise ContractError('local_browser_session_configuration')
        self._key, self._authority = key, authority
        self._exchange, self._binder = exchange, binder
        self._server_binding = server_binding
        self._clock = clock
        self._max_requests = max_requests
        self._binding = None
        self._session_end = None
        self._closed = False
        self._proofs = weakref.WeakKeyDictionary()
        self._pending = 0

    def __repr__(self):
        return '<LocalBrowserSession private>'

    @property
    def expires_at(self):
        """The immutable outer session bound; each action still needs fresh authority."""
        return self._session_end

    @classmethod
    async def open(cls, key, authority, exchange, *, clock=None):
        """Open against an in-process identity-service exchange."""
        from hub.client_launch_connection import ClientConnectionOwner
        if isinstance(getattr(exchange, '__self__', None), ClientConnectionOwner):
            raise ContractError('local_browser_connection_owner_required')
        session = cls(key, authority, exchange, clock=clock)
        current = _now(session._clock)
        session._session_end = current + _SESSION_LIFETIME
        binding = await session._bind(current, discovery=True)
        session._binding = binding
        await session._check_human(binding)
        return session

    @classmethod
    async def open_connection_owner(cls, key, authority, owner, *, clock=None):
        """Open through the retained client owner and its private reply prefix."""
        from hub.client_launch_connection import ClientConnectionOwner
        if not isinstance(owner, ClientConnectionOwner):
            raise ContractError('local_browser_session_configuration')
        loop = asyncio.get_running_loop()

        async def bind():
            start = loop.time()
            return await owner.authenticate(key,
                deadline=start + _EXCHANGE_LIFETIME,
                cleanup_deadline=start + _CLEANUP_LIFETIME)

        session = cls(key, authority, binder=bind, clock=clock, max_requests=1)
        current = _now(session._clock)
        session._session_end = current + _SESSION_LIFETIME
        binding = await session._bind(current, discovery=True)
        session._binding = binding
        await session._check_human(binding)
        return session

    @classmethod
    async def open_server_binding(cls, binding, authority, *, clock=None):
        """Open only from the identity service's private verified runtime binding."""
        session = cls(None, authority, server_binding=binding, clock=clock)
        current = _now(session._clock)
        session._session_end = current + _SESSION_LIFETIME
        verified = await session._bind(current, discovery=True)
        session._binding = verified
        await session._check_human(verified)
        return session

    def _request_claims(self, now, *, discovery):
        selection = self._key.selection
        end = now + timedelta(seconds=5)
        if self._session_end is not None:
            end = min(end, self._session_end)
        if not now < end:
            raise ContractError('local_browser_session_expired')
        claims = {key: selection[key] for key in (
            'hubId', 'profileId', 'authorityId', 'instanceId', 'releaseDigest',
            'policyRef', 'workspaceRef', 'transportRef', 'grantRef')}
        claims.update(purpose='agentmux-application-discovery-request-v1' if discovery else
                      'agentmux-application-binding-request-v1',
                      requestId='request_' + secrets.token_hex(32), nonce=secrets.token_hex(32),
                      replySubject='_INBOX.' + secrets.token_hex(24),
                      issuedAt=_stamp(now), expiresAt=_stamp(end))
        if not discovery:
            claims.update(generation=self._binding['generation'],
                          lifetimeId=self._binding['lifetimeId'])
        return claims

    async def _bind(self, now, *, discovery=False):
        if self._server_binding is not None:
            return self._check_binding(await self._server_binding.current())
        if self._binder is not None:
            binding = await self._binder()
            return self._check_binding(binding)
        claims = self._request_claims(now, discovery=discovery)
        request = (self._key.sign_discovery(claims, now=now) if discovery else
                   self._key.sign_binding(claims, now=now))
        response = await self._exchange(request)
        binding = self._key.verify_response(response, request, now=_now(self._clock))
        return self._check_binding(binding)

    def _check_binding(self, binding):
        try:
            binding = strict_loads(canonical_bytes(binding))
            if (type(binding['generation']) is not int
                    or not isinstance(binding['lifetimeId'], str)
                    or not isinstance(binding['instanceId'], str)
                    or type(binding['authoritySequence']) is not int
                    or not isinstance(binding['authorityRef'], dict)
                    or not isinstance(binding['validUntil'], str)):
                raise ValueError()
        except (ContractError, KeyError, TypeError, ValueError, OverflowError):
            raise ContractError('local_browser_session_changed')
        if self._binding is not None and (binding['callerRef'] != self._binding['callerRef']
                or binding['scope'] != self._binding['scope']
                or binding['generation'] != self._binding['generation']
                or binding['lifetimeId'] != self._binding['lifetimeId']
                or binding['authoritySequence'] < self._binding['authoritySequence']):
            raise ContractError('local_browser_session_changed')
        return binding

    async def _check_human(self, binding):
        snapshot = await self._authority.current()
        now = _now(self._clock)
        if now >= self._session_end:
            raise ContractError('local_browser_session_expired')
        if now >= datetime.fromisoformat(binding['validUntil']):
            raise ContractError('local_browser_binding_expired')
        record = strict_loads(snapshot.record)
        state = record['state']
        index = _indexes(state, record['ownerHubId'])
        caller = index['identities'].get(_key(binding['callerRef']))
        scope = binding['scope']
        project = scope.get('projectId') if isinstance(scope, dict) else None
        if (binding['authorityRef'] != {'id': record['entityId'], 'ownerHubId': record['ownerHubId'],
                'revision': record['entityVersion']}
                or snapshot.sequence < binding['authoritySequence']
                or caller is None or caller['kind'] != 'human' or not _active(caller, now)
                or not isinstance(project, str) or not project.strip()):
            raise ContractError('local_browser_human_unavailable')
        if self._key is not None:
            selection = self._key.selection
            if (binding['callerRef'] != selection['callerRef'] or scope != selection['scope']
                    or binding.get('instanceId', selection['instanceId']) != selection['instanceId']):
                raise ContractError('local_browser_session_changed')
            instance_id = selection['instanceId']
        else:
            instance_id = binding['instanceId']
        _permission(index, caller['ref'], scope, 'application-bind', instance_id, now)
        return LocalBrowserContext(canonical_bytes(caller['ref']), canonical_bytes(scope),
            canonical_bytes(binding['authorityRef']),
            binding['authoritySequence'], binding['validUntil'], _CONTEXT_BRAND)

    async def authorize(self, method, path, body):
        """Return one opaque proof for one exact definition request."""
        current = _now(self._clock)
        if self._closed:
            raise ContractError('local_browser_session_closed')
        if self._session_end is None or current >= self._session_end:
            raise ContractError('local_browser_session_expired')
        if (method, path) not in _ROUTES or not isinstance(body, dict):
            raise ContractError('local_browser_request_unavailable')
        raw = canonical_bytes(body)
        if len(raw) > 65536:
            raise ContractError('owner_body_limit')
        decoded = strict_loads(raw)
        if _has_identity_field(decoded):
            raise ContractError('local_browser_identity_field_refused')
        if len(self._proofs) + self._pending >= self._max_requests:
            raise ContractError('local_browser_session_busy')
        self._pending += 1
        monotonic_start = time.monotonic()
        try:
            binding = await self._bind(current)
            if self._closed:
                raise ContractError('local_browser_session_closed')
            context = await self._check_human(binding)
            if self._closed:
                raise ContractError('local_browser_session_closed')
        finally:
            self._pending -= 1
        proof = object.__new__(LocalBrowserRequestProof)
        digest = payload_digest({'method': method, 'path': path, 'body': decoded})
        binding_end = datetime.fromisoformat(binding['validUntil'])
        self._proofs[proof] = (digest, context, monotonic_start + max(0, min(5,
            (self._session_end - current).total_seconds(),
            (binding_end - current).total_seconds())))
        return proof

    async def verify_identity(self):
        """Refresh this enrolled human/project binding without authorizing an action."""
        current = _now(self._clock)
        if self._closed:
            raise ContractError('local_browser_session_closed')
        if self._session_end is None or current >= self._session_end:
            raise ContractError('local_browser_session_expired')
        if len(self._proofs) + self._pending >= self._max_requests:
            raise ContractError('local_browser_session_busy')
        self._pending += 1
        try:
            binding = await self._bind(current)
            if self._closed:
                raise ContractError('local_browser_session_closed')
            return await self._check_human(binding)
        finally:
            self._pending -= 1

    def consume(self, proof, method, path, body):
        """Consume a proof once and return its verified identity context."""
        if self._closed or type(proof) is not LocalBrowserRequestProof:
            raise ContractError('local_browser_proof_unavailable')
        retained = self._proofs.pop(proof, None)
        if retained is None:
            raise ContractError('local_browser_proof_unavailable')
        try:
            wanted = payload_digest({'method': method, 'path': path, 'body': body})
        except ContractError:
            raise ContractError('local_browser_proof_unavailable') from None
        if retained[0] != wanted or time.monotonic() >= retained[2]:
            raise ContractError('local_browser_proof_unavailable')
        return retained[1]

    def close(self):
        self._closed = True
        self._proofs.clear()

