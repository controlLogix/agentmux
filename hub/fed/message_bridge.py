"""Host-only, single-use intent for the qualified legacy message bridge.

The signed bridge transport authenticates the application principal. These
objects retain the actual local admission boundary; they are never wire claims
or a way for plugin-provided decisions to grant authority.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import time
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed import guard


class MessageIntent:
    __slots__ = ('__weakref__',)

    def __new__(cls):
        raise TypeError('Federation admission is required')

    def __repr__(self):
        return '<MessageIntent private>'


@dataclass(frozen=True, repr=False)
class AdmittedMessageIntent:
    content: bytes
    expires_monotonic: float
    valid_until: datetime
    transport_session: object | None = None
    transport_connection: object | None = None


class MessageBridgeIntents:
    """Owned by one real Federation, its Hub and its enrolled bridge client."""
    def __init__(self, federation, client):
        from hub.fed.runtime import Federation
        from hub.server import Hub
        from capability_owner.legacy_messages_client import LegacyMessageCommandClient
        if (type(federation) is not Federation or not isinstance(federation.hub, Hub)
                or type(client) is not LegacyMessageCommandClient or client._hub is not federation.hub):
            raise ContractError('legacy_message_intent_configuration')
        self._federation, self._client = federation, client
        self._pending = weakref.WeakKeyDictionary()
        self._current = ContextVar('legacy_message_intent', default=None)

    def __repr__(self):
        return '<MessageBridgeIntents private>'

    def _session(self, *, inbound=True):
        from hub.fed.session import FederationSession
        self._client.check(self._federation)
        if not inbound:
            return None
        session = self._federation.session
        if type(session) is not FederationSession or self._federation.nc is None:
            raise ContractError('legacy_message_intent_unavailable')
        session.check_open()
        return session

    @contextmanager
    def _retain(self, content, *, seconds=5, session=None, connection=None):
        if not 0 < seconds <= 5:
            raise ContractError('legacy_message_intent_expired')
        proof = object.__new__(MessageIntent)
        record = AdmittedMessageIntent(canonical_bytes(content), time.monotonic() + seconds,
            datetime.now(timezone.utc) + timedelta(seconds=seconds), session, connection)
        self._pending[proof] = record
        token = self._current.set(proof)
        try:
            yield
        finally:
            self._pending.pop(proof, None)
            self._current.reset(token)

    def inbound(self, subject, envelope, decision, message):
        from nats.aio.msg import Msg
        session = self._session()
        fed = self._federation
        subscription = getattr(fed.nc, '_subs', {}).get(getattr(message, '_sid', None))
        owned = session._resources.get(id(subscription))
        current = guard.inbound(fed.policy, subject, envelope)
        if (type(message) is not Msg or message._client is not fed.nc
                or message.subject != subject or canonical_bytes(strict_loads(message.data)) != canonical_bytes(envelope)
                or subscription is None or owned is None or owned[1] is not subscription
                or getattr(subscription, '_closed', True) or current.action != 'deliver'
                or decision != current):
            raise ContractError('legacy_message_intent_unavailable')
        binding = self._client.intent_binding('deliver', envelope)
        content = {'command': 'deliver', 'envelope': envelope, 'subject': subject,
            'localNode': fed.node, 'binding': binding, 'quarantineId': None, 'privileged': False,
            'approver': None}
        return self._retain(content, session=session, connection=fed.nc)

    def approved(self, quarantine, caller):
        self._session(inbound=False)
        fed = self._federation
        proof = fed.hub.current_authenticated_caller()
        authenticated = fed.hub._consume_authenticated_caller(proof)
        request = strict_loads(authenticated.request)
        args = request.get('args', {})
        if (authenticated.authenticated_caller != 'operator' or authenticated.caller != 'operator'
                or caller != 'operator' or request.get('verb') != 'fed_approve'
                or type(args) is not dict or set(args) - {'id', 'privileged'}
                or args.get('id') != quarantine.get('id') or quarantine.get('state') != 'held'
                or type(args.get('privileged', False)) is not bool):
            raise ContractError('legacy_message_approval_unavailable')
        envelope, subject = quarantine['envelope'], quarantine['subject']
        binding = self._client.intent_binding('approve', envelope)
        content = {'command': 'approve', 'envelope': envelope, 'subject': subject,
            'localNode': fed.node, 'binding': binding, 'quarantineId': quarantine['id'],
            'privileged': args.get('privileged', False), 'approver': authenticated.authenticated_caller}
        return self._retain(content, seconds=min(5, authenticated.expires_monotonic - time.monotonic()))

    def consume(self, envelope, decision):
        proof = self._current.get()
        retained = self._pending.pop(proof, None) if type(proof) is MessageIntent else None
        if retained is None or time.monotonic() >= retained.expires_monotonic:
            raise ContractError('legacy_message_intent_unavailable')
        value = strict_loads(retained.content)
        session = self._session(inbound=value['command'] == 'deliver')
        if (value['envelope'] != envelope or bool(decision.approved) != (value['command'] == 'approve')
                or bool(decision.privileged_ok) != value['privileged']
                or value['command'] == 'deliver' and (session is not retained.transport_session
                    or self._federation.nc is not retained.transport_connection)
                or self._client.intent_binding(value['command'], envelope) != value['binding']):
            raise ContractError('legacy_message_intent_binding')
        return retained


def intent_operation(binding, command, envelope_id, quarantine_id=None):
    """Stable intent ID; altered content conflicts instead of becoming a retry."""
    value = {'binding': binding, 'command': command, 'envelopeId': envelope_id,
        'quarantineId': quarantine_id}
    return 'legacy_message_' + hashlib.sha256(canonical_bytes(value)).hexdigest()
