"""Opaque code admissions from actual broker, approval and owned events."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import time
import weakref

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from . import envelope, guard


class CodeIntent:
    def __new__(cls):
        raise TypeError('Current code admission is required')


@dataclass(frozen=True, repr=False)
class AdmittedCodeIntent:
    content: bytes
    expires_monotonic: float
    valid_until: datetime
    session: object = None
    connection: object = None


class CodeBridgeIntents:
    def __init__(self, federation, client):
        from .runtime import Federation
        from hub.server import Hub
        from capability_owner.legacy_code_client import LegacyCodeCommandClient
        if (type(federation) is not Federation or not isinstance(federation.hub, Hub)
                or type(client) is not LegacyCodeCommandClient or client._hub is not federation.hub):
            raise ContractError('legacy_code_intent_configuration')
        self._federation, self._client = federation, client
        self._pending = weakref.WeakKeyDictionary()
        self._current = ContextVar('legacy_code_intent', default=None)

    def _session(self):
        from .session import FederationSession
        self._client.check(self._federation)
        session = self._federation.session
        if type(session) is not FederationSession or self._federation.nc is None:
            raise ContractError('legacy_code_intent_unavailable')
        session.check_open()
        return session

    @contextmanager
    def _retain(self, value, *, seconds=5, session=None, connection=None):
        if not 0 < seconds <= 5:
            raise ContractError('legacy_code_intent_expired')
        proof = object.__new__(CodeIntent)
        self._pending[proof] = AdmittedCodeIntent(canonical_bytes(value), time.monotonic() + seconds,
            datetime.now(timezone.utc) + timedelta(seconds=seconds), session, connection)
        token = self._current.set(proof)
        try:
            yield
        finally:
            self._pending.pop(proof, None)
            self._current.reset(token)

    def inbound(self, subject, item, decision, message):
        from nats.aio.msg import Msg
        session = self._session()
        fed = self._federation
        subscription = getattr(fed.nc, '_subs', {}).get(getattr(message, '_sid', None))
        owned = session._resources.get(id(subscription))
        current = guard.inbound(fed.policy, subject, item)
        if (type(message) is not Msg or message._client is not fed.nc or item.get('type') != 'code'
                or message.subject != subject or canonical_bytes(strict_loads(message.data)) != canonical_bytes(item)
                or subscription is None or owned is None or owned[1] is not subscription
                or getattr(subscription, '_closed', True) or current.action != 'deliver' or decision != current):
            raise ContractError('legacy_code_intent_unavailable')
        return self._retain({'command': 'index', 'envelope': item, 'subject': subject,
            'decision': asdict(decision), 'binding': self._client.intent_binding('index', item)},
            session=session, connection=fed.nc)

    def approved(self, quarantine, caller, decision):
        self._client.check(self._federation)
        proof = self._federation.hub.current_authenticated_caller()
        admitted = self._federation.hub._consume_authenticated_caller(proof)
        request = strict_loads(admitted.request)
        args = request.get('args', {})
        item = quarantine['envelope']
        if (admitted.authenticated_caller != 'operator' or admitted.caller != 'operator' or caller != 'operator'
                or request.get('verb') != 'fed_approve' or type(args) is not dict
                or set(args) - {'id', 'privileged'} or args.get('id') != quarantine['id']
                or quarantine['state'] != 'held' or quarantine['plane'] != 'code' or item['type'] != 'code'
                or type(args.get('privileged', False)) is not bool):
            raise ContractError('legacy_code_approval_unavailable')
        return self._retain({'command': 'approve', 'envelope': item, 'subject': quarantine['subject'],
            'decision': asdict(decision), 'binding': self._client.intent_binding('approve', item),
            'quarantineId': quarantine['id'], 'privileged': args.get('privileged', False)},
            seconds=min(5, admitted.expires_monotonic - time.monotonic()))

    def _consume(self):
        proof = self._current.get()
        retained = self._pending.pop(proof, None) if type(proof) is CodeIntent else None
        if retained is None or time.monotonic() >= retained.expires_monotonic:
            raise ContractError('legacy_code_intent_unavailable')
        self._client.check(self._federation)
        return retained

    def consume_inbound(self, item, decision):
        retained = self._consume()
        value = strict_loads(retained.content)
        if (value['command'] not in ('index', 'approve') or value['envelope'] != item
                or value['decision'] != asdict(decision)
                or bool(decision.approved) != (value['command'] == 'approve')
                or self._client.intent_binding(value['command'], item) != value['binding']):
            raise ContractError('legacy_code_intent_binding')
        if value['command'] == 'index':
            if self._session() is not retained.session or self._federation.nc is not retained.connection:
                raise ContractError('legacy_code_intent_binding')
        elif bool(decision.privileged_ok) != value['privileged']:
            raise ContractError('legacy_code_intent_binding')
        return retained

