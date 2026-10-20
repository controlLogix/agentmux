"""Opaque knowledge admissions from actual broker, approval and owned events."""
from contextlib import contextmanager, asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import json
import time
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from . import envelope, guard


class KnowledgeIntent:
    def __new__(cls):
        raise TypeError('Current knowledge admission is required')


@dataclass(frozen=True, repr=False)
class AdmittedKnowledgeIntent:
    content: bytes
    expires_monotonic: float
    valid_until: datetime
    session: object = None
    connection: object = None


class KnowledgeBridgeIntents:
    def __init__(self, federation, client):
        from .runtime import Federation
        from hub.server import Hub
        from capability_owner.legacy_knowledge_client import LegacyKnowledgeCommandClient
        if (type(federation) is not Federation or not isinstance(federation.hub, Hub)
                or type(client) is not LegacyKnowledgeCommandClient or client._hub is not federation.hub):
            raise ContractError('legacy_knowledge_intent_configuration')
        self._federation, self._client = federation, client
        self._pending = weakref.WeakKeyDictionary()
        self._current = ContextVar('legacy_knowledge_intent', default=None)
        self._handoff = ContextVar('legacy_knowledge_handoff', default=None)

    def _session(self):
        from .session import FederationSession
        self._client.check(self._federation)
        session = self._federation.session
        if type(session) is not FederationSession or self._federation.nc is None:
            raise ContractError('legacy_knowledge_intent_unavailable')
        session.check_open()
        return session

    @contextmanager
    def _retain(self, value, *, seconds=5, session=None, connection=None, _valid_until=None):
        if not 0 < seconds <= 5:
            raise ContractError('legacy_knowledge_intent_expired')
        now = datetime.now(timezone.utc)
        end = now + timedelta(seconds=seconds)
        if _valid_until is not None:
            end = min(end, _valid_until)
        remaining = (end - now).total_seconds()
        if remaining <= 0:
            raise ContractError('legacy_knowledge_intent_expired')
        proof = object.__new__(KnowledgeIntent)
        self._pending[proof] = AdmittedKnowledgeIntent(canonical_bytes(value), time.monotonic() + remaining,
            end, session, connection)
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
        if (type(message) is not Msg or message._client is not fed.nc or item.get('type') != 'knowledge'
                or message.subject != subject or canonical_bytes(strict_loads(message.data)) != canonical_bytes(item)
                or subscription is None or owned is None or owned[1] is not subscription
                or getattr(subscription, '_closed', True) or current.action != 'deliver' or decision != current):
            raise ContractError('legacy_knowledge_intent_unavailable')
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
                or quarantine['state'] != 'held' or quarantine['plane'] != 'know' or item['type'] != 'knowledge'
                or type(args.get('privileged', False)) is not bool):
            raise ContractError('legacy_knowledge_approval_unavailable')
        return self._retain({'command': 'approve', 'envelope': item, 'subject': quarantine['subject'],
            'decision': asdict(decision), 'binding': self._client.intent_binding('approve', item),
            'quarantineId': quarantine['id'], 'privileged': args.get('privileged', False)},
            seconds=min(5, admitted.expires_monotonic - time.monotonic()))

    def _consume(self):
        proof = self._current.get()
        retained = self._pending.pop(proof, None) if type(proof) is KnowledgeIntent else None
        if retained is None or time.monotonic() >= retained.expires_monotonic:
            raise ContractError('legacy_knowledge_intent_unavailable')
        self._client.check(self._federation)
        return retained

    def consume_inbound(self, item, decision):
        retained = self._consume()
        value = strict_loads(retained.content)
        if (value['command'] not in ('index', 'approve') or value['envelope'] != item
                or value['decision'] != asdict(decision)
                or bool(decision.approved) != (value['command'] == 'approve')
                or self._client.intent_binding(value['command'], item) != value['binding']):
            raise ContractError('legacy_knowledge_intent_binding')
        if value['command'] == 'index':
            if self._session() is not retained.session or self._federation.nc is not retained.connection:
                raise ContractError('legacy_knowledge_intent_binding')
        elif bool(decision.privileged_ok) != value['privileged']:
            raise ContractError('legacy_knowledge_intent_binding')
        return retained

    @asynccontextmanager
    async def control(self, subject, item, message):
        """Retain a candidate; only the owner's enrolled receipt grants withdrawal."""
        import asyncio
        from nats.aio.msg import Msg
        from identity.peer_control import HEADER
        from .peer_control import HEADER_REPOSITORY
        session, fed = self._session(), self._federation
        subscription = getattr(fed.nc, '_subs', {}).get(getattr(message, '_sid', None))
        owned = session._resources.get(id(subscription))
        plane, peer, _ = envelope.validate_route(subject, item)
        headers = message.headers or {}
        repository_id = headers.get(HEADER_REPOSITORY)
        if (type(message) is not Msg or message._client is not fed.nc or message.subject != subject
                or canonical_bytes(strict_loads(message.data)) != canonical_bytes(item)
                or subscription is None or owned is None or owned[1] is not subscription
                or getattr(subscription, '_closed', True)
                or asyncio.current_task() is not subscription._wait_for_msgs_task
                or plane != 'ctl' or item['type'] != 'revoke' or peer == fed.me
                or item['rid'] is not None or item['to'] != '*'
                or type(headers.get(HEADER)) is not str or type(repository_id) is not str):
            raise ContractError('legacy_knowledge_control_unavailable')
        repo = fed.policy.local_of(repository_id)
        if repo is None:
            raise ContractError('legacy_knowledge_control_unavailable')
        _, enrollment = self._client._select('federation', 'withdraw', repo)[0]
        selector = {'eventId': item['id'], 'eventDigest': payload_digest(item), 'subject': subject,
            'signature': headers[HEADER], 'repositoryId': repository_id}
        with self._retain({'command': 'withdraw', 'peer': peer, 'control': selector,
                'binding': self._client._binding(enrollment)}, session=session, connection=fed.nc):
            yield

    def consume_control(self, peer):
        retained = self._consume()
        value = strict_loads(retained.content)
        if (value.get('command') != 'withdraw' or value['peer'] != peer
                or self._session() is not retained.session or self._federation.nc is not retained.connection):
            raise ContractError('legacy_knowledge_control_unavailable')
        return retained

    @contextmanager
    def handoff_source(self, source):
        self._client.check(self._federation)
        token = self._handoff.set(canonical_bytes(source))
        try:
            yield
        finally:
            self._handoff.reset(token)

    @staticmethod
    def _arguments(kind, data):
        repo = data.get('repo')
        if kind == 'handoff_sent' and repo:
            return {'caller': data['by'], 'repo': repo, 'title': 'handoff to ' + data['to'],
                'body': data['body'], 'tags': ['auto', 'handoff'], 'reference': data.get('ref'), 'source': 'auto:handoff'}
        if kind == 'work_released' and data.get('state') == 'done' and data.get('result'):
            caller = data.get('claimed_by') or 'operator'
            if not caller.startswith(('fed:', 'peer:', 'nats:')):
                return {'caller': caller, 'repo': repo, 'title': 'done: ' + data['title'], 'body': data['result'],
                    'tags': ['auto', 'work'], 'reference': data.get('task_key') or data['id'], 'source': 'auto:work'}
        if kind == 'fed_result' and data.get('result'):
            return {'caller': 'operator', 'repo': repo, 'title': f"result from {data['from_peer']}: {data['title']}",
                'body': data['result'], 'tags': ['auto', 'result'],
                'reference': data.get('task_key') or data['id'], 'source': 'auto:result'}
        return None

    @asynccontextmanager
    async def local_event(self, kind, data):
        self._client.check(self._federation)
        arguments = self._arguments(kind, data) if isinstance(data, dict) else None
        if arguments is None or not self._federation.policy.rid_of(arguments['repo'] or ''):
            yield
            return
        valid_until = None
        if kind == 'handoff_sent':
            raw = self._handoff.get()
            if raw is None:
                raise ContractError('legacy_knowledge_source_unavailable')
            source = strict_loads(raw)
        elif (kind == 'work_released'
                and getattr(self._federation.hub, '_work_storage_commands', None) is not None):
            from capability_owner.work_rpc import WorkRpc
            rpc = getattr(self._federation.hub, '_work_rpc', None)
            if type(rpc) is not WorkRpc:
                raise ContractError('legacy_knowledge_source_unavailable')
            source, valid_until = await rpc.capture_source(data)
        elif kind == 'fed_result' and getattr(self._federation, '_qualified_work', False):
            from capability_owner.federated_work_client import FederatedWorkCommandClient
            work = getattr(self._federation, '_work_commands', None)
            if type(work) is not FederatedWorkCommandClient:
                raise ContractError('legacy_knowledge_source_unavailable')
            source, valid_until = await work.capture_source(data)
        else:
            row = await self._federation.hub.db(self._federation.store.q1,
                'SELECT * FROM work_items WHERE id=?', (data['id'],))
            if row is None or any(data.get(key) != field for key, field in row.items()):
                raise ContractError('legacy_knowledge_source_changed')
            if kind == 'fed_result':
                flags = json.loads(row.get('fed_flags') or '{}')
                if data.get('from_peer') != flags.get('executor', {}).get('peer'):
                    raise ContractError('legacy_knowledge_source_changed')
            source = {'kind': 'work-released' if kind == 'work_released' else 'fed-result',
                'id': row['id'], 'digest': payload_digest(row)}
        _, enrollment = self._client._select('federation', 'capture', arguments['repo'])[0]
        with self._retain({'command': 'capture', 'arguments': arguments, 'source': source,
                'binding': self._client._binding(enrollment)}, _valid_until=valid_until):
            yield

    def consume_event(self, caller, repo, title, body, tags, reference, source):
        retained = self._consume()
        value = strict_loads(retained.content)
        arguments = {'caller': caller, 'repo': repo, 'title': title, 'body': body,
            'tags': list(tags), 'reference': reference, 'source': source}
        if value.get('command') != 'capture' or value['arguments'] != arguments:
            raise ContractError('legacy_knowledge_intent_binding')
        return retained
