"""Own protected core work subscriptions, original publisher proof and cleanup."""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import secrets
import ssl
from weakref import WeakKeyDictionary

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.session import FederationSession, SessionCleanupFailure
from hub.nats_transport import new_client
from identity.core_work_transport import (HEADER, INGEST, RESULT, body_route, check_authority,
    group_binding, identity_generation, local_credential, receiver_subjects, refused, selected_route,
    signed_claims, subjects, verify_event)


class CoreWorkEvent:
    __slots__ = ('__weakref__',)

    def __new__(cls):
        raise TypeError('Core work admission is required')

    def __repr__(self):
        return '<CoreWorkEvent private>'


@dataclass(frozen=True, repr=False)
class _Event:
    proof: bytes
    deadline: datetime
    session: object
    connection: object


class CoreWorkIngress:
    """One exact receiver group; signatures choose from its finite peer routes."""
    def __init__(self, selection, identity, source, dispatch, *, route_ids, resource_binding):
        from identity.application_service_selection import ApplicationServiceSelection
        from capability_owner.work_host import WorkStoreHost
        from capability_owner.messages_host import MessageStoreHost
        from capability_owner.knowledge_host import KnowledgeStoreHost
        from capability_owner.code_host import CodeStoreHost
        from capability_owner.selected_storage import BoardAuditMirrorHost
        if (type(selection) is not ApplicationServiceSelection or type(route_ids) is not tuple
                or not route_ids or len(route_ids) > 64 or len(set(route_ids)) != len(route_ids)
                or not callable(dispatch) or type(source) not in (
                    WorkStoreHost, MessageStoreHost, KnowledgeStoreHost, CodeStoreHost, BoardAuditMirrorHost)):
            refused()
        self._selection, self._identity, self._source, self._dispatch = selection, identity, source, dispatch
        self._routes = {rid: canonical_bytes(selected_route(selection, rid)) for rid in route_ids}
        pins = [strict_loads(r) for r in self._routes.values()]
        self._common = canonical_bytes(group_binding(pins[0]))
        if any(canonical_bytes(group_binding(pin)) != self._common for pin in pins):
            refused()
        self._authority, self._enrolled = selection.check_storage_identity_source(identity)
        self._identity_generation = identity_generation(identity)
        self._selection_document = selection.document
        selected, _, repository, scope = selection.work_channel_projection(pins[0]['resourceRef'])
        default_repository = selected['repository']
        if (source._pins != selected['source'] or canonical_bytes(repository) != canonical_bytes(pins[0]['repository'])
                or scope != pins[0]['scope']
                or (default_repository is None) != (source._repository is None)
                or default_repository is not None and any(
                    source._repository.get(k) != v for k, v in default_repository.items())):
            refused()
        self._store, self._db, self._executor = source._store, source._store.db, source._executor
        self._source_pins = canonical_bytes(source._pins)
        if type(resource_binding) is not bytes:
            refused()
        self._resource_binding = resource_binding
        self._binding_digest = 'sha256:' + hashlib.sha256(resource_binding).hexdigest()
        self._session = FederationSession()
        self._connection = new_client(require_tls=True,
            leaf_certificate_sha256=pins[0]['connection']['leafCertificateSHA256'])
        self._connection._agentmux_session = self._session
        self._nonce = secrets.token_hex(24)
        self._subscriptions, self._handles = {}, WeakKeyDictionary()
        self._dispatch_tasks = {}
        self._active, self._workers = set(), set()
        self._started = self._closing = None
        self._closed, self._policy_paused = False, False
        self._subscription_lock = asyncio.Lock()
        self._prefix = 'core-work-proof:' + hashlib.sha256(canonical_bytes({
            'group': strict_loads(self._common), 'source': source._pins, 'ownerBindingDigest': self._binding_digest})).hexdigest() + ':'

    def __repr__(self):
        return '<CoreWorkIngress private>'

    def check(self):
        if (self._policy_paused or self._closed or self._started is None or not self._started.done()
                or self._started.cancelled() or self._started.exception() is not None
                or not self._connection.is_connected or self._source._store is not self._store
                or self._store.db is not self._db or self._source._executor is not self._executor
                or canonical_bytes(self._source._pins) != self._source_pins
                or self._selection.document != self._selection_document
                or identity_generation(self._identity) != self._identity_generation):
            refused()
        self._session.check_open()
        if getattr(self._source._worker, 'active', False):
            if (self._identity._closed or self._identity.reader is not self._authority
                    or self._identity.ingress is not self._enrolled):
                refused()
        else:
            authority, enrolled = self._selection.check_storage_identity_source(self._identity)
            if authority is not self._authority or enrolled is not self._enrolled:
                refused()
        for rid, pin in self._routes.items():
            if canonical_bytes(selected_route(self._selection, rid)) != pin:
                refused()
        if getattr(self._source._worker, 'active', False):
            self._source._check_files()
        else:
            self._source.check_health()

    async def start(self):
        if self._started is not None or self._closed:
            refused()
        async def opening():
            pin = strict_loads(next(iter(self._routes.values())))
            for rid, raw in self._routes.items():
                route = strict_loads(raw)
                for contract in route['peer']['grantRefs']:
                    await check_authority(self._selection, self._identity, route_id=rid, contract=contract)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls.minimum_version = ssl.TLSVersion.TLSv1_3
            tls.load_verify_locations(cadata=pin['connection']['rootsPEM'])
            def jwt():
                return local_credential(self._selection, pin)[0]
            def sign(nonce):
                if type(nonce) is not str or not 0 < len(nonce) <= 4096:
                    refused()
                key = nkeys.from_seed(local_credential(self._selection, pin)[1])
                try:
                    return base64.b64encode(key.sign(nonce.encode('ascii')))
                finally:
                    key.wipe()
            connection = pin['connection']
            async with asyncio.timeout(5):
                await self._connection.connect(servers=[connection['endpoint']], tls=tls,
                    tls_hostname=connection['serverName'], tls_handshake_first=True,
                    user_jwt_cb=jwt, signature_cb=sign, allow_reconnect=False,
                    connect_timeout=3, error_cb=self._error)
                for subject in sorted({s for raw in self._routes.values()
                                       for s in strict_loads(raw)['resultSubjects']}):
                    self._subscriptions[subject] = await self._connection.subscribe_owned(
                        self._session, subject, cb=self._receive)
                    self._dispatch_tasks[subject] = self._subscriptions[subject]._wait_for_msgs_task
                await self._connection.flush(timeout=1)
        self._started = asyncio.create_task(opening(), name='core-work:opening')
        self._started.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        await asyncio.shield(self._started)
        self.check()

    async def _error(self, error):
        # Broker diagnostics and message content remain private.
        return None

    async def set_work_subjects(self, wanted):
        async with self._subscription_lock:
            await self._set_work_subjects(wanted)

    async def _set_work_subjects(self, wanted):
        self.check()
        if type(wanted) not in (set, frozenset, tuple, list):
            refused()
        wanted = set(wanted)
        allowed = {s for raw in self._routes.values() for s in strict_loads(raw)['workSubjects']}
        if not wanted <= allowed:
            refused()
        for subject in sorted(wanted - self._subscriptions.keys()):
            self._subscriptions[subject] = await self._connection.subscribe_owned(self._session,
                subject, queue=subject.replace('.', '_'), cb=self._receive)
            self._dispatch_tasks[subject] = self._subscriptions[subject]._wait_for_msgs_task
            self.check()
        for subject in sorted((self._subscriptions.keys() & allowed) - wanted):
            original = self._subscriptions[subject]
            await original.unsubscribe()
            if self._subscriptions.get(subject) is original:
                self._subscriptions.pop(subject)
                self._dispatch_tasks.pop(subject, None)
        await self._connection.flush(timeout=1)
        self.check()

    def _message(self, message):
        from nats.aio.msg import Msg
        self.check()
        subscription = self._subscriptions.get(getattr(message, 'subject', None))
        owned = self._session._resources.get(id(subscription))
        if (type(message) is not Msg or message._client is not self._connection
                or subscription is None or self._connection._subs.get(message._sid) is not subscription
                or owned is None or owned[1] is not subscription or subscription._closed
                or asyncio.current_task() is not subscription._wait_for_msgs_task):
            refused()
        signature = (message.headers or {}).get(HEADER)
        matches = []
        for rid, raw in self._routes.items():
            pin = strict_loads(raw)
            if message.subject not in subjects(pin):
                continue
            try:
                verify_event(pin, message.data, message.subject, signature)
            except ContractError:
                continue
            matches.append((rid, pin))
        if len(matches) != 1:
            refused()
        return (*matches[0], signature)

    def key(self, route_id, event_id, admission_id):
        if route_id not in self._routes or type(event_id) is not str or not 0 < len(event_id) <= 512:
            refused()
        if type(admission_id) is not str or not admission_id.startswith('core_admission_') or not re_nonce(admission_id.removeprefix('core_admission_')):
            refused()
        return self._prefix + hashlib.sha256(canonical_bytes([route_id, event_id, admission_id])).hexdigest()

    def proof(self, raw, *, route_id, event_id, event_digest, admission_id):
        value = strict_loads(raw)
        required = {'formatVersion', 'route', 'source', 'body', 'subject', 'signature',
            'eventId', 'eventDigest', 'sessionNonce', 'authoritySequence', 'admittedAt', 'validUntil',
            'ownerBindingDigest', 'admissionId'}
        if (type(value) is not dict or set(value) != required or type(value['formatVersion']) is not int
                or value['formatVersion'] != 1 or route_id not in self._routes
                or canonical_bytes(value['route']) != self._routes[route_id]
                or canonical_bytes(value['source']) != self._source_pins
                or value['ownerBindingDigest'] != self._binding_digest
                or value['eventId'] != event_id or value['eventDigest'] != event_digest
                or value['admissionId'] != admission_id
                or type(value['authoritySequence']) is not int or value['authoritySequence'] < 1
                or type(value['sessionNonce']) is not str
                or re_nonce(value['sessionNonce']) is False):
            refused()
        try:
            body = base64.b64decode(value['body'], validate=True)
            admitted = datetime.fromisoformat(value['admittedAt'])
            deadline = datetime.fromisoformat(value['validUntil'])
            if admitted.utcoffset() is None or deadline.utcoffset() is None or admitted >= deadline:
                refused()
        except (ValueError, TypeError):
            refused()
        pin = strict_loads(self._routes[route_id])
        claims = signed_claims(pin, body, value['subject'])
        if claims['eventId'] != event_id or claims['bodySha256'] != event_digest:
            refused()
        verify_event(pin, body, value['subject'], value['signature'], now=admitted)
        if canonical_bytes(value) != raw:
            refused()
        return value, body

    def _retain(self, route_id, body, subject, signature, snapshot, deadline):
        self.check()
        self._source._check_files()
        pin = strict_loads(self._routes[route_id])
        claims = signed_claims(pin, body, subject)
        event_id, digest = claims['eventId'], claims['bodySha256']
        admission_id = 'core_admission_' + secrets.token_hex(24)
        raw = canonical_bytes({'formatVersion': 1, 'route': pin, 'source': strict_loads(self._source_pins),
            'body': base64.b64encode(body).decode(), 'subject': subject, 'signature': signature,
            'eventId': event_id, 'eventDigest': digest, 'sessionNonce': self._nonce, 'admissionId': admission_id,
            'authoritySequence': snapshot.sequence, 'ownerBindingDigest': self._binding_digest, 'admittedAt': datetime.now(timezone.utc).isoformat(),
            'validUntil': deadline.isoformat()})
        self.proof(raw, route_id=route_id, event_id=event_id, event_digest=digest, admission_id=admission_id)
        with self._store.tx():
            event_key = self._prefix + 'event:' + hashlib.sha256(canonical_bytes([route_id, event_id])).hexdigest()
            event = {'route': pin, 'body': base64.b64encode(body).decode(), 'subject': subject,
                     'signature': signature, 'eventId': event_id, 'eventDigest': digest,
                     'source': strict_loads(self._source_pins), 'ownerBindingDigest': self._binding_digest}
            prior = self._store.q1('SELECT v FROM fed_state WHERE k=?', (event_key,))
            if prior is not None and prior['v'] != canonical_bytes(event).decode():
                refused()
            self._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?) ON CONFLICT(k) DO NOTHING',
                                   (event_key, canonical_bytes(event).decode()))
            self._store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                                   (self.key(route_id, event_id, admission_id), raw.decode()))
        return raw

    async def _owned_db(self, function, *args):
        original = asyncio.create_task(self._source.db(function, *args))
        self._workers.add(original)
        try:
            return await asyncio.shield(original)
        except asyncio.CancelledError:
            while not original.done():
                try:
                    await asyncio.wait({original})
                except asyncio.CancelledError:
                    continue
            if not original.cancelled():
                original.exception()
            raise
        finally:
            if original.done():
                self._workers.discard(original)

    async def _receive(self, message):
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        handle = None
        try:
            route_id, pin, signature = self._message(message)
            _, contract, _, _ = body_route(pin, message.data, message.subject)
            snapshot, deadline = await check_authority(self._selection, self._identity,
                route_id=route_id, contract=contract)
            self._message(message)
            raw = await self._owned_db(self._retain, route_id, message.data, message.subject,
                                      signature, snapshot, deadline)
            self._message(message)
            if len(self._handles) >= 32 or datetime.now(timezone.utc) >= deadline:
                refused()
            handle = object.__new__(CoreWorkEvent)
            self._handles[handle] = _Event(raw, deadline, self._session, self._connection)
            await self._dispatch(message, handle)
        except ContractError:
            # A refused publisher cannot terminate the receiver's callback loop.
            return
        finally:
            if handle is not None:
                self._handles.pop(handle, None)
            completion.set_result(None)
            self._active.discard(completion)

    async def consume(self, handle):
        self.check()
        event = self._handles.pop(handle, None) if type(handle) is CoreWorkEvent else None
        if (event is None or event.session is not self._session or event.connection is not self._connection
                or datetime.now(timezone.utc) >= event.deadline):
            refused()
        value = strict_loads(event.proof)
        _, contract, _, _ = body_route(value['route'], base64.b64decode(value['body']), value['subject'])
        _, deadline = await check_authority(self._selection, self._identity,
            route_id=value['route']['routeId'], contract=contract)
        self.check()
        return event.proof, min(event.deadline, deadline)

    async def load(self, route_id, event_id, event_digest, admission_id):
        self.check()
        def read():
            self.check()
            row = self._store.q1('SELECT v FROM fed_state WHERE k=?', (self.key(route_id, event_id, admission_id),))
            if row is None:
                refused()
            raw = row['v'].encode()
            self.proof(raw, route_id=route_id, event_id=event_id, event_digest=event_digest, admission_id=admission_id)
            return raw
        return await self._owned_db(read)

    def begin_policy_pause(self):
        if self._closed:
            refused()
        self._policy_paused = True

    async def join_policy_pause(self):
        if not self._policy_paused:
            refused()
        pending = {*self._active, *self._workers}
        if pending:
            await asyncio.wait(pending)

    def end_policy_pause(self):
        if self._closed or not self._policy_paused:
            refused()
        self._policy_paused = False

    async def close(self, *, timeout=5):
        self._closed = True
        self._handles.clear()
        if self._closing is None:
            self._closing = asyncio.create_task(self._close(), name='core-work:cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('core_work_cleanup_incomplete')
        self._closing.result()

    async def _close(self):
        if self._started is not None:
            await asyncio.gather(self._started, return_exceptions=True)
        try:
            await self._session.close()
        except SessionCleanupFailure:
            if self._session.close_task is None:
                raise
            await asyncio.shield(self._session.close_task)
        pending = {*self._workers, *self._active}
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await self._connection.close()


def re_nonce(value):
    return len(value) == 48 and all(c in '0123456789abcdef' for c in value)


class CoreWorkPublisher:
    """Sign a retained outbox body, without changing its IDs or wire payload."""
    def __init__(self, selection, identity, *, route_id):
        from identity.application_service_selection import ApplicationServiceSelection
        if type(selection) is not ApplicationServiceSelection:
            refused()
        self._selection, self._identity, self._route_id = selection, identity, route_id
        self._pin = canonical_bytes(selected_route(selection, route_id))
        pin = strict_loads(self._pin)
        if 'publisher' not in pin:
            refused()
        self._authority, self._enrolled = selection.check_storage_identity_source(identity)
        self._session = FederationSession()
        self._connection = new_client(require_tls=True,
            leaf_certificate_sha256=pin['connection']['leafCertificateSHA256'])
        self._connection._agentmux_session = self._session
        self._started = self._closing = None
        self._closed, self._active, self._policy_paused = False, set(), False

    def __repr__(self):
        return '<CoreWorkPublisher private>'

    def check(self):
        if (self._policy_paused or self._closed or self._started is None or not self._started.done()
                or self._started.cancelled() or self._started.exception() is not None
                or not self._connection.is_connected
                or canonical_bytes(selected_route(self._selection, self._route_id)) != self._pin):
            refused()
        authority, enrolled = self._selection.check_storage_identity_source(self._identity)
        if authority is not self._authority or enrolled is not self._enrolled:
            refused()
        self._session.check_open()

    async def start(self):
        if self._started is not None or self._closed:
            refused()
        async def opening():
            pin = strict_loads(self._pin)
            for contract in pin['publisher']['grantRefs']:
                await check_authority(self._selection, self._identity, route_id=self._route_id,
                                      contract=contract, publisher=True)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            tls.minimum_version = ssl.TLSVersion.TLSv1_3
            tls.load_verify_locations(cadata=pin['connection']['rootsPEM'])
            def jwt():
                return local_credential(self._selection, pin, publisher=True)[0]
            def sign(nonce):
                if type(nonce) is not str or not 0 < len(nonce) <= 4096:
                    refused()
                key = nkeys.from_seed(local_credential(self._selection, pin, publisher=True)[1])
                try:
                    return base64.b64encode(key.sign(nonce.encode('ascii')))
                finally:
                    key.wipe()
            async with asyncio.timeout(5):
                await self._connection.connect(servers=[pin['connection']['endpoint']], tls=tls,
                    tls_hostname=pin['connection']['serverName'], tls_handshake_first=True,
                    user_jwt_cb=jwt, signature_cb=sign, allow_reconnect=False, connect_timeout=3,
                    error_cb=self._error)
        self._started = asyncio.create_task(opening(), name='core-work:publisher-opening')
        self._started.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        await asyncio.shield(self._started)
        self.check()

    async def _error(self, error):
        return None

    async def publish(self, subject, body, *, expires=None):
        self.check()
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            pin = strict_loads(self._pin)
            _, contract, _, _ = body_route(pin, body, subject, publisher=True)
            _, deadline = await check_authority(self._selection, self._identity,
                route_id=self._route_id, contract=contract, publisher=True)
            if expires is not None:
                deadline = min(deadline, expires)
            self.check()
            key = nkeys.from_seed(local_credential(self._selection, pin, publisher=True)[1])
            try:
                signature = base64.b64encode(key.sign(canonical_bytes(
                    signed_claims(pin, body, subject, publisher=True)))).decode()
            finally:
                key.wipe()
            if datetime.now(timezone.utc) >= deadline:
                refused()
            await self._connection.publish(subject, body, headers={HEADER: signature})
            await self._connection.flush(timeout=1)
            self.check()
            if datetime.now(timezone.utc) >= deadline:
                refused()
        finally:
            if not completion.done():
                completion.set_result(None)
            self._active.discard(completion)

    def begin_policy_pause(self):
        if self._closed:
            refused()
        self._policy_paused = True

    async def join_policy_pause(self):
        if not self._policy_paused:
            refused()
        pending = set(self._active)
        if pending:
            await asyncio.wait(pending)

    def end_policy_pause(self):
        if self._closed or not self._policy_paused:
            refused()
        self._policy_paused = False

    async def close(self, *, timeout=5):
        self._closed = True
        if self._closing is None:
            self._closing = asyncio.create_task(self._close(), name='core-work:publisher-cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('core_work_cleanup_incomplete')
        self._closing.result()

    async def _close(self):
        if self._started is not None:
            await asyncio.gather(self._started, return_exceptions=True)
        if self._active:
            await asyncio.gather(*self._active, return_exceptions=True)
        try:
            await self._session.close()
        except SessionCleanupFailure:
            if self._session.close_task is None:
                raise
            await asyncio.shield(self._session.close_task)
        await self._connection.close()
