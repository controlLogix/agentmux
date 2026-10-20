"""Own the enrolled control subscription and retain original event admission.

Stored provenance is an audit fact. Only a current opaque handle authorizes its
consumer; recovering old bytes always repeats current enrollment checks.
"""
import asyncio
import base64
from dataclasses import dataclass
import hashlib
import secrets
import ssl
from weakref import WeakKeyDictionary

import nkeys
from nacl.signing import VerifyKey

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.nats_transport import new_client
from identity.peer_control import (HEADER, check_authority, control_claims, local_credential,
    control_storage, public_credential, receiver_credential, selected_route)
from . import envelope
from .session import FederationSession

# A public lookup hint. The possession signature still binds the exact selected
# repository, resource and scope, and the owner validates the retained receipt.
HEADER_REPOSITORY = 'Agentmux-Peer-Control-Repository'


class PeerControlEvent:
    __slots__ = ('__weakref__',)

    def __new__(cls):
        raise TypeError('Current peer control admission is required')

    def __repr__(self):
        return '<PeerControlEvent private>'


@dataclass(frozen=True, repr=False)
class _Event:
    proof: bytes
    session: object
    connection: object


class PeerControlIngress:
    def __init__(self, selection, identity, store_owner, dispatch, *, route_id):
        from identity.application_service_selection import ApplicationServiceSelection
        from capability_owner.knowledge_host import KnowledgeStoreHost
        from capability_owner.messages_host import MessageStoreHost
        from capability_owner.selected_storage import BoardAuditMirrorHost
        from capability_owner.work_host import WorkStoreHost
        from capability_owner.code_host import CodeStoreHost
        if (type(selection) is not ApplicationServiceSelection or 'peerControl' not in selection.policy
                or not callable(dispatch)):
            raise ContractError('peer_control_configuration')
        self._selection, self._identity, self._store_owner = selection, identity, store_owner
        self._pin = selected_route(selection, route_id)
        self._route_id = route_id
        self._storage_domain, declaration = control_storage(selection.policy, self._pin)
        allowed_hosts = ((WorkStoreHost, KnowledgeStoreHost, MessageStoreHost,
            BoardAuditMirrorHost, CodeStoreHost) if self._storage_domain == 'work'
            else (KnowledgeStoreHost, MessageStoreHost, BoardAuditMirrorHost))
        if (type(store_owner) not in allowed_hosts
                or store_owner._pins != declaration['source'] or store_owner._repository is None
                or any(store_owner._repository.get(key) != value for key, value in self._pin['repository'].items())
                or store_owner._peer != self._pin['localPeer']):
            raise ContractError('peer_control_configuration')
        selection.check_storage_identity_source(identity)
        self._dispatch = dispatch
        self._connection = new_client(require_tls=True,
            leaf_certificate_sha256=self._pin['connection']['leafCertificateSHA256'])
        self._session = FederationSession()
        self._connection._agentmux_session = self._session
        self._nonce = secrets.token_hex(24)
        self._handles = WeakKeyDictionary()
        self._active, self._workers = set(), set()
        self._started = self._closing = None
        self._closed = False
        self._policy_paused = False
        self._subscription = None
        self._route = self._binding()
        self._prefix = 'peer-control:' + hashlib.sha256(canonical_bytes(self._route)).hexdigest() + ':'

    def __repr__(self):
        return '<PeerControlIngress private>'

    def _binding(self):
        selected = self._pin
        return {key: selected[key] for key in ('routeId', 'scope', 'resourceRef', 'repository', 'localPeer',
            'localNode', 'accountPublicKey', 'connection', 'receiver', 'peer')}

    def check(self):
        if self._policy_paused:
            raise ContractError('peer_control_unavailable')
        self.check_health()

    def check_health(self):
        if (self._closed or self._started is None or not self._started.done() or self._started.cancelled()
                or self._started.exception() is not None or not self._connection.is_connected
                or selected_route(self._selection, self._route_id) != self._pin):
            raise ContractError('peer_control_unavailable')
        self._session.check_open()
        self._store_owner.check_health()

    async def start(self, *, _bootstrap=None):
        if self._started is not None or self._closed:
            raise ContractError('peer_control_unavailable')
        if _bootstrap is not None:
            from capability_owner.policy_bootstrap import PolicyResourceBootstrap
            if type(_bootstrap) is not PolicyResourceBootstrap:
                raise ContractError('peer_control_configuration')
            state = _bootstrap._state()
            if state[0] is not self._store_owner or state[4] != self._storage_domain:
                raise ContractError('peer_control_configuration')
        async def opening():
            from capability_owner.knowledge_host import KnowledgeStoreHost
            from capability_owner.work_host import WorkStoreHost
            check_tables = (WorkStoreHost.check_work_tables if self._storage_domain == 'work'
                else KnowledgeStoreHost.check_knowledge_tables)
            if _bootstrap is None:
                await self._store_owner.db(check_tables, self._store_owner._store)
            else:
                await _bootstrap.submit(check_tables, self._store_owner._store)
            await check_authority(self._selection, self._identity, route_id=self._route_id)
            connection = self._pin['connection']
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(cadata=connection['rootsPEM'])
            def jwt():
                return receiver_credential(self._pin)[0]
            def sign(nonce):
                if type(nonce) is not str or not 0 < len(nonce) <= 4096:
                    raise ContractError('peer_control_unavailable')
                key = nkeys.from_seed(receiver_credential(self._pin)[1])
                try:
                    return base64.b64encode(key.sign(nonce.encode('ascii')))
                finally:
                    key.wipe()
            async with asyncio.timeout(5):
                await self._connection.connect(servers=[connection['endpoint']], tls=context,
                    tls_hostname=connection['serverName'], tls_handshake_first=True,
                    user_jwt_cb=jwt, signature_cb=sign, allow_reconnect=False,
                    connect_timeout=3, error_cb=self._error)
                self._subscription = await self._connection.subscribe_owned(self._session,
                    'am.ctl.' + self._pin['peer']['peerId'], cb=self._receive)
                await self._connection.flush(timeout=1)
            await check_authority(self._selection, self._identity, route_id=self._route_id)
        self._started = (asyncio.create_task(opening(), name='peer-control:opening')
            if _bootstrap is None else _bootstrap._start_owned(opening))
        self._started.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        await asyncio.shield(self._started)
        self.check()

    async def _error(self, error):
        # Never echo broker replies, addresses, credentials or control content.
        return None

    def _message(self, message):
        from nats.aio.msg import Msg
        self.check()
        subscription = self._subscription
        owned = self._session._resources.get(id(subscription))
        if (type(message) is not Msg or message._client is not self._connection
                or self._connection._subs.get(message._sid) is not subscription
                or owned is None or owned[1] is not subscription
                or subscription._closed or asyncio.current_task() is not subscription._wait_for_msgs_task):
            raise ContractError('peer_control_message_unadmitted')
        item = strict_loads(message.data)
        signature = (message.headers or {}).get(HEADER)
        if (message.headers or {}).get(HEADER_REPOSITORY) != self._pin['repository']['repositoryId']:
            raise ContractError('peer_control_message_unadmitted')
        self._verify_event(item, message.subject, signature)
        return item, signature

    def _verify_event(self, item, subject, signature):
        plane, sender, _ = envelope.validate_route(subject, item)
        peer = self._pin['peer']
        if (plane != 'ctl' or sender != peer['peerId'] or item['type'] != 'revoke' or item['node'] != peer['nodeId']
                or item['rid'] is not None or item['to'] != '*' or sender == self._pin['localPeer']):
            raise ContractError('peer_control_message_unadmitted')
        if type(signature) is not str:
            raise ContractError('peer_control_message_unadmitted')
        _, public = public_credential(peer['credentialJWT'], account=self._pin['accountPublicKey'],
            user=peer['userPublicKey'], peer=peer['peerId'])
        try:
            VerifyKey(public).verify(canonical_bytes(control_claims(self._pin, item, subject)),
                base64.b64decode(signature, validate=True))
        except Exception:
            raise ContractError('peer_control_message_unadmitted') from None

    def _proof(self, raw, event_id, event_digest):
        value = strict_loads(raw)
        if (type(value) is not dict or set(value) != {'formatVersion', 'binding', 'event', 'eventDigest',
                'subject', 'signature', 'sessionNonce', 'authoritySequence'}
                or type(value['formatVersion']) is not int or value['formatVersion'] != 1
                or value['binding'] != self._route or type(value['event']) is not dict
                or value['event'].get('id') != event_id
                or value['eventDigest'] != event_digest or payload_digest(value['event']) != event_digest
                or type(value['authoritySequence']) is not int or not 1 <= value['authoritySequence'] <= 9007199254740991
                or type(value['sessionNonce']) is not str
                or len(value['sessionNonce']) != 48
                or any(c not in '0123456789abcdef' for c in value['sessionNonce'])):
            raise ContractError('peer_control_event_conflict')
        self._verify_event(value['event'], value['subject'], value['signature'])
        return canonical_bytes(value)

    def _key(self, event_id):
        return self._prefix + hashlib.sha256(event_id.encode()).hexdigest()

    def _retain(self, item, signature, sequence):
        self._store_owner._check_files()
        store = self._store_owner._store
        proof = {'formatVersion': 1, 'binding': self._route, 'event': item,
            'eventDigest': payload_digest(item), 'subject': 'am.ctl.' + self._pin['peer']['peerId'],
            'signature': signature, 'sessionNonce': self._nonce, 'authoritySequence': sequence}
        raw = canonical_bytes(proof)
        self._proof(raw, item['id'], payload_digest(item))
        if len(raw) > 65536:
            raise ContractError('peer_control_capacity')
        with store.tx():
            previous = store.q1('SELECT v FROM fed_state WHERE k=?', (self._key(item['id']),))
            if previous is not None:
                retained = strict_loads(self._proof(previous['v'], item['id'], payload_digest(item)))
                if (retained['binding'] != self._route or retained['event'] != item
                        or retained['eventDigest'] != payload_digest(item) or retained['signature'] != signature):
                    raise ContractError('peer_control_event_conflict')
                return canonical_bytes(retained)
            store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)', (self._key(item['id']), raw.decode()))
        return raw

    def _handle(self, raw):
        if len(self._handles) >= 32:
            raise ContractError('peer_control_capacity')
        handle = object.__new__(PeerControlEvent)
        self._handles[handle] = _Event(raw, self._session, self._connection)
        return handle

    async def _receive(self, message):
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        handle = None
        try:
            item, signature = self._message(message)
            snapshot = await check_authority(self._selection, self._identity, route_id=self._route_id)
            self._message(message)
            worker = asyncio.create_task(self._store_owner.db(self._retain, item, signature, snapshot.sequence))
            self._workers.add(worker)
            worker.add_done_callback(lambda done: self._finished(done))
            raw = await asyncio.shield(worker)
            self.check()
            await check_authority(self._selection, self._identity, route_id=self._route_id)
            self._message(message)
            handle = self._handle(raw)
            await self._dispatch(message, handle)
        finally:
            if handle is not None:
                self._handles.pop(handle, None)
            completion.set_result(None)
            self._active.discard(completion)

    def _finished(self, worker):
        self._workers.discard(worker)
        if not worker.cancelled():
            worker.exception()

    async def consume(self, handle, *, peer, repository_id):
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            return await self._consume(handle, peer=peer, repository_id=repository_id)
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    async def _consume(self, handle, *, peer, repository_id):
        self.check()
        event = self._handles.pop(handle, None) if type(handle) is PeerControlEvent else None
        if (event is None or event.session is not self._session or event.connection is not self._connection
                or peer != self._pin['peer']['peerId'] or repository_id != self._pin['repository']['repositoryId']):
            raise ContractError('peer_control_event_unadmitted')
        await check_authority(self._selection, self._identity, route_id=self._route_id)
        self.check()
        return event.proof

    async def recover(self, event_id, event_digest):
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            return await self._recover(event_id, event_digest)
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    async def _recover(self, event_id, event_digest):
        self.check()
        snapshot = await check_authority(self._selection, self._identity, route_id=self._route_id)
        self.check()
        def load():
            self._store_owner._check_files()
            row = self._store_owner._store.q1('SELECT v FROM fed_state WHERE k=?', (self._key(event_id),))
            if row is None:
                raise ContractError('peer_control_event_unadmitted')
            raw = self._proof(row['v'], event_id, event_digest)
            if strict_loads(raw)['authoritySequence'] > snapshot.sequence:
                raise ContractError('peer_control_event_conflict')
            return raw
        worker = asyncio.create_task(self._store_owner.db(load))
        self._workers.add(worker)
        worker.add_done_callback(self._finished)
        raw = await asyncio.shield(worker)
        await check_authority(self._selection, self._identity, route_id=self._route_id)
        self.check()
        return self._handle(raw)

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('peer_control_cleanup_invalid')
        self._closed = True
        self._handles.clear()
        if self._closing is None:
            self._closing = asyncio.create_task(self._close(), name='peer-control:cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('peer_control_cleanup_incomplete')
        self._closing.result()

    def begin_policy_pause(self):
        if self._closed:
            raise ContractError('peer_control_unavailable')
        self._policy_paused = True

    async def join_policy_pause(self):
        if not self._policy_paused:
            raise ContractError('peer_control_unavailable')
        pending = {*self._active, *self._workers}
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def end_policy_pause(self):
        if self._closed or not self._policy_paused:
            raise ContractError('peer_control_unavailable')
        self._policy_paused = False
        self.check()

    async def _close(self):
        if self._started is not None:
            await asyncio.gather(self._started, return_exceptions=True)
        from .session import SessionCleanupFailure
        try:
            await self._session.close()
        except SessionCleanupFailure:
            # The public session deadline retains its exact cleanup. Keep our
            # original owner pending until that same attempt has joined.
            if self._session.close_task is None:
                raise
            await asyncio.shield(self._session.close_task)
        pending = {*self._active, *self._workers}
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await self._connection.close()


class PeerControlPublisher:
    """Publish one owned self-revoke without borrowing mutable federation auth."""
    def __init__(self, selection, identity, *, route_id):
        from identity.application_service_selection import ApplicationServiceSelection
        if type(selection) is not ApplicationServiceSelection or not selected_route(selection, route_id).get('publisher'):
            raise ContractError('peer_control_configuration')
        selection.check_storage_identity_source(identity)
        self._selection, self._identity = selection, identity
        self._pin = selected_route(selection, route_id)
        self._route_id = route_id
        self._connection = new_client(require_tls=True,
            leaf_certificate_sha256=self._pin['connection']['leafCertificateSHA256'])
        self._started = self._closing = None
        self._closed = False
        self._workers = set()

    def __repr__(self):
        return '<PeerControlPublisher private>'

    def check(self):
        if (self._closed or self._started is None or not self._started.done() or self._started.cancelled()
                or self._started.exception() is not None or not self._connection.is_connected
                or selected_route(self._selection, self._route_id) != self._pin):
            raise ContractError('peer_control_unavailable')

    async def start(self):
        if self._closed or self._started is not None:
            raise ContractError('peer_control_unavailable')
        async def opening():
            await check_authority(self._selection, self._identity, route_id=self._route_id, publisher=True)
            connection = self._pin['connection']
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(cadata=connection['rootsPEM'])
            def jwt():
                return local_credential(self._pin, publisher=True)[0]
            def sign(nonce):
                if type(nonce) is not str or not 0 < len(nonce) <= 4096:
                    raise ContractError('peer_control_unavailable')
                key = nkeys.from_seed(local_credential(self._pin, publisher=True)[1])
                try:
                    return base64.b64encode(key.sign(nonce.encode('ascii')))
                finally:
                    key.wipe()
            async def quiet(error):
                return None
            async with asyncio.timeout(5):
                await self._connection.connect(servers=[connection['endpoint']], tls=context,
                    tls_hostname=connection['serverName'], tls_handshake_first=True,
                    user_jwt_cb=jwt, signature_cb=sign, allow_reconnect=False,
                    connect_timeout=3, error_cb=quiet)
                await self._connection.flush(timeout=1)
            await check_authority(self._selection, self._identity, route_id=self._route_id, publisher=True)
        self._started = asyncio.create_task(opening(), name='peer-control:publisher-opening')
        self._started.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        await asyncio.shield(self._started)
        self.check()

    async def publish_revoke(self, original):
        self.check()
        item = strict_loads(canonical_bytes(original))
        subject = 'am.ctl.' + self._pin['localPeer']
        envelope.validate_route(subject, item)
        if (item['type'] != 'revoke' or item['from'] != self._pin['localPeer']
                or item['node'] != self._pin['localNode'] or item['rid'] is not None or item['to'] != '*'):
            raise ContractError('peer_control_message_unadmitted')
        async def publish():
            await check_authority(self._selection, self._identity, route_id=self._route_id, publisher=True)
            self.check()
            key = nkeys.from_seed(local_credential(self._pin, publisher=True)[1])
            try:
                signature = base64.b64encode(key.sign(canonical_bytes(control_claims(self._pin, item, subject)))).decode()
            finally:
                key.wipe()
            # Retain this original send and flush. Cancellation never launches
            # a replacement send to conceal an unknown broker outcome.
            await self._connection.publish(subject, canonical_bytes(item), headers={HEADER: signature,
                HEADER_REPOSITORY: self._pin['repository']['repositoryId']})
            await self._connection.flush(timeout=1)
            await check_authority(self._selection, self._identity, route_id=self._route_id, publisher=True)
            self.check()
            return {'eventId': item['id'], 'eventDigest': payload_digest(item)}
        worker = asyncio.create_task(publish(), name='peer-control:publication')
        self._workers.add(worker)
        def finished(done):
            self._workers.discard(done)
            if not done.cancelled():
                done.exception()
        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def close(self, *, timeout=5):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('peer_control_cleanup_invalid')
        self._closed = True
        if self._closing is None:
            async def cleanup():
                if self._started is not None:
                    await asyncio.gather(self._started, return_exceptions=True)
                if self._workers:
                    await asyncio.gather(*tuple(self._workers), return_exceptions=True)
                await self._connection.close()
            self._closing = asyncio.create_task(cleanup(), name='peer-control:publisher-cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('peer_control_cleanup_incomplete')
        self._closing.result()
