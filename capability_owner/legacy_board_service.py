"""Qualified legacy board commands over a scoped, signed owner boundary.

The host supplies enrollment and borrowed connections. This module provisions
nothing and never falls back to a legacy KV client after a failed owner call.
"""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import re
import secrets

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads, validate
from hub.fed.session import FederationSession, _subscription_tasks
from hub.store import HubError
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key, evaluate_snapshot
from identity.ingress import verify_possession
from identity.legacy_board_ingress import LegacyBoardIngress
from .board_publisher import BoardAllocationRoute, BoardStorageRoute
from .board_journal import _valid_ref
from .reply_service import _INBOX, _stamp, _time


def _parse(raw, name, limit):
    if type(raw) is not bytes or len(raw) > limit:
        raise ContractError('legacy_board_frame_invalid')
    value = strict_loads(raw)
    validate(name, value)
    if canonical_bytes(value) != raw:
        raise ContractError('legacy_board_frame_invalid')
    return value


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def command_subject(hub_id, scope):
    if (type(scope) is not dict or set(scope)!={'organizationId','projectId','workspaceId'}
            or scope['organizationId'] is None or type(hub_id) is not str
            or any(type(token) is not str or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}',token) is None
                for token in (hub_id,*(v for v in scope.values() if v is not None)))):
        raise ContractError('legacy_board_scope_invalid')
    return '.'.join(('amx','v1','h',hub_id,'o',scope['organizationId'],'p',scope['projectId'] or '_',
        'w',scope['workspaceId'] or '_','board','owner','command'))


class LegacyBoardCommandService:
    """Own request workers; publishers retain the card/allocation backends."""
    def __init__(self, authority, *, routes, connection, service_identity_ref, service_instance_id,
                 signing_key_ref, signing_seed):
        if (not isinstance(authority, LedgerAuthorityReader) or type(routes) is not tuple or not routes
                or len(routes)>256 or any(type(r) not in (BoardStorageRoute,BoardAllocationRoute) for r in routes)
                or not _valid_ref(service_identity_ref) or not _valid_ref(signing_key_ref)
                or type(service_instance_id) is not str or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}',service_instance_id) is None
                or type(signing_seed) is not bytes or len(signing_seed)!=32):
            raise ContractError('legacy_board_service_configuration')
        self._authority, self._connection = authority, connection
        self._identity, self._issuer = canonical_bytes(service_identity_ref), canonical_bytes(signing_key_ref)
        self._instance, self._seed = service_instance_id, signing_seed
        self._routes = {}
        scopes = set()
        for route in routes:
            owner = self._owner(route)
            binding = owner._resource.binding
            if binding.entity_id in self._routes or owner._journal._owner != self._identity:
                raise ContractError('legacy_board_service_configuration')
            self._routes[binding.entity_id] = route
            scopes.add(binding.scope)
        if len(scopes)!=1:
            raise ContractError('legacy_board_service_configuration')
        self._scope = scopes.pop()
        self.subject = command_subject(authority._hub, strict_loads(self._scope))
        self._closed = False
        self._workers, self._callbacks = set(), set()
        self._subscription = self._starting = self._closing = None
        self._subscriptions = FederationSession()

    def __repr__(self):
        return '<LegacyBoardCommandService private>'

    def _owner(self, route):
        if type(route) is BoardStorageRoute:
            return route.check(self._authority,route.resource,self._connection)
        owner = route.owner
        if (owner._journal._authority is not self._authority
                or getattr(owner._resource._jetstream,'_nc',None) is self._connection):
            raise ContractError('legacy_board_service_configuration')
        return owner

    async def _admit(self, raw, reply_subject):
        request = _parse(raw,'federation-board-service-request',98304)
        claims = request['claims']
        envelope_raw = base64.b64decode(claims['envelopeBytes'],validate=True)
        envelope = _parse(envelope_raw,'message-envelope',65536)
        if base64.b64encode(envelope_raw).decode()!=claims['envelopeBytes']:
            raise ContractError('legacy_board_delivery_refused')
        contract = envelope['contractId']
        if contract not in ('federation-board-command','capability-outcome-query'):
            raise ContractError('legacy_board_delivery_refused')
        validate(contract,envelope['payload'])
        if contract=='capability-outcome-query' and envelope['payload']['input']['contractId']!='federation-board-command':
            raise ContractError('legacy_board_delivery_refused')
        now = datetime.now(timezone.utc)
        start,end = _time(claims['issuedAt']),_time(claims['validUntil'])
        if (claims['replySubject']!=reply_subject or not _INBOX.fullmatch(reply_subject)
                or claims['hubId']!=self._authority._hub or claims['profileId']!=self._authority._profile
                or claims['authorityId']!=self._authority._entity or canonical_bytes(claims['scope'])!=self._scope
                or envelope['operation']['scope']!=claims['scope'] or not start<=now<end
                or end-start>timedelta(seconds=5)
                or claims['transportRef']!=envelope['ingressAttestation']['claims']['authenticatedTransportRef']):
            raise ContractError('legacy_board_delivery_refused')
        snapshot = await self._authority.current()
        now = datetime.now(timezone.utc)
        if not start<=now<end:
            raise ContractError('legacy_board_delivery_refused')
        state = strict_loads(snapshot.record)['state']
        index = _indexes(state,self._authority._hub)
        transport = index['transports'].get(_key(claims['transportRef']))
        if (transport is None or not _active(transport,now)
                or transport['method']!='nats-credential-mapping'
                or transport['identityRef']!=envelope['operation']['caller']['authenticatedIdentityRef']):
            raise ContractError('legacy_board_delivery_refused')
        verify_possession(claims,request['signature'],transport['publicKey'])
        audience = 'storage-owner' if contract=='federation-board-command' else 'outcome-owner'
        decision = evaluate_snapshot(snapshot,envelope_raw,audience={'hubId':self._authority._hub,'serviceId':audience},now=now)
        if decision.outcome!='allowed':
            raise ContractError('legacy_board_delivery_refused')
        route = self._routes.get(envelope['payload']['resourceRef']['id'])
        if route is None:
            raise ContractError('legacy_board_route_unavailable')
        owner = self._owner(route)
        if (envelope['payload']['resourceRef']['ownerHubId']!=owner._resource.binding.hub_id
                or owner._resource.binding.scope!=self._scope):
            raise ContractError('legacy_board_delivery_refused')
        signer = index['issuers'].get(_key(strict_loads(self._issuer)))
        identity = index['identities'].get(_key(strict_loads(self._identity)))
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')
        if (signer is None or identity is None or not _active(signer,now) or not _active(identity,now)
                or identity['kind']!='service' or canonical_bytes(signer['identityRef'])!=self._identity
                or signer['instanceId']!=self._instance or signer['publicKey']!=public):
            raise ContractError('legacy_board_signer_unavailable')
        return request,envelope_raw,envelope,owner,min(end,decision.valid_until,_time(signer['expiresAt']))

    async def _execute(self, raw, reply_subject):
        if self._closed:
            raise ContractError('legacy_board_service_unavailable')
        request,inner,envelope,owner,_ = await self._admit(raw,reply_subject)
        if self._closed:
            raise ContractError('legacy_board_service_unavailable')
        query = envelope['contractId']=='capability-outcome-query'
        if type(self._routes[owner._resource.binding.entity_id]) is BoardStorageRoute:
            result = await owner.legacy_result(inner,query=query)
            original = envelope['payload']['input'] if query else envelope['operation']
            group = None if result is None else await owner._group(original)
        else:
            if query:
                outcome = await owner.reconcile(inner)
                result = None if outcome is None else owner._result(await owner._group(envelope['payload']['input']))
            else:
                result = await owner.apply(inner)
            original = envelope['payload']['input'] if query else envelope['operation']
            group = None if result is None else await owner._group(original)
            if result is not None:
                result = {k:v for k,v in result.items() if k not in
                    ('cardRef','receiptRef','_agentmuxOperation','_agentmuxRecoveryFence')}
        _,_,_,_,end = await self._admit(raw,reply_subject)
        if self._closed:
            raise ContractError('legacy_board_service_unavailable')
        claims = request['claims']
        response = {k:claims[k] for k in ('hubId','profileId','authorityId','scope','replySubject')}
        response.update(purpose='agentmux-legacy-board-response-v1',serviceIdentityRef=strict_loads(self._identity),
            serviceInstanceId=self._instance,signingKeyRef=strict_loads(self._issuer),requestDigest=_digest(raw),
            operationId=original['operationId'],payloadDigest=original['payloadDigest'],
            resourceRef=envelope['payload']['resourceRef'],receiptRef=None if group is None else owner._journal._ref(group['latest']),
            result=result,issuedAt=_stamp(datetime.now(timezone.utc)),validUntil=_stamp(end))
        packet = {'schemaVersion':'1.0.0','claims':response,'signature':sign_claims(response,self._seed)}
        encoded = canonical_bytes(packet)
        _parse(encoded,'federation-board-service-response',65536)
        return encoded

    async def handle(self, raw, *, received_reply_subject):
        if self._closed or len(self._workers)>=32:
            raise ContractError('legacy_board_service_unavailable')
        task = asyncio.create_task(self._execute(raw,received_reply_subject))
        self._workers.add(task)
        def finished(original):
            self._workers.discard(original)
            if not original.cancelled():original.exception()
        task.add_done_callback(finished)
        try:
            await asyncio.wait({task})
            return task.result()
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ContractError('legacy_board_service_unavailable') from None

    async def _receive(self, message):
        if self._closed or not isinstance(message.reply,str) or not _INBOX.fullmatch(message.reply):
            return
        async def deliver():
            try:
                raw = await self.handle(message.data,received_reply_subject=message.reply)
                if not self._closed:
                    await self._connection.publish(message.reply,raw)
            except Exception:
                return
        task = asyncio.create_task(deliver())
        self._callbacks.add(task)
        task.add_done_callback(self._callbacks.discard)
        await asyncio.wait({task})
        task.result()

    async def start(self):
        if self._closed or self._starting is not None or getattr(self._connection,'max_payload',0)<98304:
            raise ContractError('legacy_board_service_unavailable')
        async def subscribe():
            self._subscription = await self._connection.subscribe_owned(self._subscriptions,self.subject,cb=self._receive,
                pending_msgs_limit=32,pending_bytes_limit=32*98304)
            await self._connection.flush()
        self._starting = asyncio.create_task(subscribe())
        try:
            await asyncio.wait({self._starting})
            self._starting.result()
            if self._closed:raise ContractError('legacy_board_service_unavailable')
        except asyncio.CancelledError:
            self._closed=True
            raise
        except Exception:
            self._closed=True
            raise ContractError('legacy_board_service_unavailable') from None

    async def _cleanup(self):
        if self._starting is not None:
            await asyncio.gather(asyncio.shield(self._starting),return_exceptions=True)
        tasks = _subscription_tasks(self._subscription)
        connection=getattr(self._subscription,'_conn',None)
        transport_tasks = (getattr(connection,'_reading_task',None),getattr(connection,'_flusher_task',None))
        def closed_locally():
            if connection is not self._connection or not connection.is_closed or connection._subs:
                return False
            loops=(getattr(connection,name,None) for name in
                ('_reading_task','_flusher_task','_ping_interval_task','_reconnection_task'))
            if any(task is not None and (not isinstance(task,asyncio.Task) or not task.done()) for task in loops):
                return False
            transport=getattr(connection,'_transport',None)
            if transport is None:
                return True
            from hub.nats_transport import PairedTCPTransport
            if not isinstance(transport,PairedTCPTransport) or transport.current_close_task is None:
                return False
            closes=(transport.current_close_task,transport.prior_close_task)
            return all(task is None or (task.done() and not task.cancelled() and task.exception() is None)
                       for task in closes)

        def check_confirmation_path():
            if connection is self._connection and not closed_locally():
                current=(getattr(connection,'_reading_task',None),getattr(connection,'_flusher_task',None))
                if (not connection.is_connected or current!=transport_tasks
                        or any(not isinstance(task,asyncio.Task) or task.done() for task in current)):
                    raise ContractError('legacy_board_cleanup_incomplete')
        try:
            check_confirmation_path()
            if closed_locally():
                # This is local disposal after the original transport closed,
                # not a remote unsubscribe acknowledgement.
                self._subscription._closed=True
            if self._subscription is not None and not getattr(self._subscription,'_closed',False):
                if connection is self._connection:
                    subscription=self._subscription
                    try:
                        # Follow the pinned drain sequence, retaining the entry
                        # until the live PING/PONG path confirms this UNSUB.
                        await connection._send_unsubscribe(subscription._id)
                        check_confirmation_path()
                        await connection.flush(timeout=5)
                        check_confirmation_path()
                        if subscription._pending_queue:
                            await subscription._pending_queue.join()
                        check_confirmation_path()
                        subscription._stop_processing()
                        if connection._subs.get(subscription._id) is subscription:
                            connection._remove_sub(subscription._id)
                    finally:
                        subscription._closed=True
                else:
                    await self._subscription.drain()
            check_confirmation_path()
        finally:
            # A failed drain may mark the subscription closed before joining it.
            for task in tasks:
                if not task.done():task.cancel()
            if tasks:
                await asyncio.gather(*tasks,return_exceptions=True)
            if self._callbacks:
                await asyncio.gather(*tuple(self._callbacks),return_exceptions=True)
            if self._workers:
                await asyncio.gather(*tuple(self._workers),return_exceptions=True)
            check_confirmation_path()
            subscription=self._subscription
            connection=getattr(subscription,'_conn',None)
            sid=getattr(subscription,'_id',None)
            if (connection is self._connection and getattr(subscription,'_closed',False)
                    and connection._subs.get(sid) is subscription):
                # A failed NATS drain marks closed without removing its entry.
                # Confirm the exact UNSUB before releasing the local handle.
                await connection._send_unsubscribe(sid)
                check_confirmation_path()
                await connection.flush(timeout=5)
                check_confirmation_path()
                if connection._subs.get(sid) is subscription:
                    connection._remove_sub(sid)
            await self._subscriptions.close()

    async def close(self, *, timeout=5):
        if type(timeout) not in (int,float) or not 0<timeout<=10:
            raise ContractError('legacy_board_cleanup_invalid')
        self._closed = True
        failed = self._closing is not None and self._closing.done() and (
            self._closing.cancelled() or self._closing.exception() is not None)
        if self._closing is None or failed:
            self._closing = asyncio.create_task(self._cleanup())
        try:
            _,pending = await asyncio.wait({self._closing},timeout=timeout)
            if pending:raise TimeoutError()
            self._closing.result()
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ContractError('legacy_board_cleanup_incomplete') from None


@dataclass(frozen=True,repr=False)
class LegacyBoardRecovery:
    original: bytes
    request: bytes
    caller: str

    def __repr__(self):
        return '<LegacyBoardRecovery private>'

    def recovery_bytes(self):
        return canonical_bytes({'originalEnvelopeBytes':base64.b64encode(self.original).decode(),
            'authenticatedRequestBytes':base64.b64encode(self.request).decode(),'authenticatedCaller':self.caller})

    @classmethod
    def from_bytes(cls, raw):
        if type(raw) is not bytes or len(raw)>180224:
            raise ContractError('legacy_board_recovery_invalid')
        value=strict_loads(raw)
        if (canonical_bytes(value)!=raw or type(value) is not dict
                or set(value)!={'originalEnvelopeBytes','authenticatedRequestBytes','authenticatedCaller'}
                or type(value['authenticatedCaller']) is not str or not value['authenticatedCaller']):
            raise ContractError('legacy_board_recovery_invalid')
        original=base64.b64decode(value['originalEnvelopeBytes'],validate=True)
        request=base64.b64decode(value['authenticatedRequestBytes'],validate=True)
        _parse(original,'message-envelope',65536)
        if len(request)>65536 or type(strict_loads(request)) is not dict:
            raise ContractError('legacy_board_recovery_invalid')
        return cls(original,request,value['authenticatedCaller'])


class LegacyBoardCommandClient:
    """The five legacy verbs, backed exclusively by the selected owner route."""
    def __init__(self, hub, connection, *, ingresses, lifetime, service_identity_ref, service_instance_id, signing_key_ref,
                 retain_recovery):
        if (type(ingresses) is not tuple or not ingresses or len(ingresses)>64
                or any(type(i) is not LegacyBoardIngress or i._hub is not hub for i in ingresses)
                or len({i._enrollment.authenticated_caller for i in ingresses})!=len(ingresses)
                or len({id(i._ingress._reader) for i in ingresses})!=1
                or any(r.recovery_grant_ref is None for i in ingresses for r in i._enrollment.routes)
                or not isinstance(lifetime,FederationSession)
                or not callable(getattr(connection,"subscribe_owned",None))
                or not callable(retain_recovery)
                or type(service_instance_id) is not str or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}',service_instance_id) is None
                or not _valid_ref(service_identity_ref) or not _valid_ref(signing_key_ref)):
            raise ContractError('legacy_board_client_configuration')
        self._hub,self._connection,self._ingresses,self._lifetime = hub,connection,ingresses,lifetime
        self._identity,self._instance,self._issuer = (strict_loads(canonical_bytes(service_identity_ref)),service_instance_id,
            strict_loads(canonical_bytes(signing_key_ref)))
        self._retain_recovery = retain_recovery
        self._federation = self._federation_session = None
        self._pending,self._workers = {},set()
        self._reply_sessions = set()
        self._closing = None
        self._closed = False
        self._admission_lock = asyncio.Lock()

    def __repr__(self):
        return '<LegacyBoardCommandClient private>'

    def bind(self, federation):
        if federation.hub is not self._hub or (self._federation is not None and federation is not self._federation):
            raise HubError('qualified board route is unavailable')
        self._federation=federation

    def check(self, federation=None):
        if federation is not None:
            self.bind(federation)
        self._lifetime.check_open()
        if self._federation is not None:
            current=self._federation.session
            if not isinstance(current,FederationSession):
                raise HubError('qualified board route is unavailable')
            if self._federation_session is None:
                self._federation_session=current
            if current is not self._federation_session:
                raise HubError('qualified board route is unavailable')
            self._federation_session.check_open()
        if self._closed or not self._connection.is_connected:
            raise HubError('qualified board route is unavailable')

    def pending_recovery(self):
        return tuple(self._pending.values())

    def restore_recovery(self, recovery):
        if type(recovery) is bytes:
            recovery=LegacyBoardRecovery.from_bytes(recovery)
        if type(recovery) is not LegacyBoardRecovery:
            raise HubError('qualified board recovery is unavailable')
        key = (recovery.caller,hashlib.sha256(recovery.request).hexdigest())
        prior = self._pending.get(key)
        if (prior is not None and prior!=recovery) or (prior is None and len(self._pending)>=32):
            raise HubError('qualified board recovery is unavailable')
        if prior is None:self._pending[key] = recovery

    async def _send(self, bridge, inner):
        self.check()
        enrollment = bridge._enrollment
        envelope = _parse(inner,'message-envelope',65536)
        now = datetime.now(timezone.utc)
        claims = {'purpose':'agentmux-legacy-board-request-v1','hubId':enrollment.hub_id,
            'profileId':enrollment.profile_id,'authorityId':enrollment.authority_id,'scope':envelope['operation']['scope'],
            'transportRef':strict_loads(enrollment.transport_ref),'envelopeBytes':base64.b64encode(inner).decode(),
            'replySubject':self._connection.new_inbox(),'issuedAt':_stamp(now),
            'validUntil':_stamp(min(now+timedelta(seconds=5),_time(envelope['operation']['deadline'])))}
        raw = canonical_bytes({'schemaVersion':'1.0.0','claims':claims,'signature':sign_claims(claims,enrollment.signing_seed)})
        _parse(raw,'federation-board-service-request',98304)
        session = FederationSession()
        self._reply_sessions.add(session)
        try:
            subscription = await session.acquire(self._connection.subscribe_owned(session,claims['replySubject']),session.own_subscription)
            self.check()
            await self._connection.flush()
            await self._connection.publish(command_subject(enrollment.hub_id,claims['scope']),raw,reply=claims['replySubject'])
            response = _parse((await subscription.next_msg(timeout=5)).data,'federation-board-service-response',65536)
        finally:
            await session.close()
            self._reply_sessions.discard(session)
        self.check()
        value = response['claims']
        original = envelope['payload']['input'] if envelope['contractId']=='capability-outcome-query' else envelope['operation']
        if (any(value[k]!=claims[k] for k in ('hubId','profileId','authorityId','scope','replySubject'))
                or value['requestDigest']!=_digest(raw) or value['serviceIdentityRef']!=self._identity
                or value['serviceInstanceId']!=self._instance or value['signingKeyRef']!=self._issuer
                or value['resourceRef']!=envelope['payload']['resourceRef']
                or any(value[k]!=original[k] for k in ('operationId','payloadDigest'))
                or not _time(claims['issuedAt'])<=_time(value['issuedAt'])<=datetime.now(timezone.utc)<_time(value['validUntil'])
                or _time(value['validUntil'])>_time(claims['validUntil'])):
            raise ContractError('legacy_board_reply_refused')
        snapshot = await bridge._ingress._reader.current()
        index = _indexes(strict_loads(snapshot.record)['state'],enrollment.hub_id)
        issuer = index['issuers'].get(_key(self._issuer))
        identity = index['identities'].get(_key(self._identity))
        self.check()
        now = datetime.now(timezone.utc)
        if not _time(value['issuedAt'])<=now<_time(value['validUntil']):
            raise ContractError('legacy_board_reply_refused')
        if (issuer is None or identity is None or not _active(issuer,now) or not _active(identity,now)
                or issuer['identityRef']!=self._identity or identity['kind']!='service' or issuer['instanceId']!=self._instance):
            raise ContractError('legacy_board_reply_refused')
        verify_possession(value,response['signature'],issuer['publicKey'])
        decision = evaluate_snapshot(snapshot,inner,audience={'hubId':enrollment.hub_id,
            'serviceId':'outcome-owner' if envelope['contractId']=='capability-outcome-query' else 'storage-owner'},now=now)
        if decision.outcome!='allowed':
            raise ContractError('legacy_board_reply_refused')
        return value['result']

    async def _prepare_command(self, command, args, caller):
        self.check()
        proof = self._hub.current_authenticated_caller()
        authenticated = self._hub._authenticated_callers.get(proof)
        request = strict_loads(authenticated.request)
        if (request.get('verb')!='fed_board_'+command or request.get('args',{})!=args or authenticated.caller!=caller):
            raise HubError('qualified board request does not match authentication')
        matches = [i for i in self._ingresses if i._enrollment.authenticated_caller==authenticated.authenticated_caller]
        if len(matches)!=1:
            raise HubError('qualified board enrollment is unavailable')
        bridge = matches[0]
        key = (authenticated.authenticated_caller,authenticated.request_digest)
        prior = self._pending.get(key)
        if prior is None and len(self._pending)>=32:
            raise HubError('qualified board recovery capacity is exhausted')
        cancel = {'id':'board-cancel-'+secrets.token_hex(24),'ownerHubId':bridge._enrollment.hub_id,'revision':0}
        if prior is None:
            admitted = await bridge.admit_local(proof,operation_id='legacy-board-'+secrets.token_hex(24),cancellation_ref=cancel)
        else:
            admitted = await bridge.admit_recovery(proof,prior.original,operation_id='legacy-query-'+secrets.token_hex(24),
                cancellation_ref=cancel)
        if admitted.envelope is None or admitted.decision.outcome!='allowed':
            raise HubError('qualified board permission was refused')
        if prior is None:
            self._pending[key] = LegacyBoardRecovery(admitted.envelope,authenticated.request,authenticated.authenticated_caller)
            # The protected host saves these immutable bytes before publication.
            await self._retain_recovery(self._pending[key].recovery_bytes())
        return bridge,admitted.envelope,key,self._pending[key]

    async def _command(self, command, args, caller):
        try:
            async with self._admission_lock:
                bridge,inner,key,original = await self._prepare_command(command,args,caller)
            result = await self._send(bridge,inner)
            if result is None:
                raise HubError('qualified board outcome is unavailable')
            if self._pending.get(key) is original:
                self._pending.pop(key)
            return result
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HubError('qualified board outcome is unconfirmed; original recovery is retained') from None

    async def _owned(self, command, args, caller):
        self.check()
        if len(self._workers)>=32:
            raise HubError('qualified board request capacity is exhausted')
        worker = asyncio.current_task()
        self._workers.add(worker)
        try:
            return await self._command(command,args,caller)
        finally:
            self._workers.discard(worker)

    async def add(self,args,caller):return await self._owned('add',args,caller)
    async def move(self,args,caller):return await self._owned('move',args,caller)
    async def assign(self,args,caller):return await self._owned('assign',args,caller)
    async def comment(self,args,caller):return await self._owned('comment',args,caller)
    async def claim(self,args,caller):return await self._owned('claim',args,caller)

    async def close(self, *, timeout=5):
        if type(timeout) not in (int,float) or not 0<timeout<=10:
            raise HubError('qualified board cleanup timeout is invalid')
        self._closed=True
        async def cleanup():
            if self._workers:
                await asyncio.gather(*tuple(self._workers),return_exceptions=True)
            for session in tuple(self._reply_sessions):
                await session.close()
                self._reply_sessions.discard(session)
        failed = self._closing is not None and self._closing.done() and (
            self._closing.cancelled() or self._closing.exception() is not None)
        if self._closing is None or failed:
            self._closing=asyncio.create_task(cleanup())
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        try:
            _,pending = await asyncio.wait({self._closing},timeout=timeout)
            if pending:raise TimeoutError()
            self._closing.result()
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HubError('qualified board cleanup is incomplete') from None
