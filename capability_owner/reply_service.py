"""Signed, request-bound capability replies using current retained enrollment."""
import asyncio
import base64
import hashlib
import re
from datetime import datetime, timedelta, timezone

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key
from identity.ingress import verify_possession
from identity.capability_service import evaluate_capability_service_request
from identity.capability_routes import CAPABILITY_DESTINATIONS
from hub.fed.session import FederationSession
from .receiver import CapabilityReceiver

REQUEST_LIMIT = 98304
ENVELOPE_LIMIT = RESPONSE_LIMIT = 65536
_INBOX = re.compile(r'_INBOX\.[A-Za-z0-9_-]{16,128}(?:\.[A-Za-z0-9_-]{1,128})?\Z')
_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _time(value):
    return datetime.fromisoformat(value)


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _parse(raw, schema, limit):
    if type(raw) is not bytes or len(raw) > limit:
        raise ContractError('capability_service_frame_invalid')
    value = strict_loads(raw)
    validate(schema, value)
    if canonical_bytes(value) != raw:
        raise ContractError('capability_service_frame_invalid')
    return value


def _envelope(claims):
    try:
        raw = base64.b64decode(claims['envelopeBytes'], validate=True)
        if len(raw) > ENVELOPE_LIMIT or base64.b64encode(raw).decode('ascii') != claims['envelopeBytes']:
            raise ValueError()
        return raw, strict_loads(raw)
    except (ValueError, TypeError):
        raise ContractError('capability_service_frame_invalid') from None


def _reference(value):
    if (type(value) is not dict or set(value) != {'id', 'ownerHubId', 'revision'}
            or any(not isinstance(value[k], str) or not _ID.fullmatch(value[k]) for k in ('id', 'ownerHubId'))
            or type(value['revision']) is not int or not 0 <= value['revision'] <= 9007199254740991):
        raise ContractError('capability_service_configuration')
    return strict_loads(canonical_bytes(value))


class CapabilityReplyService:
    def __init__(self, authority, *, resources, hub_id, profile_id, authority_id, service_id,
                 service_identity_ref, service_instance_id, signing_key_ref, signing_seed,
                 request_signing_key_ref, connection=None, board_routes=(), message_bridge=None,
                 knowledge_bridge=None, peer_control=None, code_bridge=None, work_bridge=None):
        if (not isinstance(authority, LedgerAuthorityReader)
                or not all(isinstance(v, str) and _ID.fullmatch(v)
                           for v in (hub_id, profile_id, authority_id, service_id, service_instance_id))
                or service_id not in CAPABILITY_DESTINATIONS.values()
                or type(signing_seed) is not bytes or len(signing_seed) != 32):
            raise ContractError('capability_service_configuration')
        resources = tuple(resources)
        if not resources or len(resources) > 256 or len({r.binding.scope for r in resources}) != 1:
            raise ContractError('capability_service_configuration')
        self._reader = authority
        self._receiver = CapabilityReceiver(authority, hub_id=hub_id, resources=resources,
            board_routes=board_routes,receiving_connection=connection)
        self._hub, self._profile, self._authority_id, self._service = hub_id, profile_id, authority_id, service_id
        self._identity = _reference(service_identity_ref)
        self._issuer = _reference(signing_key_ref)
        self._request_issuer = _reference(request_signing_key_ref)
        self._instance, self._seed = service_instance_id, signing_seed
        self._scope = resources[0].binding.scope
        if message_bridge is not None:
            from .message_bridge_service import MessageBridgeService
            if (type(message_bridge) is not MessageBridgeService or service_id != 'storage-owner'
                    or message_bridge._authority is not authority
                    or any(not any(resource is owned for owned in resources)
                        for resource in message_bridge._resources.values())
                    or message_bridge._identity != canonical_bytes(self._identity)
                    or message_bridge._issuer != canonical_bytes(self._issuer)
                    or message_bridge._instance != self._instance
                    or message_bridge._seed != self._seed):
                raise ContractError('capability_service_configuration')
        self._message_bridge = message_bridge
        if knowledge_bridge is not None:
            from .knowledge_bridge_service import KnowledgeBridgeService
            if (type(knowledge_bridge) is not KnowledgeBridgeService or service_id != 'storage-owner'
                    or knowledge_bridge._authority is not authority
                    or any(self._receiver._resources.get(resource.binding.entity_id) is not resource
                        for resource in knowledge_bridge._resources.values())
                    or knowledge_bridge._identity != canonical_bytes(self._identity)
                    or knowledge_bridge._issuer != canonical_bytes(self._issuer)
                    or knowledge_bridge._instance != self._instance or knowledge_bridge._seed != self._seed):
                raise ContractError('capability_service_configuration')
        self._knowledge_bridge = knowledge_bridge
        if code_bridge is not None:
            from .code_bridge_service import CodeBridgeService
            if (type(code_bridge) is not CodeBridgeService or service_id != 'storage-owner'
                    or code_bridge._authority is not authority
                    or any(self._receiver._resources.get(resource.binding.entity_id) is not resource
                        for resource in code_bridge._resources.values())
                    or code_bridge._identity != canonical_bytes(self._identity)
                    or code_bridge._issuer != canonical_bytes(self._issuer)
                    or code_bridge._instance != self._instance or code_bridge._seed != self._seed):
                raise ContractError('capability_service_configuration')
        self._code_bridge = code_bridge
        if work_bridge is not None:
            from .work_bridge_service import WorkBridgeService
            if (type(work_bridge) is not WorkBridgeService or service_id != 'storage-owner'
                    or work_bridge._authority is not authority
                    or any(self._receiver._resources.get(resource.binding.entity_id) is not resource
                        for resource in work_bridge._resources.values())
                    or work_bridge._identity != canonical_bytes(self._identity)
                    or work_bridge._issuer != canonical_bytes(self._issuer)
                    or work_bridge._instance != self._instance or work_bridge._seed != self._seed):
                raise ContractError('capability_service_configuration')
        self._work_bridge = work_bridge
        # Fixed lifecycle batches need all participants admitted before any can
        # finish. This bound comes from attached owners, never request metadata.
        from .work_lifecycle import WorkLifecycleOwner
        lifecycle_sizes = (() if work_bridge is None else tuple(
            len(owner._resources) for resource in work_bridge._resources.values()
            if type(owner := getattr(resource, '_lifecycle_owner', None)) is WorkLifecycleOwner))
        self._lifecycle_capacity = max((2 * size + 32 for size in lifecycle_sizes), default=32)
        if peer_control is not None:
            from .peer_control_service import PeerControlCommandService
            from .knowledge import KnowledgeStorageResource
            from .work import WorkStorageResource
            if (type(peer_control) is not PeerControlCommandService or service_id != 'storage-owner'
                    or peer_control._owner._authority is not authority
                    or peer_control._identity != canonical_bytes(self._identity)
                    or peer_control._issuer != canonical_bytes(self._issuer)
                    or peer_control._instance != self._instance or peer_control._seed != self._seed):
                raise ContractError('capability_service_configuration')
            for publisher in peer_control._owner._publishers.values():
                reference = publisher._pin['resourceRef']
                resource = self._receiver._resources.get(reference['id'])
                if (type(resource) not in (KnowledgeStorageResource, WorkStorageResource)
                        or reference['ownerHubId'] != resource.binding.hub_id
                        or publisher._pin['scope'] != strict_loads(resource.binding.scope)
                        or getattr(resource._owner, '_source', None) is not peer_control._owner._source):
                    raise ContractError('capability_service_configuration')
        self._peer_control = peer_control
        self._request_limit = (REQUEST_LIMIT
            if message_bridge is None and knowledge_bridge is None and code_bridge is None
                and work_bridge is None else 1048576)
        scope = strict_loads(self._scope)
        self._subject = '.'.join(('amx', 'v1', 'h', hub_id, 'o', scope['organizationId'],
            'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_', 'capability', service_id, 'command'))
        self._connection = connection
        self._active, self._callbacks = set(), set()
        self._admissions = set()
        self._policy_paused = False
        self._closed = False
        self._subscribe_task = self._subscription = self._cleanup_task = None
        self._lock = asyncio.Lock()
        self._subscriptions = FederationSession()

    def __repr__(self):
        return '<CapabilityReplyService private>'

    @property
    def subject(self):
        return self._subject

    async def _admit(self, request, reply_subject):
        claims = request['claims']
        if (claims['replySubject'] != reply_subject or not _INBOX.fullmatch(reply_subject)
                or (claims['hubId'], claims['profileId'], claims['authorityId'], claims['serviceId'])
                    != (self._hub, self._profile, self._authority_id, self._service)
                or claims['signingKeyRef'] != self._request_issuer
                or canonical_bytes(claims['scope']) != self._scope):
            raise ContractError('capability_service_refused')
        snapshot = await self._reader.current()
        now = datetime.now(timezone.utc)
        decision = evaluate_capability_service_request(snapshot, canonical_bytes(request),
            service_id=self._service, now=now)
        self._receiver.check_service_request(snapshot, claims)
        end = decision.valid_until
        record = strict_loads(snapshot.record)
        state = record['state']
        if (record['ownerHubId'], record['entityId'], state['profileId']) != (
                self._hub, self._authority_id, self._profile):
            raise ContractError('capability_service_refused')
        index = _indexes(state, self._hub)
        def current(collection, reference):
            item = index[collection].get(_key(reference))
            if item is None or not _active(item, now):
                raise ContractError('capability_service_refused')
            return item
        request_issuer = current('issuers', self._request_issuer)
        request_identity = current('identities', request_issuer['identityRef'])
        if request_identity['kind'] != 'service':
            raise ContractError('capability_service_refused')
        verify_possession(claims, request['signature'], request_issuer['publicKey'])
        signer = current('issuers', self._issuer)
        identity = current('identities', self._identity)
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')
        if (identity['kind'] != 'service' or signer['identityRef'] != self._identity
                or signer['instanceId'] != self._instance or signer['publicKey'] != public):
            raise ContractError('capability_service_refused')
        # Service signing authority can end before the domain permission does.
        for timed in (request_issuer, request_identity, signer, identity):
            if 'expiresAt' in timed:
                end = min(end, _time(timed['expiresAt']))
        if end <= now:
            raise ContractError('capability_service_expired')
        return now, end, strict_loads(decision.authority_ref)

    def _lifecycle_route(self, raw):
        """Choose bounded scheduling only; the endpoint still authenticates it."""
        if self._work_bridge is None or type(raw) is not bytes or len(raw) > self._request_limit:
            return False
        try:
            from .work_lifecycle import LIFECYCLE_COMMANDS, WorkLifecycleOwner
            packet = strict_loads(raw)
            claims = packet['claims']
            resource = self._work_bridge._resources.get(claims['payload']['resourceRef']['id'])
            return (claims.get('purpose') == 'agentmux-client-possession-v1'
                and claims.get('contractId') in LIFECYCLE_COMMANDS
                and resource is not None
                and type(getattr(resource, '_lifecycle_owner', None)) is WorkLifecycleOwner)
        except (ContractError, KeyError, TypeError, AttributeError):
            return False

    async def handle(self, request_bytes, *, received_reply_subject):
        limit = self._lifecycle_capacity if self._lifecycle_route(request_bytes) else 32
        if self._closed or self._policy_paused or len(self._active) >= limit:
            raise ContractError('capability_service_unavailable')
        task = asyncio.current_task()
        completion = asyncio.get_running_loop().create_future()
        self._admissions.add(completion)
        self._active.add(task)
        try:
            async with asyncio.timeout(5):
                if (self._message_bridge is not None or self._knowledge_bridge is not None
                        or self._code_bridge is not None or self._work_bridge is not None
                        or self._peer_control is not None):
                    # Only the separate closed possession protocol can reach
                    # the legacy bridge. Native admission remains unchanged.
                    if type(request_bytes) is bytes and len(request_bytes) <= self._request_limit:
                        packet = strict_loads(request_bytes)
                        if (type(packet) is dict and type(packet.get('claims')) is dict
                                and packet['claims'].get('purpose') == 'agentmux-client-possession-v1'):
                            from identity.authority import MESSAGE_COMMANDS, KNOWLEDGE_COMMANDS, CODE_COMMANDS, WORK_COMMANDS, PEER_CONTROL_COMMANDS
                            contract = packet['claims'].get('contractId')
                            if contract in PEER_CONTROL_COMMANDS and self._peer_control is not None:
                                return await self._peer_control.handle(request_bytes,
                                    received_reply_subject=received_reply_subject)
                            if contract in KNOWLEDGE_COMMANDS and self._knowledge_bridge is not None:
                                return await self._knowledge_bridge.handle(request_bytes,
                                    received_reply_subject=received_reply_subject)
                            if contract in CODE_COMMANDS and self._code_bridge is not None:
                                return await self._code_bridge.handle(request_bytes,
                                    received_reply_subject=received_reply_subject)
                            if contract in WORK_COMMANDS and self._work_bridge is not None:
                                return await self._work_bridge.handle(request_bytes,
                                    received_reply_subject=received_reply_subject)
                            if contract in MESSAGE_COMMANDS and self._message_bridge is not None:
                                return await self._message_bridge.handle(request_bytes,
                                    received_reply_subject=received_reply_subject)
                            raise ContractError('capability_service_unavailable')
                request = _parse(request_bytes, 'capability-service-request', REQUEST_LIMIT)
                inner_raw, envelope = _envelope(request['claims'])
                await self._admit(request, received_reply_subject)
                if self._closed or task.cancelling():
                    raise asyncio.CancelledError()
                reply = await self._receiver.handle(inner_raw, service_request_bytes=request_bytes)
                now, end, authority_ref = await self._admit(request, received_reply_subject)
                await self._receiver.check_disclosure(inner_raw)
                now = datetime.now(timezone.utc)
                if end <= now:
                    raise ContractError('capability_service_expired')
                if self._closed or task.cancelling():
                    raise asyncio.CancelledError()
                wanted = request['claims']
                self._receiver.check_current(wanted['resourceRef'])
                if (reply.contract_id != wanted['replyContractId'] or reply.operation_id != wanted['operationId']
                        or reply.request_digest != payload_digest(envelope)):
                    raise ContractError('capability_service_refused')
                claims = {k: wanted[k] for k in ('requestId', 'profileId', 'hubId', 'authorityId', 'owner',
                    'serviceId', 'requestContractId', 'replyContractId', 'operationId', 'resourceRef', 'scope', 'replySubject')}
                claims.update(purpose='agentmux-capability-service-response-v1',
                    serviceIdentityRef=self._identity, serviceInstanceId=self._instance,
                    requestDigest=_digest(request_bytes), envelopeDigest=_digest(inner_raw),
                    signingKeyRef=self._issuer, authorityRef=authority_ref,
                    issuedAt=_stamp(now), validUntil=_stamp(end), payload=strict_loads(reply.payload))
                response = {'schemaVersion':'1.0.0', 'algorithm':'Ed25519',
                    'canonicalization':'RFC8785-JCS-UTF8', 'claims':claims, 'signature':sign_claims(claims, self._seed)}
                validate('capability-service-response', response)
                encoded = canonical_bytes(response)
                if len(encoded) > RESPONSE_LIMIT:
                    raise ContractError('capability_service_frame_invalid')
                return encoded
        except asyncio.CancelledError:
            raise
        except Exception:
            # No raw issuer, broker, path, request or receiver diagnostic escapes.
            raise ContractError('capability_service_unavailable') from None
        finally:
            self._active.discard(task)
            completion.set_result(None)
            self._admissions.discard(completion)

    def begin_policy_pause(self):
        if self._closed:
            raise ContractError('capability_service_unavailable')
        self._policy_paused = True

    async def join_policy_pause(self):
        if self._closed or not self._policy_paused:
            raise ContractError('capability_service_unavailable')
        # Method completions do not include an external caller's later work.
        # Actual broker callbacks are separately owned through reply publication.
        pending = {*self._admissions, *self._callbacks}
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        workers = set(self._receiver._workers)
        if self._message_bridge is not None:
            workers.update(self._message_bridge._workers)
        if self._knowledge_bridge is not None:
            workers.update(self._knowledge_bridge._workers)
        if self._code_bridge is not None:
            workers.update(self._code_bridge._workers)
        if self._work_bridge is not None:
            workers.update(self._work_bridge._workers)
        if self._peer_control is not None:
            workers.update(self._peer_control._workers)
            workers.update(self._peer_control._owner._workers)
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

    def end_policy_pause(self):
        if self._closed or not self._policy_paused:
            raise ContractError('capability_service_unavailable')
        self._policy_paused = False

    async def start(self):
        async with self._lock:
            if self._closed or self._subscribe_task is not None or self._connection is None:
                raise ContractError('capability_service_unavailable')
            # NATS has a negotiated frame limit. Never assume the wrapper fits
            # because the inner envelope did; do not change broker configuration.
            if getattr(self._connection, 'max_payload', 0) < self._request_limit:
                raise ContractError('capability_service_frame_limit')
            async def subscribe():
                owned = getattr(self._connection, 'subscribe_owned', None)
                if callable(owned):
                    return await owned(self._subscriptions, self._subject, cb=self._receive,
                        pending_msgs_limit=self._lifecycle_capacity, pending_bytes_limit=self._lifecycle_capacity * self._request_limit)
                return await self._connection.subscribe(self._subject,
                    cb=self._receive, pending_msgs_limit=self._lifecycle_capacity, pending_bytes_limit=self._lifecycle_capacity * self._request_limit)
            self._subscribe_task = asyncio.create_task(subscribe())
        try:
            self._subscription = await asyncio.shield(self._subscribe_task)
            if self._closed:
                raise ContractError('capability_service_unavailable')
            await asyncio.wait_for(self._connection.flush(), 3)
            if self._closed:
                raise ContractError('capability_service_unavailable')
        except asyncio.CancelledError:
            self._closed = True
            raise
        except Exception:
            self._closed = True
            raise ContractError('capability_service_unavailable') from None

    async def _receive(self, message):
        if self._closed or not isinstance(message.reply, str) or not _INBOX.fullmatch(message.reply):
            return
        # A serial delivery worker must release the first lifecycle participant
        # so the rest of its fixed batch can arrive. Other callbacks retain their
        # existing synchronous delivery behavior. All child work stays owned.
        lifecycle = self._lifecycle_route(message.data)
        if lifecycle and (self._policy_paused or len(self._callbacks) >= self._lifecycle_capacity):
            return
        task = asyncio.create_task(self._deliver(message))
        self._callbacks.add(task)
        task.add_done_callback(self._callbacks.discard)
        if lifecycle:
            return
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if asyncio.current_task().cancelling():
                raise
            # close() cancelled the owned request, not the delivery worker.

    async def _deliver(self, message):
        try:
            response = await self.handle(message.data, received_reply_subject=message.reply)
            claims = strict_loads(response)['claims']
            if not self._closed and datetime.now(timezone.utc) < _time(claims['validUntil']):
                await self._connection.publish(claims['replySubject'], response)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Silence is an unconfirmed outcome, never a fabricated rejection.
            return

    async def _cleanup(self):
        receiver_close = asyncio.create_task(self._receiver.close(timeout=None))
        bridge_close = (None if self._message_bridge is None else
            asyncio.create_task(self._message_bridge.close(timeout=None)))
        knowledge_close = (None if self._knowledge_bridge is None else
            asyncio.create_task(self._knowledge_bridge.close(timeout=None)))
        code_close = (None if self._code_bridge is None else
            asyncio.create_task(self._code_bridge.close(timeout=None)))
        work_close = (None if self._work_bridge is None else
            asyncio.create_task(self._work_bridge.close(timeout=None)))
        peer_close = (None if self._peer_control is None else
            asyncio.create_task(self._peer_control.close(timeout=None)))
        try:
            if self._subscribe_task is not None:
                await asyncio.wait({self._subscribe_task})
                if not self._subscribe_task.cancelled() and self._subscribe_task.exception() is None:
                    self._subscription = self._subscribe_task.result()
                # Failure remains on the original task. Allocation-time custody
                # still owns a subscription whose SUB send did not finish.
            if self._subscription is not None:
                await self._subscription.drain()
            if self._callbacks or self._active:
                await asyncio.gather(*tuple(self._callbacks | self._active), return_exceptions=True)
            await self._subscriptions.close()
        finally:
            await asyncio.gather(receiver_close, *(() if bridge_close is None else (bridge_close,)),
                *(() if knowledge_close is None else (knowledge_close,)),
                *(() if code_close is None else (code_close,)),
                *(() if work_close is None else (work_close,)),
                *(() if peer_close is None else (peer_close,)))

    async def close(self, *, timeout=5.0):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise ContractError('capability_cleanup_invalid')
        self._closed = True
        for task in tuple(self._callbacks | self._active):
            task.cancel()
        async with self._lock:
            failed = (self._cleanup_task is not None and self._cleanup_task.done()
                      and (self._cleanup_task.cancelled() or self._cleanup_task.exception() is not None))
            if self._cleanup_task is None or failed:
                self._cleanup_task = asyncio.create_task(self._cleanup())
        try:
            await asyncio.wait_for(asyncio.shield(self._cleanup_task), timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ContractError('capability_cleanup_incomplete') from None


def verify_capability_response(response_bytes, request_bytes, *, public_key, signing_key_ref,
                               service_identity_ref, service_instance_id, now):
    """Verify against trusted enrollment supplied by the host, never reply keys."""
    try:
        response = _parse(response_bytes, 'capability-service-response', RESPONSE_LIMIT)
        request = _parse(request_bytes, 'capability-service-request', REQUEST_LIMIT)
        claims, wanted = response['claims'], request['claims']
        inner_raw, _ = _envelope(wanted)
        verify_possession(claims, response['signature'], public_key)
        fields = ('requestId', 'profileId', 'hubId', 'authorityId', 'owner', 'serviceId',
                  'requestContractId', 'replyContractId', 'operationId', 'resourceRef', 'scope', 'replySubject')
        if (any(claims[k] != wanted[k] for k in fields)
                or claims['requestDigest'] != _digest(request_bytes)
                or claims['envelopeDigest'] != _digest(inner_raw)
                or claims['signingKeyRef'] != signing_key_ref or claims['serviceIdentityRef'] != service_identity_ref
                or claims['serviceInstanceId'] != service_instance_id
                or claims['authorityRef']['id'] != wanted['authorityId']
                or claims['authorityRef']['ownerHubId'] != wanted['hubId']
                or claims['authorityRef']['revision'] < 1
                or not _time(wanted['issuedAt']) <= _time(claims['issuedAt']) <= now < _time(claims['validUntil'])
                or _time(claims['validUntil']) > _time(wanted['validUntil'])
                or _time(wanted['validUntil']) - _time(wanted['issuedAt']) > timedelta(seconds=5)):
            raise ContractError('capability_reply_binding')
        return canonical_bytes(claims['payload'])
    except Exception:
        raise ContractError('capability_reply_unconfirmed') from None
