"""Authenticated task requests and signed replies on one enrolled transport."""
import asyncio
import base64
from datetime import datetime, timezone
import re

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import _active, _indexes, _key, evaluate_snapshot
from identity.ingress import EnrolledIngress, verify_possession
from .configuration import _callback_worker, _join_callback_worker
from .ledger import MAX_RECORD_BYTES, StoredRecord, validate_record
from .recovery import _binding
from .task import TaskOwner

REQUEST_LIMIT = 65536
ENCODED_RECORD_LIMIT = 4 * ((MAX_RECORD_BYTES + 2) // 3)
REPLY_METADATA_LIMIT = 8192
RESPONSE_LIMIT = ENCODED_RECORD_LIMIT + REPLY_METADATA_LIMIT
DELIVERY_SECONDS = 8
_INBOX = re.compile(r'_INBOX\.[A-Za-z0-9_-]{16,128}(?:\.[A-Za-z0-9_-]{1,128})?\Z')


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def task_source_pin(ledger, *, account_public_key, jetstream_domain):
    if (type(account_public_key) is not str or not re.fullmatch(r'A[A-Z2-7]{55}', account_public_key)
            or jetstream_domain is not None and (type(jetstream_domain) is not str
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', jetstream_domain))):
        raise ContractError('task_service_configuration')
    created = _stamp(ledger._identity.created)
    return {'streamCreated': created, 'bindingDigest': payload_digest({
        'binding': _binding(ledger._binding), 'accountPublicKey': account_public_key,
        'jetstreamDomain': jetstream_domain, 'stream': ledger._stream,
        'subject': ledger._subject, 'streamCreated': created})}


class TaskService:
    def __init__(self, owner, ingress, *, connection, service_identity_ref, service_instance_id,
                 signing_key_ref, signing_seed, requester_reply_prefix, account_public_key,
                 jetstream_domain=None):
        if (type(owner) is not TaskOwner or type(ingress) is not EnrolledIngress
                or ingress._reader is not owner._authority or type(signing_seed) is not bytes
                or len(signing_seed) != 32 or type(service_instance_id) is not str
                or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', service_instance_id)
                or type(requester_reply_prefix) is not str
                or not re.fullmatch(r'_INBOX\.[A-Za-z0-9_-]{16,128}', requester_reply_prefix)):
            raise ContractError('task_service_configuration')
        self.owner, self.ingress, self._connection = owner, ingress, connection
        self._identity, self._issuer = map(canonical_bytes, (service_identity_ref, signing_key_ref))
        self._instance, self._seed = service_instance_id, signing_seed
        self._reply_prefix = requester_reply_prefix + '.'
        self._source = task_source_pin(owner._ledger, account_public_key=account_public_key,
            jetstream_domain=jetstream_domain)
        binding = owner._ledger._binding
        scope = strict_loads(binding.scope)
        self.subject = '.'.join(('amx', 'v1', 'h', binding.hub_id, 'o', scope['organizationId'],
            'p', scope['projectId'] or '_', 'w', scope['workspaceId'] or '_', 'task', binding.entity_id, 'command'))
        self._active, self._requests = set(), set()
        self._closed = False
        self._host = None
        self._startup = self._subscribe_task = self._subscription = self._worker = self._closing = None
        self._drained = False
        self.done = asyncio.Event()

    def __repr__(self):
        return '<TaskService private>'

    @property
    def source_pin(self):
        return strict_loads(canonical_bytes(self._source))

    def check_health(self):
        if self._closed:
            raise ContractError('task_service_unavailable')
        if self._host is not None:
            self._host.check_health()

    async def handle(self, raw, *, received_reply_subject):
        self.check_health()
        if len(self._active) >= 32 or type(raw) is not bytes or len(raw) > REQUEST_LIMIT:
            raise ContractError('task_service_unavailable')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            async with asyncio.timeout(5):
                request = strict_loads(raw)
                validate('identity-ingress-request', request)
                claims = request['claims']
                if (canonical_bytes(request) != raw or claims['contractId'] not in ('task-inspect', 'task-reserve')
                        or claims.get('replySubject') != received_reply_subject
                        or type(received_reply_subject) is not str or not _INBOX.fullmatch(received_reply_subject)
                        or not received_reply_subject.startswith(self._reply_prefix)):
                    raise ContractError('task_service_request_invalid')
                references = self.owner.reservation_references(claims['operationId'])
                cancellation = {'id': 'cancel_' + references['delegationRef']['id'].split('_', 1)[1],
                    'ownerHubId': self.owner._ledger._binding.hub_id, 'revision': 1}
                prepared = None
                if claims['contractId'] == 'task-reserve':
                    await self.ingress.authorize_reservation_preparation(raw)
                    self.check_health()
                    prepared = await self.owner.prepare_reservation(raw, cancellation)
                admitted = await self.ingress.admit(raw, cancellation_ref=cancellation, reservation_context=prepared)
                self.check_health()
                if admitted.envelope is None or admitted.decision.outcome != 'allowed':
                    raise ContractError('task_access_refused')
                stored = await self.owner.handle(admitted.envelope, reservation_context=prepared)
                self.check_health()
                return await self._reply(raw, request, admitted.envelope, stored)
        finally:
            self._active.discard(task)

    async def _reply(self, raw, request, envelope, stored):
        self.owner._retained(stored)
        snapshot = await self.owner._authority.current()
        self.check_health()
        now = datetime.now(timezone.utc)
        binding = self.owner._ledger._binding
        decision = evaluate_snapshot(snapshot, envelope,
            audience={'hubId': binding.hub_id, 'serviceId': 'task-owner'}, now=now)
        if decision.outcome != 'allowed' or decision.valid_until is None:
            raise ContractError('task_access_refused')
        authority = strict_loads(snapshot.record)
        index = _indexes(authority['state'], binding.hub_id)
        signer = index['issuers'].get(_key(strict_loads(self._issuer)))
        identity = index['identities'].get(_key(strict_loads(self._identity)))
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')
        if (signer is None or not _active(signer, now) or signer['publicKey'] != public
                or signer['identityRef'] != strict_loads(self._identity) or signer['instanceId'] != self._instance
                or identity is None or identity['kind'] != 'service' or not _active(identity, now)):
            raise ContractError('task_service_signer_unavailable')
        end = min(decision.valid_until, datetime.fromisoformat(signer['expiresAt']),
            datetime.fromisoformat(request['claims']['expiresAt']))
        if not now < end:
            raise ContractError('task_service_signer_unavailable')
        record = strict_loads(stored.record)
        wanted = request['claims']
        claims = {'purpose': 'agentmux-task-response-v1', 'responseContractId': 'task-reply',
            'profileId': self.owner._authority._profile, 'hubId': binding.hub_id,
            'authorityId': self.owner._authority._entity, 'serviceIdentityRef': strict_loads(self._identity),
            'serviceInstanceId': self._instance, 'signingKeyRef': strict_loads(self._issuer),
            'requestContractId': wanted['contractId'], 'operationId': wanted['operationId'],
            'payloadDigest': payload_digest(wanted['payload']), 'requestDigest': payload_digest(request),
            'replySubject': wanted['replySubject'], 'outcome': 'committed' if wanted['contractId']=='task-reserve' else 'record',
            'taskRef': {'id': binding.entity_id, 'ownerHubId': binding.hub_id, 'revision': stored.sequence},
            'recordRef': {'id': record['recordId'], 'ownerHubId': binding.hub_id, 'revision': stored.sequence},
            'sourceRevision': stored.sequence, 'source': self.source_pin, 'recordBytes': '', 'replayed': stored.replayed,
            'authorityRef': strict_loads(decision.authority_ref), 'issuedAt': _stamp(now), 'validUntil': _stamp(end)}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519', 'canonicalization': 'RFC8785-JCS-UTF8',
            'claims': claims, 'signature': sign_claims(claims, self._seed)}
        if len(canonical_bytes(response)) > REPLY_METADATA_LIMIT or len(stored.record) > MAX_RECORD_BYTES:
            raise ContractError('task_service_reply_limit')
        claims['recordBytes'] = base64.b64encode(stored.record).decode()
        response['signature'] = sign_claims(claims, self._seed)
        validate('task-reply', response)
        result = canonical_bytes(response)
        if len(result) > RESPONSE_LIMIT:
            raise ContractError('task_service_reply_limit')
        return result

    async def _start(self):
        if self._closed or getattr(self._connection, 'max_payload', 0) < RESPONSE_LIMIT:
            raise ContractError('task_service_frame_limit')
        self._subscribe_task = asyncio.create_task(self._connection.subscribe(self.subject, cb=self._receive,
            pending_msgs_limit=32, pending_bytes_limit=32*REQUEST_LIMIT))
        self._subscription = await asyncio.shield(self._subscribe_task)
        self._worker = _callback_worker(self._subscription)
        if self._closed:
            raise ContractError('task_service_unavailable')
        await asyncio.wait_for(self._connection.flush(), 3)
        if self._closed:
            raise ContractError('task_service_unavailable')

    async def start(self):
        if self._startup is not None or self._closed:
            raise ContractError('task_service_unavailable')
        self._startup = asyncio.create_task(self._start())
        await asyncio.shield(self._startup)

    async def _receive(self, message):
        deadline = asyncio.get_running_loop().time() + DELIVERY_SECONDS
        if (self._closed or len(self._requests) >= 32 or type(message.reply) is not str
                or not _INBOX.fullmatch(message.reply) or not message.reply.startswith(self._reply_prefix)
                or type(message.data) is not bytes or len(message.data) > REQUEST_LIMIT):
            return
        task = asyncio.create_task(self._deliver(message.data, message.reply, deadline=deadline))
        self._requests.add(task)
        def finished(original):
            self._requests.discard(original)
            if not original.cancelled():
                original.exception()
        task.add_done_callback(finished)

    async def _deliver(self, raw, reply, *, deadline):
        try:
            if asyncio.get_running_loop().time() >= deadline:
                return
            async with asyncio.timeout_at(deadline):
                response = await self.handle(raw, received_reply_subject=reply)
                end = datetime.fromisoformat(strict_loads(response)['claims']['validUntil'])
                if not self._closed:
                    timeout = min(3, (end-datetime.now(timezone.utc)).total_seconds())
                    if timeout > 0:
                        async with asyncio.timeout(timeout):
                            await self._connection.publish(reply, response)
                            await self._connection.flush()
        except asyncio.CancelledError:
            raise
        except Exception:
            pass  # Silence preserves an unconfirmed outcome; never publish private errors.

    async def _close(self):
        if self._startup is not None and not self._startup.done():
            self._startup.cancel()
        if self._startup is not None:
            await asyncio.gather(self._startup, return_exceptions=True)
        if self._subscribe_task is not None:
            self._subscription = await asyncio.shield(self._subscribe_task)
            worker = _callback_worker(self._subscription)
            if self._worker is not None and worker is not self._worker:
                raise ContractError('task_service_cleanup_incomplete')
            self._worker = worker
        for task in tuple(self._active):
            task.cancel()
        if self._active:
            await asyncio.gather(*tuple(self._active), return_exceptions=True)
        if self._requests:
            await asyncio.gather(*tuple(self._requests), return_exceptions=True)
        if self._subscription is not None:
            if not self._drained:
                await self._subscription.drain()
                self._drained = True
            await _join_callback_worker(self._worker)
        self.done.set()

    async def close(self, *, timeout=3):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('task_service_cleanup_incomplete')
        self._closed = True
        if self.done.is_set():
            return
        if self._closing is None or (self._closing.done() and self._closing.exception() is not None):
            self._closing = asyncio.create_task(self._close())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('task_service_cleanup_incomplete')
        try:
            self._closing.result()
        except Exception:
            raise ContractError('task_service_cleanup_incomplete') from None


def verify_task_reply(raw, request_bytes, *, binding, source_pin, public_key, signing_key_ref,
                      service_identity_ref, service_instance_id, minimum_source_revision, now):
    """Use the caller's trusted enrollment, never keys or source pins from a reply."""
    try:
        if (type(raw) is not bytes or len(raw) > RESPONSE_LIMIT
                or type(request_bytes) is not bytes or len(request_bytes) > REQUEST_LIMIT):
            raise ValueError()
        response, request = strict_loads(raw), strict_loads(request_bytes)
        validate('task-reply', response)
        validate('identity-ingress-request', request)
        claims, wanted = response['claims'], request['claims']
        verify_possession(claims, response['signature'], public_key)
        metadata = {**response, 'claims': {**claims, 'recordBytes': ''}}
        if (canonical_bytes(response) != raw or canonical_bytes(request) != request_bytes
                or len(canonical_bytes(metadata)) > REPLY_METADATA_LIMIT or claims['source'] != source_pin
                or claims['signingKeyRef'] != signing_key_ref or claims['serviceIdentityRef'] != service_identity_ref
                or claims['serviceInstanceId'] != service_instance_id
                or any(claims[k] != wanted[k] for k in ('profileId', 'hubId', 'authorityId', 'operationId', 'replySubject'))
                or claims['requestContractId'] != wanted['contractId'] or claims['requestDigest'] != payload_digest(request)
                or claims['payloadDigest'] != payload_digest(wanted['payload'])
                or type(minimum_source_revision) is not int or minimum_source_revision < 0
                or claims['sourceRevision'] < minimum_source_revision
                or claims['taskRef'] != {'id': binding.entity_id, 'ownerHubId': binding.hub_id, 'revision': claims['sourceRevision']}
                or wanted['payload']['taskId'] != binding.entity_id or wanted['hubId'] != binding.hub_id
                or claims['authorityRef']['id'] != wanted['authorityId']
                or claims['authorityRef']['ownerHubId'] != binding.hub_id or claims['authorityRef']['revision'] < 1
                or not datetime.fromisoformat(wanted['issuedAt']) <= datetime.fromisoformat(claims['issuedAt']) <= now < datetime.fromisoformat(claims['validUntil'])
                or datetime.fromisoformat(claims['validUntil']) > datetime.fromisoformat(wanted['expiresAt'])):
            raise ValueError()
        record_raw = base64.b64decode(claims['recordBytes'], validate=True)
        if len(record_raw) > MAX_RECORD_BYTES or base64.b64encode(record_raw).decode() != claims['recordBytes']:
            raise ValueError()
        record = validate_record(record_raw, binding)
        if (canonical_bytes(record) != record_raw or record['entityVersion'] != claims['sourceRevision']
                or claims['recordRef'] != {'id': record['recordId'], 'ownerHubId': binding.hub_id, 'revision': claims['sourceRevision']}
                or claims['outcome'] != ('committed' if wanted['contractId']=='task-reserve' else 'record')
                or wanted['contractId']=='task-reserve' and (record['operation']['operationId'] != wanted['operationId']
                    or record['operation']['payloadDigest'] != claims['payloadDigest']
                    or record['outcome'] != 'committed' or record['state']['reservation'] != wanted['payload'])):
            raise ValueError()
        return StoredRecord(record_raw, claims['sourceRevision'], replayed=claims['replayed'])
    except Exception:
        raise ContractError('task_reply_unconfirmed') from None
