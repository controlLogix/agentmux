"""Signed recovery replies from the retained authority-switch owner."""
from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re

from nacl.signing import SigningKey
from agentmux_contracts import (ContractError, canonical_bytes, payload_digest,
                                sign_claims, strict_loads, validate)
from identity.authority import _active, _indexes, _key
from identity.ingress import EnrolledIngress, verify_possession
from .authority_switch import AuthoritySwitchOwner, VerifiedLegacyRecoveryPermit
from .ledger import StreamIdentity

REQUEST_LIMIT = RESPONSE_LIMIT = 65_536
_INBOX = re.compile(r'_INBOX\.[A-Za-z0-9_-]{16,128}(?:\.[A-Za-z0-9_-]{1,128})?\Z')


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _reference(value):
    if (type(value) is not dict or set(value) != {'id', 'ownerHubId', 'revision'}
            or value['revision'] < 0):
        raise ContractError('authority_switch_service_configuration')
    return canonical_bytes(value)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class VerifiedEnrolledRecovery:
    """Opaque result of one exact enrolled request and signed service reply."""
    _seal: object
    _request: bytes
    _response: bytes
    _valid_until: datetime

    def __repr__(self):
        return '<VerifiedEnrolledRecovery private>'


class AuthoritySwitchService:
    """Own the broker route while the owner keeps all ledger credentials."""
    def __init__(self, owner, ingress, *, connection, profile_id, authority_id,
                 service_identity_ref, service_instance_id, signing_key_ref,
                 signing_seed):
        binding = getattr(getattr(owner, '_ledger', None), '_binding', None)
        scope = {} if binding is None else strict_loads(binding.scope)
        if (type(owner) is not AuthoritySwitchOwner or type(ingress) is not EnrolledIngress
                or ingress._reader is not owner._authority
                or type(signing_seed) is not bytes or len(signing_seed) != 32
                or type(profile_id) is not str or type(authority_id) is not str
                or type(service_instance_id) is not str
                or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', service_instance_id)
                or scope.get('projectId') is not None or scope.get('workspaceId') is not None):
            raise ContractError('authority_switch_service_configuration')
        self.owner, self.ingress, self._connection = owner, ingress, connection
        self._profile, self._authority_id = profile_id, authority_id
        self._identity, self._issuer = map(_reference,
            (service_identity_ref, signing_key_ref))
        self._instance, self._seed = service_instance_id, signing_seed
        self.subject = '.'.join(('amx', 'v1', 'h', binding.hub_id, 'o',
            scope['organizationId'], 'authority-switch', binding.entity_id, 'command'))
        self._active, self._callbacks = set(), set()
        self._closed = False
        self._subscribe_task = self._subscription = self._cleanup_task = None

    def __repr__(self):
        return '<AuthoritySwitchService private>'

    async def _reply_authority(self, envelope, request, permit):
        receipt = permit.receipt
        stream = receipt['stream']
        await self.owner.validate_recovery_permit(permit, source=receipt['source'],
            switch_id=receipt['switchRef']['id'],
            stream_identity=StreamIdentity(datetime.fromisoformat(stream['created']),
                                           stream['minimumSequence']))
        decision = await self.owner._authorize(canonical_bytes(envelope), envelope)
        snapshot = await self.owner._authority.current()
        now = datetime.now(timezone.utc)
        record = strict_loads(snapshot.record)
        state = record['state']
        index = _indexes(state, record['ownerHubId'])

        def current(collection, raw):
            value = strict_loads(raw)
            item = index[collection].get(_key(value))
            if item is None or not _active(item, now):
                raise ContractError('authority_switch_service_refused')
            return item

        signer = current('issuers', self._issuer)
        identity = current('identities', self._identity)
        public = base64.urlsafe_b64encode(bytes(
            SigningKey(self._seed).verify_key)).decode().rstrip('=')
        if (record['entityId'] != self._authority_id or state['profileId'] != self._profile
                or identity['kind'] != 'service' or signer['identityRef'] != strict_loads(self._identity)
                or signer['instanceId'] != self._instance or signer['publicKey'] != public):
            raise ContractError('authority_switch_service_refused')
        end = min(decision.valid_until, datetime.fromisoformat(receipt['validUntil']),
                  datetime.fromisoformat(request['claims']['expiresAt']))
        for item in (signer, identity):
            if 'expiresAt' in item:
                end = min(end, datetime.fromisoformat(item['expiresAt']))
        if not now < end:
            raise ContractError('authority_switch_service_refused')
        operation = envelope['operation']
        claims = {'purpose': 'agentmux-authority-switch-recovery-response-v1',
            'profileId': self._profile, 'hubId': record['ownerHubId'],
            'authorityId': self._authority_id, 'serviceId': 'authority-switch-owner',
            'serviceIdentityRef': strict_loads(self._identity),
            'serviceInstanceId': self._instance,
            'signingKeyRef': strict_loads(self._issuer),
            'requestDigest': payload_digest(request), 'operation': operation,
            'payloadDigest': payload_digest(envelope['payload']),
            'replySubject': request['claims']['replySubject'],
            **{key: receipt[key] for key in ('decision', 'switchRef', 'recordDigest',
                                              'source', 'stream', 'authorityRef')},
            'grantRef': operation['grantRef'], 'issuedAt': _stamp(now),
            'validUntil': _stamp(end)}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
            'signature': sign_claims(claims, self._seed)}
        validate('authority-switch-recovery-response', response)
        raw = canonical_bytes(response)
        if len(raw) > RESPONSE_LIMIT:
            raise ContractError('authority_switch_service_reply_limit')
        return raw

    async def handle(self, raw, *, received_reply_subject):
        if (self._closed or len(self._active) >= 8 or type(raw) is not bytes
                or len(raw) > REQUEST_LIMIT):
            raise ContractError('authority_switch_service_unavailable')
        task = asyncio.current_task()
        self._active.add(task)
        try:
            async with asyncio.timeout(5):
                request = strict_loads(raw)
                validate('identity-ingress-request', request)
                claims = request['claims']
                if (canonical_bytes(request) != raw or claims['contractId'] != 'authority-switch'
                        or claims['payload'].get('action') != 'request-recovery'
                        or claims.get('replySubject') != received_reply_subject
                        or type(received_reply_subject) is not str
                        or not _INBOX.fullmatch(received_reply_subject)):
                    raise ContractError('authority_switch_service_request_invalid')
                cancellation = {'id': 'cancel_' + hashlib.sha256(raw).hexdigest()[:32],
                    'ownerHubId': claims['hubId'], 'revision': 1}
                admitted = await self.ingress.admit(raw, cancellation_ref=cancellation)
                if admitted.envelope is None or admitted.decision.outcome != 'allowed':
                    raise ContractError('authority_switch_service_refused')
                envelope = strict_loads(admitted.envelope)
                permit = await self.owner.handle(admitted.envelope)
                if type(permit) is not VerifiedLegacyRecoveryPermit:
                    raise ContractError('authority_switch_service_refused')
                # Re-admission checks current transport, membership and grant after
                # the owner read/append. The response deadline remains the commit cap.
                current = await self.ingress.admit(raw, cancellation_ref=cancellation)
                if current.envelope is None or current.decision.outcome != 'allowed':
                    raise ContractError('authority_switch_service_refused')
                return await self._reply_authority(envelope, request, permit)
        finally:
            self._active.discard(task)

    async def start(self):
        if (self._closed or self._subscribe_task is not None or self._connection is None
                or getattr(self._connection, 'max_payload', 0) < RESPONSE_LIMIT):
            raise ContractError('authority_switch_service_unavailable')
        self._subscribe_task = asyncio.create_task(self._connection.subscribe(
            self.subject, cb=self._receive, pending_msgs_limit=8,
            pending_bytes_limit=8 * REQUEST_LIMIT))
        self._subscription = await asyncio.shield(self._subscribe_task)
        await asyncio.wait_for(self._connection.flush(), 3)
        if self._closed:
            raise ContractError('authority_switch_service_unavailable')

    async def _receive(self, message):
        if self._closed or not isinstance(message.reply, str) or not _INBOX.fullmatch(message.reply):
            return
        task = asyncio.create_task(self._deliver(message))
        self._callbacks.add(task)
        task.add_done_callback(self._callbacks.discard)
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if asyncio.current_task().cancelling():
                raise

    async def _deliver(self, message):
        try:
            response = await self.handle(message.data,
                received_reply_subject=message.reply)
            if not self._closed:
                await self._connection.publish(message.reply, response)
        except asyncio.CancelledError:
            raise
        except Exception:
            return

    async def close(self, *, timeout=5):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise ContractError('authority_switch_service_cleanup_incomplete')
        self._closed = True
        for task in tuple(self._callbacks | self._active):
            task.cancel()
        async def cleanup():
            if self._subscribe_task is not None:
                await asyncio.gather(self._subscribe_task, return_exceptions=True)
            if self._subscription is not None:
                await self._subscription.drain()
            if self._callbacks or self._active:
                await asyncio.gather(*tuple(self._callbacks | self._active),
                                     return_exceptions=True)
        if self._cleanup_task is None or (self._cleanup_task.done()
                and self._cleanup_task.exception() is not None):
            self._cleanup_task = asyncio.create_task(cleanup())
        try:
            await asyncio.wait_for(asyncio.shield(self._cleanup_task), timeout)
        except Exception:
            raise ContractError('authority_switch_service_cleanup_incomplete') from None


def verify_recovery_response(raw, request_bytes, *, public_key, signing_key_ref,
                             service_identity_ref, service_instance_id,
                             source, switch_id, stream_identity, expected_scope,
                             caller_ref, seal, now):
    """Mint an opaque authorization only from exact trusted enrollment pins."""
    try:
        if (type(raw) is not bytes or len(raw) > RESPONSE_LIMIT
                or type(request_bytes) is not bytes or len(request_bytes) > REQUEST_LIMIT):
            raise ValueError()
        response, request = strict_loads(raw), strict_loads(request_bytes)
        validate('authority-switch-recovery-response', response)
        validate('identity-ingress-request', request)
        claims, wanted = response['claims'], request['claims']
        verify_possession(claims, response['signature'], public_key)
        operation = claims['operation']
        response_stream = claims['stream']
        if (canonical_bytes(response) != raw or canonical_bytes(request) != request_bytes
                or claims['purpose'] != 'agentmux-authority-switch-recovery-response-v1'
                or claims['serviceId'] != 'authority-switch-owner'
                or claims['decision'] != 'pre-cutover-abort'
                or claims['signingKeyRef'] != signing_key_ref
                or claims['serviceIdentityRef'] != service_identity_ref
                or claims['serviceInstanceId'] != service_instance_id
                or claims['requestDigest'] != payload_digest(request)
                or claims['payloadDigest'] != payload_digest(wanted['payload'])
                or claims['replySubject'] != wanted['replySubject']
                or claims['operation']['operationId'] != wanted['operationId']
                or claims['operation']['expectedVersion'] != wanted['expectedVersion']
                or claims['operation']['payloadDigest'] != claims['payloadDigest']
                or claims['operation']['grantRef'] != wanted['grantRef']
                or claims['operation']['scope'] != expected_scope
                or claims['operation']['caller']['authenticatedIdentityRef'] != caller_ref
                or claims['operation']['effectiveActorRef'] != caller_ref
                or claims['operation']['approvalRefs'] != []
                or claims['operation']['deadline'] != wanted['expiresAt']
                or claims['source'] != source or claims['switchRef'] != {
                    'id': switch_id, 'ownerHubId': wanted['hubId'], 'revision': 2}
                or response_stream['created'] != _stamp(stream_identity.created)
                or response_stream['minimumSequence'] != claims['switchRef']['revision']
                or response_stream['minimumSequence'] < stream_identity.minimum_sequence
                or claims['hubId'] != wanted['hubId']
                or claims['profileId'] != wanted['profileId']
                or claims['authorityId'] != wanted['authorityId']
                or wanted['contractId'] != 'authority-switch'
                or wanted['payload'] != {'action': 'request-recovery',
                    'switchId': switch_id, 'source': source}
                or wanted['approvalRefs'] != []
                or claims['authorityRef']['id'] != wanted['authorityId']
                or claims['authorityRef']['ownerHubId'] != wanted['hubId']
                or claims['authorityRef']['revision'] < 1
                or claims['grantRef'] != wanted['grantRef']):
            raise ValueError()
        issued = datetime.fromisoformat(claims['issuedAt'])
        valid = datetime.fromisoformat(claims['validUntil'])
        request_issued = datetime.fromisoformat(wanted['issuedAt'])
        request_expiry = datetime.fromisoformat(wanted['expiresAt'])
        if (any(value.utcoffset() != timedelta(0) for value in
                (issued, valid, request_issued, request_expiry, now))
                or not request_issued <= issued <= now < valid <= request_expiry):
            raise ValueError()
        result = object.__new__(VerifiedEnrolledRecovery)
        object.__setattr__(result, '_seal', seal)
        object.__setattr__(result, '_request', request_bytes)
        object.__setattr__(result, '_response', raw)
        object.__setattr__(result, '_valid_until', valid)
        return result
    except Exception:
        raise ContractError('authority_switch_recovery_unconfirmed') from None
