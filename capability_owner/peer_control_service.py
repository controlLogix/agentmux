"""Signed operator command endpoint; protected publishers stay in their owner."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import re

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import _active, _indexes, _key
from identity.ingress import EnrolledIngress, verify_possession
from identity.peer_control_commands import COMMANDS
from .peer_control_command import PeerControlCommandOwner


def _time(value):
    return datetime.fromisoformat(value)


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


class PeerControlCommandService:
    def __init__(self, ingress, owner, *, service_identity_ref, service_instance_id, signing_key_ref, signing_seed):
        if (type(ingress) is not EnrolledIngress or type(owner) is not PeerControlCommandOwner
                or ingress._reader is not owner._authority or ingress is not owner._ingress
                or type(signing_seed) is not bytes or len(signing_seed) != 32):
            raise ContractError('peer_control_command_configuration')
        self._ingress, self._owner = ingress, owner
        self._identity, self._issuer = map(canonical_bytes, (service_identity_ref, signing_key_ref))
        self._instance, self._seed = service_instance_id, signing_seed
        self._closed, self._closing = False, None
        self._active, self._workers = set(), set()

    def __repr__(self):
        return '<PeerControlCommandService private>'

    async def _admit(self, raw, reply_subject):
        if type(raw) is not bytes or len(raw) > 65536:
            raise ContractError('peer_control_command_refused')
        request = strict_loads(raw)
        validate('identity-ingress-request', request)
        claims = request['claims']
        if (canonical_bytes(request) != raw or claims['contractId'] not in COMMANDS
                or claims.get('replySubject') != reply_subject or type(reply_subject) is not str
                or not re.fullmatch(r'_INBOX\.[A-Za-z0-9_-]{16,128}(?:\.[A-Za-z0-9_-]{1,128})?', reply_subject)
                or _time(claims['expiresAt']) - _time(claims['issuedAt']) > timedelta(seconds=5)):
            raise ContractError('peer_control_command_refused')
        await self._ingress._request_authority(raw)
        cancellation = {'id': 'cancel_' + __import__('hashlib').sha256(claims['operationId'].encode()).hexdigest(),
            'ownerHubId': self._owner._authority._hub, 'revision': 1}
        admitted = await self._ingress.admit(raw, cancellation_ref=cancellation)
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('peer_control_command_refused')
        snapshot, decision, route = await self._owner.authorize(admitted.envelope)
        return request, admitted.envelope, snapshot, decision, route

    def _sign(self, request, result, snapshot, decision):
        claims = request['claims']
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], self._owner._authority._hub)
        now = datetime.now(timezone.utc)
        signer = index['issuers'].get(_key(strict_loads(self._issuer)))
        principal = index['identities'].get(_key(strict_loads(self._identity)))
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')
        if (signer is None or principal is None or not _active(signer, now) or not _active(principal, now)
                or principal['kind'] != 'service' or signer['identityRef'] != strict_loads(self._identity)
                or signer['instanceId'] != self._instance or signer['publicKey'] != public):
            raise ContractError('peer_control_command_unavailable')
        end = min(decision.valid_until, _time(claims['expiresAt']), _time(signer['expiresAt']))
        self._owner.check()
        if self._closed or not now < end:
            raise ContractError('peer_control_command_unavailable')
        response = {k: claims[k] for k in ('profileId', 'hubId', 'authorityId', 'operationId', 'replySubject')}
        response.update(purpose='agentmux-peer-revoke-response-v1',
            serviceIdentityRef=strict_loads(self._identity), serviceInstanceId=self._instance,
            signingKeyRef=strict_loads(self._issuer), requestContractId=claims['contractId'],
            requestDigest=payload_digest(request), payloadDigest=payload_digest(claims['payload']),
            resourceRef=claims['payload']['resourceRef'], authorityRef={'id': record['entityId'],
                'ownerHubId': record['ownerHubId'], 'revision': record['entityVersion']},
            result=result, issuedAt=_stamp(now), validUntil=_stamp(end))
        raw = canonical_bytes({'schemaVersion': '1.0.0', 'claims': response,
            'signature': sign_claims(response, self._seed)})
        validate('federation-peer-revoke-reply', strict_loads(raw))
        return raw

    async def handle(self, raw, *, received_reply_subject):
        if self._closed or len(self._active) + len(self._workers) >= 32:
            raise ContractError('peer_control_command_unavailable')
        completion = asyncio.get_running_loop().create_future()
        self._active.add(completion)
        try:
            async with asyncio.timeout(5):
                request, inner, _, _, _ = await self._admit(raw, received_reply_subject)
                if self._closed:
                    raise ContractError('peer_control_command_unavailable')
                worker = asyncio.create_task(self._owner.execute(inner))
                self._workers.add(worker)
                def finished(done):
                    self._workers.discard(done)
                    if not done.cancelled():
                        done.exception()
                worker.add_done_callback(finished)
                result = await asyncio.shield(worker)
                _, _, snapshot, decision, _ = await self._admit(raw, received_reply_subject)
                return self._sign(request, result, snapshot, decision)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ContractError('peer_control_command_unavailable') from None
        finally:
            completion.set_result(None)
            self._active.discard(completion)

    async def close(self, *, timeout=5):
        self._closed = True
        if self._closing is None:
            async def joined():
                if self._active or self._workers:
                    await asyncio.gather(*tuple(self._active | self._workers), return_exceptions=True)
            self._closing = asyncio.create_task(joined(), name='peer-control-service:cleanup')
            self._closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._closing}, timeout=timeout)
        if pending:
            raise ContractError('peer_control_command_cleanup_incomplete')
        self._closing.result()


def verify_peer_control_reply(raw, request_raw, *, public_key, service_identity_ref,
                              service_instance_id, signing_key_ref, now):
    try:
        packet, request = strict_loads(raw), strict_loads(request_raw)
        validate('federation-peer-revoke-reply', packet)
        claims, wanted = packet['claims'], request['claims']
        verify_possession(claims, packet['signature'], public_key)
        if (any(claims[k] != wanted[k] for k in ('profileId', 'hubId', 'authorityId', 'operationId', 'replySubject'))
                or claims['requestContractId'] != wanted['contractId'] or claims['requestDigest'] != payload_digest(request)
                or claims['payloadDigest'] != payload_digest(wanted['payload'])
                or claims['resourceRef'] != wanted['payload']['resourceRef']
                or claims['serviceIdentityRef'] != service_identity_ref or claims['serviceInstanceId'] != service_instance_id
                or claims['signingKeyRef'] != signing_key_ref or claims['authorityRef']['id'] != wanted['authorityId']
                or claims['authorityRef']['ownerHubId'] != wanted['hubId']
                or not _time(wanted['issuedAt']) <= _time(claims['issuedAt']) <= now < _time(claims['validUntil'])
                or _time(claims['validUntil']) > _time(wanted['expiresAt'])):
            raise ContractError('peer_control_command_reply_unconfirmed')
        return strict_loads(canonical_bytes(claims['result']))
    except Exception:
        raise ContractError('peer_control_command_reply_unconfirmed') from None
