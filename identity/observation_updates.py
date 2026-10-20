"""Signed host observation delivery on the existing enrolled identity connection."""
import asyncio
import base64
from datetime import datetime, timezone, timedelta

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from .application_binding import ApplicationObservationLease, _permission, _interval, _time, _stamp
from .authority import _indexes, _key, _active
from .ingress import verify_possession


async def update_observation(service, raw):
    request = strict_loads(raw)
    validate('application-observation-update', request)
    claims = request['claims']
    try:
        encoded = base64.b64decode(claims['observationBytes'], validate=True)
        if len(encoded) > 65536 or base64.b64encode(encoded).decode() != claims['observationBytes']:
            raise ValueError()
    except ValueError:
        raise ContractError('application_observation_encoding') from None
    observation = strict_loads(encoded)
    validate('application-runtime-observation', observation)
    observed = observation['claims']
    async with service._application_lock:
        snapshot = await service.reader.current()
        now = datetime.now(timezone.utc)
        record = strict_loads(snapshot.record)
        state = record['state']
        index = _indexes(state, record['ownerHubId'])
        end = _interval(claims, now)
        if (service._closed or claims['authorityId'] != record['entityId']
                or claims['hubId'] != record['ownerHubId'] or claims['profileId'] != state['profileId']
                or any(claims[k] != observed[k] for k in ('hubId', 'profileId', 'generation', 'lifetimeId'))):
            raise ContractError('application_binding_mismatch')
        transport = index['transports'].get(_key(claims['transportRef']))
        observer = index['issuers'].get(_key(observed['signingKeyRef']))
        issuer = index['issuers'].get(_key(strict_loads(service._issuer)))
        if any(item is None or not _active(item, now) for item in (transport, observer, issuer)):
            raise ContractError('application_credential_unavailable')
        identity = index['identities'].get(_key(observer['identityRef']))
        server = index['identities'].get(_key(issuer['identityRef']))
        public = base64.urlsafe_b64encode(bytes(SigningKey(service._seed).verify_key)).decode().rstrip('=')
        if (identity is None or identity['kind'] != 'service' or not _active(identity, now)
                or server is None or server['kind'] != 'service' or not _active(server, now)
                or transport['identityRef'] != identity['ref'] or transport['issuerRef'] != issuer['ref']
                or transport['method'] != 'nats-credential-mapping' or issuer['publicKey'] != public):
            raise ContractError('application_credential_unavailable')
        verify_possession(claims, request['signature'], transport['publicKey'])
        verify_possession(observed, observation['signature'], observer['publicKey'])
        _permission(index, identity['ref'], observed['scope'], 'application-attest', observed['instanceId'], now)
        previous = service._application_lease
        replacement = None
        expired_previous = False
        if claims['action'] == 'refresh':
            end = min(end, _interval(observed, now))
            if previous is not None and previous.generation == observed['generation']:
                previous.validate_refresh(encoded)
            else:
                expired_previous = previous is not None and _time(
                    strict_loads(previous.observation)['claims']['expiresAt']) <= now
                replacement = ApplicationObservationLease(encoded, asyncio.Event())
                if previous is not None and (replacement.generation <= previous.generation
                        or replacement.lifetime_id == previous.lifetime_id
                        or not (previous.done.is_set() or expired_previous)):
                    raise ContractError('application_generation_mismatch')
        elif previous is None or any(observed[k] != strict_loads(previous.observation)['claims'][k]
                                    for k in ApplicationObservationLease._PIN):
            raise ContractError('application_generation_mismatch')
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            for item in state[collection]:
                if item['status'] == 'active':
                    for key in ('issuedAt', 'expiresAt'):
                        boundary = _time(item[key])
                        if boundary > now:
                            end = min(end, boundary)
        response_claims = {'purpose': 'agentmux-application-observation-receipt-v1',
            **{k: claims[k] for k in ('requestId', 'hubId', 'profileId', 'authorityId', 'action', 'generation', 'lifetimeId')},
            'requestDigest': payload_digest(request), 'signingKeyRef': issuer['ref'],
            'authorityRef': {'id': record['entityId'], 'ownerHubId': record['ownerHubId'], 'revision': record['entityVersion']},
            'issuedAt': _stamp(now), 'validUntil': _stamp(end)}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519', 'canonicalization': 'RFC8785-JCS-UTF8',
            'claims': response_claims, 'signature': sign_claims(response_claims, service._seed)}
        validate('application-observation-receipt', response)
        result = canonical_bytes(response)
        if datetime.now(timezone.utc) >= end:
            raise ContractError('application_observation_expired')
        if claims['action'] == 'end':
            previous.done.set()
        elif replacement is not None:
            if expired_previous:
                previous.done.set()
            service.replace_application_lease(replacement)
        else:
            previous.refresh(encoded)
        return result
