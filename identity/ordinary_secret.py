"""Public ordinary-secret enrollment and current two-proof admission.

This owner reads no secret material. The following custody owner must recheck
admission before each effect and recovery, and authenticate the exact consumer.
An old public resolution is never permission to use cached secret material.
"""
from dataclasses import dataclass, replace
import base64
from datetime import datetime, timezone

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from .authority import AuthoritySnapshot, LedgerAuthorityReader, _active, _indexes, _key, evaluate_snapshot
from .capability_routes import CAPABILITY_DESTINATIONS


def _within(child, parent):
    return (child['organizationId'] == parent['organizationId']
        and child['projectId'] == parent['projectId']
        and (parent['workspaceId'] is None or child['workspaceId'] == parent['workspaceId']))


def validate_enrollment(state, index, item, hub_id):
    """Validate public bindings; the signed identity command authorizes writes."""
    validate('identity-ordinary-secret-reference', item)
    if (item['profileId'] != state['profileId']
            or item['scope']['organizationId'] != state['organizationId']
            or item['scope']['projectId'] is None
            or item['ownerAudience'] != {'hubId': hub_id,
                'serviceId': CAPABILITY_DESTINATIONS['capability-secret-use']}
            or any(item[field]['ownerHubId'] != hub_id for field in
                ('ref', 'generationRef', 'ownerIdentityRef', 'callerIdentityRef', 'consumerRef', 'purposeRef'))
            or item['generationRef']['revision'] != 1 or item['purposeRef']['revision'] < 1):
        raise ContractError('ordinary_secret_binding_invalid')
    start, end = (datetime.fromisoformat(item[key]) for key in ('issuedAt', 'expiresAt'))
    if start >= end:
        raise ContractError('ordinary_secret_validity_invalid')
    for field in ('ownerIdentityRef', 'callerIdentityRef', 'consumerRef'):
        identity = index['identities'].get(_key(item[field]))
        if (identity is None or identity['status'] != 'active'
                or field in ('ownerIdentityRef', 'consumerRef') and identity['kind'] != 'service'
                or not any(member['identityRef'] == item[field]
                    and member['scope'] == item['scope'] and member['status'] == 'active'
                    for member in index['memberships'].values())):
            raise ContractError('ordinary_secret_identity_unavailable')


@dataclass(frozen=True, slots=True, repr=False)
class OrdinarySecretResolution:
    """Immutable public bindings, never a bearer permit or plaintext resolver."""
    record: bytes
    original_operation: bytes
    original_request_digest: str
    scope: bytes
    authority_sequence: int
    valid_until: datetime

    def __repr__(self):
        return '<OrdinarySecretResolution public references>'

    def claims(self):
        item, operation = strict_loads(self.record), strict_loads(self.original_operation)
        return {'secretRef': item['ref'], 'generationRef': item['generationRef'],
            'consumerRef': item['consumerRef'], 'purposeRef': item['purposeRef'],
            'ownerAudience': item['ownerAudience'], 'scope': strict_loads(self.scope),
            'callerRef': operation['effectiveActorRef'],
            'custodyIdentityRef': item['ownerIdentityRef'],
            'originalOperationId': operation['operationId'],
            'originalPayloadDigest': operation['payloadDigest'],
            'originalRequestDigest': self.original_request_digest,
            'authoritySequence': self.authority_sequence}


def resolve_snapshot(snapshot, request_bytes, *, audience, now):
    """Check custody proof and actual original Secret.Use proof independently.

    The outer request comes from the enrolled custody service. It cannot name an
    original caller: that caller comes only from the inner verified attestation.
    Its resolve grant never replaces the original Secret.Use grant or approval.
    The owner audience is pinned in enrollment and checked against fixed routes.
    """
    if type(snapshot) is not AuthoritySnapshot or type(request_bytes) is not bytes or len(request_bytes) > 65536:
        raise ContractError('ordinary_secret_resolution_invalid')
    request = strict_loads(request_bytes)
    validate('message-envelope', request)
    if request['contractId'] != 'identity-ordinary-secret-resolve':
        raise ContractError('ordinary_secret_resolution_invalid')
    payload = request['payload']
    validate('identity-ordinary-secret-resolve', payload)
    decision = evaluate_snapshot(snapshot, request_bytes, audience=audience, now=now)
    if decision.outcome != 'allowed' or decision.operation is None or decision.valid_until is None:
        raise ContractError('ordinary_secret_not_authorized')
    record = strict_loads(snapshot.record)
    index = _indexes(record['state'], record['ownerHubId'])
    item = index['ordinarySecretReferences'].get(_key(payload['secretRef']))
    if item is None or not _active(item, now):
        raise ContractError('ordinary_secret_unavailable')
    validate_enrollment(record['state'], index, item, record['ownerHubId'])
    outer = strict_loads(decision.operation)
    if (outer['effectiveActorRef'] != item['ownerIdentityRef']
            or any(payload[field] != item[field] for field in
                ('generationRef', 'profileId', 'consumerRef', 'purposeRef'))
            or not _within(payload['scope'], item['scope'])):
        raise ContractError('ordinary_secret_binding_mismatch')
    original = payload['originalEnvelope']
    if original['contractId'] != 'capability-secret-use':
        raise ContractError('ordinary_secret_original_invalid')
    raw = canonical_bytes(original)
    original_decision = evaluate_snapshot(snapshot, raw, audience=item['ownerAudience'], now=now)
    if (original_decision.outcome != 'allowed' or original_decision.operation is None
            or original_decision.valid_until is None):
        raise ContractError('ordinary_secret_original_not_authorized')
    operation = strict_loads(original_decision.operation)
    if (operation['effectiveActorRef'] != item['callerIdentityRef']
            or operation['scope'] != payload['scope']
            or original['payload']['resourceRef'] != item['ref']
            or original['payload']['input'] != {
                'consumerRef': item['consumerRef'], 'purposeRef': item['purposeRef']}
            or operation['expectedVersion'] != item['ref']['revision']):
        raise ContractError('ordinary_secret_original_binding')
    end = min(decision.valid_until, original_decision.valid_until,
              datetime.fromisoformat(item['expiresAt']))
    if now >= end:
        raise ContractError('ordinary_secret_not_authorized')
    return OrdinarySecretResolution(canonical_bytes(item), original_decision.operation,
        payload_digest(original), canonical_bytes(operation['scope']), snapshot.sequence, end)


class OrdinarySecretAuthority:
    """Read the actual retained identity owner again for use or recovery."""
    def __init__(self, reader):
        if type(reader) is not LedgerAuthorityReader:
            raise ContractError('ordinary_secret_authority_required')
        self._reader = reader

    async def resolve(self, request_bytes, *, native_proof=None):
        snapshot = await self._reader.current()
        now = datetime.now(timezone.utc)
        result = resolve_snapshot(snapshot, request_bytes,
            audience={'hubId': self._reader._hub, 'serviceId': 'identity-owner'},
            now=now)
        if native_proof is not None:
            original = canonical_bytes(strict_loads(request_bytes)['payload']['originalEnvelope'])
            end = await authorize_native_secret_proof(native_proof, self._reader, snapshot, original, now=now)
            if native_proof.caller_ingress is not None and native_proof.caller_ingress._session_authorizer is not None:
                snapshot = await self._reader.current()
                now = datetime.now(timezone.utc)
                result = resolve_snapshot(snapshot, request_bytes,
                    audience={'hubId': self._reader._hub, 'serviceId': 'identity-owner'}, now=now)
                end = min(end, _check_native_secret_proof(native_proof, snapshot, original, now=now))
            result = replace(result, valid_until=min(result.valid_until, end))
        return result


@dataclass(frozen=True, slots=True, repr=False)
class NativeSecretProof:
    """Exact native request bytes; every use still requires current authority."""
    request: bytes
    plugin_identity: bytes | None = None
    instance_id: str | None = None
    package_id: str | None = None
    caller_ingress: object = None

    def __post_init__(self):
        if type(self.request) is not bytes or not 0 < len(self.request) <= 98304:
            raise ContractError('ordinary_secret_native_refused')
        if self.caller_ingress is not None:
            from .ingress import EnrolledIngress
            if type(self.caller_ingress) is not EnrolledIngress:
                raise ContractError('ordinary_secret_native_refused')

    def __repr__(self):
        return '<NativeSecretProof private; current authority required>'


def _check_native_secret_proof(proof, snapshot, original, *, now):
    from .capability_service import evaluate_capability_service_request
    if type(proof) is not NativeSecretProof:
        raise ContractError('ordinary_secret_native_refused')
    packet = strict_loads(proof.request)
    validate('capability-service-request', packet)
    if canonical_bytes(packet) != proof.request:
        raise ContractError('ordinary_secret_native_refused')
    claims = packet['claims']
    inner = base64.b64decode(claims['envelopeBytes'], validate=True)
    envelope = strict_loads(original)
    contract = envelope['contractId']
    if (inner != original or canonical_bytes(envelope) != original
            or contract not in ('capability-secret-use', 'capability-outcome-query')
            or contract == 'capability-outcome-query'
                and envelope['payload']['input']['contractId'] != 'capability-secret-use'):
        raise ContractError('ordinary_secret_native_refused')
    decision = evaluate_capability_service_request(snapshot, proof.request,
        service_id=CAPABILITY_DESTINATIONS[contract], now=now)
    if proof.plugin_identity is not None:
        rows = [row for row in strict_loads(snapshot.record)['state'].get('nativeInstances', [])
            if row['owner'] == claims['owner']]
        if (len(rows) != 1 or canonical_bytes(rows[0]['identityRef']) != proof.plugin_identity
                or rows[0]['owner']['instanceId'] != proof.instance_id
                or rows[0]['owner']['pin']['packageId'] != proof.package_id):
            raise ContractError('ordinary_secret_native_refused')
    if decision.valid_until is None or now >= decision.valid_until:
        raise ContractError('ordinary_secret_native_refused')
    return decision.valid_until


async def authorize_native_secret_proof(proof, reader, snapshot, original, *, now):
    """Refresh the exact human gate independently of the internal service signer."""
    end = _check_native_secret_proof(proof, snapshot, original, now=now)
    ingress = proof.caller_ingress
    if ingress is not None:
        if ingress._reader is not reader:
            raise ContractError('ordinary_secret_native_refused')
        await ingress.authorize_terminal(strict_loads(original)['operation'])
        now = datetime.now(timezone.utc)
        if now >= end:
            raise ContractError('ordinary_secret_native_refused')
        if ingress._session_authorizer is not None:
            current = await reader.current()
            now = datetime.now(timezone.utc)
            end = min(end, _check_native_secret_proof(proof, current, original, now=now))
    return end


async def refresh_secret_query_authority(proof, reader, snapshot, raw, *, now, valid_until):
    """Return one post-session snapshot for native, query and enrollment checks."""
    end = min(valid_until, await authorize_native_secret_proof(proof, reader, snapshot, raw, now=now))
    current = await reader.current()
    now = datetime.now(timezone.utc)
    envelope = strict_loads(raw)
    decision = evaluate_snapshot(current, raw,
        audience={'hubId': reader._hub, 'serviceId': 'outcome-owner'}, now=now)
    if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(envelope['operation'])
            or decision.valid_until is None):
        raise ContractError('ordinary_secret_query_refused')
    end = min(end, decision.valid_until, _check_native_secret_proof(proof, current, raw, now=now))
    if now >= end:
        raise ContractError('ordinary_secret_query_refused')
    return current, now


def verify_resolution(response_bytes, request_bytes, *, public_key, issuer_ref, now):
    """Verify exact public reply bindings. Re-read authority before any effect."""
    from .ingress import verify_possession
    if (type(response_bytes) is not bytes or len(response_bytes) > 65536
            or type(request_bytes) is not bytes or len(request_bytes) > 65536):
        raise ContractError('ordinary_secret_resolution_invalid')
    response, request = strict_loads(response_bytes), strict_loads(request_bytes)
    validate('identity-ordinary-secret-resolution', response)
    validate('identity-ingress-request', request)
    outer = request['claims']
    if outer['contractId'] != 'identity-ordinary-secret-resolve':
        raise ContractError('ordinary_secret_resolution_invalid')
    payload = outer['payload']
    validate('identity-ordinary-secret-resolve', payload)
    original = payload['originalEnvelope']
    if original['contractId'] != 'capability-secret-use':
        raise ContractError('ordinary_secret_original_invalid')
    claims = response['claims']
    verify_possession(claims, response['signature'], public_key)
    if (claims['issuerRef'] != issuer_ref or claims['requestDigest'] != payload_digest(request)
            or any(claims[key] != outer[key] for key in ('hubId', 'profileId', 'authorityId', 'operationId'))
            or any(claims[key] != payload[key] for key in
                ('secretRef', 'generationRef', 'consumerRef', 'purposeRef', 'scope'))
            or claims['originalOperationId'] != original['operation']['operationId']
            or claims['originalPayloadDigest'] != original['operation']['payloadDigest']
            or claims['originalRequestDigest'] != payload_digest(original)
            or claims['callerRef'] != original['operation']['effectiveActorRef']
            or claims['ownerAudience'] != {'hubId': outer['hubId'],
                'serviceId': CAPABILITY_DESTINATIONS['capability-secret-use']}
            or not datetime.fromisoformat(claims['issuedAt']) <= now < datetime.fromisoformat(claims['validUntil'])
            or datetime.fromisoformat(claims['validUntil']) > datetime.fromisoformat(outer['expiresAt'])):
        raise ContractError('ordinary_secret_resolution_binding')
    return strict_loads(canonical_bytes(claims))
