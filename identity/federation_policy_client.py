"""Verify policy receipts against protected client pins before signing again."""
import base64
from dataclasses import dataclass, field
from datetime import datetime

from jsonschema import Draft202012Validator
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from .ingress import verify_possession
from state_owner.federation_policy import FEDERATION_POLICY_SCHEMA, SCHEMA_REF, _digest


def _receipt(raw, request, *, schema, public_key, issuer_ref, target, now):
    if type(raw) is not bytes or len(raw) > 65536 or type(request) is not bytes or len(request) > 65536:
        raise ContractError('federation_policy_response_binding')
    response, envelope = strict_loads(raw), strict_loads(request)
    validate(schema, response)
    validate('message-envelope', envelope)
    claims = response['claims']
    verify_possession(claims, response['signature'], public_key)
    expiry = min(datetime.fromisoformat(envelope['operation']['deadline']),
        datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt']))
    if (claims['signingKeyRef'] != issuer_ref or claims['requestDigest'] != payload_digest(envelope)
            or claims['target'] != target or claims['owner'] != envelope['payload']['owner']
            or claims['configurationRef'] != envelope['payload']['configurationRef']
            or not datetime.fromisoformat(claims['issuedAt']) <= now < datetime.fromisoformat(claims['validUntil'])
            or datetime.fromisoformat(claims['validUntil']) > expiry):
        raise ContractError('federation_policy_response_binding')
    return envelope, claims


def verify_policy_preparation(raw, request, *, public_key, issuer_ref, target, now):
    """Return descriptor bytes to sign anew; this is no committed-state reply."""
    envelope, claims = _receipt(raw, request, schema='federation-policy-prepared-reply',
        public_key=public_key, issuer_ref=issuer_ref, target=target, now=now)
    payload, operation = envelope['payload'], envelope['operation']
    validate('configuration-set', payload)
    try:
        proposal = strict_loads(base64.b64decode(payload['configurationBytes'], validate=True))
        descriptor = base64.b64decode(claims['descriptorBytes'], validate=True)
        document = strict_loads(descriptor)
        Draft202012Validator(strict_loads(FEDERATION_POLICY_SCHEMA)).validate(document)
        intent = document['projectionIntent']
        if (envelope['contractId'] != 'configuration-set' or not 1 <= len(descriptor) <= 16384
                or canonical_bytes(document) != descriptor
                or base64.b64encode(descriptor).decode() != claims['descriptorBytes']
                or proposal['format'] != 'amx-federation-policy-preparation-v1'
                or proposal['target'] != target or document['target'] != target
                or document['previousRevision'] != operation['expectedVersion']
                or claims['previousRevision'] != operation['expectedVersion']
                or proposal['previousRevision'] != operation['expectedVersion']
                or document['originDigest'] != proposal['originDigest']
                or any({key: document[name][key] for key in ('digest', 'bytes')} != proposal[name]
                    for name in ('oldPolicy', 'desiredPolicy'))
                or intent['change'] != proposal['change']
                or claims['operationId'] != operation['operationId']
                or claims['preparationDigest'] != operation['payloadDigest']
                or intent['operationId'] != operation['operationId']
                or intent['preparationDigest'] != operation['payloadDigest']
                or intent['actorRef'] != operation['effectiveActorRef']
                or intent['callerRef'] != operation['caller']['authenticatedIdentityRef']
                or any(document[name]['keyRef'] not in payload['secretReferences']
                    for name in ('oldPolicy', 'desiredPolicy'))):
            raise ValueError()
    except Exception:
        raise ContractError('federation_policy_response_binding') from None
    return descriptor


def verify_policy_projection(raw, request, *, public_key, issuer_ref, target, now):
    """Verify only this original committed intent was reconciled."""
    envelope, claims = _receipt(raw, request, schema='federation-policy-projected-reply',
        public_key=public_key, issuer_ref=issuer_ref, target=target, now=now)
    validate('federation-policy-project', envelope['payload'])
    if (envelope['contractId'] != 'federation-policy-project'
            or any(claims[key] != envelope['payload'][key] for key in
                ('originalOperationId', 'originalPayloadDigest', 'desiredPolicyDigest'))):
        raise ContractError('federation_policy_response_binding')
    return strict_loads(canonical_bytes(claims))


@dataclass(frozen=True, repr=False)
class PolicyClientResult:
    kind: str
    data: bytes = field(repr=False)

    def __repr__(self):
        return '<PolicyClientResult private>'


def verify_policy_client_response(raw, request, *, reply_subject, public_key, issuer_ref,
                                  target, owner, caller_ref, scope, now):
    """Verify the exact external possession packet, never an invented envelope."""
    if type(raw) is not bytes or type(request) is not bytes or len(raw) > 65536 or len(request) > 65536:
        raise ContractError('federation_policy_response_binding')
    packet, response = strict_loads(request), strict_loads(raw)
    validate('identity-ingress-request', packet)
    validate('federation-policy-client-reply', response)
    claims, external = response['claims'], packet['claims']
    verify_possession(claims, response['signature'], public_key)
    binding = {**{name: external[name] for name in ('hubId', 'profileId', 'authorityId', 'transportRef',
        'grantRef', 'contractId', 'operationId', 'expectedVersion')},
        'payloadDigest': payload_digest(external['payload']), 'callerRef': caller_ref, 'scope': scope}
    if (claims['requestDigest'] != payload_digest(packet) or claims['replySubject'] != reply_subject
            or claims['requestBinding'] != binding or claims['signingKeyRef'] != issuer_ref
            or claims['authorityRef']['id'] != external['authorityId']
            or claims['authorityRef']['ownerHubId'] != external['hubId']
            or claims['owner'] != owner or claims['owner'] != external['payload']['owner']
            or claims['target'] != target or claims['configurationRef'] != external['payload']['configurationRef']
            or not datetime.fromisoformat(claims['issuedAt']) <= now < datetime.fromisoformat(claims['validUntil'])
            or datetime.fromisoformat(claims['validUntil']) > datetime.fromisoformat(external['expiresAt'])):
        raise ContractError('federation_policy_response_binding')
    try:
        result = base64.b64decode(claims['resultBytes'], validate=True)
        if base64.b64encode(result).decode() != claims['resultBytes']:
            raise ValueError()
        payload, kind = external['payload'], claims['kind']
        if kind == 'prepared':
            if external['contractId'] != 'configuration-set' or payload['schemaRef'] != SCHEMA_REF:
                raise ValueError()
            proposal = strict_loads(base64.b64decode(payload['configurationBytes'], validate=True))
            document = strict_loads(result)
            Draft202012Validator(strict_loads(FEDERATION_POLICY_SCHEMA)).validate(document)
            intent = document['projectionIntent']
            if (not 1 <= len(result) <= 16384 or canonical_bytes(document) != result
                    or proposal['format'] != 'amx-federation-policy-preparation-v1'
                    or proposal['target'] != target or document['target'] != target
                    or document['previousRevision'] != external['expectedVersion']
                    or proposal['previousRevision'] != external['expectedVersion']
                    or document['originDigest'] != proposal['originDigest']
                    or intent['operationId'] != external['operationId']
                    or intent['preparationDigest'] != payload_digest(payload)
                    or intent['actorRef'] != caller_ref or intent['callerRef'] != caller_ref
                    or intent['change'] != proposal['change']
                    or any({key: document[name][key] for key in ('digest', 'bytes')} != proposal[name]
                        or document[name]['keyRef'] not in payload['secretReferences']
                        for name in ('oldPolicy', 'desiredPolicy'))):
                raise ValueError()
        elif kind == 'committed':
            inner = strict_loads(result)
            validate('configuration-reply', inner)
            receipt = inner['claims']
            verify_possession(receipt, inner['signature'], public_key)
            state = receipt['state']
            value = base64.b64decode(state['configurationBytes'], validate=True)
            if (external['contractId'] != 'configuration-set'
                    or receipt['signingKeyRef'] != issuer_ref or receipt['owner'] != owner or state['owner'] != owner
                    or receipt['configurationRef'] != {**payload['configurationRef'], 'revision': external['expectedVersion']+1}
                    or state['revision'] != external['expectedVersion']+1
                    or any(state[name] != payload[name] for name in ('configurationBytes', 'schemaRef', 'secretReferences'))
                    or not 1 <= len(value) <= 16384 or state['configurationChecksum'] != _digest(value)
                    or base64.b64encode(value).decode() != state['configurationBytes']
                    or not datetime.fromisoformat(receipt['issuedAt']) <= now < datetime.fromisoformat(receipt['validUntil'])
                    or datetime.fromisoformat(receipt['validUntil']) > datetime.fromisoformat(external['expiresAt'])):
                raise ValueError()
        elif kind == 'projected':
            inner = strict_loads(result)
            validate('federation-policy-projected-reply', inner)
            receipt = inner['claims']
            verify_possession(receipt, inner['signature'], public_key)
            if (external['contractId'] != 'federation-policy-project' or receipt['signingKeyRef'] != issuer_ref
                    or receipt['owner'] != owner or receipt['target'] != target
                    or receipt['configurationRef'] != payload['configurationRef']
                    or any(receipt[name] != payload[name] for name in
                        ('originalOperationId', 'originalPayloadDigest', 'desiredPolicyDigest'))
                    or not datetime.fromisoformat(receipt['issuedAt']) <= now < datetime.fromisoformat(receipt['validUntil'])
                    or datetime.fromisoformat(receipt['validUntil']) > datetime.fromisoformat(external['expiresAt'])):
                raise ValueError()
        elif kind == 'current':
            if external['contractId'] != 'configuration-read':
                raise ValueError()
            current = strict_loads(result)
            validate('federation-policy-current-state', current)
            reference = current['configurationRef']
            revision = reference['revision']
            wanted = payload['configurationRef']
            if (current['owner'] != owner or current['target'] != target
                    or reference['id'] != wanted['id'] or reference['ownerHubId'] != wanted['ownerHubId']
                    or revision < wanted['revision']):
                raise ValueError()
            if revision == 0:
                if current['projected'] or any(current[name] is not None for name in
                        ('state', 'operation', 'originalOperationId', 'originalPayloadDigest')):
                    raise ValueError()
            else:
                state, operation = current['state'], current['operation']
                if (state is None or operation is None or state['owner'] != owner
                        or state['schemaRef'] != SCHEMA_REF or state['revision'] != revision
                        or operation['expectedVersion'] + 1 != revision or operation['scope'] != scope
                        or current['originalOperationId'] != operation['operationId']
                        or current['originalPayloadDigest'] != operation['payloadDigest']):
                    raise ValueError()
                document_bytes = base64.b64decode(state['configurationBytes'], validate=True)
                document = strict_loads(document_bytes)
                Draft202012Validator(strict_loads(FEDERATION_POLICY_SCHEMA)).validate(document)
                intent = document['projectionIntent']
                original_payload = {name: state[name] for name in
                    ('owner', 'schemaRef', 'configurationBytes', 'secretReferences')}
                original_payload['configurationRef'] = dict(reference, revision=revision-1)
                if (not 1 <= len(document_bytes) <= 16384 or canonical_bytes(document) != document_bytes
                        or base64.b64encode(document_bytes).decode() != state['configurationBytes']
                        or state['configurationChecksum'] != _digest(document_bytes)
                        or document['target'] != target or document['previousRevision'] + 1 != revision
                        or intent['operationId'] != operation['operationId']
                        or intent['actorRef'] != operation['effectiveActorRef']
                        or intent['callerRef'] != operation['caller']['authenticatedIdentityRef']
                        or operation['payloadDigest'] != payload_digest(original_payload)
                        or state['secretReferences'] != [document['oldPolicy']['keyRef']]
                        or document['desiredPolicy']['keyRef'] != document['oldPolicy']['keyRef']):
                    raise ValueError()
        else:
            raise ValueError()
    except Exception:
        raise ContractError('federation_policy_response_binding') from None
    return PolicyClientResult(kind, result)
