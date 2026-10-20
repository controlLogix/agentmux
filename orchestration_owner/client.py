"""Verify signed orchestration receipts against one exact client request."""
from agentmux_contracts import (ContractError, canonical_bytes, payload_digest,
                                strict_loads, validate)
from identity.ingress import verify_possession


def verify_receipt(response_bytes, request_bytes, *, public_key, issuer_ref):
    if (type(response_bytes) is not bytes or len(response_bytes) > 65_536
            or type(request_bytes) is not bytes or len(request_bytes) > 65_536):
        raise ContractError('orchestration_receipt_invalid')
    response, request = strict_loads(response_bytes), strict_loads(request_bytes)
    validate('identity-ingress-request', request)
    validate('orchestration-command-receipt', response)
    claims = response['claims']
    verify_possession(claims, response['signature'], public_key)
    if (claims['issuerRef'] != issuer_ref
            or claims['requestDigest'] != payload_digest(request)
            or any(claims[key] != request['claims'][key]
                   for key in ('hubId', 'profileId', 'authorityId'))
            or claims['receipt']['operationId'] != request['claims']['operationId']):
        raise ContractError('orchestration_receipt_binding')
    return strict_loads(canonical_bytes(claims['receipt']))
