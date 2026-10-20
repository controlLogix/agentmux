"""Client-safe signed integration receipts; no service or provider dependencies."""
import base64
import re

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate

COMMANDS = frozenset({"integration-intent", "integration-effect-query",
    "integration-attempt-start", "integration-attempt-complete", "integration-effect-reconcile"})


def verify_possession(claims, signature, public_key):
    """Use the same canonical bytes and Ed25519 library as the existing SDK."""
    try:
        key = base64.urlsafe_b64decode(public_key + '=')
        sig = base64.b64decode(signature + '==', altchars=b'-_', validate=True)
        if (base64.urlsafe_b64encode(key).decode().rstrip('=') != public_key
                or base64.urlsafe_b64encode(sig).decode().rstrip('=') != signature):
            raise ValueError()
        VerifyKey(key).verify(canonical_bytes(claims), sig)
    except (ValueError, TypeError, BadSignatureError):
        raise ContractError('credential_possession_invalid') from None



def _validate_receipt(response):
    """Closed signed wrapper around the canonical integration-effect-reply."""
    if (type(response) is not dict or set(response) != {'schemaVersion', 'claims', 'signature'}
            or response['schemaVersion'] != '1.0.0' or type(response['signature']) is not str
            or not re.fullmatch(r'[A-Za-z0-9_-]{86}', response['signature'])):
        raise ContractError('integration_receipt_invalid')
    claims = response['claims']
    if (type(claims) is not dict or set(claims) != {'purpose', 'hubId', 'profileId',
            'authorityId', 'issuerRef', 'requestDigest', 'receipt'}
            or claims['purpose'] != 'agentmux-integration-command-receipt-v1'):
        raise ContractError('integration_receipt_invalid')
    from .intent import reference, ID, DIGEST
    reference(claims['issuerRef'])
    if (any(type(claims[k]) is not str or not ID.fullmatch(claims[k])
            for k in ('hubId', 'profileId', 'authorityId'))
            or type(claims['requestDigest']) is not str or not DIGEST.fullmatch(claims['requestDigest'])):
        raise ContractError('integration_receipt_invalid')
    validate('integration-effect-reply', claims['receipt'])


def verify_receipt(response_bytes, request_bytes, *, public_key, issuer_ref):
    """Verify a receipt against the exact request and a trusted enrolled key.

    This is an outcome receipt, never a reusable authorization grant. An unsigned
    failure means that the client must reconcile its original operation identity.
    """
    if (type(response_bytes) is not bytes or len(response_bytes) > 65536
            or type(request_bytes) is not bytes or len(request_bytes) > 65536):
        raise ContractError('integration_receipt_invalid')
    response, request = strict_loads(response_bytes), strict_loads(request_bytes)
    validate('identity-ingress-request', request)
    if (type(response) is not dict or set(response) != {'schemaVersion', 'claims', 'signature'}
            or response['schemaVersion'] != '1.0.0'):
        raise ContractError('integration_outcome_unconfirmed')
    _validate_receipt(response)
    if request['claims']['contractId'] not in COMMANDS:
        raise ContractError('integration_receipt_binding')
    validate(request['claims']['contractId'], request['claims']['payload'])
    claims = response['claims']
    verify_possession(claims, response['signature'], public_key)
    if (claims.get('purpose') != 'agentmux-integration-command-receipt-v1'
            or claims.get('issuerRef') != issuer_ref
            or claims.get('requestDigest') != payload_digest(request)
            or any(claims.get(k) != request['claims'][k] for k in ('hubId', 'profileId', 'authorityId'))
            or claims.get('receipt', {}).get('operationId') != request['claims']['operationId']):
        raise ContractError('integration_receipt_binding')
    caller, receipt = request['claims'], claims['receipt']
    original_id = (caller['operationId'] if caller['contractId'] == 'integration-intent'
                   else caller['payload']['originalOperationId'])
    original_digest = (payload_digest(caller['payload']) if caller['contractId'] == 'integration-intent'
                       else caller['payload']['originalPayloadDigest'])
    if (receipt['originalOperationId'] != original_id
            or receipt['originalPayloadDigest'] != original_digest
            or (caller['contractId'] == 'integration-intent'
                and (receipt['sequence'] != 1 or receipt['phase'] != 'intent-committed'
                     or receipt['attemptOperationId'] is not None))
            or (caller['contractId'] in COMMANDS - {'integration-intent', 'integration-effect-query'}
                and receipt['attemptOperationId'] != caller['payload']['attemptOperationId'])):
        raise ContractError('integration_receipt_binding')
    return strict_loads(canonical_bytes(claims['receipt']))
