"""Current enrolled checks for a signed native capability transport wrapper."""
from dataclasses import replace
from datetime import datetime, timedelta

from agentmux_contracts import ContractError, payload_digest, strict_loads, validate
from .authority import _active, _indexes, _key, evaluate_snapshot
from .downstream import CAPABILITY_REPLIES, check_domain_binding
from .capability_routes import CAPABILITY_DESTINATIONS
from .ingress import verify_possession
from .native_records import validate_native_lineage


def evaluate_capability_service_request(snapshot, raw, *, service_id, now):
    from .native_bridge import _decode
    if type(raw) is not bytes or len(raw) > 98304:
        raise ContractError('capability_service_body_limit')
    request = strict_loads(raw)
    validate('capability-service-request', request)
    claims = request['claims']
    encoded = _decode(claims['envelopeBytes'])
    envelope = strict_loads(encoded)
    record = strict_loads(snapshot.record)
    state = record['state']
    index = _indexes(state, record['ownerHubId'])
    issuer = index['issuers'].get(_key(claims['signingKeyRef']))
    host_transport = index['transports'].get(_key(claims['hostTransportRef']))
    if (issuer is None or not _active(issuer, now) or host_transport is None
            or not _active(host_transport, now) or host_transport['issuerRef'] != issuer['ref']
            or host_transport['method'] != 'nats-credential-mapping'):
        raise ContractError('capability_service_credential_unavailable')
    verify_possession(claims, request['signature'], issuer['publicKey'])
    issued, end = (datetime.fromisoformat(claims[k]) for k in ('issuedAt', 'validUntil'))
    if not issued <= now < end or end - issued > timedelta(seconds=5):
        raise ContractError('capability_service_expired')
    contract = claims['requestContractId']
    validate('message-envelope', envelope)
    operation = envelope['operation']
    if (claims['profileId'] != state['profileId'] or claims['hubId'] != record['ownerHubId']
            or claims['authorityId'] != record['entityId'] or claims['serviceId'] != service_id
            or CAPABILITY_DESTINATIONS.get(contract) != service_id
            or claims['replyContractId'] != CAPABILITY_REPLIES.get(contract)
            or envelope['contractId'] != contract or envelope['destinationServiceId'] != service_id
            or envelope['destinationHubId'] != claims['hubId']
            or envelope['correlationId'] != claims['requestId']
            or operation['operationId'] != claims['operationId'] or operation['scope'] != claims['scope']
            or envelope['payload']['resourceRef'] != claims['resourceRef']
            or envelope['ingressAttestation']['claims']['signingKeyRef'] != issuer['ref']):
        raise ContractError('capability_service_binding')
    rows = [r for r in state.get('nativeInstances', []) if r['owner'] == claims['owner']]
    if len(rows) != 1:
        raise ContractError('capability_service_native_unavailable')
    row = rows[0]
    host = index['identities'].get(_key(row['hostIdentityRef']))
    plugin = index['identities'].get(_key(row['identityRef']))
    if (row['status'] != 'active'
            or host is None or host['kind'] != 'service' or not _active(host, now)
            or plugin is None or not _active(plugin, now)
            or host_transport['identityRef'] != host['ref']
            or claims['nativeFactsDigest'] != payload_digest(row['facts'])):
        raise ContractError('capability_service_native_unavailable')
    grants = [g for g in state['grants'] if _active(g, now)
        and g['callerRef'] == host['ref'] and g['actorRef'] == host['ref']
        and g['scope'] == claims['scope'] and g['resourceId'] == row['owner']['instanceId']
        and g['contractId'] == 'native-authority-prepare-domain-call' and g['delegationRef'] is None]
    if (not any(g['decision'] == 'allowed' for g in grants)
            or any(g['decision'] == 'denied' for g in grants)
            or not any(_active(m, now) and m['identityRef'] == host['ref']
                       and m['scope'] == claims['scope'] for m in state['memberships'])):
        raise ContractError('capability_service_native_unavailable')
    # Resolve exact current ancestry from this same snapshot. Go remains the
    # authority for package intersection and original parent process lifetime.
    end = min(end, validate_native_lineage(state, index, row, now))
    check_domain_binding(row, binding_id=None, contract=contract, resource=claims['resourceRef']['id'],
                         scope=claims['scope'], now=now)
    if contract == 'capability-outcome-query':
        # Recovery requires the native instance's original permission as well
        # as the human original grant checked by evaluate_snapshot below.
        check_domain_binding(row, binding_id=None, contract=envelope['payload']['input']['contractId'],
            resource=claims['resourceRef']['id'], scope=claims['scope'], now=now)
    for timed in (row['facts']['grant'], row['facts']['policy']):
        start, expiry = (datetime.fromisoformat(timed[k]) for k in ('issuedAt', 'expiresAt'))
        if not start <= now < expiry:
            raise ContractError('capability_service_expired')
        end = min(end, expiry)
    decision = evaluate_snapshot(snapshot, encoded,
        audience={'hubId': claims['hubId'], 'serviceId': service_id}, now=now)
    if decision.outcome != 'allowed':
        raise ContractError('capability_service_not_authorized')
    return replace(decision, valid_until=min(end, decision.valid_until))
