"""Prepare ordinary configuration reads under current native and host authority."""
import uuid
import base64
import hashlib

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from .authority import _active, evaluate_snapshot


def prepare_configuration_envelope(snapshot, claims, row, *, host, transport, issuer, signing_seed, now, end):
    inp = claims['input']
    if claims['method'] == 'prepare-configuration-initialization':
        contract, payload = 'configuration-set', inp['payload']
        validate(contract, payload)
        reference = payload['configurationRef']
        try:
            raw = base64.b64decode(payload['configurationBytes'], validate=True)
        except (ValueError, TypeError):
            raise ContractError('native_configuration_binding') from None
        if (payload['owner'] != row['owner']
                or reference['revision'] + 1 != row['facts']['configurationRevision']
                or base64.b64encode(raw).decode() != payload['configurationBytes']
                or 'sha256:' + hashlib.sha256(raw).hexdigest() != row['configurationChecksum']
                or payload['secretReferences'] != row['facts']['secretReferences']):
            raise ContractError('native_configuration_binding')
    else:
        contract, reference = inp['contractId'], inp['configurationRef']
        if contract not in ('configuration-read', 'configuration-watch'):
            raise ContractError('native_configuration_binding')
        payload = {'configurationRef': reference, 'owner': row['owner']}
        if contract == 'configuration-watch':
            payload['afterRevision'] = inp['afterRevision']
    hub = claims['hubId']
    if reference['ownerHubId'] != hub or inp['cancellationRef']['ownerHubId'] != hub:
        raise ContractError('native_configuration_binding')
    validate(contract, payload)
    state = strict_loads(snapshot.record)['state']
    scope = row['facts']['grant']['scope']
    grants = [g for g in state['grants'] if _active(g, now)
              and g['callerRef'] == host['ref'] and g['actorRef'] == host['ref']
              and g['scope'] == scope and g['contractId'] == contract
              and g['resourceId'] == reference['id'] and g['delegationRef'] is None
              and g['decision'] != 'denied']
    if len(grants) != 1:
        raise ContractError('native_configuration_grant_unavailable')
    stamp = lambda value: value.isoformat(timespec='microseconds').replace('+00:00', 'Z')
    operation_id = 'configuration_' + payload_digest(claims).split(':')[1]
    operation = {'schemaVersion':'1.0.0', 'operationId':operation_id,
        'payloadDigest':payload_digest(payload), 'expectedVersion':reference['revision'],
        'caller':{'principalId':host['principalId'], 'kind':host['kind'], 'authenticatedIdentityRef':host['ref']},
        'effectiveActorRef':host['ref'], 'scope':scope, 'taskId':None, 'runId':None, 'attemptId':None,
        'delegationRef':None, 'grantRef':grants[0]['ref'], 'approvalRefs':[],
        'traceId':operation_id, 'causationId':claims['requestId'], 'deadline':stamp(end),
        'cancellationRef':inp['cancellationRef']}
    operation['approvalRefs'] = [a['ref'] for a in state['approvals'] if _active(a, now)
        and a['operationId'] == operation_id and a['payloadDigest'] == operation['payloadDigest']
        and a['grantRef'] == operation['grantRef']]
    signed = {'purpose':'agentmux-ingress-v1', 'issuerHubId':hub, 'signingKeyRef':issuer['ref'],
        'authenticationMethod':transport['method'], 'authenticatedTransportRef':transport['ref'],
        'audience':{'hubId':hub, 'serviceId':'configuration-owner'}, 'issuedAt':stamp(now), 'expiresAt':stamp(end),
        'messageId':'message-'+uuid.uuid4().hex, 'kind':'command', 'contractId':contract, 'contractMajor':1,
        'sourceHubId':hub, 'sourceInstanceId':issuer['instanceId'], 'sentAt':stamp(now),
        'correlationId':claims['requestId'], 'operation':operation}

    def encode():
        envelope = {key:signed[key] for key in ('messageId','kind','contractId','contractMajor',
                    'sourceHubId','sourceInstanceId','sentAt','correlationId','operation')}
        envelope.update(schemaVersion='1.0.0', destinationHubId=hub, destinationServiceId='configuration-owner',
            payload=payload, ingressAttestation={'schemaVersion':'1.0.0', 'algorithm':'Ed25519',
                'canonicalization':'RFC8785-JCS-UTF8', 'claims':signed, 'signature':sign_claims(signed, signing_seed)})
        return canonical_bytes(envelope)

    raw = encode()
    decision = evaluate_snapshot(snapshot, raw, audience=signed['audience'], now=now)
    if decision.outcome != 'allowed' or decision.valid_until is None:
        raise ContractError('native_configuration_not_authorized')
    # Authorization may shorten the original request, but must never renew it.
    end = min(end, decision.valid_until)
    operation['deadline'] = signed['expiresAt'] = stamp(end)
    raw = encode()
    checked = evaluate_snapshot(snapshot, raw, audience=signed['audience'], now=now)
    if checked.outcome != 'allowed':
        raise ContractError('native_configuration_not_authorized')
    return raw, checked
