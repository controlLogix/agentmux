"""Create a fresh, independently authorized domain operation from admitted lineage."""
import hashlib
import uuid

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from .authority import _active, evaluate_snapshot
from .capability_routes import CAPABILITY_DESTINATIONS

CAPABILITY_REPLIES = {name: name + '-reply' for name in CAPABILITY_DESTINATIONS}
for _name in ('capability-storage-read', 'capability-artifact-read', 'capability-workspace-read'):
    CAPABILITY_REPLIES[_name] = 'capability-content-reply'


def check_domain_binding(row, *, binding_id, contract, resource, scope, now):
    facts = row['facts']
    bindings = [b for b in facts['domainBindings'] if b['contractId'] == contract
                and (binding_id is None or b['id'] == binding_id) and resource in b['resourceIds']]
    if len(bindings) != 1 or facts['grant']['scope'] != scope:
        raise ContractError('native_operation_binding')
    binding = bindings[0]
    access = {'action': binding['action'], 'resourceClass': binding['resourceClass'], 'resourceId': resource}
    outcomes = [d['outcome'] for d in facts['policy']['decisions'] if d['access'] == access]
    if (binding['action'] not in facts['grant']['actions'] or resource not in facts['grant']['resourceIds']
            or not outcomes or any(outcome != 'allow' for outcome in outcomes)):
        raise ContractError('native_operation_not_authorized')
    return binding


def prepare_domain_envelope(snapshot, original_bytes, inp, row, *, issuer, signing_seed, now, end,
                            configuration_subscription=False):
    original = strict_loads(original_bytes)
    audience = {'hubId': original['destinationHubId'], 'serviceId': original['destinationServiceId']}
    admitted = evaluate_snapshot(snapshot, original_bytes, audience=audience, now=now)
    record = strict_loads(snapshot.record)
    reference = inp['operationAuthorityRef']
    if (admitted.outcome != 'allowed' or strict_loads(admitted.operation) != inp['operation']
            or reference['id'] != record['entityId'] or reference['ownerHubId'] != record['ownerHubId']
            or not 0 < reference['revision'] <= record['entityVersion']):
        raise ContractError('native_operation_binding')
    contract, payload = inp['contractId'], inp['payload']
    destination = CAPABILITY_DESTINATIONS.get(contract)
    if configuration_subscription:
        if contract != 'configuration-change-subscribe':
            raise ContractError('native_downstream_contract_unavailable')
        destination = 'configuration-owner'
    if destination is None:
        raise ContractError('native_downstream_contract_unavailable')
    validate(contract, payload)
    source = strict_loads(admitted.operation)
    original_payload = original['payload']
    original_resource = (original_payload.get('taskId') or original_payload.get('definitionId')
        or original_payload.get('authorityId') or original_payload.get('resourceRef', {}).get('id'))
    check_domain_binding(row, binding_id=None, contract=original['contractId'],
        resource=original_resource, scope=source['scope'], now=now)
    resource = payload['resourceRef']
    if resource['ownerHubId'] != record['ownerHubId']:
        raise ContractError('native_operation_binding')
    check_domain_binding(row, binding_id=inp['bindingId'], contract=contract,
                         resource=resource['id'], scope=source['scope'], now=now)
    grants = [g for g in record['state']['grants'] if _active(g, now)
              and g['callerRef'] == source['caller']['authenticatedIdentityRef']
              and g['actorRef'] == source['effectiveActorRef'] and g['scope'] == source['scope']
              and g['contractId'] == contract and g['resourceId'] == resource['id']
              and g['delegationRef'] == source['delegationRef'] and g['decision'] != 'denied']
    if len(grants) != 1:
        raise ContractError('native_downstream_grant_unavailable')
    operation = strict_loads(canonical_bytes(source))
    operation.update(operationId='downstream_' + hashlib.sha256(
        (source['operationId'] + '\0' + inp['serviceRequestId']).encode()).hexdigest(),
        causationId=source['operationId'], payloadDigest=payload_digest(payload),
        expectedVersion=resource['revision'], grantRef=grants[0]['ref'], approvalRefs=[])
    operation['approvalRefs'] = [a['ref'] for a in record['state']['approvals']
        if _active(a, now) and a['operationId'] == operation['operationId']
        and a['payloadDigest'] == operation['payloadDigest'] and a['grantRef'] == operation['grantRef']]
    end = min(end, admitted.valid_until)
    stamp = lambda value: value.isoformat(timespec='microseconds').replace('+00:00', 'Z')
    # Retain the source's business deadline across attempts. The fresh signed
    # attestation below limits this delivery to the current authority window.
    # Changing the operation here makes an exact replay conflict with its record.
    signed = strict_loads(canonical_bytes(original['ingressAttestation']['claims']))
    # The enrolled issuer may attest this caller only through its retained transport mapping.
    signed.update(signingKeyRef=issuer['ref'], sourceInstanceId=issuer['instanceId'],
        audience={'hubId': record['ownerHubId'], 'serviceId': destination},
        issuedAt=stamp(now), expiresAt=stamp(end), messageId='message-' + uuid.uuid4().hex,
        contractId=contract, sentAt=stamp(now), correlationId=inp['serviceRequestId'], operation=operation)
    envelope = {key: signed[key] for key in ('messageId', 'kind', 'contractId', 'contractMajor',
                'sourceHubId', 'sourceInstanceId', 'sentAt', 'correlationId', 'operation')}
    envelope.update(schemaVersion='1.0.0', destinationHubId=record['ownerHubId'],
        destinationServiceId=destination, payload=payload,
        ingressAttestation={'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': signed,
            'signature': sign_claims(signed, signing_seed)})
    raw = canonical_bytes(envelope)
    checked = evaluate_snapshot(snapshot, raw, audience=signed['audience'], now=now)
    if checked.outcome != 'allowed':
        raise ContractError('native_downstream_not_authorized')
    return raw, checked
