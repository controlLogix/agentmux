"""Authorize subscriptions and unchanged producer events against retained pins."""
import hashlib

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from .authority import evaluate_snapshot, _indexes, _key
from .downstream import check_domain_binding, prepare_domain_envelope


def _original(snapshot, raw, inp, row, now):
    original = strict_loads(raw)
    validate('message-envelope', original)
    decision = evaluate_snapshot(snapshot, raw, audience={
        'hubId': original['destinationHubId'], 'serviceId': original['destinationServiceId']}, now=now)
    record = strict_loads(snapshot.record)
    reference = inp['operationAuthorityRef']
    if (decision.outcome != 'allowed' or decision.valid_until is None
            or strict_loads(decision.operation) != inp['operation']
            or reference['id'] != record['entityId'] or reference['ownerHubId'] != record['ownerHubId']
            or not 0 < reference['revision'] <= record['entityVersion']):
        raise ContractError('native_subscription_operation_binding')
    payload = original['payload']
    resource = (payload.get('taskId') or payload.get('definitionId') or payload.get('authorityId')
                or payload.get('resourceRef', {}).get('id'))
    check_domain_binding(row, binding_id=None, contract=original['contractId'], resource=resource,
                         scope=inp['operation']['scope'], now=now)
    return decision


def _filter(row, payload, scope, now, binding_id=None):
    validate('configuration-change-subscribe', payload)
    ref = payload['resourceRef']
    binding = check_domain_binding(row, binding_id=binding_id, contract='configuration-change-subscribe',
        resource=ref['id'], scope=scope, now=now)
    pins = [s for s in row.get('configurationEventSources', [])
            if all(s['configurationRef'][k] == ref[k] for k in ('id', 'ownerHubId'))]
    if (binding['action'] != 'subscribe' or binding['resourceClass'] != 'configuration' or len(pins) != 1
            or payload['filter']['owner'] != row['owner']):
        raise ContractError('native_subscription_source_binding')
    pin = pins[0]
    if (payload['filter']['schemaRef'] != pin['schemaRef']
            or payload['cursor']['sourceDigest'] != pin['sourceDigest']
            or payload['cursor']['streamCreated'] != pin['streamCreated']
            or ref['revision'] < pin['configurationRef']['revision']):
        raise ContractError('native_subscription_source_binding')


def prepare_subscription(snapshot, original_raw, inp, row, *, issuer, signing_seed, now, end):
    if inp['contractId'] != 'configuration-change-subscribe':
        raise ContractError('native_subscription_contract')
    _filter(row, inp['payload'], inp['operation']['scope'], now, inp['bindingId'])
    return prepare_domain_envelope(snapshot, original_raw, inp, row, issuer=issuer,
        signing_seed=signing_seed, now=now, end=end, configuration_subscription=True)


def admit_event(snapshot, original_raw, subscription_raw, event_raw, inp, row, *, now, end):
    original_decision = _original(snapshot, original_raw, inp, row, now)
    subscription, event = strict_loads(subscription_raw), strict_loads(event_raw)
    for envelope in (subscription, event):
        validate('message-envelope', envelope)
    if (subscription['contractId'] != 'configuration-change-subscribe' or subscription['kind'] != 'command'
            or event['contractId'] != 'configuration-change' or event['kind'] != 'event'):
        raise ContractError('native_subscription_contract')
    hub = strict_loads(snapshot.record)['ownerHubId']
    audience = {'hubId': hub, 'serviceId': 'configuration-owner'}
    decisions = [evaluate_snapshot(snapshot, raw, audience=audience, now=now)
                 for raw in (subscription_raw, event_raw)]
    if any(d.outcome != 'allowed' or d.valid_until is None for d in decisions):
        raise ContractError('native_subscription_not_authorized')
    source, operation = inp['operation'], subscription['operation']
    preserved = ('caller', 'effectiveActorRef', 'scope', 'taskId', 'runId', 'attemptId',
                 'delegationRef', 'traceId', 'cancellationRef')
    expected_id = 'downstream_' + hashlib.sha256(
        (source['operationId'] + '\0' + subscription['correlationId']).encode()).hexdigest()
    if (any(operation[k] != source[k] for k in preserved)
            or operation['causationId'] != source['operationId'] or operation['operationId'] != expected_id):
        raise ContractError('native_subscription_operation_binding')
    payload, emitted = subscription['payload'], event['payload']
    _filter(row, payload, source['scope'], now)
    ref = payload['resourceRef']
    if (any(emitted['configurationRef'][k] != ref[k] for k in ('id', 'ownerHubId'))
            or emitted['configurationRef']['revision'] < ref['revision']
            or emitted['configurationRef']['revision'] <= payload['cursor']['sequence']
            or emitted['owner'] != payload['filter']['owner']
            or emitted['schemaRef'] != payload['filter']['schemaRef']
            or event['operation']['scope'] != source['scope']):
        raise ContractError('native_subscription_event_binding')
    state = strict_loads(snapshot.record)['state']
    index = _indexes(state, hub)
    issuer = index['issuers'].get(_key(event['ingressAttestation']['claims']['signingKeyRef']))
    if issuer is None or issuer['identityRef'] != event['operation']['caller']['authenticatedIdentityRef']:
        raise ContractError('native_subscription_producer_binding')
    return canonical_bytes(emitted), min(end, original_decision.valid_until, *(d.valid_until for d in decisions))
