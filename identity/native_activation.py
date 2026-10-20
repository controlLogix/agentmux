"""Commit actual manager-allocated owners through ordinary identity authorization."""
from datetime import datetime, timezone

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from .authority import _active, _indexes, _key, evaluate_snapshot
from .native_records import validate_native_lineage
from .transitions import transition


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _admit(snapshot, claims, *, host, transport, issuer, now, end):
    record = strict_loads(snapshot.record)
    state, inp = record['state'], claims['input']
    row, scope = inp['record'], inp['record']['facts']['grant']['scope']
    index = _indexes(state, record['ownerHubId'])
    issuer_identity = index['identities'].get(_key(issuer['identityRef']))
    if (row['owner'] != claims['owner'] or row['hostIdentityRef'] != host['ref']
            or row['status'] != 'active' or inp['cancellationRef']['ownerHubId'] != claims['hubId']
            or row['manifestDigest'] != claims['owner']['pin']['manifestChecksum']
            or index['identities'].get(_key(host['ref'])) != host
            or index['transports'].get(_key(transport['ref'])) != transport
            or index['issuers'].get(_key(issuer['ref'])) != issuer
            or issuer_identity is None or issuer_identity['kind'] != 'service' or not _active(issuer_identity, now)
            or any(not _active(item, now) for item in (host, transport, issuer))):
        raise ContractError('native_activation_binding')
    grants = [g for g in state['grants'] if _active(g, now)
        and g['callerRef'] == host['ref'] and g['actorRef'] == host['ref'] and g['scope'] == scope
        and g['contractId'] == 'native-authority-activate-instance'
        and g['resourceId'] == row['owner']['instanceId'] and g['delegationRef'] is None]
    if (not any(m['identityRef'] == host['ref'] and m['scope'] == scope and _active(m, now) for m in state['memberships'])
            or any(g['decision'] == 'denied' for g in grants)
            or not any(g['decision'] == 'allowed' for g in grants)):
        raise ContractError('native_host_not_authorized')
    payload = {'authorityId':claims['authorityId'], 'record':row, 'previousRef':inp['previousRef']}
    retained = [r for r in state.get('nativeInstances', []) if r['ref'] == row['ref']]
    # A committed exact retry can read back its original row. Other revisions
    # still pass the ordinary transition's compare-and-set checks.
    proposed = state if retained == [row] else transition(state, 'identity-native-instance-set', payload, hub_id=claims['hubId'])
    end = min(end, validate_native_lineage(proposed, _indexes(proposed, claims['hubId']), row, now))
    for collection in ('issuers', 'transports', 'grants', 'approvals'):
        for item in state[collection]:
            if item['status'] != 'active':
                continue
            start, expiry = (datetime.fromisoformat(item[k]) for k in ('issuedAt', 'expiresAt'))
            if start > now:
                end = min(end, start)
            elif expiry > now:
                end = min(end, expiry)
    if not now < end:
        raise ContractError('native_request_expired')
    return record, payload, end


async def activate_instance(provider, snapshot, claims, *, host, transport, issuer, now, end):
    if provider._command_owner is None:
        raise ContractError('native_activation_writer_unavailable')
    record, payload, end = _admit(snapshot, claims, host=host, transport=transport, issuer=issuer, now=now, end=end)
    operation_id = 'activation_' + payload_digest(claims).split(':')[1]
    expected = claims['input']['expectedVersion']
    if expected != record['entityVersion']:
        # A new write must compare against the very snapshot that admitted its
        # native method and lineage. Only an exact committed operation may use
        # an older version; the command owner still reauthorizes that replay.
        prior = await provider._reader._ledger.outcome(operation_id, payload_digest(payload))
        stored = None if prior is None else strict_loads(prior.record)
        if (expected >= record['entityVersion'] or stored is None
                or stored['outcome'] != 'committed'
                or stored['operation']['operationId'] != operation_id
                or stored['operation']['expectedVersion'] != expected
                or stored['operation']['payloadDigest'] != payload_digest(payload)
                or stored['authorizationDecision']['decision'] != 'allowed'
                or stored['authorizationDecision']['contractId'] != 'identity-native-instance-set'):
            raise ContractError('native_activation_version_mismatch')
    scope = {'organizationId':record['state']['organizationId'], 'projectId':None, 'workspaceId':None}
    grants = [g for g in record['state']['grants'] if _active(g, now)
        and g['callerRef'] == host['ref'] and g['actorRef'] == host['ref'] and g['scope'] == scope
        and g['contractId'] == 'identity-native-instance-set' and g['resourceId'] == claims['authorityId']
        and g['delegationRef'] is None and g['decision'] != 'denied']
    if len(grants) != 1:
        raise ContractError('native_activation_grant_unavailable')
    operation = {'schemaVersion':'1.0.0', 'operationId':operation_id, 'payloadDigest':payload_digest(payload),
        'expectedVersion':claims['input']['expectedVersion'], 'caller':{'principalId':host['principalId'],
            'kind':host['kind'], 'authenticatedIdentityRef':host['ref']}, 'effectiveActorRef':host['ref'],
        'scope':scope, 'taskId':None, 'runId':None, 'attemptId':None, 'delegationRef':None,
        'grantRef':grants[0]['ref'], 'approvalRefs':[], 'traceId':operation_id, 'causationId':claims['requestId'],
        'deadline':_stamp(end), 'cancellationRef':claims['input']['cancellationRef']}
    operation['approvalRefs'] = [a['ref'] for a in record['state']['approvals'] if _active(a, now)
        and a['operationId'] == operation_id and a['payloadDigest'] == operation['payloadDigest']
        and a['grantRef'] == operation['grantRef']]
    signed = {'purpose':'agentmux-ingress-v1', 'issuerHubId':claims['hubId'], 'signingKeyRef':issuer['ref'],
        'authenticationMethod':transport['method'], 'authenticatedTransportRef':transport['ref'],
        'audience':{'hubId':claims['hubId'], 'serviceId':'identity-owner'}, 'issuedAt':_stamp(now), 'expiresAt':_stamp(end),
        'messageId':operation_id, 'kind':'command', 'contractId':'identity-native-instance-set', 'contractMajor':1,
        'sourceHubId':claims['hubId'], 'sourceInstanceId':issuer['instanceId'], 'sentAt':_stamp(now),
        'correlationId':claims['requestId'], 'operation':operation}
    envelope = {k:signed[k] for k in ('messageId','kind','contractId','contractMajor','sourceHubId',
                'sourceInstanceId','sentAt','correlationId','operation')}
    envelope.update(schemaVersion='1.0.0', destinationHubId=claims['hubId'], destinationServiceId='identity-owner',
        payload=payload, ingressAttestation={'schemaVersion':'1.0.0', 'algorithm':'Ed25519',
            'canonicalization':'RFC8785-JCS-UTF8', 'claims':signed, 'signature':sign_claims(signed, provider._seed)})
    raw = canonical_bytes(envelope)
    decision = evaluate_snapshot(snapshot, raw, audience=signed['audience'], now=now)
    if decision.outcome != 'allowed':
        raise ContractError('native_activation_not_authorized')
    receipt = await provider._command_owner.execute(raw)
    if receipt.decision != 'allowed':
        raise ContractError('native_activation_not_committed')
    current = await provider._reader.current()
    now = datetime.now(timezone.utc)
    latest, _, end = _admit(current, claims, host=host, transport=transport, issuer=issuer, now=now, end=end)
    decision = evaluate_snapshot(current, raw, audience=signed['audience'], now=now)
    row = claims['input']['record']
    if (decision.outcome != 'allowed' or decision.valid_until is None
            or current.sequence < receipt.sequence or row not in latest['state'].get('nativeInstances', [])):
        raise ContractError('native_activation_readback_refused')
    end = min(end, decision.valid_until)
    signed = {'purpose':'agentmux-native-authority-response-v1',
        **{k:claims[k] for k in ('requestId','method','profileId','hubId','authorityId','owner')},
        'requestDigest':payload_digest(claims), 'signingKeyRef':issuer['ref'],
        'authorityRef':{'id':latest['entityId'],'ownerHubId':latest['ownerHubId'],'revision':latest['entityVersion']},
        'authoritySequence':current.sequence, 'issuedAt':_stamp(now), 'validUntil':_stamp(end), 'outcome':'allowed',
        'result':{'enrollmentRef':row['ref'], 'facts':row['facts']}}
    response = {'schemaVersion':'1.0.0','algorithm':'Ed25519','canonicalization':'RFC8785-JCS-UTF8',
        'claims':signed,'signature':sign_claims(signed,provider._seed)}
    validate('native-authority-response',response)
    encoded = canonical_bytes(response)
    if len(encoded)>65536:
        raise ContractError('owner_body_limit')
    return encoded
