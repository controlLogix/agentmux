"""Resolve enrolled native facts without reimplementing Go capability intersection."""
import base64
from datetime import datetime, timezone, timedelta

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from .authority import _active, _indexes, _key, evaluate_snapshot
from .ingress import verify_possession
from .native_records import validate_native_lineage


def _decode(value):
    try:
        decoded = base64.b64decode(value, validate=True)
        if base64.b64encode(decoded).decode() != value or len(decoded) > 65536:
            raise ValueError()
        return decoded
    except (ValueError, TypeError):
        raise ContractError('native_envelope_encoding') from None


def _time(value):
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        raise ContractError('authority_time_invalid') from None


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def verify_response(raw, request_raw, *, public_key, signing_key_ref, now):
    """A trusted enrolled key is supplied by the host, never by the response."""
    if type(raw) is not bytes or len(raw) > 65536:
        raise ContractError('owner_body_limit')
    response, request = strict_loads(raw), strict_loads(request_raw)
    validate('native-authority-response', response)
    validate('native-authority-request', request)
    claims, wanted = response['claims'], request['claims']
    verify_possession(claims, response['signature'], public_key)
    if (claims['signingKeyRef'] != signing_key_ref
            or claims['requestDigest'] != payload_digest(wanted)
            or any(claims[k] != wanted[k] for k in
                   ('requestId', 'method', 'profileId', 'hubId', 'authorityId', 'owner'))
            or not _time(claims['issuedAt']) <= now < _time(claims['validUntil'])
            or _time(claims['validUntil']) > _time(wanted['expiresAt'])):
        raise ContractError('native_response_binding')
    return strict_loads(canonical_bytes(claims))


class NativeAuthorityProvider:
    """Read persisted native-instance facts from the enrolled identity aggregate.

    Requests require an enrolled service transport and an exact method grant for
    the persisted instance. Native host code still owns live generation checks
    and calls EvaluateCapabilityGrant. No caller-provided fact source is accepted.
    """
    def __init__(self, reader, *, issuer_ref, signing_seed, command_owner=None):
        from .authority import LedgerAuthorityReader
        from .commands import IdentityCommandOwner
        if (not isinstance(reader, LedgerAuthorityReader)
                or type(signing_seed) is not bytes or len(signing_seed) != 32
                or command_owner is not None and (not isinstance(command_owner, IdentityCommandOwner)
                    or command_owner._ledger is not reader._ledger)):
            raise ContractError('native_provider_configuration')
        self._reader, self._issuer, self._seed = reader, canonical_bytes(issuer_ref), signing_seed
        self._command_owner = command_owner

    def __repr__(self):
        return '<NativeAuthorityProvider private>'

    async def handle(self, raw):
        if type(raw) is not bytes or len(raw) > 65536:
            raise ContractError('owner_body_limit')
        request = strict_loads(raw)
        validate('native-authority-request', request)
        claims = request['claims']
        snapshot = await self._reader.current()
        now = datetime.now(timezone.utc)
        record = strict_loads(snapshot.record)
        state = record['state']
        index = _indexes(state, record['ownerHubId'])
        if (claims['hubId'] != record['ownerHubId'] or claims['authorityId'] != record['entityId']
                or claims['profileId'] != state['profileId']):
            raise ContractError('native_profile_mismatch')
        issued, end = _time(claims['issuedAt']), _time(claims['expiresAt'])
        if not issued <= now < end or end - issued > timedelta(seconds=5):
            raise ContractError('native_request_expired')
        issuer = index['issuers'].get(_key(strict_loads(self._issuer)))
        transport = index['transports'].get(_key(claims['signingKeyRef']))
        if (issuer is None or transport is None or not _active(issuer, now)
                or not _active(transport, now) or transport['issuerRef'] != issuer['ref']
                or transport['method'] != 'nats-credential-mapping'):
            raise ContractError('native_credential_unavailable')
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')
        issuer_identity = index['identities'].get(_key(issuer['identityRef']))
        host = index['identities'].get(_key(transport['identityRef']))
        if (public != issuer['publicKey'] or issuer_identity is None or not _active(issuer_identity, now)
                or host is None or host['kind'] != 'service' or not _active(host, now)):
            raise ContractError('native_credential_unavailable')
        verify_possession(claims, request['signature'], transport['publicKey'])
        if claims['method'] == 'activate-instance':
            from .native_activation import activate_instance
            return await activate_instance(self, snapshot, claims, host=host, transport=transport,
                issuer=issuer, now=now, end=end)
        rows = [r for r in state.get('nativeInstances', []) if r['owner'] == claims['owner']]
        if len(rows) != 1:
            raise ContractError('native_instance_unavailable')
        row = rows[0]
        identity = index['identities'].get(_key(row['identityRef']))
        if (row['status'] != 'active' or row['hostIdentityRef'] != host['ref']
                or identity is None or not _active(identity, now)):
            raise ContractError('native_instance_unavailable')
        facts = row['facts']
        scope = facts['grant']['scope']
        grants = [g for g in state['grants'] if _active(g, now)
                  and g['callerRef'] == host['ref'] and g['actorRef'] == host['ref']
                  and g['scope'] == scope and g['contractId'] == 'native-authority-' + claims['method']
                  and g['resourceId'] == row['owner']['instanceId'] and g['delegationRef'] is None]
        if (not any(m['identityRef'] == host['ref'] and m['scope'] == scope and _active(m, now)
                    for m in state['memberships'])
                or any(g['decision'] == 'denied' for g in grants)
                or not any(g['decision'] == 'allowed' for g in grants)):
            raise ContractError('native_host_not_authorized')
        end = min(end, validate_native_lineage(state, index, row, now))
        for timed in (facts['grant'], facts['policy']):
            if not _time(timed['issuedAt']) <= now < _time(timed['expiresAt']):
                raise ContractError('native_facts_expired')
            end = min(end, _time(timed['expiresAt']))
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            for item in state[collection]:
                if item['status'] != 'active':
                    continue
                start, expiry = _time(item['issuedAt']), _time(item['expiresAt'])
                if start > now:
                    end = min(end, start)
                elif expiry > now:
                    end = min(end, expiry)
        inp, method = claims['input'], claims['method']
        authority_ref = {'id': record['entityId'], 'ownerHubId': record['ownerHubId'],
                         'revision': record['entityVersion']}
        if method == 'bind-instance':
            if any(inp[k] != row[k] for k in
                   ('manifestDigest', 'relationship', 'parentOwner', 'configurationChecksum')):
                raise ContractError('native_declaration_mismatch')
            result = facts
        elif method in ('admit-operation', 'recheck'):
            original = inp['envelopeBytes'] if method == 'admit-operation' else inp['originalEnvelopeBytes']
            if method == 'recheck' and inp['instanceFactsDigest'] != payload_digest(facts):
                raise ContractError('native_facts_changed')
            if original is None:
                if inp['operation'] is not None or inp['operationAuthorityRef'] is not None:
                    raise ContractError('native_operation_binding')
                result = {**facts, 'operationAuthorityRef': None}
            else:
                encoded = _decode(original)
                envelope = strict_loads(encoded)
                validate('message-envelope', envelope)
                audience = {'hubId': envelope['destinationHubId'], 'serviceId': envelope['destinationServiceId']}
                if method == 'admit-operation' and audience != inp['audience']:
                    raise ContractError('native_operation_binding')
                decision = evaluate_snapshot(snapshot, encoded, audience=audience, now=now)
                if decision.outcome != 'allowed':
                    raise ContractError('native_operation_not_authorized')
                operation = strict_loads(decision.operation)
                payload = envelope['payload']
                resource = (payload.get('taskId') or payload.get('definitionId')
                            or payload.get('authorityId') or payload.get('resourceRef', {}).get('id'))
                if operation['scope'] != scope or not any(
                        b['contractId'] == envelope['contractId'] and resource in b['resourceIds']
                        for b in facts['domainBindings']):
                    raise ContractError('native_operation_binding')
                if method == 'recheck' and (inp['operation'] != operation
                        or inp['operationAuthorityRef'] is None
                        or inp['operationAuthorityRef']['id'] != record['entityId']
                        or inp['operationAuthorityRef']['ownerHubId'] != record['ownerHubId']
                        or not 0 < inp['operationAuthorityRef']['revision'] <= record['entityVersion']):
                    raise ContractError('native_operation_binding')
                end = min(end, _time(operation['deadline']),
                          _time(envelope['ingressAttestation']['claims']['expiresAt']))
                result = ({'operation': operation, 'authorityRef': authority_ref}
                          if method == 'admit-operation' else {**facts, 'operationAuthorityRef': authority_ref})
        elif method in ('prepare-configuration-request', 'prepare-configuration-initialization'):
            from .native_configuration import prepare_configuration_envelope
            downstream, decision = prepare_configuration_envelope(snapshot, claims, row,
                host=host, transport=transport, issuer=issuer, signing_seed=self._seed, now=now, end=end)
            end = min(end, decision.valid_until)
            result = {'envelopeBytes': base64.b64encode(downstream).decode()}
        elif method == 'prepare-subscription-call':
            from .native_subscriptions import prepare_subscription
            downstream, decision = prepare_subscription(snapshot, _decode(inp['originalEnvelopeBytes']),
                inp, row, issuer=issuer, signing_seed=self._seed, now=now, end=end)
            end = min(end, decision.valid_until)
            result = {'bindingId': inp['bindingId'], 'envelopeBytes': base64.b64encode(downstream).decode()}
        elif method == 'admit-domain-event':
            from .native_subscriptions import admit_event
            payload, end = admit_event(snapshot, _decode(inp['originalEnvelopeBytes']),
                _decode(inp['subscriptionEnvelopeBytes']), _decode(inp['eventEnvelopeBytes']),
                inp, row, now=now, end=end)
            result = {'payloadBytes': base64.b64encode(payload).decode()}
        elif method == 'prepare-domain-call':
            from .downstream import prepare_domain_envelope, CAPABILITY_REPLIES
            from .capability_service import evaluate_capability_service_request
            downstream, decision = prepare_domain_envelope(snapshot, _decode(inp['originalEnvelopeBytes']),
                inp, row, issuer=issuer, signing_seed=self._seed, now=now, end=end)
            inner = strict_loads(downstream)
            end = min(end, decision.valid_until)
            service_claims = {'purpose': 'agentmux-capability-service-request-v1',
                **{k: claims[k] for k in ('profileId', 'hubId', 'authorityId', 'owner')},
                'requestId': inp['serviceRequestId'], 'serviceId': inner['destinationServiceId'],
                'requestContractId': inp['contractId'], 'replyContractId': CAPABILITY_REPLIES[inp['contractId']],
                'operationId': inner['operation']['operationId'], 'resourceRef': inner['payload']['resourceRef'],
                'scope': inner['operation']['scope'], 'replySubject': inp['serviceReplySubject'],
                'issuedAt': _stamp(now), 'validUntil': _stamp(end), 'signingKeyRef': issuer['ref'],
                'hostTransportRef': transport['ref'], 'nativeFactsDigest': payload_digest(facts),
                'envelopeBytes': base64.b64encode(downstream).decode()}
            service_request = canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
                'canonicalization': 'RFC8785-JCS-UTF8', 'claims': service_claims,
                'signature': sign_claims(service_claims, self._seed)})
            evaluate_capability_service_request(snapshot, service_request,
                service_id=inner['destinationServiceId'], now=now)
            result = {'bindingId': inp['bindingId'], 'envelopeBytes': base64.b64encode(downstream).decode(),
                      'serviceRequestBytes': base64.b64encode(service_request).decode()}
        else:
            raise ContractError('native_downstream_authority_unavailable')
        signed = {'purpose': 'agentmux-native-authority-response-v1',
            **{k: claims[k] for k in ('requestId', 'method', 'profileId', 'hubId', 'authorityId', 'owner')},
            'requestDigest': payload_digest(claims), 'signingKeyRef': strict_loads(self._issuer),
            'authorityRef': authority_ref, 'authoritySequence': snapshot.sequence,
            'issuedAt': _stamp(now), 'validUntil': _stamp(end), 'outcome': 'allowed', 'result': result}
        response = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': signed, 'signature': sign_claims(signed, self._seed)}
        validate('native-authority-response', response)
        encoded = canonical_bytes(response)
        if len(encoded) > 65536:
            raise ContractError('owner_body_limit')
        return encoded
