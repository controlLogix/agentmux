"""Authenticate subscription controls without granting reads during cleanup."""
from dataclasses import dataclass
from datetime import datetime, timedelta

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from .authority import _active, _indexes, _key, evaluate_snapshot
from .ingress import verify_possession
from .native_bridge import _decode
from .native_records import validate_native_lineage
from .native_subscriptions import _filter


@dataclass(frozen=True, repr=False)
class SubscriptionAllocationAuthority:
    """Service-owned proof from an admitted open; never accept this from wire data."""
    open_claims: bytes
    subscription: bytes
    host_public_key: str
    authority_ref: bytes

    def __repr__(self):
        return '<SubscriptionAllocationAuthority private>'


@dataclass(frozen=True, repr=False)
class SubscriptionControlAdmission:
    action: str
    claims: bytes
    allocation: SubscriptionAllocationAuthority
    valid_until: datetime
    authority_ref: bytes
    can_read: bool

    def __repr__(self):
        return '<SubscriptionControlAdmission private>'


def evaluate_control(snapshot, raw, *, now, reply_subject, allocation=None,
                     expected_cursor=None, expected_lease_id=None):
    """Authenticate one control; the caller owns allocation lookup and joining.

    For next, supply the original allocation and its current cursor and lease ID.
    For close, the original allocation is required, but current read authority is
    deliberately not used. A null lease ID supports cleanup after a lost open reply.
    The caller must cancel and join the original allocation before reporting joined.
    """
    if type(raw) is not bytes or len(raw) > 65536:
        raise ContractError('subscription_control_body_limit')
    request = strict_loads(raw)
    validate('configuration-subscription-control', request)
    claims = request['claims']
    issued, end = (datetime.fromisoformat(claims[k]) for k in ('issuedAt', 'expiresAt'))
    if not issued <= now < end or end - issued > timedelta(seconds=5):
        raise ContractError('subscription_control_expired')
    if claims['replySubject'] != reply_subject:
        raise ContractError('subscription_control_reply_binding')
    action = claims['action']
    if allocation is not None:
        if not isinstance(allocation, SubscriptionAllocationAuthority):
            raise ContractError('subscription_control_allocation_required')
        opened = strict_loads(allocation.open_claims)
        bound = ('profileId', 'hubId', 'authorityId', 'owner', 'operationId', 'openRequestId',
                 'approvedEnvelopeDigest', 'filterDigest', 'signingKeyRef')
        if (any(claims[k] != opened[k] for k in bound)
                or any(claims['cursor'][k] != opened['cursor'][k] for k in ('sourceDigest', 'streamCreated'))
                or claims['cursor']['sequence'] < opened['cursor']['sequence']):
            raise ContractError('subscription_control_allocation_binding')
        verify_possession(claims, request['signature'], allocation.host_public_key)
        if claims['leaseId'] is not None and claims['leaseId'] != expected_lease_id:
            raise ContractError('subscription_control_lease_binding')
    elif action != 'open':
        raise ContractError('subscription_control_allocation_required')
    if action == 'close':
        # This result authorizes only cancellation/join. It must never reach next().
        return SubscriptionControlAdmission(action, canonical_bytes(claims), allocation,
            end, allocation.authority_ref, False)
    if action == 'next' and (expected_cursor is None or claims['cursor'] != expected_cursor
                            or expected_lease_id is None):
        raise ContractError('subscription_control_cursor_binding')
    if action == 'open' and (claims['openRequestId'] != claims['requestId']
                            or claims['leaseId'] is not None):
        raise ContractError('subscription_control_open_binding')

    record = strict_loads(snapshot.record)
    state, hub = record['state'], record['ownerHubId']
    if (claims['hubId'] != hub or claims['profileId'] != state['profileId']
            or claims['authorityId'] != record['entityId']):
        raise ContractError('subscription_control_profile_binding')
    index = _indexes(state, hub)
    transport = index['transports'].get(_key(claims['signingKeyRef']))
    issuer = None if transport is None else index['issuers'].get(_key(transport['issuerRef']))
    if (transport is None or not _active(transport, now) or transport['method'] != 'nats-credential-mapping'
            or issuer is None or not _active(issuer, now)
            or allocation is not None and transport['publicKey'] != allocation.host_public_key):
        raise ContractError('subscription_control_transport_unavailable')
    verify_possession(claims, request['signature'], transport['publicKey'])
    rows = [r for r in state.get('nativeInstances', []) if r['owner'] == claims['owner']]
    if len(rows) != 1 or rows[0]['hostIdentityRef'] != transport['identityRef']:
        raise ContractError('subscription_control_owner_binding')
    row = rows[0]
    end = min(end, validate_native_lineage(state, index, row, now))
    host = index['identities'].get(_key(transport['identityRef']))
    issuer_identity = index['identities'].get(_key(issuer['identityRef']))
    scope = row['facts']['grant']['scope']
    if (host is None or host['kind'] != 'service' or not _active(host, now)
            or issuer_identity is None or issuer_identity['kind'] != 'service' or not _active(issuer_identity, now)
            or not any(_active(m, now) and m['identityRef'] == host['ref'] and m['scope'] == scope
                       for m in state['memberships'])):
        raise ContractError('subscription_control_host_unavailable')
    grants = [g for g in state['grants'] if _active(g, now)
        and g['callerRef'] == host['ref'] and g['actorRef'] == host['ref'] and g['scope'] == scope
        and g['resourceId'] == row['owner']['instanceId'] and g['delegationRef'] is None
        and g['contractId'] == 'native-authority-prepare-subscription-call']
    if any(g['decision'] == 'denied' for g in grants) or not any(g['decision'] == 'allowed' for g in grants):
        raise ContractError('subscription_control_host_not_authorized')
    subscription = _decode(claims['subscriptionEnvelopeBytes']) if action == 'open' else allocation.subscription
    envelope = strict_loads(subscription)
    validate('message-envelope', envelope)
    if (envelope['contractId'] != 'configuration-change-subscribe' or envelope['kind'] != 'command'
            or payload_digest(envelope) != claims['approvedEnvelopeDigest']
            or envelope['operation']['operationId'] != claims['operationId']
            or envelope['payload']['filterDigest'] != claims['filterDigest']
            or action == 'open' and envelope['payload']['cursor'] != claims['cursor']
            or allocation is not None and subscription != allocation.subscription):
        raise ContractError('subscription_control_envelope_binding')
    _filter(row, envelope['payload'], scope, now)
    decision = evaluate_snapshot(snapshot, subscription,
        audience={'hubId': hub, 'serviceId': 'configuration-owner'}, now=now)
    if decision.outcome != 'allowed' or decision.valid_until is None:
        raise ContractError('subscription_control_not_authorized')
    authority_ref = canonical_bytes({'id': record['entityId'], 'ownerHubId': hub, 'revision': record['entityVersion']})
    if allocation is None:
        allocation = SubscriptionAllocationAuthority(canonical_bytes(claims), subscription,
            transport['publicKey'], authority_ref)
    end = min(end, decision.valid_until)
    return SubscriptionControlAdmission(action, canonical_bytes(claims), allocation, end, authority_ref, True)
