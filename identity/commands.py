"""Prepare complete identity-owner records using current authenticated authority.

The shared state_owner ledger performs replay lookup and conditional append.
This module never writes a projection or maintains a second authority store.
Prepared records are not committed outcomes.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import uuid

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from .authority import evaluate_snapshot, _indexes, _key, _active
from .transitions import transition
from .capacity import require_state_capacity, require_operation_capacity

IDENTITY_COMMANDS = frozenset(('identity-enroll', 'identity-revoke', 'identity-membership-set',
                               'identity-grant-set', 'identity-approval-set', 'identity-native-instance-set',
                               'identity-legacy-alias-set', 'identity-external-account-link',
                               'identity-application-account-set', 'identity-ordinary-secret-set'))


@dataclass(frozen=True, repr=False)
class PreparedChange:
    record: bytes
    expected_sequence: int
    decision: str
    reason: str
    valid_until: datetime

    def __repr__(self):
        return f'<PreparedChange {self.decision} {self.reason} uncommitted>'


def prepare_change(snapshot, envelope_bytes, *, now=None):
    """Recompute after every CAS conflict; never append a stale prepared record."""
    if type(envelope_bytes) is not bytes or len(envelope_bytes) > 65536:
        raise ContractError('owner_body_limit')
    now = now if now is not None else datetime.now(timezone.utc)
    current = strict_loads(snapshot.record)
    if current['effects'] or current['artifacts'] or current['repository'] is not None:
        raise ContractError('identity_external_obligation_unavailable')
    envelope = strict_loads(envelope_bytes)
    if envelope.get('contractId') not in IDENTITY_COMMANDS:
        raise ContractError('identity_transition_unsupported')
    decision = evaluate_snapshot(snapshot, envelope_bytes,
        audience={'hubId': current['ownerHubId'], 'serviceId': 'identity-owner'}, now=now)
    # Never put an unauthenticated claimed author into an authoritative record.
    # Those failures require the ingress's bounded unattributed security audit.
    if decision.operation is None or decision.audit_actor is None:
        raise ContractError('identity_actor_unverified')
    operation = strict_loads(decision.operation)
    require_operation_capacity(operation)
    state = current['state']
    # The retained identity owner is organization-scoped. Preserve the original
    # signed operation; a different scope needs its own admitted audit owner.
    if operation['scope'] != {'organizationId': state['organizationId'],
                              'projectId': None, 'workspaceId': None}:
        raise ContractError('identity_audit_scope_unavailable')
    outcome, reason = decision.outcome, decision.reason
    if outcome == 'allowed' and envelope['contractId'] == 'identity-approval-set':
        approval = envelope['payload']['record']
        index = _indexes(state, current['ownerHubId'])
        target = index['grants'].get(_key(approval['grantRef']))
        approver_grant = index['grants'].get(_key(approval['approverGrantRef']))
        if (target is None or not _active(target, now)
                or approval['approverRef'] != operation['effectiveActorRef']
                or approver_grant is None or not _active(approver_grant, now)
                or approver_grant['callerRef'] != approval['approverRef']
                or approver_grant['actorRef'] != approval['approverRef']
                or approver_grant['contractId'] != 'identity-approve'
                or approver_grant['resourceId'] != target['ref']['id']
                or approver_grant['scope'] != target['scope']
                or approver_grant['decision'] != 'allowed'
                or approver_grant['delegationRef'] is not None
                or not any(m['identityRef'] == approval['approverRef'] and m['scope'] == target['scope']
                           and _active(m, now) for m in index['memberships'].values())
                or any(g['callerRef'] == approval['approverRef'] and g['actorRef'] == approval['approverRef']
                       and g['scope'] == target['scope'] and g['contractId'] == 'identity-approve'
                       and g['resourceId'] == target['ref']['id'] and g['decision'] == 'denied'
                       and _active(g, now) for g in index['grants'].values())):
            outcome, reason = 'denied', 'approval_authority_unavailable'
    if outcome == 'allowed':
        if envelope['contractId'] == 'identity-ordinary-secret-set':
            item = envelope['payload']['record']
            if not _active(item, now):
                outcome, reason = 'denied', 'ordinary_secret_validity_invalid'
    if outcome == 'allowed':
        if operation['expectedVersion'] != current['entityVersion']:
            outcome, reason = 'denied', 'identity_version_conflict'
        else:
            try:
                state = transition(state, envelope['contractId'], envelope['payload'],
                                   hub_id=current['ownerHubId'])
                if envelope['contractId'] != 'identity-revoke':
                    require_state_capacity(state)
            except ContractError as exc:
                state = current['state']
                outcome, reason = 'denied', exc.code
    if current['entityVersion'] >= 9007199254740991:
        raise ContractError('identity_revision_exhausted')
    # The complete state and exact decision share the same conditional append.
    # Rejected attempts do not change any enrollment/grant/membership record.
    audit = {'operationId': operation['operationId'], 'decision': outcome,
                            'reason': reason, 'actorRef': operation['effectiveActorRef'],
                            'contractId': envelope['contractId']}
    record = {'schemaVersion': '1.0.0', 'recordId': 'record-' + uuid.uuid4().hex,
        'entityId': current['entityId'], 'entityKind': 'identity-authority',
        'ownerHubId': current['ownerHubId'], 'ownerDomain': 'identity',
        'entityVersion': current['entityVersion'] + 1, 'previousRevision': snapshot.sequence,
        'operation': operation, 'recordedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
        'outcome': 'committed' if outcome == 'allowed' else 'rejected', 'state': state,
        'effects': [], 'artifacts': [], 'repository': None, 'authorizationDecision': audit}
    validate('owner-record', record)
    validate('identity-authority-state', state)
    raw = canonical_bytes(record)
    if len(raw) > 65536:
        raise ContractError('owner_body_limit')
    try:
        limits = [datetime.fromisoformat(envelope['ingressAttestation']['claims']['expiresAt']),
                  datetime.fromisoformat(operation['deadline'])]
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            for item in current['state'][collection]:
                if item['status'] != 'active':
                    continue
                starts = datetime.fromisoformat(item['issuedAt'])
                ends = datetime.fromisoformat(item['expiresAt'])
                # A future hard denial can change admission without a write.
                # Stop at activation as well as expiry and require reevaluation.
                if starts > now:
                    limits.append(starts)
                elif ends > now:
                    limits.append(ends)
        valid_until = min(limits)
        if envelope['contractId'] == 'identity-ordinary-secret-set' and outcome == 'allowed':
            valid_until = min(valid_until, datetime.fromisoformat(envelope['payload']['record']['expiresAt']))
    except (ValueError, TypeError):
        raise ContractError('authority_time_invalid') from None
    return PreparedChange(raw, snapshot.sequence, outcome, reason, valid_until)


@dataclass(frozen=True)
class CommandReceipt:
    operation_id: str
    decision: str
    reason: str
    entity_version: int
    sequence: int
    replayed: bool


class IdentityCommandOwner:
    """Identity transitions over the shared retained ledger, with no retry loop.

    A conflict requires a fresh execute call and fresh authentication. An uncertain
    append or cancellation must be reconciled using the original operation ID;
    neither outcome permits effects or a new business operation. Bootstrap is a
    separate explicit enrollment path: an empty ledger always refuses here.
    """
    def __init__(self, ledger, *, hub_id, entity_id, profile_id, organization_id):
        from state_owner.ledger import OwnerLedger
        if not isinstance(ledger, OwnerLedger):
            raise ContractError('identity_ledger_required')
        self._ledger = ledger
        self._hub, self._entity, self._profile = hub_id, entity_id, profile_id
        self._organization = organization_id

    def _authority(self, snapshot):
        from .authority import AuthoritySnapshot
        if snapshot.latest is None:
            raise ContractError('identity_not_enrolled')
        current = strict_loads(snapshot.latest.record)
        if (current['ownerHubId'] != self._hub or current['entityId'] != self._entity
                or current['state'].get('profileId') != self._profile
                or current['state'].get('organizationId') != self._organization):
            raise ContractError('authority_owner_mismatch')
        return AuthoritySnapshot(snapshot.latest.record, snapshot.sequence)

    async def execute(self, envelope_bytes):
        if type(envelope_bytes) is not bytes or len(envelope_bytes) > 65536:
            raise ContractError('owner_body_limit')
        envelope = strict_loads(envelope_bytes)
        if envelope.get('contractId') not in IDENTITY_COMMANDS:
            raise ContractError('identity_transition_unsupported')
        authority = self._authority(await self._ledger.current())
        decision = evaluate_snapshot(authority, envelope_bytes,
            audience={'hubId': self._hub, 'serviceId': 'identity-owner'}, now=datetime.now(timezone.utc))
        if decision.operation is None:
            raise ContractError('identity_actor_unverified')
        operation = strict_loads(decision.operation)
        existing = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
        if existing is not None:
            # Outcome reads also require current authority. In particular a replay
            # cannot expose old success after revocation during the history read.
            latest = self._authority(await self._ledger.current())
            current_decision = evaluate_snapshot(latest, envelope_bytes,
                audience={'hubId': self._hub, 'serviceId': 'identity-owner'}, now=datetime.now(timezone.utc))
            if current_decision.outcome != 'allowed':
                raise ContractError('identity_replay_not_authorized')
            return self._receipt(existing, {'operation': operation, 'authorizationDecision': {'contractId': envelope['contractId']}})
        proposal = prepare_change(authority, envelope_bytes)
        record = strict_loads(proposal.record)
        stored = await self._ledger.append(record, expected_sequence=proposal.expected_sequence,
                                           valid_until=proposal.valid_until, completion_records=0)
        if stored.replayed:
            latest = self._authority(await self._ledger.current())
            replay_decision = evaluate_snapshot(latest, envelope_bytes,
                audience={'hubId': self._hub, 'serviceId': 'identity-owner'}, now=datetime.now(timezone.utc))
            if replay_decision.outcome != 'allowed':
                raise ContractError('identity_replay_not_authorized')
        return self._receipt(stored, record)

    @staticmethod
    def _receipt(stored, proposal):
        record = strict_loads(stored.record)
        prior, wanted = record['operation'], proposal['operation']
        if (any(prior[k] != wanted[k] for k in ('operationId', 'payloadDigest', 'expectedVersion',
                                               'scope', 'effectiveActorRef'))
                or record['authorizationDecision']['contractId'] != proposal['authorizationDecision']['contractId']):
            raise ContractError('identity_operation_conflict')
        decision = record['authorizationDecision']
        return CommandReceipt(prior['operationId'], decision['decision'], decision['reason'],
                              record['entityVersion'], stored.sequence, stored.replayed)
