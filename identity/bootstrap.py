"""Explicit initial enrollment over the shared owner ledger.

A trusted provisioning ceremony supplies the permit and the already provisioned
OwnerLedger, including its trusted StreamIdentity. This module does not implement
that ceremony, provision broker credentials, create keys or trust the first client
of an empty stream. Possession proofs supplement broker credential provisioning.
"""
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import re

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from state_owner.ledger import OwnerLedger
from .authority import _active, _indexes, _key
from .capacity import require_state_capacity, require_operation_capacity
from .ingress import verify_possession, _time


@dataclass(frozen=True, repr=False)
class BootstrapPermit:
    """Host-private authorization for these exact initial bytes, not a wire token."""
    record: bytes
    hub_id: str
    entity_id: str
    profile_id: str
    organization_id: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self):
        if (any(not isinstance(t, datetime) or t.tzinfo is None
                or t.utcoffset() != timezone.utc.utcoffset(t)
                for t in (self.issued_at, self.expires_at))
                or not timedelta(0) < self.expires_at - self.issued_at <= timedelta(minutes=5)):
            raise ContractError('bootstrap_permit_time_invalid')
        if type(self.record) is not bytes or len(self.record) > 65536:
            raise ContractError('owner_body_limit')
        record = strict_loads(self.record)
        validate('owner-record', record)
        state, operation = record['state'], record['operation']
        validate('identity-authority-state', state)
        require_state_capacity(state)
        require_operation_capacity(operation)
        if (record['ownerHubId'] != self.hub_id or record['entityId'] != self.entity_id
                or state['profileId'] != self.profile_id or state['organizationId'] != self.organization_id
                or record['ownerDomain'] != 'identity' or record['entityKind'] != 'identity-authority'
                or operation['scope'] != {'organizationId': self.organization_id,
                                         'projectId': None, 'workspaceId': None}):
            raise ContractError('bootstrap_owner_mismatch')
        if (record['entityVersion'] != 1 or record['previousRevision'] != 0
                or operation['expectedVersion'] != 0 or record['outcome'] != 'committed'
                or record['effects'] or record['artifacts'] or record['repository'] is not None
                or operation['payloadDigest'] != payload_digest(state)):
            raise ContractError('bootstrap_initial_record_invalid')
        audit = record.get('authorizationDecision')
        if audit != {'operationId': operation['operationId'], 'decision': 'allowed',
                     'reason': 'explicit_enrollment', 'actorRef': operation['effectiveActorRef'],
                     'contractId': 'identity-bootstrap'}:
            raise ContractError('bootstrap_provenance_required')
        _time(record['recordedAt'])
        _time(operation['deadline'])
        index = _indexes(state, self.hub_id)
        actor = index['identities'].get(_key(operation['effectiveActorRef']))
        if (actor is None or actor['status'] != 'active'
                or operation['caller']['authenticatedIdentityRef'] != actor['ref']
                or operation['caller']['principalId'] != actor['principalId']
                or operation['caller']['kind'] != actor['kind']
                or operation['delegationRef'] is not None):
            raise ContractError('bootstrap_actor_mismatch')
        if not state['issuers'] or not state['transports']:
            raise ContractError('bootstrap_credentials_required')
        for collection in index.values():
            for item in collection.values():
                if item['ref']['revision'] != 1 or item['status'] != 'active':
                    raise ContractError('bootstrap_initial_reference_invalid')
                if 'issuedAt' in item and not _time(item['issuedAt']) < _time(item['expiresAt']):
                    raise ContractError('bootstrap_credential_time_invalid')
        for issuer in state['issuers']:
            subject = index['identities'].get(_key(issuer['identityRef']))
            if subject is None or subject['kind'] != 'service':
                raise ContractError('bootstrap_issuer_invalid')
        for transport in state['transports']:
            if (transport['method'] != 'nats-credential-mapping'
                    or _key(transport['identityRef']) not in index['identities']
                    or _key(transport['issuerRef']) not in index['issuers']):
                raise ContractError('bootstrap_transport_invalid')
        for membership in state['memberships']:
            if _key(membership['identityRef']) not in index['identities']:
                raise ContractError('bootstrap_membership_invalid')
        for grant in state['grants']:
            if (_key(grant['callerRef']) not in index['identities']
                    or grant['actorRef'] != grant['callerRef'] or grant['delegationRef'] is not None):
                raise ContractError('bootstrap_grant_invalid')
        for approval in state['approvals']:
            if (_key(approval['approverRef']) not in index['identities']
                    or _key(approval['grantRef']) not in index['grants']
                    or _key(approval['approverGrantRef']) not in index['grants']):
                raise ContractError('bootstrap_approval_invalid')
        object.__setattr__(self, 'record', canonical_bytes(record))

    def __repr__(self):
        return '<BootstrapPermit private>'


@dataclass(frozen=True)
class BootstrapReceipt:
    operation_id: str
    sequence: int
    replayed: bool


class BootstrapOwner:
    """Apply an explicit permit once; never generate a replacement retry identity.

    The caller retains this exact permit after an uncertain publish. A retry may
    reconcile only the identical original record. Expired permits require renewed
    trusted provisioning authorization, including for a retry; expiry never permits
    a new operation or silently resets the stream.
    """
    def __init__(self, ledger, permit):
        if not isinstance(ledger, OwnerLedger) or not isinstance(permit, BootstrapPermit):
            raise ContractError('bootstrap_trusted_inputs_required')
        self._ledger, self._permit = ledger, permit

    def __repr__(self):
        return '<BootstrapOwner private>'

    def _verify(self, proofs):
        permit = self._permit
        now = datetime.now(timezone.utc)
        if not permit.issued_at <= now < permit.expires_at:
            raise ContractError('bootstrap_permit_expired')
        record = strict_loads(permit.record)
        state = record['state']
        credentials = { _key(item['ref']): item for collection in ('issuers', 'transports')
                       for item in state[collection] }
        if type(proofs) is not list or len(proofs) != len(credentials):
            raise ContractError('bootstrap_proofs_incomplete')
        seen = set()
        for proof in proofs:
            if type(proof) is not dict or set(proof) != {'ref', 'proof'}:
                raise ContractError('bootstrap_proof_invalid')
            reference = proof['ref']
            if (type(reference) is not dict or set(reference) != {'ownerHubId', 'id', 'revision'}
                    or not isinstance(reference['ownerHubId'], str) or not isinstance(reference['id'], str)
                    or type(reference['revision']) is not int
                    or type(proof['proof']) is not str or re.fullmatch(r'[A-Za-z0-9_-]{86}', proof['proof']) is None):
                raise ContractError('bootstrap_proof_invalid')
            key = _key(reference)
            if key not in credentials or key in seen:
                raise ContractError('bootstrap_proofs_incomplete')
            seen.add(key)
            credential = credentials[key]
            if not _active(credential, now):
                raise ContractError('bootstrap_credential_expired')
            verify_possession({'purpose': 'agentmux-enrollment-possession-v1',
                'profileId': permit.profile_id, 'authorityId': permit.entity_id,
                'credential': credential}, proof['proof'], credential['publicKey'])
        deadline = _time(record['operation']['deadline'])
        valid_until = min(permit.expires_at, deadline,
            *(_time(item['expiresAt']) for item in credentials.values()))
        if now >= valid_until:
            raise ContractError('bootstrap_permit_expired')
        return record, valid_until

    async def execute(self, proofs):
        record, valid_until = self._verify(proofs)
        operation = record['operation']
        # This is a read of a preprovisioned pinned stream, not implicit enrollment.
        snapshot = await self._ledger.current()
        if snapshot.latest is not None:
            existing = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
            if existing is None:
                raise ContractError('bootstrap_already_enrolled')
            self._verify(proofs)
            return self._receipt(existing)
        stored = await self._ledger.append(record, expected_sequence=0, valid_until=valid_until, completion_records=0)
        if stored.replayed:
            self._verify(proofs)
        return self._receipt(stored)

    def _receipt(self, stored):
        if stored.sequence != 1 or stored.record != self._permit.record:
            raise ContractError('bootstrap_operation_conflict')
        record = strict_loads(self._permit.record)
        return BootstrapReceipt(record['operation']['operationId'], stored.sequence, stored.replayed)
