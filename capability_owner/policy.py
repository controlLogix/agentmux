"""Evaluate enrolled policy facts; a recorded decision never grants an effect."""
import asyncio
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.authority import LedgerAuthorityReader
from identity.capability_service import evaluate_capability_service_request
from state_owner.ledger import OwnerBinding, OwnerLedger, validate_record


def _reference(value):
    return (type(value) is dict and set(value) == {'id', 'ownerHubId', 'revision'}
        and all(type(value[key]) is str and re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', value[key])
                for key in ('id', 'ownerHubId'))
        and type(value['revision']) is int and 1 <= value['revision'] <= 9007199254740991)


@dataclass(frozen=True, repr=False)
class PolicyResource:
    binding: OwnerBinding = field(repr=False)
    ledger: OwnerLedger = field(repr=False)
    policy_reference: bytes = field(repr=False)
    plugin_identity: bytes = field(repr=False)
    instance_id: str = field(repr=False)
    _lock: object = field(init=False, repr=False)

    def __post_init__(self):
        try:
            reference = strict_loads(self.policy_reference)
            identity = strict_loads(self.plugin_identity)
            if (type(self.binding) is not OwnerBinding or type(self.ledger) is not OwnerLedger
                    or self.ledger._binding != self.binding or not self.ledger.completion_budget_required
                    or (self.binding.owner_domain, self.binding.entity_kind) != ('policy-evaluations', 'policy-evaluation')
                    or not _reference(reference)
                    or reference['id'] != self.binding.entity_id or reference['ownerHubId'] != self.binding.hub_id
                    or not _reference(identity)
                    or identity['ownerHubId'] != self.binding.hub_id
                    or type(self.instance_id) is not str
                    or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', self.instance_id) is None):
                raise ValueError()
            object.__setattr__(self, 'policy_reference', canonical_bytes(reference))
            object.__setattr__(self, 'plugin_identity', canonical_bytes(identity))
            object.__setattr__(self, '_lock', asyncio.Lock())
        except Exception:
            raise ContractError('capability_owner_configuration') from None

    def check_request(self, snapshot, claims):
        record = strict_loads(snapshot.record)
        rows = [row for row in record['state'].get('nativeInstances', []) if row['owner'] == claims['owner']]
        if (record['ownerHubId'] != self.binding.hub_id or len(rows) != 1
                or rows[0]['status'] != 'active' or canonical_bytes(rows[0]['identityRef']) != self.plugin_identity
                or rows[0]['owner']['instanceId'] != self.instance_id
                or rows[0]['facts']['policy']['subjectInstanceId'] != self.instance_id
                or canonical_bytes(rows[0]['facts']['policy']['reference']) != self.policy_reference
                or canonical_bytes(claims['resourceRef']) != self.policy_reference
                or canonical_bytes(claims['scope']) != self.binding.scope):
            raise ContractError('capability_access_refused')
        return record, rows[0]

    async def authorize(self, authority, raw, service_raw):
        if (not isinstance(authority, LedgerAuthorityReader) or type(service_raw) is not bytes
                or len(service_raw) > 98304):
            raise ContractError('capability_access_refused')
        wrapper = strict_loads(service_raw)
        if canonical_bytes(wrapper) != service_raw:
            raise ContractError('capability_access_refused')
        claims = wrapper['claims']
        if (claims['serviceId'] != 'policy-owner' or claims['requestContractId'] != 'capability-policy-evaluate'
                or base64.b64decode(claims['envelopeBytes'], validate=True) != raw):
            raise ContractError('capability_access_refused')
        snapshot = await authority.current()
        decision = evaluate_capability_service_request(snapshot, service_raw, service_id='policy-owner',
            now=datetime.now(timezone.utc))
        record, row = self.check_request(snapshot, claims)
        return record, row, decision

    @staticmethod
    def _outcome(row, access):
        facts = row['facts']
        # Query permission is separate from this requested access. Query approval
        # cannot satisfy a future action's operation/payload-bound approval.
        outcomes = [entry['outcome'] for entry in facts['policy']['decisions'] if entry['access'] == access]
        if (access['action'] not in facts['grant']['actions']
                or access['resourceId'] not in facts['grant']['resourceIds'] or not outcomes or 'deny' in outcomes):
            return 'deny'
        parent = facts['parentGrant']
        if parent is not None and (access not in facts['parentAccess']
                or access['action'] not in parent['actions'] or access['resourceId'] not in parent['resourceIds']):
            return 'deny'
        return 'approval_required' if 'approval_required' in outcomes else 'allow'

    def _retained(self, stored, envelope):
        record = validate_record(stored.record, self.binding)
        state = record['state']
        if (set(state) != {'formatVersion', 'policyRef', 'policyDigest', 'authorityRef', 'pluginIdentityRef',
                          'instanceId', 'nativeOwner', 'request', 'outcome'}
                or state['formatVersion'] != 1 or type(state['formatVersion']) is not int
                or record['outcome'] != 'committed' or record['effects'] or record['artifacts']
                or state['outcome'] not in ('allow', 'deny', 'approval_required')
                or canonical_bytes(state['policyRef']) != self.policy_reference
                or type(state['policyDigest']) is not str
                or re.fullmatch(r'sha256:[a-f0-9]{64}', state['policyDigest']) is None
                or not _reference(state['authorityRef'])
                or state['authorityRef']['ownerHubId'] != self.binding.hub_id
                or canonical_bytes(state['pluginIdentityRef']) != self.plugin_identity
                or state['instanceId'] != self.instance_id
                or canonical_bytes(state['request']) != canonical_bytes(envelope['payload'])
                or canonical_bytes(record['operation']) != canonical_bytes(envelope['operation'])):
            raise ContractError('capability_outcome_conflict')
        return {'receiptRef': {'id': record['recordId'], 'ownerHubId': self.binding.hub_id,
                              'revision': record['entityVersion']}, 'outcome': state['outcome']}

    async def evaluate(self, authority, raw, service_raw):
        async with self._lock:
            await self.authorize(authority, raw, service_raw)
            envelope = strict_loads(raw)
            operation = envelope['operation']
            existing = await self.ledger.outcome(operation['operationId'], operation['payloadDigest'])
            if existing is not None:
                return self._retained(existing, envelope)
            history = await self.ledger.current()
            source, row, decision = await self.authorize(authority, raw, service_raw)
            policy = row['facts']['policy']
            digest = payload_digest(policy)
            identifier = 'policy-evaluation-' + hashlib.sha256(
                (operation['operationId'] + '\0' + operation['payloadDigest']).encode()).hexdigest()
            record = {'schemaVersion': '1.0.0', 'recordId': identifier, 'entityId': self.binding.entity_id,
                'entityKind': self.binding.entity_kind, 'ownerHubId': self.binding.hub_id,
                'ownerDomain': self.binding.owner_domain, 'entityVersion': len(history.records) + 1,
                'previousRevision': history.sequence, 'operation': operation,
                'recordedAt': datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'outcome': 'committed', 'state': {'formatVersion': 1, 'policyRef': strict_loads(self.policy_reference),
                    'policyDigest': digest, 'authorityRef': {'id': source['entityId'],
                        'ownerHubId': source['ownerHubId'], 'revision': source['entityVersion']},
                    'pluginIdentityRef': strict_loads(self.plugin_identity), 'instanceId': self.instance_id,
                    'nativeOwner': row['owner'], 'request': envelope['payload'],
                    'outcome': self._outcome(row, envelope['payload']['input'])},
                'effects': [], 'artifacts': [], 'repository': None,
                'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                    'reason': 'current_authority', 'actorRef': operation['effectiveActorRef'],
                    'contractId': 'capability-policy-evaluate'}}
            stored = await self.ledger.append(record, expected_sequence=history.sequence,
                expected_target_version=strict_loads(self.policy_reference)['revision'],
                valid_until=decision.valid_until, completion_records=0)
            return self._retained(stored, envelope)
