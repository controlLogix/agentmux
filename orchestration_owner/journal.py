"""Retained progress for one exact enrolled orchestration command.

The journal owns idempotency and recovery. A prepared record does not dispatch an
effect, and a dispatch record can never return to the prepared phase.
"""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
import secrets

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.authority import LedgerAuthorityReader
from state_owner.ledger import OwnerLedger, StoredRecord, validate_record

from .commands import OrchestrationPolicyBinding, PreparedOrchestrationEffect, prepare_command
from .domain_adapter import OrchestrationObservation

ORIGINAL_CONTRACTS = frozenset(('orchestration-command',))
PHASE_CONTRACTS = frozenset(('orchestration-dispatch', 'orchestration-complete'))
_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
_LOCAL_BRAND = object()


@dataclass(frozen=True, repr=False)
class _LocalOrchestrationAdmission:
    envelope: bytes
    authority_ref: bytes
    authority_sequence: int
    caller_ref: bytes
    grant_ref: bytes
    valid_until: datetime
    _brand: object

    def __repr__(self):
        return '<LocalOrchestrationAdmission private>'


def _local_admission(envelope, *, authority_ref, authority_sequence, caller_ref,
                     grant_ref, valid_until):
    if (type(envelope) is not bytes or not _valid_ref(authority_ref)
            or not _valid_ref(caller_ref) or not _valid_ref(grant_ref)
            or type(authority_sequence) is not int or authority_sequence < 1
            or not isinstance(valid_until, datetime) or valid_until.tzinfo is None):
        raise ContractError('orchestration_local_admission_invalid')
    return _LocalOrchestrationAdmission(envelope, canonical_bytes(authority_ref),
        authority_sequence, canonical_bytes(caller_ref), canonical_bytes(grant_ref),
        valid_until, _LOCAL_BRAND)


def _fail():
    raise ContractError('orchestration_journal_invalid')


def _valid_ref(value):
    return (type(value) is dict and set(value) == {'id', 'ownerHubId', 'revision'}
            and all(type(value[key]) is str and _ID.fullmatch(value[key])
                    for key in ('id', 'ownerHubId'))
            and type(value['revision']) is int
            and 0 <= value['revision'] <= 9_007_199_254_740_991)


def _reference(identifier, hub, revision):
    return {'id': identifier, 'ownerHubId': hub, 'revision': revision}


def claim_identity(envelope):
    return 'orchestration-claim-' + hashlib.sha256(canonical_bytes({
        'purpose': 'agentmux-orchestration-claim-v1',
        'operation': envelope['operation'],
        'contractId': envelope['contractId'],
        'payload': envelope['payload'],
    })).hexdigest()


def _same_operation(left, right):
    return all(canonical_bytes(left[key]) == canonical_bytes(right[key]) for key in
               ('operation', 'contractId', 'payload', 'destinationHubId',
                'destinationServiceId'))


@dataclass(frozen=True, repr=False)
class OrchestrationOperationOutcome:
    original_operation_id: str
    original_payload_digest: str
    phase: str
    claim_ref: bytes
    receipt_ref: bytes
    outcome: str | None
    result: bytes | None

    def __repr__(self):
        return '<OrchestrationOperationOutcome private>'


class OrchestrationOperationJournal:
    """Append-only orchestration state backed by one preprovisioned owner ledger."""
    def __init__(self, ledger, authority, *, owner_service_identity_ref, policy_binding):
        if (type(policy_binding) is not OrchestrationPolicyBinding
                or not isinstance(ledger, OwnerLedger)
                or not ledger.completion_budget_required
                or (ledger._binding.owner_domain, ledger._binding.entity_kind)
                    != ('orchestration-operations', 'attempt')
                or ledger._binding.scope != policy_binding.scope
                or ledger._binding.entity_id != strict_loads(policy_binding.resource_ref)['id']
                or not isinstance(authority, LedgerAuthorityReader)):
            raise ContractError('orchestration_journal_configuration')
        owner = (strict_loads(owner_service_identity_ref)
                 if type(owner_service_identity_ref) is bytes else owner_service_identity_ref)
        if not _valid_ref(owner) or owner['ownerHubId'] != ledger._binding.hub_id:
            raise ContractError('orchestration_journal_configuration')
        self._ledger, self._authority, self._binding = ledger, authority, ledger._binding
        self._policy = policy_binding
        self._owner = canonical_bytes(owner)
        self._lock = asyncio.Lock()
        self._observations = {}

    def __repr__(self):
        return '<OrchestrationOperationJournal private>'

    async def _authorize(self, raw, contracts):
        if type(raw) is not bytes or len(raw) > 65_536:
            _fail()
        envelope = strict_loads(raw)
        if canonical_bytes(envelope) != raw or envelope.get('contractId') not in contracts:
            _fail()
        decision = await self._authority.evaluate(raw, audience={
            'hubId': self._binding.hub_id, 'serviceId': 'orchestration-owner'})
        operation, payload = envelope['operation'], envelope['payload']
        resource = strict_loads(self._policy.resource_ref)
        if (decision.outcome != 'allowed'
                or canonical_bytes(operation['scope']) != self._binding.scope
                or payload['resourceRef'] != resource):
            raise ContractError('orchestration_journal_access_refused')
        if envelope['contractId'] == 'orchestration-command':
            environment = (None if self._policy.environment_ref is None
                           else strict_loads(self._policy.environment_ref))
            if payload['environmentRef'] != environment:
                raise ContractError('orchestration_journal_access_refused')
        else:
            if (operation['caller']['kind'] != 'service'
                    or canonical_bytes(operation['caller']['authenticatedIdentityRef']) != self._owner
                    or canonical_bytes(operation['effectiveActorRef']) != self._owner):
                raise ContractError('orchestration_journal_access_refused')
        return envelope, decision

    def _record(self, snapshot, envelope, state, *, identifier=None):
        operation = envelope['operation']
        return {'schemaVersion': '1.0.0',
            'recordId': identifier or 'orchestration-phase-' + secrets.token_hex(24),
            'entityId': self._binding.entity_id, 'entityKind': 'attempt',
            'ownerHubId': self._binding.hub_id,
            'ownerDomain': self._binding.owner_domain,
            'entityVersion': len(snapshot.records) + 1,
            'previousRevision': snapshot.sequence, 'operation': operation,
            'recordedAt': datetime.now(timezone.utc).isoformat(
                timespec='microseconds').replace('+00:00', 'Z'),
            'outcome': 'committed', 'state': state, 'effects': [],
            'artifacts': [], 'repository': None,
            'authorizationDecision': {'operationId': operation['operationId'],
                'decision': 'allowed', 'reason': 'current_authority',
                'actorRef': operation['effectiveActorRef'],
                'contractId': envelope['contractId']}}

    def _ref(self, stored):
        return _reference(strict_loads(stored.record)['recordId'],
                          self._binding.hub_id, stored.sequence)

    def _read(self, snapshot):
        groups = {}
        for stored in snapshot.records:
            record = validate_record(stored.record, self._binding)
            state = record['state']
            required = {'format', 'original', 'claimId', 'resourceRef',
                'environmentRef', 'candidateBytes', 'candidateDigest', 'phase',
                'dispatchRef', 'observation', 'phaseEnvelope', 'actor', 'provenance',
                'localAdmission'}
            if (type(state) is not dict or set(state) != required
                    or state['format'] != 'amx-orchestration-operation-v1'):
                _fail()
            original = state['original']
            operation = original.get('operation', {})
            local = state['localAdmission']
            if local is not None:
                if (type(local) is not dict or set(local) != {'authorityRef',
                        'authoritySequence', 'callerRef', 'grantRef'}
                        or not all(_valid_ref(local[name]) for name in
                                   ('authorityRef', 'callerRef', 'grantRef'))
                        or type(local['authoritySequence']) is not int
                        or local['authoritySequence'] < 1
                        or operation.get('caller', {}).get('kind') != 'human'
                        or operation.get('caller', {}).get('authenticatedIdentityRef')
                            != local['callerRef']
                        or operation.get('effectiveActorRef') != local['callerRef']
                        or operation.get('grantRef') != local['grantRef']):
                    _fail()
            try:
                candidate = base64.b64decode(state['candidateBytes'], validate=True)
                prepared = prepare_command(strict_loads(candidate), self._policy)
            except (ValueError, TypeError, ContractError):
                _fail()
            if (original.get('contractId') != 'orchestration-command'
                    or payload_digest(original['payload']) != operation.get('payloadDigest')
                    or state['claimId'] != claim_identity(original)
                    or state['resourceRef'] != strict_loads(self._policy.resource_ref)
                    or state['environmentRef'] != (None if self._policy.environment_ref is None
                        else strict_loads(self._policy.environment_ref))
                    or prepared.candidate != candidate
                    or prepared.candidate_digest != state['candidateDigest']
                    or not _DIGEST.fullmatch(state['candidateDigest'])
                    or type(state['actor']) is not str or not state['actor']
                    or state['provenance'] != self._policy.orchestrator_agent):
                _fail()
            key = operation['operationId']
            if key not in groups:
                if (state['phase'] != 'prepared' or state['phaseEnvelope'] is not None
                        or state['dispatchRef'] is not None or state['observation'] is not None
                        or record['recordId'] != state['claimId']
                        or record['operation'] != operation):
                    _fail()
                groups[key] = {'original': original, 'claim': stored,
                               'latest': stored, 'state': state}
                continue
            group = groups[key]
            before = group['state']
            stable = required - {'phase', 'dispatchRef', 'observation', 'phaseEnvelope'}
            if any(state[name] != before[name] for name in stable):
                _fail()
            phase = state['phaseEnvelope']
            if type(phase) is not dict or type(phase.get('operation')) is not dict:
                _fail()
            phase_operation, phase_payload = phase['operation'], phase['payload']
            if (phase.get('contractId') not in PHASE_CONTRACTS
                    or record['operation'] != phase_operation
                    or payload_digest(phase_payload) != phase_operation['payloadDigest']
                    or phase_payload['originalOperationId'] != key
                    or phase_payload['originalPayloadDigest'] != operation['payloadDigest']
                    or phase_payload['candidateDigest'] != state['candidateDigest']
                    or phase_payload['claimRef'] != self._ref(group['claim'])
                    or phase_payload['journalRef'] != _reference(self._binding.entity_id,
                        self._binding.hub_id, group['latest'].sequence)
                    or phase_operation['caller']['kind'] != 'service'
                    or canonical_bytes(phase_operation['caller']['authenticatedIdentityRef'])
                        != self._owner
                    or canonical_bytes(phase_operation['effectiveActorRef']) != self._owner):
                _fail()
            if phase['contractId'] == 'orchestration-dispatch':
                if (before['phase'] != 'prepared' or state['phase'] != 'dispatching'
                        or state['observation'] is not None
                        or state['dispatchRef'] != _reference(record['recordId'],
                            self._binding.hub_id, stored.sequence)):
                    _fail()
            else:
                observation = state['observation']
                if (before['phase'] not in ('dispatching', 'uncertain')
                        or state['dispatchRef'] != before['dispatchRef']
                        or type(observation) is not dict
                        or set(observation) != {'outcome', 'result'}
                        or observation['outcome'] not in
                            ('applied', 'refused', 'not-dispatched', 'uncertain')
                        or state['phase'] != ('uncertain' if observation['outcome'] == 'uncertain'
                                             else 'finished')):
                    _fail()
                result = observation['result']
                if (type(result) is not dict
                        or set(result) != {'command', 'outcome', 'exitCode', 'result'}
                        or result['command'] != prepared.command
                        or result['outcome'] != observation['outcome']
                        or result['exitCode'] is not None
                        and type(result['exitCode']) is not int):
                    _fail()
            group.update(latest=stored, state=state)
        return groups

    async def prepare(self, caller_envelope, *, expected_sequence, effect, actor, provenance):
        async with self._lock:
            envelope, decision = await self._authorize(caller_envelope, ORIGINAL_CONTRACTS)
            snapshot = await self._ledger.current()
            groups = self._read(snapshot)
            operation = envelope['operation']
            existing = groups.get(operation['operationId'])
            if existing is not None:
                if not _same_operation(existing['original'], envelope):
                    raise ContractError('owner_operation_conflict')
                return StoredRecord(existing['claim'].record, existing['claim'].sequence, True)
            if (snapshot.sequence != expected_sequence
                    or snapshot.latest is not None
                    and strict_loads(snapshot.latest.record)['state']['phase'] != 'finished'
                    or type(effect) is not PreparedOrchestrationEffect
                    or effect.candidate != canonical_bytes(envelope['payload'])
                    or type(actor) is not str or not actor
                    or provenance != self._policy.orchestrator_agent):
                raise ContractError('orchestration_journal_busy')
            state = {'format': 'amx-orchestration-operation-v1', 'original': envelope,
                'claimId': claim_identity(envelope),
                'resourceRef': strict_loads(self._policy.resource_ref),
                'environmentRef': (None if self._policy.environment_ref is None
                    else strict_loads(self._policy.environment_ref)),
                'candidateBytes': base64.b64encode(effect.candidate).decode(),
                'candidateDigest': effect.candidate_digest, 'phase': 'prepared',
                'dispatchRef': None, 'observation': None, 'phaseEnvelope': None,
                'actor': actor, 'provenance': provenance}
            state['localAdmission'] = None
            record = self._record(snapshot, envelope, state, identifier=state['claimId'])
            _, decision = await self._authorize(caller_envelope, ORIGINAL_CONTRACTS)
            target = ({} if operation['expectedVersion'] == snapshot.sequence else
                      {'expected_target_version': operation['expectedVersion']})
            return await self._ledger.append(record, expected_sequence=snapshot.sequence,
                valid_until=decision.valid_until, completion_records=2, **target)

    async def prepare_local(self, admission, *, expected_sequence, effect, actor,
                            provenance, authorize):
        if (type(admission) is not _LocalOrchestrationAdmission
                or admission._brand is not _LOCAL_BRAND or not callable(authorize)):
            raise ContractError('orchestration_local_admission_invalid')
        async with self._lock:
            envelope = strict_loads(admission.envelope)
            snapshot = await self._ledger.current()
            groups = self._read(snapshot)
            operation = envelope['operation']
            existing = groups.get(operation['operationId'])
            if existing is not None:
                if not _same_operation(existing['original'], envelope):
                    raise ContractError('owner_operation_conflict')
                return StoredRecord(existing['claim'].record, existing['claim'].sequence, True)
            if (snapshot.sequence != expected_sequence
                    or snapshot.latest is not None
                    and strict_loads(snapshot.latest.record)['state']['phase'] != 'finished'
                    or type(effect) is not PreparedOrchestrationEffect
                    or effect.candidate != canonical_bytes(envelope['payload'])
                    or type(actor) is not str or not actor
                    or provenance != self._policy.orchestrator_agent):
                raise ContractError('orchestration_journal_busy')
            valid_until = await authorize(admission)
            if (not isinstance(valid_until, datetime) or valid_until.tzinfo is None
                    or valid_until > admission.valid_until):
                raise ContractError('orchestration_local_admission_invalid')
            state = {'format': 'amx-orchestration-operation-v1', 'original': envelope,
                'claimId': claim_identity(envelope),
                'resourceRef': strict_loads(self._policy.resource_ref),
                'environmentRef': (None if self._policy.environment_ref is None
                    else strict_loads(self._policy.environment_ref)),
                'candidateBytes': base64.b64encode(effect.candidate).decode(),
                'candidateDigest': effect.candidate_digest, 'phase': 'prepared',
                'dispatchRef': None, 'observation': None, 'phaseEnvelope': None,
                'actor': actor, 'provenance': provenance,
                'localAdmission': {
                    'authorityRef': strict_loads(admission.authority_ref),
                    'authoritySequence': admission.authority_sequence,
                    'callerRef': strict_loads(admission.caller_ref),
                    'grantRef': strict_loads(admission.grant_ref)}}
            record = self._record(snapshot, envelope, state, identifier=state['claimId'])
            valid_until = await authorize(admission)
            target = ({} if operation['expectedVersion'] == snapshot.sequence else
                      {'expected_target_version': operation['expectedVersion']})
            return await self._ledger.append(record, expected_sequence=snapshot.sequence,
                valid_until=valid_until, completion_records=2, **target)

    def _observe(self, claim_ref, observation):
        if (type(observation) is not OrchestrationObservation
                or observation.outcome not in
                    ('applied', 'refused', 'not-dispatched', 'uncertain')
                or len(observation.result) > 4096):
            _fail()
        identifier = 'orchestration-observation-' + secrets.token_hex(24)
        self._observations[identifier] = (canonical_bytes(claim_ref), observation)
        return identifier

    async def advance(self, owner_envelope, *, expected_sequence):
        async with self._lock:
            envelope, decision = await self._authorize(owner_envelope, PHASE_CONTRACTS)
            snapshot = await self._ledger.current()
            groups = self._read(snapshot)
            operation, payload = envelope['operation'], envelope['payload']
            replay = await self._ledger.outcome(operation['operationId'],
                                                operation['payloadDigest'])
            if replay is not None:
                if envelope['contractId'] == 'orchestration-complete':
                    self._observations.pop(payload['observationId'], None)
                return replay
            group = groups.get(payload['originalOperationId'])
            if (group is None or snapshot.sequence != expected_sequence
                    or group['original']['operation']['payloadDigest']
                        != payload['originalPayloadDigest']):
                _fail()
            state = strict_loads(canonical_bytes(group['state']))
            state['phaseEnvelope'] = envelope
            identifier = 'orchestration-phase-' + secrets.token_hex(24)
            if envelope['contractId'] == 'orchestration-dispatch':
                state['phase'] = 'dispatching'
                state['dispatchRef'] = _reference(identifier, self._binding.hub_id,
                                                  snapshot.sequence + 1)
                completion_records = 1
            else:
                held = self._observations.get(payload['observationId'])
                if held is None or held[0] != canonical_bytes(payload['claimRef']):
                    raise ContractError('orchestration_observation_unavailable')
                observation = held[1]
                state['observation'] = {'outcome': observation.outcome,
                                        'result': observation.private_copy()}
                state['phase'] = ('uncertain' if observation.outcome == 'uncertain'
                                  else 'finished')
                completion_records = 1 if state['phase'] == 'uncertain' else 0
            record = self._record(snapshot, envelope, state, identifier=identifier)
            _, decision = await self._authorize(owner_envelope, PHASE_CONTRACTS)
            stored = await self._ledger.append(record, expected_sequence=snapshot.sequence,
                valid_until=decision.valid_until,
                admission='reconciliation' if state['phase'] == 'uncertain' else 'completion',
                completion_records=completion_records)
            if envelope['contractId'] == 'orchestration-complete':
                self._observations.pop(payload['observationId'], None)
            return stored

    async def outcome(self, original_operation_id, original_payload_digest):
        groups = self._read(await self._ledger.current())
        group = groups.get(original_operation_id)
        if group is None:
            return None
        if group['original']['operation']['payloadDigest'] != original_payload_digest:
            raise ContractError('owner_operation_conflict')
        observation = group['state']['observation']
        return OrchestrationOperationOutcome(original_operation_id,
            original_payload_digest, group['state']['phase'],
            canonical_bytes(self._ref(group['claim'])),
            canonical_bytes(self._ref(group['latest'])),
            None if observation is None else observation['outcome'],
            None if observation is None else canonical_bytes(observation['result']))
