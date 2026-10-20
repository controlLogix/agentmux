"""Retain board command progress without replacing authoritative card state.

Every journal mutation needs an actual freshly admitted envelope. Reading this
private history grants no authority and never dispatches or repeats a card write.
"""
import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import secrets
import re

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.fed.board_services import PreparedBoardChange
from identity.authority import LedgerAuthorityReader
from identity.capability_service import evaluate_capability_service_request
from state_owner.ledger import OwnerLedger, StoredRecord, validate_record

from .board_target import BoardTargetBinding

ORIGINAL_CONTRACTS = frozenset(('capability-storage-write', 'federation-board-command'))
PHASE_CONTRACTS = frozenset(('federation-board-dispatch', 'federation-board-complete'))
_MARKER = '_agentmuxOperation'
_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')

def _valid_ref(value):
    return (type(value) is dict and set(value) == {'id','ownerHubId','revision'}
        and all(type(value[k]) is str and _ID.fullmatch(value[k]) for k in ('id','ownerHubId'))
        and type(value['revision']) is int and 0 <= value['revision'] <= 9_007_199_254_740_991)


def _fail():
    raise ContractError('board_journal_invalid')


def candidate_digest(value):
    if type(value) is not bytes or not 0 < len(value) <= 45000:
        _fail()
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def claim_identity(envelope):
    return 'board-claim-' + hashlib.sha256(canonical_bytes({
        'purpose':'agentmux-board-claim-v1', 'operation':envelope['operation'],
        'contractId':envelope['contractId'], 'payload':envelope['payload']})).hexdigest()


def claim_marker(envelope):
    return {'claimId':claim_identity(envelope), 'operationId':envelope['operation']['operationId'],
            'payloadDigest':envelope['operation']['payloadDigest']}


def _same_operation(left, right):
    # Fresh ingress delivery may change its message ID and signature. It cannot
    # change the retained business operation, payload or destination.
    return all(canonical_bytes(left[k]) == canonical_bytes(right[k]) for k in
        ('operation','contractId','payload','destinationHubId','destinationServiceId'))


def _reference(identifier, hub, revision):
    return {'id':identifier, 'ownerHubId':hub, 'revision':revision}


@dataclass(frozen=True, repr=False)
class BoardOperationOutcome:
    original_operation_id: str
    original_payload_digest: str
    phase: str
    claim_ref: bytes
    receipt_ref: bytes
    resource_ref: bytes | None
    result: str | None

    def __repr__(self):
        return '<BoardOperationOutcome private>'


class BoardOperationJournal:
    def __init__(self, ledger, authority, *, owner_service_identity_ref, target_binding):
        if (not isinstance(target_binding,BoardTargetBinding)
                or not isinstance(ledger, OwnerLedger) or not ledger.completion_budget_required
                or (ledger._binding.owner_domain,ledger._binding.entity_kind)
                    != ('federation-board-operations','attempt')
                or strict_loads(ledger._binding.scope)['projectId'] is None
                or not isinstance(authority, LedgerAuthorityReader)):
            raise ContractError('board_journal_configuration')
        self._ledger, self._authority, self._binding = ledger, authority, ledger._binding
        self._target = target_binding
        self._owner = canonical_bytes(owner_service_identity_ref)
        owner = strict_loads(self._owner)
        if not _valid_ref(owner) or owner['ownerHubId'] != self._binding.hub_id:
            raise ContractError('board_journal_configuration')
        self._lock = asyncio.Lock()
        self._observations = {}

    def __repr__(self):
        return '<BoardOperationJournal private>'

    async def _authorize(self, raw, contracts, service_request_bytes=None):
        if type(raw) is not bytes or len(raw) > 65536:
            _fail()
        envelope = strict_loads(raw)
        if canonical_bytes(envelope) != raw or envelope['contractId'] not in contracts:
            _fail()
        if envelope['contractId'] == 'capability-storage-write':
            if type(service_request_bytes) is not bytes:
                raise ContractError('board_journal_native_required')
            if len(service_request_bytes) > 98304:
                _fail()
            wrapper = strict_loads(service_request_bytes)
            if (canonical_bytes(wrapper) != service_request_bytes
                    or base64.b64decode(wrapper['claims']['envelopeBytes'],validate=True) != raw):
                raise ContractError('board_journal_access_refused')
            snapshot = await self._authority.current()
            decision = evaluate_capability_service_request(snapshot,service_request_bytes,
                service_id='storage-owner',now=datetime.now(timezone.utc))
        else:
            decision = await self._authority.evaluate(raw, audience={
                'hubId':self._binding.hub_id,'serviceId':'storage-owner'})
        if (decision.outcome != 'allowed' or canonical_bytes(envelope['operation']['scope']) != self._binding.scope
                or envelope['payload']['resourceRef']['id'] != self._binding.entity_id
                or envelope['payload']['resourceRef']['ownerHubId'] != self._binding.hub_id):
            raise ContractError('board_journal_access_refused')
        if envelope['contractId'] in PHASE_CONTRACTS:
            operation = envelope['operation']
            if (operation['caller']['kind'] != 'service'
                    or canonical_bytes(operation['caller']['authenticatedIdentityRef']) != self._owner
                    or canonical_bytes(operation['effectiveActorRef']) != self._owner):
                raise ContractError('board_journal_access_refused')
        return envelope, decision

    def _read(self, snapshot):
        """Validate every retained transition, including old operation groups."""
        groups = {}
        previous = None
        source_floor = self._target.stream_identity.minimum_sequence
        card_floor = 0
        for stored in snapshot.records:
            record = validate_record(stored.record,self._binding)
            state = record['state']
            fields = {'format','original','claimId','targetRef','candidateDigest','preparedBy',
                              'preparedAt','phase','dispatchRef','result','phaseEnvelope','targetBinding','observedSequence','preparationAudit'}
            legacy_result = state.get('format') == 'amx-board-operation-v2'
            if (set(state) != fields | ({'candidateBytes','legacyAttempts'} if legacy_result else set())
                    or state['format'] not in ('amx-board-operation-v1','amx-board-operation-v2') or record['outcome'] != 'committed'
                    or record['effects'] or record['artifacts'] or record['repository'] is not None):
                _fail()
            original = state['original']
            validate('message-envelope',original)
            if legacy_result:
                try:
                    candidate = base64.b64decode(state['candidateBytes'], validate=True)
                    card = strict_loads(candidate)
                    if (base64.b64encode(candidate).decode() != state['candidateBytes']
                            or candidate_digest(candidate) != state['candidateDigest']
                            or original['contractId'] != 'federation-board-command'
                            or card.get('rid') != self._target.repository_id or card.get('key') != self._target.card_key
                            or card.get(_MARKER) != claim_marker(original)
                            or type(state['legacyAttempts']) is not int or not 1 <= state['legacyAttempts'] <= 3
                            or (state['phaseEnvelope'] is not None and len(canonical_bytes(state['phaseEnvelope'])) > 16384)):
                        _fail()
                except (ValueError, TypeError, AttributeError):
                    _fail()
            op = original['operation']
            if (original['contractId'] not in ORIGINAL_CONTRACTS
                    or payload_digest(original['payload']) != op['payloadDigest']
                    or state['claimId'] != claim_identity(original)
                    or canonical_bytes(state['targetBinding']) != self._target.canonical
                    or not _valid_ref(state['targetRef'])
                    or type(state['observedSequence']) is not int
                    or state['observedSequence'] > 9_007_199_254_740_991
                    or state['observedSequence'] < max(self._target.stream_identity.minimum_sequence,
                                                     state['targetRef']['revision'])
                    or canonical_bytes(op['scope']) != self._binding.scope
                    or original['payload']['resourceRef']['id'] != self._binding.entity_id
                    or original['payload']['resourceRef']['ownerHubId'] != self._binding.hub_id
                    or not _valid_ref(state['targetRef'])
                    or type(state['candidateDigest']) is not str or not _DIGEST.fullmatch(state['candidateDigest'])
                    or type(state['preparedBy']) is not str or not state['preparedBy']
                    or type(state['preparedAt']) is not str or not state['preparedAt']
                    or type(state['preparationAudit']) is not dict
                    or set(state['preparationAudit']) != {'kinds','what'}
                    or type(state['preparationAudit']['kinds']) is not list
                    or any(type(kind) is not str for kind in state['preparationAudit']['kinds'])
                    or type(state['preparationAudit']['what']) is not str
                    or (original['contractId'] == 'capability-storage-write'
                        and state['targetRef'] != original['payload']['resourceRef'])
                    or state['targetRef']['id'] != self._binding.entity_id
                    or state['targetRef']['ownerHubId'] != self._binding.hub_id):
                _fail()
            audit = record.get('authorizationDecision',{})
            if audit != {'operationId':record['operation']['operationId'],'decision':'allowed',
                         'reason':'current_authority','actorRef':record['operation']['effectiveActorRef'],
                         'contractId':original['contractId'] if state['phaseEnvelope'] is None
                                      else state['phaseEnvelope']['contractId']}:
                _fail()
            key = op['operationId']
            if key not in groups:
                if (state['observedSequence'] < source_floor
                        or previous is not None and previous['state']['phase'] != 'finished'
                        or state['phase'] != 'prepared' or state['phaseEnvelope'] is not None
                        or record['operation'] != op or state['dispatchRef'] is not None
                        or state['result'] is not None or record['recordId'] != state['claimId']):
                    _fail()
                groups[key] = {'original':original,'claim':stored,'state':state,'latest':stored}
            else:
                group = groups[key]
                if previous is None or previous['state']['original'] != original or group['original'] != original:
                    _fail()
                self._transition(group, state, record, previous)
                group.update(state=state,latest=stored)
            if state['result'] is not None:
                revision = state['result']['resourceRef']['revision']
                if revision < card_floor:
                    _fail()
                card_floor = revision
                source_floor = max(source_floor,revision)
            source_floor = max(source_floor,state['observedSequence'])
            previous = {'state':state,'stored':stored}
        return groups

    def _transition(self, group, state, record, previous):
        before = group['state']
        stable = ('format','original','claimId','targetRef','candidateDigest','preparedBy','preparedAt','targetBinding','observedSequence','preparationAudit')
        if before['format'] == 'amx-board-operation-v2':
            stable += ('candidateBytes','legacyAttempts')
        if any(state[k] != before[k] for k in stable):
            _fail()
        envelope = state['phaseEnvelope']
        validate('message-envelope',envelope)
        operation, payload = envelope['operation'],envelope['payload']
        if (envelope['contractId'] not in PHASE_CONTRACTS or record['operation'] != operation
                or payload_digest(payload) != operation['payloadDigest']
                or operation['caller']['kind'] != 'service'
                or canonical_bytes(operation['caller']['authenticatedIdentityRef']) != self._owner
                or canonical_bytes(operation['effectiveActorRef']) != self._owner
                or payload['originalOperationId'] != group['original']['operation']['operationId']
                or payload['originalPayloadDigest'] != group['original']['operation']['payloadDigest']
                or payload['candidateDigest'] != state['candidateDigest']
                or payload['resourceRef'] != state['targetRef']
                or payload['claimRef'] != self._ref(group['claim'])
                or payload['journalRef'] != _reference(self._binding.entity_id,self._binding.hub_id,
                                                     previous['stored'].sequence)
                or operation['expectedVersion'] != previous['stored'].sequence):
            _fail()
        if envelope['contractId'] == 'federation-board-dispatch':
            if (before['phase'] != 'prepared' or state['phase'] != 'dispatching'
                    or state['result'] is not None or state['dispatchRef'] != _reference(
                        record['recordId'],self._binding.hub_id,record['entityVersion'])):
                _fail()
        else:
            if before['phase'] not in ('dispatching','uncertain','settled') or state['dispatchRef'] != before['dispatchRef']:
                _fail()
            result = state['result']
            if state['phase'] == 'uncertain':
                if before['phase'] == 'settled' or result is not None:
                    _fail()
            elif state['phase'] in ('settled','finished'):
                if (type(result) is not dict or set(result) != {'outcome','resourceRef','auditDone','projectionDone'}
                        or result['outcome'] not in ('applied','conflict','rejected')
                        or type(result['auditDone']) is not bool or type(result['projectionDone']) is not bool
                        or not _valid_ref(result['resourceRef'])
                        or result['resourceRef']['id'] != self._binding.entity_id
                        or result['resourceRef']['ownerHubId'] != self._binding.hub_id
                        or type(result['resourceRef']['revision']) is not int
                        or result['resourceRef']['revision'] < state['targetRef']['revision']
                        or (result['outcome']=='applied'
                            and result['resourceRef']['revision'] <= state['observedSequence'])
                        or (result['outcome'] in ('applied','conflict')
                            and result['resourceRef']['revision'] == state['targetRef']['revision'])
                        or (state['phase'] == 'finished') != (result['auditDone'] and result['projectionDone'])):
                    _fail()
                if before['result'] is not None and (any(result[k] != before['result'][k]
                        for k in ('outcome','resourceRef')) or any(before['result'][k] and not result[k]
                        for k in ('auditDone','projectionDone'))):
                    _fail()
            else:
                _fail()

    def _source_floor(self, groups):
        return max((self._target.stream_identity.minimum_sequence,*(
            max(group['state']['observedSequence'],
                0 if group['state']['result'] is None else group['state']['result']['resourceRef']['revision'])
            for group in groups.values())))

    async def source_floor(self):
        """Minimum actual stream observation required before dispatch or recovery."""
        return self._source_floor(self._read(await self._ledger.current()))

    def _ref(self, stored):
        return _reference(strict_loads(stored.record)['recordId'],self._binding.hub_id,stored.sequence)

    def _record(self, snapshot, envelope, state, *, identifier=None):
        operation = envelope['operation']
        return {'schemaVersion':'1.0.0','recordId':identifier or 'board-phase-'+secrets.token_hex(24),
            'entityId':self._binding.entity_id,'entityKind':'attempt','ownerHubId':self._binding.hub_id,
            'ownerDomain':self._binding.owner_domain,'entityVersion':len(snapshot.records)+1,
            'previousRevision':snapshot.sequence,'operation':operation,
            'recordedAt':datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z'),
            'outcome':'committed','state':state,'effects':[],'artifacts':[],'repository':None,
            'authorizationDecision':{'operationId':operation['operationId'],'decision':'allowed',
                'reason':'current_authority','actorRef':operation['effectiveActorRef'],'contractId':envelope['contractId']}}

    async def prepare(self, caller_envelope, *, expected_sequence, candidate, target_ref, observed_sequence, service_request_bytes=None,
                      legacy_attempts=None):
        async with self._lock:
            envelope, decision = await self._authorize(caller_envelope,ORIGINAL_CONTRACTS,service_request_bytes)
            snapshot = await self._ledger.current()
            groups = self._read(snapshot)
            operation = envelope['operation']
            existing = groups.get(operation['operationId'])
            if existing is not None:
                if not _same_operation(existing['original'],envelope):
                    raise ContractError('owner_operation_conflict')
                return StoredRecord(existing['claim'].record,existing['claim'].sequence,True)
            if (snapshot.sequence != expected_sequence or not isinstance(candidate,PreparedBoardChange)
                    or (snapshot.latest is not None and strict_loads(snapshot.latest.record)['state']['phase'] != 'finished')):
                raise ContractError('board_journal_busy')
            if type(observed_sequence) is int and observed_sequence < self._source_floor(groups):
                raise ContractError('board_source_recovery_required')
            if (not _valid_ref(target_ref) or type(observed_sequence) is not int
                    or observed_sequence > 9_007_199_254_740_991
                    or observed_sequence < max(self._target.stream_identity.minimum_sequence,target_ref['revision'])
                    or target_ref['id'] != self._binding.entity_id or target_ref['ownerHubId'] != self._binding.hub_id
                    or (envelope['contractId'] == 'capability-storage-write'
                        and target_ref != envelope['payload']['resourceRef'])
                    or candidate.card.get('rid') != self._target.repository_id
                    or candidate.card.get('key') != self._target.card_key
                    or candidate.card.get(_MARKER) != claim_marker(envelope)):
                _fail()
            state = {'format':'amx-board-operation-v1','original':envelope,'claimId':claim_identity(envelope),
                'targetRef':strict_loads(canonical_bytes(target_ref)),'candidateDigest':candidate_digest(candidate.value),
                'targetBinding':strict_loads(self._target.canonical),'observedSequence':observed_sequence,
                'preparedBy':candidate.card['updated_by'],'preparedAt':candidate.card['updated_at'],
                'preparationAudit':{'kinds':list(candidate.kinds),'what':candidate.what},
                'phase':'prepared','dispatchRef':None,'result':None,'phaseEnvelope':None}
            if legacy_attempts is not None:
                if (envelope['contractId'] != 'federation-board-command' or type(legacy_attempts) is not int
                        or not 1 <= legacy_attempts <= 3):
                    _fail()
                state.update(format='amx-board-operation-v2', candidateBytes=base64.b64encode(candidate.value).decode(),
                             legacyAttempts=legacy_attempts)
            record = self._record(snapshot,envelope,state,identifier=state['claimId'])
            # Reserve the phase envelope, its top-level operation and bounded
            # completion references before retaining a legacy result or effect.
            if legacy_attempts is not None and len(canonical_bytes(record)) > 65536 - 2 * 16384 - 1024:
                raise ContractError('board_legacy_result_capacity')
            self._read(type(snapshot)((*snapshot.records,StoredRecord(canonical_bytes(record),snapshot.sequence+1)),snapshot.sequence+1))
            _, decision = await self._authorize(caller_envelope,ORIGINAL_CONTRACTS,service_request_bytes)
            return await self._ledger.append(record,expected_sequence=snapshot.sequence,
                expected_target_version=operation['expectedVersion'],valid_until=decision.valid_until,completion_records=3)

    def _observe(self, claim_ref, *, result):
        """Called only by the owner holding the actual broker/audit observation.

        The network completion supplies this opaque ID, never these result fields.
        The owner must retain its original dispatch worker until it joins.
        """
        identifier = 'board-observation-'+secrets.token_hex(24)
        self._observations[identifier] = (canonical_bytes(claim_ref),canonical_bytes(result))
        return identifier

    async def advance(self, owner_envelope, *, expected_sequence):
        async with self._lock:
            envelope, decision = await self._authorize(owner_envelope,PHASE_CONTRACTS)
            snapshot = await self._ledger.current()
            groups = self._read(snapshot)
            operation,payload = envelope['operation'],envelope['payload']
            replay = await self._ledger.outcome(operation['operationId'],operation['payloadDigest'])
            if replay is not None:
                if not _same_operation(strict_loads(replay.record)['state']['phaseEnvelope'],envelope):
                    raise ContractError('owner_operation_conflict')
                if envelope['contractId']=='federation-board-complete':
                    self._observations.pop(payload['observationId'],None)
                return replay
            group = groups.get(payload['originalOperationId'])
            if (group is None or group['original']['operation']['payloadDigest'] != payload['originalPayloadDigest']
                    or snapshot.sequence != expected_sequence):
                _fail()
            state = strict_loads(canonical_bytes(group['state']))
            state['phaseEnvelope'] = envelope
            identifier = 'board-phase-'+secrets.token_hex(24)
            if envelope['contractId'] == 'federation-board-dispatch':
                state.update(phase='dispatching',dispatchRef=_reference(identifier,self._binding.hub_id,snapshot.sequence+1))
                remaining,admission = 2,'completion'
            else:
                observation = self._observations.get(payload['observationId'])
                if observation is None or observation[0] != canonical_bytes(payload['claimRef']):
                    raise ContractError('board_observation_unavailable')
                result = strict_loads(observation[1])
                state['result'] = result
                state['phase'] = ('uncertain' if result is None else
                    'finished' if result['auditDone'] and result['projectionDone'] else 'settled')
                remaining = 2 if result is None else 0 if state['phase']=='finished' else 1
                admission = 'reconciliation' if result is None else 'completion'
            record = self._record(snapshot,envelope,state,identifier=identifier)
            self._read(type(snapshot)((*snapshot.records,StoredRecord(canonical_bytes(record),snapshot.sequence+1)),snapshot.sequence+1))
            _, decision = await self._authorize(owner_envelope,PHASE_CONTRACTS)
            stored = await self._ledger.append(record,expected_sequence=snapshot.sequence,
                expected_target_version=operation['expectedVersion'],valid_until=decision.valid_until,
                admission=admission,completion_records=remaining)
            if envelope['contractId']=='federation-board-complete':
                self._observations.pop(payload['observationId'],None)
            return stored

    async def outcome(self, original_operation_id, original_payload_digest):
        groups = self._read(await self._ledger.current())
        group = groups.get(original_operation_id)
        if group is None:
            return None
        if group['original']['operation']['payloadDigest'] != original_payload_digest:
            raise ContractError('owner_operation_conflict')
        state,result = group['state'],group['state']['result']
        return BoardOperationOutcome(original_operation_id,original_payload_digest,state['phase'],
            canonical_bytes(self._ref(group['claim'])),canonical_bytes(self._ref(group['latest'])),
            None if result is None else canonical_bytes(result['resourceRef']),
            None if result is None else result['outcome'])
