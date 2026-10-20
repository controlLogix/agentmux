"""Freshly authorized effect status, completion and retry over retained intent.

Status never replays an expired save/drop. Completion records this owner's
observation, not a caller's claim or an inference from matching file bytes.
"""
import asyncio
from dataclasses import dataclass, replace
import uuid

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from identity import authority as identity_authority
from state_owner.ledger import validate_record
from definition_owner_adapter import _validate_catalog
from definition_service import _WRITE_LOCK

EFFECT_COMMANDS = ('definition-effect-query', 'definition-effect-complete', 'definition-effect-retry')
_CORE = ('definitionId', 'name', 'targetScope', 'version', 'checksum', 'deleted', 'contentRef')


def same_definition(left, right):
    return left is not None and all(left.get(key) == right.get(key) for key in _CORE)


@dataclass(frozen=True, repr=False)
class DefinitionEffectStatus:
    original_operation_id: str
    effect_id: str
    definition_version: int
    current_definition_version: int
    catalog_sequence: int
    attempt_operation_id: str
    status: str
    receipt_sequence: int | None = None
    observed_at: str | None = None
    observed_file_status: str | None = None
    replayed: bool = False

    def __repr__(self):
        return f'<DefinitionEffectStatus {self.status}>'


def catalog_head(snapshot, binding):
    latest = snapshot.latest
    if latest is None or latest.sequence != snapshot.sequence:
        raise ContractError('definition_catalog_unavailable')
    record = validate_record(latest.record, binding)
    if record['entityVersion'] != snapshot.sequence or record['previousRevision'] != snapshot.sequence - 1:
        raise ContractError('definition_catalog_unavailable')
    _validate_catalog(record['state'])
    if canonical_bytes(record['state']['scope']) != binding.scope:
        raise ContractError('definition_admission_scope')
    return record


def _matches(receipt, original, effect, entry):
    return all(receipt.get(key) == value for key, value in {
        'definitionId': entry['definitionId'], 'definitionVersion': entry['version'],
        'originalOperationId': original['operation']['operationId'],
        'originalPayloadDigest': original['operation']['payloadDigest'], 'effectId': effect['effectId']}.items())


def _release_observation(owner, receipt):
    attempt = receipt['attemptOperationId']
    observed = owner._observations.get(attempt)
    identity = ('definitionId', 'definitionVersion', 'originalOperationId',
                'originalPayloadDigest', 'effectId', 'attemptOperationId')
    if observed is not None and all(observed.get(key) == receipt[key] for key in identity):
        owner._observations.pop(attempt, None)


def _prune_superseded(owner, state):
    versions = {row['definitionId']: row['version'] for row in state['definitions']}
    for attempt, observed in list(owner._observations.items()):
        current = versions.get(observed.get('definitionId'))
        version = observed.get('definitionVersion')
        if current is not None and type(version) is int and current > version:
            owner._observations.pop(attempt, None)


def _receipt_record(owner, stored, original, effect, entry):
    record = validate_record(stored.record, owner._binding)
    receipt = record.get('definitionEffectReceipt')
    audit = record.get('authorizationDecision', {})
    expected_contract = 'definition-effect-retry' if receipt and receipt['status'] == 'retry-authorized' else 'definition-effect-complete'
    if (record['outcome'] != 'committed' or not isinstance(receipt, dict)
            or not _matches(receipt, original, effect, entry) or len(canonical_bytes(receipt)) > 4096
            or audit.get('decision') != 'allowed' or audit.get('contractId') != expected_contract
            or audit.get('operationId') != record['operation']['operationId']
            or audit.get('actorRef') != record['operation']['effectiveActorRef']
            or (receipt['status'] == 'applied' and receipt['observedAt'] is None)
            or (expected_contract == 'definition-effect-retry' and
                (receipt['attemptOperationId'] != record['operation']['operationId']
                 or record['effects'] != [effect] or receipt['observedAt'] is not None))
            or (expected_contract == 'definition-effect-complete' and record['effects'])):
        raise ContractError('definition_receipt_invalid')
    _validate_catalog(record['state'])
    prior = next((row for row in record['state']['definitions'] if row['definitionId'] == entry['definitionId']), None)
    reference = {'operationId': record['operation']['operationId'], 'payloadDigest': record['operation']['payloadDigest']}
    if (not same_definition(prior, entry) or prior.get('effectReceiptRef') != reference
            or canonical_bytes(record['state']['scope']) != owner._binding.scope):
        raise ContractError('definition_receipt_invalid')
    return record, receipt


async def effect_progress(owner, original, effect, entry, *, snapshot=None):
    snapshot = snapshot if snapshot is not None else await owner._ledger.current()
    head = catalog_head(snapshot, owner._binding)
    _prune_superseded(owner, head['state'])
    current = next((row for row in head['state']['definitions'] if row['definitionId'] == entry['definitionId']), None)
    if (current is None or current['name'] != entry['name'] or current['targetScope'] != entry['targetScope']
            or current['version'] < entry['version']):
        raise ContractError('definition_catalog_conflict')
    result = DefinitionEffectStatus(original['operation']['operationId'], effect['effectId'], entry['version'],
        current['version'], snapshot.sequence, original['operation']['operationId'], 'pending')
    if current['version'] > entry['version']:
        return replace(result, status='superseded')
    if not same_definition(current, entry):
        raise ContractError('definition_catalog_conflict')
    reference = current.get('effectReceiptRef')
    if reference is None:
        return result
    stored = await owner._ledger.outcome(reference['operationId'], reference['payloadDigest'])
    if stored is None or stored.sequence > snapshot.sequence:
        raise ContractError('definition_receipt_unavailable')
    _, receipt = _receipt_record(owner, stored, original, effect, entry)
    for attempt, observed in list(owner._observations.items()):
        if attempt != receipt['attemptOperationId'] and _matches(observed, original, effect, entry):
            owner._observations.pop(attempt, None)
    if receipt['status'] != 'retry-authorized':
        _release_observation(owner, receipt)
    return replace(result, attempt_operation_id=receipt['attemptOperationId'], status=receipt['status'],
                   receipt_sequence=stored.sequence, observed_at=receipt['observedAt'])


async def _original(owner, payload):
    stored = await owner._ledger.outcome(payload['originalOperationId'], payload['originalPayloadDigest'])
    if stored is None:
        raise ContractError('definition_outcome_not_found')
    record = validate_record(stored.record, owner._binding)
    if len(record['effects']) != 1:
        raise ContractError('definition_outcome_invalid')
    effect = record['effects'][0]
    envelope = {'contractId': effect['contractId'], 'payload': effect['payload']}
    record, effect, entry = owner._retained(stored, record['operation'], envelope)
    if (effect['effectId'] != payload['effectId'] or entry['definitionId'] != payload['definitionId']
            or entry['name'] != payload['name'] or entry['targetScope'] != payload['scope']):
        raise ContractError('definition_effect_binding_mismatch')
    return record, effect, entry


async def handle_effect_command(owner, raw, envelope, operation, *, authorize=None):
    from definition_commands import _joined, _record_capacity
    from definition_budget import completion_records

    contract, payload = envelope['contractId'], envelope['payload']
    async def current_authority():
        if authorize is not None:
            return await authorize()
        return (await owner._authorize(raw))[3]
    if operation['operationId'] == payload['originalOperationId']:
        raise ContractError('owner_operation_conflict')
    original, effect, entry = await _original(owner, payload)
    if contract == 'definition-effect-query':
        if await owner._ledger.outcome(operation['operationId'], operation['payloadDigest']) is not None:
            raise ContractError('owner_operation_conflict')
        progress = await effect_progress(owner, original, effect, entry)
        await current_authority()
        return progress
    await _joined(owner._service.check_retained_writer, owner._target_scope, owner._writer)
    # A durable completion/retry is a new signed operation. Never rewrite the
    # original operation or revive its expired authority.
    existing = await owner._ledger.outcome(operation['operationId'], operation['payloadDigest'])
    replayed = existing is not None
    if existing is not None:
        owner._admission._replay(existing, operation)
        value, receipt = _receipt_record(owner, existing, original, effect, entry)
        if value['authorizationDecision']['contractId'] != contract:
            raise ContractError('definition_receipt_invalid')
        if contract == 'definition-effect-complete':
            _release_observation(owner, receipt)
        await current_authority()
        if contract == 'definition-effect-complete':
            return DefinitionEffectStatus(payload['originalOperationId'], payload['effectId'], entry['version'],
                value['operation']['expectedVersion'], existing.sequence, receipt['attemptOperationId'],
                receipt['status'], existing.sequence, receipt['observedAt'], replayed=True)
        progress = await effect_progress(owner, original, effect, entry)
        if progress.status != 'retry-authorized' or progress.attempt_operation_id != operation['operationId']:
            return replace(progress, replayed=True)
    else:
        loop = asyncio.get_running_loop()

        async def retain():
            nonlocal replayed
            replay = await owner._ledger.outcome(operation['operationId'], operation['payloadDigest'])
            if replay is not None:
                replayed = True
                owner._admission._replay(replay, operation)
                prior, receipt = _receipt_record(owner, replay, original, effect, entry)
                if prior['authorizationDecision']['contractId'] != contract:
                    raise ContractError('definition_receipt_invalid')
                if contract == 'definition-effect-complete':
                    _release_observation(owner, receipt)
                await current_authority()
                return replay
            snapshot = await owner._ledger.current()
            head = catalog_head(snapshot, owner._binding)
            progress = await effect_progress(owner, original, effect, entry, snapshot=snapshot)
            if (progress.status == 'superseded' or operation['expectedVersion'] != progress.current_definition_version
                    or payload['attemptOperationId'] != progress.attempt_operation_id):
                raise ContractError('definition_attempt_conflict')
            if contract == 'definition-effect-complete':
                if progress.status not in ('pending', 'retry-authorized'):
                    raise ContractError('definition_attempt_already_recorded')
                observed = owner._observations.get(payload['attemptOperationId'])
                if observed is not None and not _matches(observed, original, effect, entry):
                    raise ContractError('definition_observation_invalid')
                status = observed['status'] if observed is not None else 'reconciliation-required'
                observed_at = observed['observedAt'] if observed is not None else None
                attempt = payload['attemptOperationId']
            else:
                if progress.status not in ('pending', 'retry-authorized', 'reconciliation-required'):
                    raise ContractError('definition_attempt_conflict')
                status, observed_at, attempt = 'retry-authorized', None, operation['operationId']
            receipt = {'definitionId': entry['definitionId'], 'definitionVersion': entry['version'],
                'originalOperationId': payload['originalOperationId'], 'originalPayloadDigest': payload['originalPayloadDigest'],
                'effectId': payload['effectId'], 'attemptOperationId': attempt, 'status': status, 'observedAt': observed_at}
            if len(canonical_bytes(receipt)) > 4096:
                raise ContractError('definition_receipt_size')
            state = head['state']
            current = next(row for row in state['definitions'] if row['definitionId'] == entry['definitionId'])
            current['effectReceiptRef'] = {'operationId': operation['operationId'], 'payloadDigest': operation['payloadDigest']}
            _validate_catalog(state)
            valid_until = await current_authority()
            record = {'schemaVersion': '1.0.0', 'recordId': 'record-' + uuid.uuid4().hex,
                'entityId': owner._binding.entity_id, 'entityKind': owner._binding.entity_kind,
                'ownerHubId': owner._binding.hub_id, 'ownerDomain': owner._binding.owner_domain,
                'entityVersion': head['entityVersion'] + 1, 'previousRevision': snapshot.sequence,
                'operation': operation, 'recordedAt': identity_authority._utc_now().isoformat(timespec='microseconds').replace('+00:00', 'Z'),
                'outcome': 'committed', 'state': state, 'effects': [effect] if status == 'retry-authorized' else [],
                'artifacts': [], 'repository': None, 'definitionEffectReceipt': receipt,
                'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed', 'reason': 'authorized',
                    'actorRef': operation['effectiveActorRef'], 'contractId': contract}}
            validate('owner-record', record)
            _record_capacity(record)
            remaining = await completion_records(owner, record, expected_sequence=snapshot.sequence)
            valid_until = await current_authority()
            try:
                stored = await owner._ledger.append(record, expected_sequence=snapshot.sequence,
                    expected_target_version=current['version'], valid_until=valid_until,
                    admission='reconciliation' if status == 'retry-authorized' else 'completion',
                    completion_records=remaining)
            except ContractError as exc:
                if exc.code != 'owner_commit_uncertain':
                    raise
                replayed = True
                try:
                    stored = await owner._ledger.outcome(operation['operationId'], operation['payloadDigest'])
                except ContractError:
                    raise ContractError('owner_commit_uncertain') from None
                if stored is None:
                    raise ContractError('owner_commit_uncertain') from None
            owner._admission._replay(stored, operation)
            retained, receipt = _receipt_record(owner, stored, original, effect, entry)
            if retained['authorizationDecision']['contractId'] != contract:
                raise ContractError('definition_receipt_conflict')
            if contract == 'definition-effect-complete':
                _release_observation(owner, receipt)
            return stored

        def locked_retain():
            with _WRITE_LOCK, owner._service._writer_lock(owner._target_scope):
                owner._service._check_writer_locked(owner._target_scope, owner._writer)
                return asyncio.run_coroutine_threadsafe(retain(), loop).result()

        existing = await _joined(locked_retain)
        await current_authority()
        progress = await effect_progress(owner, original, effect, entry)
    if contract == 'definition-effect-complete':
        return replace(progress, replayed=replayed)
    status = await owner._execute_effect(raw, original, effect, entry, attempt_operation_id=operation['operationId'])
    return replace(progress, observed_file_status=status, replayed=replayed)
