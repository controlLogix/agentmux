"""Conditional lifecycle records and fixed worker handoff after actual admission."""
import copy
from datetime import datetime, timezone
import uuid

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from state_owner.ledger import find_outcome
from .lifecycle import read_lifecycle
from .observations import ProviderObservation, observation


def completion_records(state):
    """All remaining writes for this aggregate's one immutable effect intent."""
    counts = {'intent-committed': 3, 'dispatch-claimed': 2,
              'reconciliation-required': 1, 'applied': 0, 'not-dispatched': 0}
    if state['phase'] not in counts:
        raise ContractError('integration_lifecycle_invalid')
    return counts[state['phase']]


async def append_transition(owner, raw, envelope, snapshot, original, state, record_id):
    operation = envelope['operation']
    first = strict_loads(original.record)
    record = {**first, 'recordId': record_id, 'entityVersion': snapshot.sequence + 1,
        'previousRevision': snapshot.sequence, 'operation': operation,
        'recordedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'state': state, 'authorizationDecision': {'operationId': operation['operationId'],
            'decision': 'allowed', 'reason': 'authorized', 'actorRef': operation['effectiveActorRef'],
            'contractId': envelope['contractId']}}
    validate('integration-effect-state', state)
    validate('owner-record', record)
    if len(canonical_bytes(record)) > 65536:
        raise ContractError('integration_record_limit')
    decision = await owner._authorize(raw, envelope)
    try:
        stored = await owner._ledger.append(record, expected_sequence=snapshot.sequence,
            valid_until=decision.valid_until,
            admission='bulk' if envelope['contractId'] == 'integration-attempt-start' else 'completion',
            completion_records=completion_records(state))
        fresh = not stored.replayed
    except ContractError as error:
        if error.code != 'owner_commit_uncertain':
            raise
        try:
            stored = await owner._ledger.outcome(operation['operationId'], operation['payloadDigest'])
        except ContractError:
            raise ContractError('integration_reconciliation_required') from None
        if stored is None:
            raise ContractError('integration_reconciliation_required') from None
        fresh = False
    return stored, fresh


async def handle_lifecycle(owner, raw, envelope, body):
    operation, contract = envelope['operation'], envelope['contractId']
    if operation['operationId'] == body['originalOperationId']:
        raise ContractError('integration_original_identity_conflict')
    if ((contract == 'integration-attempt-start' and body['attemptOperationId'] != operation['operationId'])
            or (contract != 'integration-attempt-start' and body['attemptOperationId'] == operation['operationId'])):
        raise ContractError('integration_original_identity_conflict')
    snapshot = await owner._ledger.current()
    view = read_lifecycle(snapshot, owner._binding)
    if view.original is None:
        raise ContractError('integration_reconciliation_required')
    owner._retained(view.original)
    state = strict_loads(view.state)
    if (state['originalOperationId'] != body['originalOperationId']
            or state['originalPayloadDigest'] != body['originalPayloadDigest']):
        raise ContractError('integration_original_identity_conflict')
    replay = find_outcome(snapshot, operation['operationId'], operation['payloadDigest'])
    if replay is not None:
        if strict_loads(replay.record)['operation'] != operation:
            raise ContractError('integration_original_identity_conflict')
        await owner._authorize(raw, envelope)
        return owner._reply(operation['operationId'], state, snapshot.sequence)
    if snapshot.sequence != operation['expectedVersion']:
        raise ContractError('integration_revision_conflict')
    record_id = 'i' + uuid.uuid4().hex
    candidate = copy.deepcopy(state)
    attempt_id = body['attemptOperationId']
    if contract == 'integration-attempt-start':
        if state['phase'] != 'intent-committed' or owner._worker is None:
            raise ContractError('integration_worker_unavailable')
        content_ref = state['intent']['contentRef']
        content = None
        if content_ref is not None:
            if owner._artifacts is None:
                raise ContractError('integration_artifact_unavailable')
            content = await owner._artifacts.retrieve(content_ref)
            await owner._authorize(raw, envelope)
        job = owner._worker.prepare(body['originalOperationId'], body['originalPayloadDigest'],
                                    attempt_id, state['intent'], content)
        candidate.update(phase='dispatch-claimed', observation=None, attempt={
            'operationId': attempt_id, 'payloadDigest': operation['payloadDigest'],
            'claimRecordId': record_id, 'claimSequence': snapshot.sequence + 1})
        stored, fresh = await append_transition(owner, raw, envelope, snapshot, view.original, candidate, record_id)
        if fresh:
            # Only the instance that obtained the unique original append ACK may
            # start I/O. A reconciled/lost ACK or replay never grants dispatch.
            current = await owner._ledger.current()
            if current.latest is None or current.latest.record != stored.record:
                raise ContractError('integration_reconciliation_required')
            try:
                await owner._authorize(raw, envelope)
                owner._worker._start(job)
            except ContractError:
                owner._observations[attempt_id] = observation(body['originalOperationId'],
                    body['originalPayloadDigest'], attempt_id, kind='not-dispatched')
                raise
        await owner._authorize(raw, envelope)
        return owner._reply(operation['operationId'], candidate, stored.sequence)
    if (state['phase'] not in ('dispatch-claimed', 'reconciliation-required')
            or state['attempt']['operationId'] != attempt_id):
        raise ContractError('integration_attempt_conflict')
    release_id = None
    if contract == 'integration-attempt-complete':
        observed = owner._observations.get(attempt_id)
        if observed is None:
            if owner._worker is None or attempt_id not in owner._worker._tasks:
                raise ContractError('integration_reconciliation_required')
            observed = await owner._worker.wait(attempt_id)
            release_id = attempt_id
        phases = {'acknowledged': 'applied', 'not-dispatched': 'not-dispatched',
                  'uncertain': 'reconciliation-required'}
        phase = phases.get(observed.private_copy()['kind'])
        if phase is None:
            raise ContractError('integration_observation_invalid')
    else:
        if owner._worker is None:
            observed = observation(body['originalOperationId'], body['originalPayloadDigest'], attempt_id, kind='uncertain')
        else:
            # This explicit read cannot execute a write or authorize retry.
            owner._worker._start_read(operation['operationId'], body['originalOperationId'],
                body['originalPayloadDigest'], attempt_id, state['intent'])
            observed = await owner._worker.wait(operation['operationId'])
            release_id = operation['operationId']
        phase = 'reconciliation-required'
    if type(observed) is not ProviderObservation:
        raise ContractError('integration_observation_invalid')
    candidate.update(phase=phase, observation=observed.private_copy())
    stored, _ = await append_transition(owner, raw, envelope, snapshot, view.original, candidate, record_id)
    latest = await owner._ledger.current()
    checked = read_lifecycle(latest, owner._binding)
    retained = strict_loads(checked.state)
    if retained.get('observation') == observed.private_copy():
        if release_id is not None:
            owner._worker._release(release_id, observed)
        owner._observations.pop(attempt_id, None)
    await owner._authorize(raw, envelope)
    return owner._reply(operation['operationId'], retained, latest.sequence)
