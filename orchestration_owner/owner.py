"""Enrolled orchestration owner with retained dispatch and completion phases."""
import asyncio

from agentmux_contracts import ContractError, canonical_bytes, strict_loads

from .commands import prepare_command
from .domain_adapter import OrchestrationObservation
from .journal import (ORIGINAL_CONTRACTS, OrchestrationOperationJournal,
                      _LocalOrchestrationAdmission, _same_operation)
from .phase_signer import OrchestrationPhaseSigner
from .worker import OrchestrationWorker


class OrchestrationOwner:
    def __init__(self, journal, phase_signer, worker):
        if (type(journal) is not OrchestrationOperationJournal
                or type(phase_signer) is not OrchestrationPhaseSigner
                or phase_signer._journal is not journal
                or type(worker) is not OrchestrationWorker
                or worker._adapter._binding != journal._policy):
            raise ContractError('orchestration_owner_configuration')
        self._journal, self._phases, self._worker = journal, phase_signer, worker
        self._tasks, self._originals = set(), {}
        self._closed = False

    def __repr__(self):
        return '<OrchestrationOwner private>'

    async def apply(self, raw):
        if self._closed or len(self._tasks) >= 16:
            raise ContractError('orchestration_owner_unavailable')
        task = asyncio.create_task(self._apply(raw))
        self._tasks.add(task)
        def finished(done):
            self._tasks.discard(done)
            if not done.cancelled():
                done.exception()
        task.add_done_callback(finished)
        return await asyncio.shield(task)

    async def close(self, *, timeout=5.0):
        self._closed = True
        if self._tasks:
            _, pending = await asyncio.wait(tuple(self._tasks), timeout=timeout)
            if pending:
                raise ContractError('orchestration_owner_cleanup_incomplete')
        await self._worker.close(timeout=timeout)

    async def _apply(self, raw):
        envelope, _ = await self._journal._authorize(raw, ORIGINAL_CONTRACTS)
        operation = envelope['operation']
        key = operation['operationId'], operation['payloadDigest']
        active = self._originals.get(key)
        if active is not None:
            if not _same_operation(active[0], envelope):
                raise ContractError('owner_operation_conflict')
            return await asyncio.shield(active[1])
        task = asyncio.current_task()
        self._originals[key] = envelope, task
        try:
            result = await self._execute(raw, envelope)
            await self._journal._authorize(raw, ORIGINAL_CONTRACTS)
            return result
        finally:
            if self._originals.get(key, (None, None))[1] is task:
                self._originals.pop(key, None)

    async def apply_local(self, admission, *, authorize):
        if (self._closed or type(admission) is not _LocalOrchestrationAdmission
                or not callable(authorize)):
            raise ContractError('orchestration_owner_unavailable')
        envelope = strict_loads(admission.envelope)
        operation = envelope['operation']
        key = operation['operationId'], operation['payloadDigest']
        active = self._originals.get(key)
        if active is not None:
            if not _same_operation(active[0], envelope):
                raise ContractError('owner_operation_conflict')
            return await asyncio.shield(active[1])
        task = asyncio.current_task()
        self._originals[key] = envelope, task
        try:
            result = await self._execute(None, envelope, admission=admission,
                                         authorize=authorize)
            await authorize(admission)
            return result
        finally:
            if self._originals.get(key, (None, None))[1] is task:
                self._originals.pop(key, None)

    async def _group(self, operation):
        groups = self._journal._read(await self._journal._ledger.current())
        group = groups.get(operation['operationId'])
        if (group is None or group['original']['operation']['payloadDigest']
                != operation['payloadDigest']):
            raise ContractError('orchestration_journal_invalid')
        return group

    async def _phase(self, contract, group, *, observation_id=None):
        snapshot = await self._journal._ledger.current()
        state, original = group['state'], group['original']['operation']
        payload = {'resourceRef': state['resourceRef'],
            'journalRef': {'id': self._journal._binding.entity_id,
                'ownerHubId': self._journal._binding.hub_id,
                'revision': group['latest'].sequence},
            'claimRef': self._journal._ref(group['claim']),
            'originalOperationId': original['operationId'],
            'originalPayloadDigest': original['payloadDigest'],
            'candidateDigest': state['candidateDigest']}
        if observation_id is not None:
            payload['observationId'] = observation_id
        admitted = await self._phases.admit(contract,
            expected_sequence=snapshot.sequence, payload=payload,
            cancellation_ref=original['cancellationRef'])
        try:
            return await self._journal.advance(admitted.envelope,
                                               expected_sequence=snapshot.sequence)
        except ContractError as exc:
            if exc.code != 'owner_commit_uncertain':
                raise
            return await self._journal.advance(admitted.envelope,
                                               expected_sequence=snapshot.sequence)

    def _receipt(self, group):
        observation = group['state']['observation']
        if observation is None or observation['outcome'] == 'uncertain':
            raise ContractError('orchestration_outcome_uncertain')
        return {'receiptRef': self._journal._ref(group['latest']),
                'resourceRef': group['state']['resourceRef'],
                'outcome': observation['outcome'], 'result': observation['result']}

    async def _complete(self, group, observation):
        observation_id = self._journal._observe(self._journal._ref(group['claim']),
                                                observation)
        await self._phase('orchestration-complete', group,
                          observation_id=observation_id)
        return await self._group(group['original']['operation'])

    async def _execute(self, raw, envelope, *, admission=None, authorize=None):
        operation = envelope['operation']
        prior = await self._journal.outcome(operation['operationId'],
                                            operation['payloadDigest'])
        if prior is not None:
            group = await self._group(operation)
            if not _same_operation(group['original'], envelope):
                raise ContractError('owner_operation_conflict')
            if group['state']['phase'] == 'finished':
                return self._receipt(group)
            raise ContractError('orchestration_outcome_uncertain')

        effect = prepare_command(envelope['payload'], self._journal._policy)
        actor = operation['effectiveActorRef']['id']
        snapshot = await self._journal._ledger.current()
        if admission is None:
            claim = await self._journal.prepare(raw, expected_sequence=snapshot.sequence,
                effect=effect, actor=actor,
                provenance=self._journal._policy.orchestrator_agent)
        else:
            claim = await self._journal.prepare_local(admission,
                expected_sequence=snapshot.sequence, effect=effect, actor=actor,
                provenance=self._journal._policy.orchestrator_agent,
                authorize=authorize)
        group = await self._group(operation)
        if claim.replayed:
            raise ContractError('orchestration_outcome_uncertain')
        dispatch = await self._phase('orchestration-dispatch', group)
        group = await self._group(operation)
        dispatch_operation = strict_loads(dispatch.record)['operation']
        job = self._worker.prepare(operation['operationId'], effect.candidate_digest,
            dispatch_operation['operationId'], effect, actor=actor,
            provenance=self._journal._policy.orchestrator_agent)
        try:
            if admission is None:
                await self._journal._authorize(raw, ORIGINAL_CONTRACTS)
            else:
                await authorize(admission)
        except ContractError:
            observation = OrchestrationObservation('not-dispatched', canonical_bytes({
                'command': effect.command, 'outcome': 'not-dispatched',
                'exitCode': None, 'result': None}))
            group = await self._complete(group, observation)
            return self._receipt(group)
        self._worker._start(job)
        observation = await self._worker.wait(job.attempt_operation_id)
        try:
            group = await self._complete(group, observation)
        except BaseException:
            raise  # worker and observation remain owned until completion is retained
        self._worker._release(job.attempt_operation_id, observation)
        return self._receipt(group)

    async def query(self, raw):
        if type(raw) is not bytes:
            raise ContractError('orchestration_query_invalid')
        envelope = strict_loads(raw)
        if (canonical_bytes(envelope) != raw
                or envelope.get('contractId') != 'orchestration-outcome-query'):
            raise ContractError('orchestration_query_invalid')
        decision = await self._journal._authority.evaluate(raw, audience={
            'hubId': self._journal._binding.hub_id,
            'serviceId': 'orchestration-owner'})
        payload, operation = envelope['payload'], envelope['operation']
        if (decision.outcome != 'allowed'
                or canonical_bytes(operation['scope']) != self._journal._binding.scope
                or payload['resourceRef'] != strict_loads(self._journal._policy.resource_ref)):
            raise ContractError('orchestration_query_access_refused')
        outcome = await self._journal.outcome(payload['originalOperationId'],
                                              payload['originalPayloadDigest'])
        if outcome is None:
            return None
        return {'receiptRef': strict_loads(outcome.receipt_ref),
                'resourceRef': payload['resourceRef'], 'phase': outcome.phase,
                'outcome': outcome.outcome,
                'result': None if outcome.result is None else strict_loads(outcome.result)}

    async def reconcile(self, original_raw, observation):
        """Retain a trusted recovery observation without repeating the effect."""
        if type(observation) is not OrchestrationObservation:
            raise ContractError('orchestration_observation_unavailable')
        envelope, _ = await self._journal._authorize(original_raw, ORIGINAL_CONTRACTS)
        group = await self._group(envelope['operation'])
        if group['state']['phase'] != 'uncertain':
            raise ContractError('orchestration_recovery_not_required')
        group = await self._complete(group, observation)
        return self._receipt(group)
