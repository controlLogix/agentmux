"""Host-private execution after the orchestration owner retains a dispatch claim."""
import asyncio
from dataclasses import dataclass, field
import re

from agentmux_contracts import ContractError, canonical_bytes
from .commands import PreparedOrchestrationEffect
from .domain_adapter import OrchestrationDomainAdapter, OrchestrationObservation

_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')


@dataclass(frozen=True, repr=False)
class PreparedOrchestrationDispatch:
    original_operation_id: str
    original_payload_digest: str
    attempt_operation_id: str
    actor: str
    provenance: str
    effect: PreparedOrchestrationEffect = field(repr=False)

    def __repr__(self):
        return '<PreparedOrchestrationDispatch private; not authority>'


class OrchestrationWorker:
    """Own each fixed local effect until its observation is durably retained."""
    def __init__(self, adapter):
        if type(adapter) is not OrchestrationDomainAdapter:
            raise ContractError('orchestration_worker_configuration')
        self._adapter = adapter
        self._tasks = {}
        self._prepared = {}
        self._closed = False

    def __repr__(self):
        return '<OrchestrationWorker private>'

    def prepare(self, original_operation_id, original_payload_digest,
                attempt_operation_id, effect, *, actor, provenance):
        if (self._closed or not isinstance(original_operation_id, str)
                or not _ID.fullmatch(original_operation_id)
                or not isinstance(attempt_operation_id, str)
                or not _ID.fullmatch(attempt_operation_id)
                or attempt_operation_id == original_operation_id
                or not isinstance(original_payload_digest, str)
                or not _DIGEST.fullmatch(original_payload_digest)
                or type(effect) is not PreparedOrchestrationEffect
                or effect.candidate_digest != original_payload_digest
                or type(actor) is not str or not actor
                or type(provenance) is not str or not provenance):
            raise ContractError('orchestration_worker_refused')
        return PreparedOrchestrationDispatch(original_operation_id,
            original_payload_digest, attempt_operation_id, actor, provenance, effect)

    def _perform(self, job):
        try:
            return self._adapter.perform(job.effect, actor=job.actor,
                                         provenance=job.provenance)
        except ContractError as exc:
            # These failures can occur after the process effect began. The owner must
            # recover from observed domain state and must not dispatch it again.
            if exc.code in {
                    'orchestration_cleanup_incomplete',
                    'orchestration_effect_uncertain',
                    'orchestration_process_changed',
                    'orchestration_process_identity_unavailable'}:
                return OrchestrationObservation('uncertain', canonical_bytes({
                    'command': job.effect.command, 'outcome': 'uncertain',
                    'exitCode': None, 'result': None}))
            return OrchestrationObservation('not-dispatched', canonical_bytes({
                'command': job.effect.command, 'outcome': 'not-dispatched',
                'exitCode': None, 'result': None}))
        except Exception:
            return OrchestrationObservation('uncertain', canonical_bytes({
                'command': job.effect.command, 'outcome': 'uncertain',
                'exitCode': None, 'result': None}))

    def _start(self, job):
        """Called only after a fresh durable dispatch claim and authority recheck."""
        if self._closed or type(job) is not PreparedOrchestrationDispatch:
            raise ContractError('orchestration_worker_refused')
        existing = self._tasks.get(job.attempt_operation_id)
        if existing is not None:
            if self._prepared[job.attempt_operation_id] != job:
                raise ContractError('orchestration_attempt_conflict')
            return existing
        if len(self._tasks) >= 8:
            raise ContractError('orchestration_worker_capacity')
        task = asyncio.create_task(asyncio.to_thread(self._perform, job))
        self._prepared[job.attempt_operation_id] = job
        self._tasks[job.attempt_operation_id] = task
        return task

    async def wait(self, attempt_operation_id):
        task = self._tasks.get(attempt_operation_id)
        if task is None:
            raise ContractError('orchestration_attempt_unavailable')
        return await asyncio.shield(task)

    def _release(self, attempt_operation_id, observation):
        task = self._tasks.get(attempt_operation_id)
        if (task is None or not task.done() or task.cancelled()
                or type(observation) is not OrchestrationObservation
                or task.result() != observation):
            raise ContractError('orchestration_cleanup_incomplete')
        del self._tasks[attempt_operation_id]
        del self._prepared[attempt_operation_id]

    async def close(self, *, timeout=5.0):
        self._closed = True
        if self._tasks:
            _, pending = await asyncio.wait(tuple(self._tasks.values()), timeout=timeout)
            if pending or self._tasks:
                raise ContractError('orchestration_cleanup_incomplete')
