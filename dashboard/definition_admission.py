"""Authenticated, read-only definition preparation. No command route or writes.

The host pins real authority and retained-owner readers. An admission is a private
proposal, not a credential or a commit: the future writer must recheck authority,
retained revisions and file identity under its mutation lock before any effect.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.authority import AuthorityReader, Decision
from state_owner.ledger import OwnerBinding, OwnerLedger, StoredRecord
from definition_owner_adapter import prepare_catalog_change, _validate_catalog, catalog_head_for_worker
from definition_service import DefinitionService


@dataclass(frozen=True, repr=False)
class AdmissionPreparation:
    decision: Decision
    outcome: StoredRecord | None = None
    preparation: object | None = None

    @property
    def audit_actor(self):
        return self.decision.audit_actor

    @property
    def authority_ref(self):
        return self.decision.authority_ref

    def __repr__(self):
        return '<AdmissionPreparation private; no effect applied>'


class DefinitionAdmission:
    def __init__(self, service, authority, ledger, binding):
        if (not isinstance(service, DefinitionService)
                or not isinstance(authority, AuthorityReader)
                or not isinstance(ledger, OwnerLedger)
                or not isinstance(binding, OwnerBinding)
                or binding.entity_kind != 'definition-catalog'
                or ledger._binding != binding or authority._hub != binding.hub_id):
            raise ContractError('definition_admission_configuration')
        scope = strict_loads(binding.scope)
        if authority._organization != scope['organizationId']:
            raise ContractError('definition_admission_scope')
        if scope['projectId'] is not None and scope['projectId'] != service.scope.project_id:
            raise ContractError('definition_admission_scope')
        self._service, self._authority, self._ledger, self._binding = service, authority, ledger, binding
        # This serializes this receiver's preparations only. It does not replace
        # the durable owner's compare-and-append or the legacy file writer lock.
        self._lock = asyncio.Lock()

    def __repr__(self):
        return '<DefinitionAdmission private; preparation only>'

    def _operation(self, decision, envelope, *, contracts=('definition-save', 'definition-drop')):
        operation = strict_loads(decision.operation)
        if (canonical_bytes(operation['scope']) != self._binding.scope
                or envelope['contractId'] not in contracts
                or envelope['destinationServiceId'] != 'definition-owner'):
            raise ContractError('definition_admission_scope')
        global_scope = operation['scope']['projectId'] is None
        if (envelope['payload']['scope'] == 'global') != global_scope:
            raise ContractError('definition_admission_scope')
        return operation

    def _replay(self, outcome, operation):
        if outcome is not None:
            record = strict_loads(outcome.record)
            if canonical_bytes(record['operation']) != canonical_bytes(operation):
                raise ContractError('owner_operation_conflict')
            _validate_catalog(record['state'])
            if canonical_bytes(record['state']['scope']) != self._binding.scope:
                raise ContractError('definition_admission_scope')
        return outcome

    async def prepare(self, envelope_bytes):
        if type(envelope_bytes) is not bytes:
            raise ContractError('definition_envelope_required')
        audience = {'hubId': self._binding.hub_id, 'serviceId': 'definition-owner'}
        async with self._lock:
            decision = await self._authority.evaluate(envelope_bytes, audience=audience)
            if decision.outcome != 'allowed':
                return AdmissionPreparation(decision)
            envelope = strict_loads(envelope_bytes)
            operation = self._operation(decision, envelope)
            outcome = self._replay(await self._ledger.outcome(operation['operationId'], operation['payloadDigest']), operation)
            if outcome is not None:
                decision = await self._authority.evaluate(envelope_bytes, audience=audience)
                if decision.outcome != 'allowed':
                    return AdmissionPreparation(decision)
                self._operation(decision, envelope)
                return AdmissionPreparation(decision, outcome=outcome)
            snapshot = await self._ledger.current()
            # A future append must reconcile an intervening outcome or conflict.
            # Do not scan the ledger's verified, potentially large lazy history.
            decision = await self._authority.evaluate(envelope_bytes, audience=audience)
            if decision.outcome != 'allowed':
                return AdmissionPreparation(decision)
            operation = self._operation(decision, envelope)
            worker_snapshot = catalog_head_for_worker(snapshot)
            worker = asyncio.create_task(asyncio.to_thread(
                prepare_catalog_change, self._service, worker_snapshot, self._binding,
                envelope['contractId'], envelope['payload'], operation['expectedVersion']))
            try:
                await asyncio.wait({worker})
                preparation = worker.result()
            except asyncio.CancelledError:
                # Read/encode work still owns its exact file handles and lock.
                while not worker.done():
                    try:
                        await asyncio.wait({worker})
                    except asyncio.CancelledError:
                        continue
                if not worker.cancelled():
                    worker.exception()
                raise
            return AdmissionPreparation(decision, preparation=preparation)
