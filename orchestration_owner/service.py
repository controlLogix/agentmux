"""Enrolled orchestration service boundary and signed outcome receipts."""
import asyncio
from datetime import datetime
import secrets

from agentmux_contracts import (ContractError, canonical_bytes, payload_digest,
                                sign_claims, strict_loads, validate)
from identity.ingress import EnrolledIngress
from identity.authority import LedgerAuthorityReader
from identity import authority as identity_authority
from identity.application_binding import _permission
from identity.local_browser_session import verified_local_browser_context
from state_owner.ledger import OwnerLedger, owner_subject

from .commands import OrchestrationPolicyBinding, prepare_command
from .domain_adapter import OrchestrationDomainAdapter
from .journal import OrchestrationOperationJournal
from .journal import _local_admission, _same_operation
from .owner import OrchestrationOwner
from .phase_signer import OrchestrationPhaseSigner
from .worker import OrchestrationWorker


class OrchestrationCommandService:
    def __init__(self, owner, ingress, *, issuer_ref, signing_seed):
        if (type(owner) is not OrchestrationOwner
                or not isinstance(ingress, EnrolledIngress)
                or ingress._reader is not owner._journal._authority
                or type(signing_seed) is not bytes or len(signing_seed) != 32):
            raise ContractError('orchestration_service_configuration')
        issuer = strict_loads(issuer_ref) if type(issuer_ref) is bytes else issuer_ref
        from .journal import _valid_ref
        if not _valid_ref(issuer) or issuer['ownerHubId'] != owner._journal._binding.hub_id:
            raise ContractError('orchestration_service_configuration')
        self.owner, self.ingress = owner, ingress
        self._issuer, self._seed = canonical_bytes(issuer), signing_seed
        reader = owner._journal._authority
        self._hub, self._profile, self._authority_id = (
            reader._hub, reader._profile, reader._entity)
        self._lock = asyncio.Lock()
        self._browser_lock = asyncio.Lock()
        self._active = set()
        self._ready = self._closed = False

    def __repr__(self):
        return '<OrchestrationCommandService private>'

    @classmethod
    def from_enrolled_host(cls, connection, *, policy_binding, authority, ingress, binding,
                           stream, stream_identity, retention, history, issuer_ref,
                           signing_seed, owner_service_identity_ref,
                           owner_transport_ref, phase_grants, phase_signing_seed,
                           jetstream_domain=None):
        """Compose selected host resources without provisioning or ambient lookup."""
        if (type(policy_binding) is not OrchestrationPolicyBinding
                or not isinstance(authority, LedgerAuthorityReader)
                or not isinstance(ingress, EnrolledIngress)
                or ingress._reader is not authority):
            raise ContractError('orchestration_service_configuration')
        jetstream = (connection.jetstream() if jetstream_domain is None
                     else connection.jetstream(domain=jetstream_domain))
        ledger = OwnerLedger(jetstream, stream=stream, subject=owner_subject(binding),
            binding=binding, retention=retention, stream_identity=stream_identity,
            history=history, require_completion_budget=True)
        journal = OrchestrationOperationJournal(ledger, authority,
            owner_service_identity_ref=owner_service_identity_ref,
            policy_binding=policy_binding)
        # Incoming caller and phase transports belong to the selected identity
        # ingress. The separate orchestration key signs only this service's receipts.
        phases = OrchestrationPhaseSigner(journal, ingress,
            transport_ref=owner_transport_ref, grants=phase_grants,
            signing_seed=phase_signing_seed)
        adapter = OrchestrationDomainAdapter(policy_binding)
        owner = OrchestrationOwner(journal, phases, OrchestrationWorker(adapter))
        return cls(owner, ingress, issuer_ref=issuer_ref, signing_seed=signing_seed)

    async def start(self):
        async with self._lock:
            if self._closed or self._ready:
                raise ContractError('orchestration_service_lifecycle')
            ledger = self.owner._journal._ledger
            if ledger._history is None:
                # A non-indexed owner still validates the complete retained chain.
                await ledger.current()
                self._ready = True
                return self
            while True:
                progress = await ledger.prepare_history()
                if progress.ready:
                    self._ready = True
                    return self
                await asyncio.sleep(0)

    async def handle(self, request_bytes):
        self.check_health()
        if len(self._active) >= 16:
            raise ContractError('orchestration_service_busy')
        task = asyncio.create_task(self._handle(request_bytes))
        self._active.add(task)
        def finished(done):
            self._active.discard(done)
            if not done.cancelled():
                done.exception()
        task.add_done_callback(finished)
        return await asyncio.shield(task)

    def check_health(self):
        history = self.owner._journal._ledger._history
        if (self._closed or not self._ready or self.owner._closed
                or self.owner._worker._closed
                or (history is not None and history._closed)):
            raise ContractError('orchestration_service_unavailable')

    async def _handle(self, request_bytes):
        if type(request_bytes) is not bytes or len(request_bytes) > 65_536:
            raise ContractError('orchestration_body_limit')
        request = strict_loads(request_bytes)
        validate('identity-ingress-request', request)
        contract = request['claims']['contractId']
        if contract not in ('orchestration-command', 'orchestration-outcome-query'):
            raise ContractError('orchestration_contract_unsupported')
        operation_id = request['claims']['operationId']
        admitted = await self.ingress.admit(request_bytes, cancellation_ref={
            'id': operation_id, 'ownerHubId': self._hub, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('orchestration_not_authorized')
        envelope = strict_loads(admitted.envelope)
        operation = envelope['operation']
        if contract == 'orchestration-command':
            value = await self.owner.apply(admitted.envelope)
            receipt = {'operationId': operation_id,
                'actorRef': operation['effectiveActorRef'],
                'resourceRef': value['resourceRef'],
                'environmentRef': envelope['payload']['environmentRef'],
                'originalOperationId': operation_id,
                'originalPayloadDigest': operation['payloadDigest'],
                'receiptRef': value['receiptRef'], 'phase': 'finished',
                'outcome': value['outcome'], 'result': value['result']}
        else:
            value = await self.owner.query(admitted.envelope)
            payload = envelope['payload']
            receipt = {'operationId': operation_id,
                'actorRef': operation['effectiveActorRef'],
                'resourceRef': payload['resourceRef'],
                'environmentRef': (None if self.owner._journal._policy.environment_ref is None
                    else strict_loads(self.owner._journal._policy.environment_ref)),
                'originalOperationId': payload['originalOperationId'],
                'originalPayloadDigest': payload['originalPayloadDigest'],
                'receiptRef': None if value is None else value['receiptRef'],
                'phase': 'absent' if value is None else value['phase'],
                'outcome': None if value is None else value['outcome'],
                'result': None if value is None else value['result']}
        claims = {'purpose': 'agentmux-orchestration-command-receipt-v1',
            'hubId': self._hub, 'profileId': self._profile,
            'authorityId': self._authority_id,
            'issuerRef': strict_loads(self._issuer),
            'requestDigest': payload_digest(request), 'receipt': receipt}
        response = {'schemaVersion': '1.0.0', 'claims': claims,
                    'signature': sign_claims(claims, self._seed)}
        validate('orchestration-command-receipt', response)
        return canonical_bytes(response)

    async def _local_authority(self, context, *, grant_ref=None):
        if not verified_local_browser_context(context):
            raise ContractError('local_browser_context_invalid')
        journal = self.owner._journal
        snapshot = await journal._authority.current()
        record = strict_loads(snapshot.record)
        now = identity_authority._utc_now()
        authority_ref = {'id': record['entityId'], 'ownerHubId': record['ownerHubId'],
                         'revision': record['entityVersion']}
        if (canonical_bytes(context.scope) != journal._binding.scope
                or context.authority_ref['id'] != authority_ref['id']
                or context.authority_ref['ownerHubId'] != authority_ref['ownerHubId']
                or context.authority_ref['revision'] > authority_ref['revision']
                or context.authority_sequence > snapshot.sequence):
            raise ContractError('orchestration_not_authorized')
        index = identity_authority._indexes(record['state'], record['ownerHubId'])
        caller = index['identities'].get(identity_authority._key(context.caller_ref))
        if caller is None or caller['kind'] != 'human' or not identity_authority._active(caller, now):
            raise ContractError('orchestration_not_authorized')
        resource = strict_loads(journal._policy.resource_ref)
        _permission(index, caller['ref'], context.scope, 'orchestration-command',
                    resource['id'], now)
        allowed = [grant for grant in index['grants'].values()
            if identity_authority._active(grant, now)
            and grant['callerRef'] == caller['ref'] and grant['actorRef'] == caller['ref']
            and grant['scope'] == context.scope
            and grant['contractId'] == 'orchestration-command'
            and grant['resourceId'] == resource['id']
            and grant['decision'] == 'allowed' and grant['delegationRef'] is None]
        if grant_ref is not None:
            allowed = [grant for grant in allowed if grant['ref'] == grant_ref]
        if len(allowed) != 1:
            raise ContractError('orchestration_not_authorized')
        valid_until = datetime.fromisoformat(context.valid_until)
        for collection in ('issuers', 'transports', 'grants', 'approvals'):
            for item in record['state'][collection]:
                if item['status'] == 'active':
                    for key in ('issuedAt', 'expiresAt'):
                        boundary = datetime.fromisoformat(item[key])
                        if boundary > now:
                            valid_until = min(valid_until, boundary)
        if now >= valid_until:
            raise ContractError('orchestration_not_authorized')
        return caller, allowed[0], valid_until, authority_ref, snapshot.sequence

    async def handle_local_browser(self, context, command_input, *, operation_id):
        """Admit a closed browser command without claiming possession-signature proof."""
        self.check_health()
        if len(self._active) >= 16:
            raise ContractError('orchestration_service_busy')
        command = strict_loads(canonical_bytes(command_input))
        task = asyncio.create_task(self._browser_command(context, command, operation_id))
        self._active.add(task)
        def finished(done):
            self._active.discard(done)
            if not done.cancelled():
                done.exception()
        task.add_done_callback(finished)
        return await asyncio.shield(task)

    async def _browser_command(self, context, command_input, operation_id):
        # Serialize admission through retention so concurrent first deliveries
        # cannot mint different originals. A cancelled waiter leaves this job owned.
        async with self._browser_lock:
            self.check_health()
            return await self._handle_local_browser(context, command_input, operation_id)

    async def _handle_local_browser(self, context, command_input, operation_id):
        if self._closed or not self._ready or not isinstance(operation_id, str):
            raise ContractError('orchestration_service_unavailable')
        payload = {'resourceRef': strict_loads(self.owner._journal._policy.resource_ref),
            'environmentRef': (None if self.owner._journal._policy.environment_ref is None
                else strict_loads(self.owner._journal._policy.environment_ref)),
            'input': strict_loads(canonical_bytes(command_input))}
        effect = prepare_command(payload, self.owner._journal._policy)
        if not operation_id.startswith('browser_') or len(operation_id) != 40:
            raise ContractError('local_browser_request_unavailable')
        caller, grant, valid_until, authority_ref, authority_sequence = \
            await self._local_authority(context)
        journal = self.owner._journal
        groups = journal._read(await journal._ledger.current())
        prior = groups.get(operation_id)
        if prior is not None and prior['state']['localAdmission'] is None:
            raise ContractError('owner_operation_conflict')
        original = None if prior is None else prior['original']
        retained_operation = None if original is None else original['operation']
        operation = {'schemaVersion': '1.0.0', 'operationId': operation_id,
            'payloadDigest': payload_digest(payload),
            'expectedVersion': payload['resourceRef']['revision'],
            'caller': {'principalId': caller['principalId'], 'kind': 'human',
                'authenticatedIdentityRef': caller['ref']},
            'effectiveActorRef': caller['ref'], 'scope': context.scope,
            'taskId': None, 'runId': None, 'attemptId': None,
            'delegationRef': None, 'grantRef': grant['ref'], 'approvalRefs': [],
            'traceId': ('browser_' + secrets.token_hex(16) if original is None
                        else retained_operation['traceId']),
            'causationId': operation_id,
            'deadline': (valid_until.isoformat(timespec='microseconds').replace('+00:00', 'Z')
                         if original is None else retained_operation['deadline']),
            'cancellationRef': ({'id': 'browser_' + secrets.token_hex(16),
                'ownerHubId': self._hub, 'revision': 1} if original is None
                else retained_operation['cancellationRef'])}
        envelope = {'contractId': 'orchestration-command',
            'destinationHubId': self._hub,
            'destinationServiceId': 'orchestration-owner',
            'operation': operation, 'payload': payload}
        if original is not None:
            # Only server-generated delivery fields come from retained custody.
            # Every current caller, grant, scope, target and input still matches
            # the unchanged generic operation comparison.
            if not _same_operation(original, envelope):
                raise ContractError('owner_operation_conflict')
            envelope = original
            valid_until = min(valid_until,
                              datetime.fromisoformat(retained_operation['deadline']))
            if identity_authority._utc_now() >= valid_until:
                raise ContractError('orchestration_not_authorized')
        admission = _local_admission(canonical_bytes(envelope),
            authority_ref=authority_ref, authority_sequence=authority_sequence,
            caller_ref=caller['ref'], grant_ref=grant['ref'], valid_until=valid_until)

        async def refresh(original):
            current, current_grant, current_until, _, _ = await self._local_authority(
                context, grant_ref=strict_loads(original.grant_ref))
            if (current['ref'] != strict_loads(original.caller_ref)
                    or current_grant['ref'] != strict_loads(original.grant_ref)):
                raise ContractError('orchestration_not_authorized')
            until = min(original.valid_until, current_until)
            if identity_authority._utc_now() >= until:
                raise ContractError('orchestration_not_authorized')
            return until

        result = await self.owner.apply_local(admission, authorize=refresh)
        return {'operationId': operation_id, 'actorRef': caller['ref'],
                'resourceRef': result['resourceRef'], 'receiptRef': result['receiptRef'],
                'outcome': result['outcome'], 'result': result['result']}

    async def close(self):
        async with self._lock:
            self._closed = True
            self._ready = False
            if self._active:
                _, pending = await asyncio.wait(tuple(self._active), timeout=5)
                if pending:
                    raise ContractError('orchestration_service_cleanup_incomplete')
            await self.owner.close()
            history = self.owner._journal._ledger._history
            if history is not None:
                history.close()

