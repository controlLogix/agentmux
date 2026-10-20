"""Approved execution metadata and fresh admission; no process or secret I/O."""
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import uuid

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key, approval_reason, evaluate_snapshot
from identity.ingress import EnrolledIngress
from state_owner.ledger import OwnerLedger, find_outcome, validate_record
from state_owner.task import TaskOwner


COMMANDS = frozenset(('execution-plan-enroll', 'execution-plan-read', 'execution-plan-revoke'))


def _fail(code='execution_plan_refused'):
    raise ContractError(code) from None


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _time(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() != timezone.utc.utcoffset(result):
        _fail()
    return result


@dataclass(frozen=True, slots=True, repr=False)
class ExecutionPlanView:
    definition: bytes
    status: str
    owner_ref: bytes

    def __repr__(self):
        return '<ExecutionPlanView references; not execution authority>'


@dataclass(frozen=True, slots=True, repr=False)
class ExecutionAdmission:
    """One exact original. Call recheck with a fresh signed task inspection."""
    _owner: object
    _original: bytes
    binding: bytes
    valid_until: datetime
    _native_evidence: object = None
    native_binding: bytes | None = None

    def __repr__(self):
        return '<ExecutionAdmission current checks required>'

    async def recheck(self, task_inspection):
        if datetime.now(timezone.utc) >= self.valid_until:
            _fail('execution_admission_expired')
        current = await self._owner._owned(self._owner._admit_start, self._original,
            task_inspection, self.binding, self._native_evidence, self.native_binding)
        end = min(self.valid_until, current.valid_until)
        if datetime.now(timezone.utc) >= end:
            _fail('execution_admission_expired')
        return ExecutionAdmission(self._owner, self._original, self.binding, end, current._native_evidence, self.native_binding)


class ExecutionPlanOwner:
    """One selected plan's immutable revisions over the real retained owners.

    The host supplies the exact profile and task owner. Request data cannot
    choose a source, verifier, process adapter or credential resolver.
    """
    def __init__(self, authority, ledger, task_owner, ingress, *, executor_ref,
                 enrollment_identity_ref, profile):
        if (type(authority) is not LedgerAuthorityReader or not isinstance(ledger, OwnerLedger)
                or type(task_owner) is not TaskOwner or type(ingress) is not EnrolledIngress
                or ingress._reader is not authority or task_owner._authority is not authority
                or (ledger._binding.owner_domain, ledger._binding.entity_kind) !=
                    ('execution-plans', 'approved-execution-plan')
                or not ledger.completion_budget_required
                or ledger._binding.hub_id != authority._hub
                or task_owner._ledger._binding.scope != ledger._binding.scope):
            _fail('execution_plan_configuration')
        validate('execution-plan-read', {'planRef': executor_ref})
        validate('execution-plan-read', {'planRef': enrollment_identity_ref})
        validate('approved-execution-profile', profile)
        self._authority, self._ledger, self._task, self._ingress = authority, ledger, task_owner, ingress
        self._executor, self._administrator = canonical_bytes(executor_ref), canonical_bytes(enrollment_identity_ref)
        self._profile = canonical_bytes(profile)
        self._closed, self._loop = False, None
        self._workers, self._gate = set(), asyncio.Lock()
        if (executor_ref['ownerHubId'] != authority._hub
                or enrollment_identity_ref['ownerHubId'] != authority._hub
                or profile['profileId'] != authority._profile
                or canonical_bytes(profile['scope']) != ledger._binding.scope):
            _fail('execution_plan_configuration')
        self._profile_shape(profile)

    def __repr__(self):
        return '<ExecutionPlanOwner private>'

    def _current(self):
        if self._closed:
            _fail('execution_plan_closed')

    def _ref(self, revision):
        return {'id': self._ledger._binding.entity_id,
            'ownerHubId': self._ledger._binding.hub_id, 'revision': revision}

    def _profile_shape(self, profile):
        if (profile['scope']['projectId'] is None
                or profile['limits']['offlineSeconds'] > profile['limits']['maxSeconds']
                or any(part in ('.', '..') for part in profile['recipe']['path'].split('/'))
                or any(value['ownerHubId'] != self._authority._hub for value in (
                    profile['profileRef'], profile['workspaceRef'], profile['workerIdentityRef'],
                    profile['consumerRef'], profile['credentialRef'], profile['network']['profileRef'],
                    *profile['network']['destinationRefs']))
                or profile['workerIdentityRef'] == strict_loads(self._administrator)
                or profile['consumerRef'] == strict_loads(self._administrator)):
            _fail('execution_profile_invalid')

    def _plan_shape(self, plan):
        validate('approved-execution-plan', plan)
        self._profile_shape(plan['profile'])
        if (plan['ref']['id'] != self._ledger._binding.entity_id
                or plan['executorRef'] != strict_loads(self._executor)
                or plan['profileId'] != self._authority._profile
                or canonical_bytes(plan['scope']) != self._ledger._binding.scope
                or plan['profile']['scope'] != plan['scope']
                or plan['profile']['profileId'] != plan['profileId']
                or plan['callerIdentityRef'] == strict_loads(self._administrator)
                or plan['taskRef']['id'] != self._task._ledger._binding.entity_id
                or any(plan[name]['ownerHubId'] != self._authority._hub for name in
                    ('ref', 'executorRef', 'callerIdentityRef', 'taskRef', 'taskInputRef',
                     'delegationRef', 'executionGrantRef'))
                or not _time(plan['issuedAt']) < _time(plan['expiresAt'])):
            _fail('execution_plan_binding_mismatch')

    def _history(self, snapshot):
        previous = None
        for stored in snapshot.records:
            record = validate_record(stored.record, self._ledger._binding)
            state, operation = record['state'], record['operation']
            validate('execution-plan-state', state)
            self._plan_shape(state['plan'])
            contract = record.get('authorizationDecision', {}).get('contractId')
            if (record['outcome'] != 'committed' or record['effects'] or record['artifacts']
                    or record['repository'] is not None
                    or contract not in ('execution-plan-enroll', 'execution-plan-revoke')
                    or operation['effectiveActorRef'] != strict_loads(self._administrator)
                    or operation['caller']['authenticatedIdentityRef'] != operation['effectiveActorRef']
                    or operation['caller']['kind'] not in ('human', 'service')
                    or record['authorizationDecision'] != {'operationId': operation['operationId'],
                        'decision': 'allowed', 'reason': 'authorized',
                        'actorRef': operation['effectiveActorRef'], 'contractId': contract}):
                _fail('execution_plan_history_invalid')
            if contract == 'execution-plan-enroll':
                original_payload = {'plan': state['plan'],
                    'previousRef': None if previous is None else self._ref(stored.sequence-1)}
                if state['status'] != 'approved' or state['plan']['ref'] != self._ref(stored.sequence):
                    _fail('execution_plan_history_invalid')
            else:
                if (previous is None or state['status'] != 'revoked'
                        or state['plan'] != previous['plan']):
                    _fail('execution_plan_history_invalid')
                original_payload = {'planRef': previous['plan']['ref']}
            if (operation['expectedVersion'] != stored.sequence-1
                    or operation['payloadDigest'] != payload_digest(original_payload)):
                _fail('execution_plan_history_invalid')
            previous = state
        return previous

    async def _authorize(self, raw, envelope):
        self._current()
        snapshot = await self._authority.current()
        now = datetime.now(timezone.utc)
        decision = evaluate_snapshot(snapshot, raw,
            audience={'hubId': self._authority._hub, 'serviceId': 'process-owner'}, now=now)
        operation = envelope['operation']
        if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(operation)
                or decision.valid_until is None or now >= decision.valid_until
                or canonical_bytes(operation['scope']) != self._ledger._binding.scope):
            _fail('execution_plan_not_authorized')
        end = decision.valid_until
        if operation['caller']['kind'] == 'human':
            # Service enrollment has its own signed service permission. Human
            # operations use the actual selected terminal gate, never an exemption.
            await self._ingress.authorize_terminal(operation)
            snapshot = await self._authority.current()
            now = datetime.now(timezone.utc)
            decision = evaluate_snapshot(snapshot, raw,
                audience={'hubId': self._authority._hub, 'serviceId': 'process-owner'}, now=now)
            if decision.outcome != 'allowed' or decision.valid_until is None:
                _fail('execution_plan_not_authorized')
            end = min(end, decision.valid_until)
        if datetime.now(timezone.utc) >= end:
            _fail('execution_admission_expired')
        self._current()
        return snapshot, end

    async def _task_state(self, task_inspection, plan):
        if type(task_inspection) is not bytes:
            _fail('execution_task_inspection_required')
        request = strict_loads(task_inspection)
        if (request.get('contractId') != 'task-inspect'
                or request.get('payload') != {'taskId': plan['taskRef']['id']}):
            _fail('execution_task_inspection_required')
        stored = await self._task.handle(task_inspection)
        record = self._task._retained(stored)
        state = record['state']
        reservation, grant = state.get('reservation'), state.get('executionGrant')
        if (state.get('status') != 'reserved' or type(reservation) is not dict or type(grant) is not dict
                or stored.sequence != plan['taskRef']['revision']
                or state.get('taskInputRef') != plan['taskInputRef']
                or state.get('assignmentEpoch') != plan['assignmentEpoch']
                or reservation['attemptId'] != plan['attemptId']
                or reservation['assignmentEpoch'] != plan['assignmentEpoch']
                or reservation['repositoryRevision'] != plan['repositoryRevision']
                or reservation['executorHubId'] != self._authority._hub
                or reservation['grantRef'] != plan['executionGrantRef']
                or state['delegation']['ref'] != plan['delegationRef']
                or grant['issuedBy'] != plan['callerIdentityRef']):
            _fail('execution_task_binding_mismatch')
        return record

    def _task_authority(self, snapshot, task, plan, now):
        state = strict_loads(snapshot.record)['state']
        index = _indexes(state, self._authority._hub)
        execution = task['state']['executionGrant']
        requester = index['grants'].get(_key(execution['requesterGrantRef']))
        actor = index['identities'].get(_key(plan['callerIdentityRef']))
        matches = [item for item in index['grants'].values() if _active(item, now)
            and item['callerRef'] == plan['callerIdentityRef'] and item['actorRef'] == plan['callerIdentityRef']
            and item['scope'] == plan['scope'] and item['contractId'] == 'task-reserve'
            and item['resourceId'] == plan['taskRef']['id']]
        if (actor is None or not _active(actor, now) or requester not in matches
                or not any(member['identityRef'] == plan['callerIdentityRef']
                    and member['scope'] == plan['scope'] and _active(member, now)
                    for member in index['memberships'].values())
                or requester['delegationRef'] is not None
                or any(item['decision'] == 'denied' for item in matches)
                or approval_reason(index, requester, task['operation'], audience={
                    'hubId': self._authority._hub, 'serviceId': 'task-owner'}, scope=plan['scope'],
                    contract='task-reserve', now=now) is not None
                or not _time(execution['issuedAt']) <= now < _time(execution['expiresAt'])):
            _fail('execution_task_authority_unavailable')
        for name in ('workerIdentityRef', 'consumerRef'):
            identity = index['identities'].get(_key(plan['profile'][name]))
            if (identity is None or identity['kind'] != 'service' or not _active(identity, now)
                    or not any(member['identityRef'] == identity['ref'] and member['scope'] == plan['scope']
                        and _active(member, now) for member in index['memberships'].values())):
                _fail('execution_consumer_unavailable')
        return min(_time(execution['expiresAt']), _time(plan['expiresAt']),
            _time(execution['issuedAt']) + timedelta(seconds=plan['profile']['limits']['offlineSeconds']))

    async def _owned(self, method, *args, **kwargs):
        self._current()
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        if self._loop is not loop or len(self._workers) >= 16:
            _fail('execution_plan_unavailable')
        worker = asyncio.create_task(method(*args, **kwargs), name='execution-plan-owner')
        self._workers.add(worker)
        def done(original):
            self._workers.discard(original)
            if not original.cancelled():
                original.exception()
        worker.add_done_callback(done)
        return await asyncio.shield(worker)

    async def handle(self, raw, *, task_inspection=None):
        return await self._owned(self._handle, raw, task_inspection)

    async def _handle(self, raw, task_inspection):
        if type(raw) is not bytes or len(raw) > 65536:
            _fail()
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        contract, operation, payload = envelope['contractId'], envelope['operation'], envelope['payload']
        if contract not in COMMANDS or canonical_bytes(envelope) != raw:
            _fail()
        validate(contract, payload)
        reference = payload['plan']['ref'] if contract == 'execution-plan-enroll' else payload['planRef']
        if reference['id'] != self._ledger._binding.entity_id or reference['ownerHubId'] != self._authority._hub:
            _fail('execution_plan_binding_mismatch')
        async with self._gate:
            _, end = await self._authorize(raw, envelope)
            snapshot = await self._ledger.current()
            current = self._history(snapshot)
            if contract == 'execution-plan-read':
                selected = self._selected(snapshot, reference)
            else:
                if operation['effectiveActorRef'] != strict_loads(self._administrator):
                    _fail('execution_plan_administrator_required')
                existing = find_outcome(snapshot, operation['operationId'], operation['payloadDigest'])
                if existing is not None:
                    if strict_loads(existing.record)['operation'] != operation:
                        _fail('owner_operation_conflict')
                    selected = self._selected(snapshot, reference)
                else:
                    if snapshot.sequence != operation['expectedVersion']:
                        _fail('owner_revision_conflict')
                    if contract == 'execution-plan-enroll':
                        plan = payload['plan']
                        self._plan_shape(plan)
                        if (plan['ref'] != self._ref(snapshot.sequence+1)
                                or payload['previousRef'] != (None if snapshot.sequence == 0 else self._ref(snapshot.sequence))
                                or canonical_bytes(plan['profile']) != self._profile
                                or not _time(plan['issuedAt']) <= datetime.now(timezone.utc) < _time(plan['expiresAt'])):
                            _fail('execution_plan_revision_or_profile_mismatch')
                        task = await self._task_state(task_inspection, plan)
                        authority, latest_end = await self._authorize(raw, envelope)
                        self._task_authority(authority, task, plan, datetime.now(timezone.utc))
                        end = min(end, latest_end)
                        next_state = {'format': 'agentmux-approved-execution-plan-v1', 'status': 'approved', 'plan': plan}
                    else:
                        if current is None or current['plan']['ref'] != reference:
                            _fail('execution_plan_revision_or_profile_mismatch')
                        next_state = {**current, 'status': 'revoked'}
                    _, latest_end = await self._authorize(raw, envelope)
                    stored = await self._append(operation, contract, next_state, snapshot.sequence, min(end, latest_end))
                    snapshot = await self._ledger.current()
                    self._history(snapshot)
                    selected = self._selected(snapshot, strict_loads(stored.record)['state']['plan']['ref'])
            await self._authorize(raw, envelope)
            latest = strict_loads(snapshot.latest.record)['state']
            status = latest['status'] if latest['plan']['ref'] == selected['ref'] else 'superseded'
            return ExecutionPlanView(canonical_bytes(selected), status, canonical_bytes(self._ref(snapshot.sequence)))

    def _selected(self, snapshot, reference):
        selected = next((item for item in snapshot.records if item.sequence == reference['revision']), None)
        if selected is None:
            _fail('execution_plan_not_found')
        record = strict_loads(selected.record)
        if (record.get('authorizationDecision', {}).get('contractId') != 'execution-plan-enroll'
                or record['state']['plan']['ref'] != reference):
            _fail('execution_plan_not_found')
        return record['state']['plan']

    async def _append(self, operation, contract, state, sequence, end):
        binding = self._ledger._binding
        record = {'schemaVersion': '1.0.0', 'recordId': 'execution-plan-'+uuid.uuid4().hex,
            'entityId': binding.entity_id, 'entityKind': binding.entity_kind, 'ownerHubId': binding.hub_id,
            'ownerDomain': binding.owner_domain, 'entityVersion': sequence+1, 'previousRevision': sequence,
            'operation': operation, 'recordedAt': _stamp(datetime.now(timezone.utc)), 'outcome': 'committed',
            'state': state, 'effects': [], 'artifacts': [], 'repository': None,
            'authorizationDecision': {'operationId': operation['operationId'], 'decision': 'allowed',
                'reason': 'authorized', 'actorRef': operation['effectiveActorRef'], 'contractId': contract}}
        return await self._ledger.append(record, expected_sequence=sequence, valid_until=end, completion_records=0)

    async def _start_authority(self, raw, envelope, evidence, retained_native):
        self._current()
        if evidence is None:
            if retained_native is not None:_fail('execution_native_evidence_required')
            snapshot,end=await self._authorize(raw,envelope)
            return snapshot,end,None
        from identity.execution_evidence import _AdmittedNativeExecution
        if type(evidence) is not _AdmittedNativeExecution or evidence._evidence.caller_ingress is not self._ingress:
            _fail('execution_native_evidence_required')
        result=await evidence.authorize(self._authority,raw,retained=retained_native)
        self._current()
        return result

    async def admit_start(self, raw, *, task_inspection, retained_binding=None,
                          native_evidence=None, retained_native_binding=None):
        if native_evidence is not None:
            from identity.execution_evidence import NativeExecutionEvidence
            if type(native_evidence) is not NativeExecutionEvidence:
                _fail('execution_native_evidence_required')
        return await self._owned(self._admit_start, raw, task_inspection, retained_binding,
            native_evidence,retained_native_binding)

    async def _admit_start(self, raw, task_inspection, retained_binding, native_evidence, retained_native_binding):
        if type(raw) is not bytes or len(raw) > 65536:
            _fail('execution_start_required')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if envelope['contractId'] != 'capability-process-start' or canonical_bytes(envelope) != raw:
            _fail('execution_start_required')
        validate('capability-process-start', envelope['payload'])
        operation = envelope['operation']
        async with self._gate:
            if native_evidence is not None:
                from identity.execution_evidence import NativeExecutionEvidence
                if type(native_evidence) is NativeExecutionEvidence:
                    if native_evidence.caller_ingress is not self._ingress:_fail('execution_native_evidence_required')
                    native_evidence=await native_evidence.admit(self._authority,raw,retained=retained_native_binding)
            _, original_end, native_binding = await self._start_authority(raw,envelope,native_evidence,retained_native_binding)
            snapshot = await self._ledger.current()
            state = self._history(snapshot)
            if state is None or state['status'] != 'approved':
                _fail('execution_plan_not_approved')
            plan = state['plan']
            if (envelope['payload'] != {'resourceRef': strict_loads(self._executor), 'input': {'planRef': plan['ref']}}
                    or operation['expectedVersion'] != plan['executorRef']['revision']
                    or operation['effectiveActorRef'] != plan['callerIdentityRef']
                    or canonical_bytes(plan['profile']) != self._profile
                    or not _time(plan['issuedAt']) <= datetime.now(timezone.utc) < _time(plan['expiresAt'])
                    or operation['taskId'] not in (None, plan['taskRef']['id'])
                    or operation['attemptId'] not in (None, plan['attemptId'])):
                _fail('execution_start_binding_mismatch')
            task = await self._task_state(task_inspection, plan)
            after = await self._ledger.current()
            if after.sequence != snapshot.sequence:
                _fail('execution_plan_changed')
            authority, current_end, _ = await self._start_authority(raw,envelope,native_evidence,native_binding)
            now = datetime.now(timezone.utc)
            execution_end = self._task_authority(authority, task, plan, now)
            end = min(original_end, current_end, execution_end)
            if now >= end:
                _fail('execution_admission_expired')
            # D retains the first exact binding and supplies it on every retry.
            # Plan rotation or changed content must collide with that original,
            # rather than choosing a second prospective run namespace.
            identity = {'format': 'agentmux-execution-run-reference-v1', 'ownerHubId': self._authority._hub,
                'scope': plan['scope'], 'executorId': plan['executorRef']['id'],
                'operationId': operation['operationId']}
            run = {'id': 'execution-'+payload_digest(identity).split(':',1)[1],
                'ownerHubId': self._authority._hub, 'revision': 1}
            if operation['runId'] not in (None, run['id']):
                _fail('execution_start_binding_mismatch')
            binding = {'format': 'agentmux-execution-run-binding-v1', 'runRef': run,
                'executorRef': plan['executorRef'], 'planRef': plan['ref'], 'scope': plan['scope'],
                'originalOperation': operation, **{key: plan[key] for key in ('taskRef', 'taskInputRef',
                    'delegationRef', 'executionGrantRef', 'attemptId', 'assignmentEpoch', 'repositoryRevision')},
                **{key: plan['profile'][key] for key in ('workerIdentityRef','consumerRef','credentialRef')},
                'executionValidUntil': _stamp(execution_end if native_binding is None else
                    _time(strict_loads(retained_native_binding)['businessEnd']) if retained_native_binding is not None else end)}
            validate('execution-run-binding', binding)
            encoded = canonical_bytes(binding)
            if retained_binding is not None and retained_binding != encoded:
                _fail('execution_original_conflict')
            if native_binding is not None and retained_native_binding is None:
                value=strict_loads(native_binding);value['businessEnd']=_stamp(end)
                native_binding=canonical_bytes(value)
            return ExecutionAdmission(self, raw, encoded, end,native_evidence,native_binding)

    async def close(self, *, timeout=5):
        self._closed = True
        if self._workers:
            _, pending = await asyncio.wait(tuple(self._workers), timeout=timeout)
            if pending:
                _fail('execution_plan_cleanup_incomplete')
