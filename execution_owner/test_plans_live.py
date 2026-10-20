"""Native TLS/JWT retained plan and task qualification using the existing fixture."""
import copy
from datetime import datetime, timedelta, timezone

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from capability_owner.test_live import stamp
from identity.test_authority import ref, SEED
from state_owner import test_task_live as live_support
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.task import TaskOwner
from state_owner.test_ledger import record
from execution_owner.plans import ExecutionPlanOwner
from execution_owner.test_plans import approved_profile


class LiveExecutionPlanTests(live_support.LiveTaskTests):
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None
    seed_ready_task = False
    create_task_host = False
    project_scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}

    def initial_authority(self):
        value = super().initial_authority()
        state = value['state']
        for name in ('administrator', 'worker', 'consumer'):
            state['identities'].append({'ref': ref(name), 'principalId': name,
                'kind': 'service', 'status': 'active', 'externalIdentity': None})
        for name in ('human', 'administrator', 'worker', 'consumer'):
            state['memberships'].append({'ref': ref(name+'-project-member'), 'identityRef': ref(name),
                'scope': self.project_scope, 'status': 'active'})
        state['transports'].append({**copy.deepcopy(state['transports'][0]),
            'ref': ref('administrator-transport'), 'identityRef': ref('administrator')})
        for contract, caller, resource in (
                ('task-inspect', 'human', 'execution-task'), ('task-reserve', 'human', 'execution-task'),
                ('task-inspect', 'administrator', 'execution-task'),
                ('execution-plan-enroll', 'administrator', 'plan-one'),
                ('execution-plan-read', 'administrator', 'plan-one'),
                ('execution-plan-revoke', 'administrator', 'plan-one'),
                ('capability-process-start', 'human', 'executor')):
            state['grants'].append({**copy.deepcopy(state['grants'][0]),
                'ref': ref('execution-'+caller+'-'+contract), 'contractId': contract, 'resourceId': resource,
                'actorRef': ref(caller), 'callerRef': ref(caller), 'scope': self.project_scope})
        return value

    async def envelope(self, contract, payload, *, caller='administrator', operation=None, expected=0,
                       reservation_context=None):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport' if caller == 'human' else 'administrator-transport'),
            'grantRef': ref('execution-'+caller+'-'+contract), 'operationId': operation or contract+'-original',
            'expectedVersion': expected, 'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=30))}
        raw = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        admitted = await self.identity.ingress.admit(raw, cancellation_ref=ref('execution-cancel'),
            reservation_context=reservation_context)
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return admitted.envelope

    async def inspection(self):
        return await self.envelope('task-inspect', {'taskId': 'execution-task'})

    async def test_tls_signed_enrollment_replay_restart_binding_and_revocation(self):
        # Provisioning creates the exact test streams. Production APIs borrow
        # selected ledgers; no caller receives this private fixture connection.
        admin = self.connections[0]
        js = admin.jetstream()
        bindings = {
            'DATA': OwnerBinding('hub-one', 'task', 'execution-task', 'task', canonical_bytes(self.project_scope)),
            'OTHER': OwnerBinding('hub-one', 'execution-plans', 'plan-one', 'approved-execution-plan',
                canonical_bytes(self.project_scope))}
        ledgers = {}
        for name, binding in bindings.items():
            info = await js.update_stream(self.policy.stream_config(stream=name, subject=owner_subject(binding)))
            ledgers[name] = OwnerLedger(js, stream=name, subject=owner_subject(binding), binding=binding,
                retention=self.policy, stream_identity=StreamIdentity(info.created, 0), require_completion_budget=True)
        initial = record('execution-import')
        initial.update(entityId='execution-task', effects=[], state={'taskId': 'execution-task', 'status': 'ready',
            'assignmentEpoch': 0, 'reservation': None, 'originHubId': 'hub-one', 'taskInputRef': ref('task-input'),
            'flags': {}, 'body': 'Preserved task', 'legacyId': 'W01ABC'})
        initial['operation']['scope'] = self.project_scope
        initial['recordedAt'] = stamp(datetime.now(timezone.utc))
        await ledgers['DATA'].append(initial, expected_sequence=0, completion_records=0)
        task_owner = TaskOwner(self.identity.reader, ledgers['DATA'])
        operation = 'execution-reserve-original'
        refs = task_owner.reservation_references(operation)
        payload = {'taskId': 'execution-task', 'delegationId': refs['delegationRef']['id'], 'attemptId': 'attempt-one',
            'executorHubId': 'hub-one', 'grantRef': refs['executionGrantRef'],
            'repositoryRevision': 'retained-source-revision', 'assignmentEpoch': 1}
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport'),
            'grantRef': ref('execution-human-task-reserve'), 'operationId': operation, 'expectedVersion': 1,
            'contractId': 'task-reserve', 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=30))}
        raw = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        prepared = await task_owner.prepare_reservation(raw, ref('execution-cancel'))
        admitted = await self.identity.ingress.admit(raw, cancellation_ref=ref('execution-cancel'),
            reservation_context=prepared)
        stored = await task_owner.handle(admitted.envelope, reservation_context=prepared)
        task = strict_loads(stored.record)['state']
        profile = approved_profile(self.project_scope)
        profile['isolation']['workerUID'] = 501
        def owner():
            return ExecutionPlanOwner(self.identity.reader, ledgers['OTHER'], task_owner, self.identity.ingress,
                executor_ref=ref('executor'), enrollment_identity_ref=ref('administrator'), profile=profile)
        plans = owner()
        self.addAsyncCleanup(plans.close)
        plan = {'schemaVersion': '1.0.0', 'ref': ref('plan-one'), 'executorRef': ref('executor'),
            'profileId': 'profile-one', 'scope': self.project_scope, 'callerIdentityRef': ref('human'),
            'taskRef': {**ref('execution-task'), 'revision': stored.sequence}, 'taskInputRef': task['taskInputRef'],
            'delegationRef': task['delegation']['ref'], 'executionGrantRef': task['executionGrant']['ref'],
            'attemptId': 'attempt-one', 'assignmentEpoch': 1, 'repositoryRevision': 'retained-source-revision',
            'profile': profile, 'issuedAt': stamp(now-timedelta(seconds=1)),
            'expiresAt': stamp(now+timedelta(seconds=60))}
        enroll = await self.envelope('execution-plan-enroll', {'plan': plan, 'previousRef': None})
        first = await plans.handle(enroll, task_inspection=await self.inspection())
        self.assertEqual(first.status, 'approved')
        await plans.close()
        plans = owner()
        self.addAsyncCleanup(plans.close)
        self.assertEqual((await plans.handle(enroll, task_inspection=await self.inspection())).definition, first.definition)
        self.assertEqual((await ledgers['OTHER'].current()).sequence, 1)
        start = await self.envelope('capability-process-start', {'resourceRef': ref('executor'),
            'input': {'planRef': plan['ref']}}, caller='human', expected=1)
        admission = await plans.admit_start(start, task_inspection=await self.inspection())
        again = await admission.recheck(await self.inspection())
        self.assertEqual(again.binding, admission.binding)
        binding = strict_loads(admission.binding)
        self.assertEqual(binding['originalOperation'], strict_loads(start)['operation'])
        self.assertEqual(binding['delegationRef'], task['delegation']['ref'])
        self.assertIsNone(binding['originalOperation']['delegationRef'])
        read = await self.envelope('execution-plan-read', {'planRef': plan['ref']}, expected=1)
        self.assertEqual((await plans.handle(read)).definition, first.definition)
        revoke = await self.envelope('execution-plan-revoke', {'planRef': plan['ref']}, expected=1)
        self.assertEqual((await plans.handle(revoke)).status, 'revoked')
        with self.assertRaisesRegex(ContractError, '^execution_plan_not_approved$'):
            await admission.recheck(await self.inspection())
        self.assertEqual((await ledgers['DATA'].current()).latest.record, stored.record)
        self.assertEqual((await ledgers['OTHER'].current()).sequence, 2)
        self.success = True
