"""Signed execution enrollment and admission over the existing retained owners."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.test_authority import ref, fixture, SEED
from identity.test_service import _Clock
from state_owner import test_task as task_support
from state_owner.test_ledger import FakeJetStream, CREATED
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from execution_owner.plans import ExecutionPlanOwner


def approved_profile(scope):
    return {'schemaVersion': '1.0.0', 'profileRef': ref('profile'), 'profileId': 'profile-one',
            'scope': scope, 'image': 'python@sha256:'+'a'*64, 'platform': 'linux/arm64',
            'recipe': {'kind': 'python-script-v1', 'path': 'task/main.py', 'sha256': 'sha256:'+'b'*64},
            'workspaceRef': ref('workspace'), 'workerIdentityRef': ref('worker'), 'consumerRef': ref('consumer'),
            'credentialRef': ref('credential'), 'network': {'profileRef': ref('network'), 'mode': 'none',
                'destinationRefs': []},
            'limits': {'maxSeconds': 60, 'offlineSeconds': 20, 'cpuMillis': 1000,
                'memoryBytes': 67108864, 'pids': 32},
            'isolation': {'homeMounted': False, 'dockerSocketMounted': False, 'hostPID': False,
                'privileged': False, 'readOnlyRootFilesystem': True, 'dropAllCapabilities': True,
                'noNewPrivileges': True, 'workerUID': 1000},
            'workingDirectory': '/workspace', 'outputPolicy': 'discard'}



class ExecutionPlanTests(unittest.IsolatedAsyncioTestCase):
    new_ledger = task_support.TaskReservationTests.new_ledger
    reset_task = task_support.TaskReservationTests.reset_task
    possession = task_support.TaskReservationTests.possession
    admitted = task_support.TaskReservationTests.admitted

    def setUp(self):
        task_support.TaskReservationTests.setUp(self)
        patch('execution_owner.plans.datetime', _Clock).start()
        self.scope['projectId'] = 'project-one'
        for item in self.record['state']['grants'] + self.record['state']['memberships']:
            item['scope'] = copy.deepcopy(self.scope)
        self.original['operation']['scope'] = copy.deepcopy(self.scope)
        self.binding = OwnerBinding('hub-one', 'task', 'task-one', 'task', canonical_bytes(self.scope))
        self.task_js.config.subjects = [owner_subject(self.binding)]
        self.reset_task()
        self.ledger = self.new_ledger()
        from state_owner.task import TaskOwner
        self.owner = TaskOwner(self.service.reader, self.ledger)
        state = self.record['state']
        # The task requester and the selected enrollment administrator differ.
        for name in ('administrator', 'worker', 'consumer'):
            state['identities'].append({'ref': ref(name), 'principalId': name,
                'kind': 'service', 'status': 'active', 'externalIdentity': None})
            state['memberships'].append({'ref': ref(name+'-membership'), 'identityRef': ref(name),
                'scope': self.scope, 'status': 'active'})
        state['transports'].append({**copy.deepcopy(state['transports'][0]),
            'ref': ref('administrator-transport'), 'identityRef': ref('administrator')})
        for contract, caller, resource in (
                ('execution-plan-enroll', 'administrator', 'plan-one'),
                ('execution-plan-read', 'administrator', 'plan-one'),
                ('execution-plan-revoke', 'administrator', 'plan-one'),
                ('task-inspect', 'administrator', 'task-one'),
                ('capability-process-start', 'human', 'executor')):
            state['grants'].append({**copy.deepcopy(state['grants'][0]),
                'ref': ref(contract+'-grant'), 'contractId': contract, 'resourceId': resource,
                'actorRef': ref(caller), 'callerRef': ref(caller)})
        self.sync()
        self.profile = approved_profile(self.scope)
        binding = OwnerBinding('hub-one', 'execution-plans', 'plan-one', 'approved-execution-plan',
            canonical_bytes(self.scope))
        self.plan_js = FakeJetStream(self.policy)
        self.plan_js.config.subjects = [owner_subject(binding)]
        self.plan_ledger = OwnerLedger(self.plan_js, stream='OWNER', subject=owner_subject(binding),
            binding=binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        self.plans = self.make_owner()
        self.addAsyncCleanup(self.plans.close)

    def make_owner(self):
        return ExecutionPlanOwner(self.service.reader, self.plan_ledger, self.owner, self.service.ingress,
            executor_ref=ref('executor'), enrollment_identity_ref=ref('administrator'), profile=self.profile)

    def sync(self):
        self.js.messages[0].data = canonical_bytes(self.record)

    async def reserve(self):
        _, prepared, envelope = await self.admitted(self.possession(executorHubId='hub-one'))
        stored = await self.owner.handle(envelope, reservation_context=prepared)
        task = strict_loads(stored.record)['state']
        self.plan = {'schemaVersion': '1.0.0', 'ref': ref('plan-one'), 'executorRef': ref('executor'),
            'profileId': 'profile-one', 'scope': self.scope, 'callerIdentityRef': ref('human'),
            'taskRef': {**ref('task-one'), 'revision': stored.sequence}, 'taskInputRef': task['taskInputRef'],
            'delegationRef': task['delegation']['ref'], 'executionGrantRef': task['executionGrant']['ref'],
            'attemptId': task['reservation']['attemptId'], 'assignmentEpoch': task['assignmentEpoch'],
            'repositoryRevision': task['reservation']['repositoryRevision'], 'profile': self.profile,
            'issuedAt': '2026-10-09T12:00:00Z', 'expiresAt': '2026-10-09T12:01:00Z'}

    def request(self, contract, payload, *, caller='administrator', operation=None, expected=None, **changes):
        env = fixture()[1]
        env.update(contractId=contract, destinationServiceId='task-owner' if contract == 'task-inspect' else 'process-owner',
            payload=copy.deepcopy(payload))
        op = env['operation']
        op.update(operationId=operation or contract+'-'+str(len(self.plan_js.messages)), payloadDigest=payload_digest(payload),
            expectedVersion=len(self.plan_js.messages) if expected is None else expected,
            caller={'principalId': caller if caller != 'human' else 'user-one',
                'kind': 'human' if caller == 'human' else 'service', 'authenticatedIdentityRef': ref(caller)},
            effectiveActorRef=ref(caller), grantRef=ref(contract+'-grant'), scope=self.scope,
            taskId='task-one' if contract == 'task-inspect' else None, runId=None, attemptId=None, delegationRef=None, approvalRefs=[])
        op.update(changes)
        claims = env['ingressAttestation']['claims']
        claims.update(contractId=contract, operation=copy.deepcopy(op),
            authenticatedTransportRef=ref('transport' if caller == 'human' else 'administrator-transport'),
            audience={'hubId': 'hub-one', 'serviceId': env['destinationServiceId']})
        env['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(env)

    def inspection(self):
        return self.request('task-inspect', {'taskId': 'task-one'})

    async def enroll(self):
        return await self.plans.handle(self.request('execution-plan-enroll', {'plan': self.plan,
            'previousRef': None if not self.plan_js.messages else {**ref('plan-one'), 'revision': len(self.plan_js.messages)}}),
            task_inspection=self.inspection())

    def start(self, **changes):
        return self.request('capability-process-start', {'resourceRef': ref('executor'),
            'input': {'planRef': self.plan['ref']}}, caller='human', expected=1, operation='original-start', **changes)

    async def test_signed_enrollment_read_and_current_binding(self):
        await self.reserve()
        view = await self.enroll()
        self.assertEqual(view.status, 'approved')
        self.assertEqual(strict_loads(view.definition), self.plan)
        read = await self.plans.handle(self.request('execution-plan-read', {'planRef': self.plan['ref']}))
        self.assertEqual(view, read)
        admission = await self.plans.admit_start(self.start(), task_inspection=self.inspection())
        binding = strict_loads(admission.binding)
        self.assertEqual(binding['originalOperation'], strict_loads(self.start())['operation'])
        self.assertEqual(binding['delegationRef'], self.plan['delegationRef'])
        self.assertIsNone(binding['originalOperation']['delegationRef'])
        self.assertEqual(len(self.plan_js.messages), 1)
        again = await admission.recheck(self.inspection())
        self.assertEqual(again.binding, admission.binding)
        self.assertLessEqual(again.valid_until, admission.valid_until)

    async def test_revoked_reserved_actor_membership_refuses_admin_enrollment(self):
        await self.reserve()
        self.record['state']['memberships'][0]['status'] = 'revoked'
        self.sync()
        with self.assertRaisesRegex(ContractError, '^execution_task_authority_unavailable$'):
            await self.enroll()
        self.assertFalse(self.plan_js.messages)

    async def test_original_reference_stays_stable_across_plan_revision_and_conflict_refuses(self):
        await self.reserve()
        await self.enroll()
        original = await self.plans.admit_start(self.start(), task_inspection=self.inspection())
        self.plan = copy.deepcopy(self.plan)
        self.plan['ref']['revision'] = 2
        await self.enroll()
        changed = await self.plans.admit_start(self.start(), task_inspection=self.inspection())
        self.assertEqual(strict_loads(original.binding)['runRef'], strict_loads(changed.binding)['runRef'])
        with self.assertRaisesRegex(ContractError, '^execution_original_conflict$'):
            await self.plans.admit_start(self.start(), task_inspection=self.inspection(),
                retained_binding=original.binding)

    async def test_actual_ingress_enrollment_requires_exact_current_approval(self):
        await self.reserve()
        payload = {'plan': self.plan, 'previousRef': None}
        grant = next(g for g in self.record['state']['grants'] if g['contractId'] == 'execution-plan-enroll')
        grant['decision'] = 'review-required'
        self.sync()
        raw = self.request('execution-plan-enroll', payload)
        with self.assertRaisesRegex(ContractError, '^execution_plan_not_authorized$'):
            await self.plans.handle(raw, task_inspection=self.inspection())
        operation = strict_loads(raw)['operation']
        approval_grant = {**copy.deepcopy(grant), 'ref': ref('approve-grant'), 'contractId': 'identity-approve',
            'resourceId': grant['ref']['id'], 'decision': 'allowed'}
        self.record['state']['grants'].append(approval_grant)
        approval = {'ref': ref('approval'), 'grantRef': grant['ref'], 'approverRef': ref('administrator'),
            'payloadDigest': operation['payloadDigest'], 'audience': {'hubId': 'hub-one', 'serviceId': 'process-owner'},
            'operationId': operation['operationId'], 'expectedVersion': 0, 'approverGrantRef': approval_grant['ref'],
            'decision': 'approved', 'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z',
            'expiresAt': '2026-10-09T12:10:00Z'}
        self.record['state']['approvals'].append(approval)
        self.sync()
        claims = {'purpose': 'agentmux-client-possession-v1', 'profileId': 'profile-one', 'hubId': 'hub-one',
            'authorityId': 'authority-one', 'transportRef': ref('administrator-transport'),
            'grantRef': grant['ref'], 'operationId': operation['operationId'], 'expectedVersion': 0,
            'contractId': 'execution-plan-enroll', 'payload': payload, 'approvalRefs': [ref('approval')],
            'issuedAt': '2026-10-09T12:00:01Z', 'expiresAt': '2026-10-09T12:00:30Z'}
        possession = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        admitted = await self.service.ingress.admit(possession, cancellation_ref=ref('enroll-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        for key, wrong in (('payloadDigest', 'sha256:'+'0'*64), ('expectedVersion', 1),
                ('operationId', 'another-original'), ('status', 'revoked'),
                ('audience', {'hubId': 'hub-one', 'serviceId': 'task-owner'})):
            old = approval[key]
            approval[key] = wrong
            self.sync()
            with self.subTest(key=key), self.assertRaises(ContractError):
                await self.plans.handle(admitted.envelope, task_inspection=self.inspection())
            approval[key] = old
        self.sync()
        view = await self.plans.handle(admitted.envelope, task_inspection=self.inspection())
        self.assertEqual(view.status, 'approved')
        self.assertEqual(len(self.plan_js.messages), 1)

    async def test_revision_read_revoke_and_restart_preserve_original(self):
        await self.reserve()
        first = await self.enroll()
        old_ref = copy.deepcopy(self.plan['ref'])
        self.plan = copy.deepcopy(self.plan)
        self.plan['ref']['revision'] = 2
        await self.enroll()
        old = await self.plans.handle(self.request('execution-plan-read', {'planRef': old_ref}))
        self.assertEqual(old.definition, first.definition)
        self.assertEqual(old.status, 'superseded')
        self.plans = self.make_owner()
        self.addAsyncCleanup(self.plans.close)
        request = self.request('execution-plan-revoke', {'planRef': self.plan['ref']})
        revoked = await self.plans.handle(request)
        self.assertEqual(revoked.status, 'revoked')
        self.assertEqual((await self.plans.handle(request)).definition, revoked.definition)
        self.assertEqual(len(self.plan_js.messages), 3)
        with self.assertRaisesRegex(ContractError, '^execution_plan_not_approved$'):
            await self.plans.admit_start(self.start(), task_inspection=self.inspection())

    async def test_current_grant_denial_membership_and_consumer_revocation(self):
        await self.reserve()
        await self.enroll()
        original = copy.deepcopy(self.record)
        changes = (
            lambda s: s['grants'][-1].update(status='revoked'),
            lambda s: s['memberships'][0].update(status='revoked'),
            lambda s: s['identities'][-1].update(status='revoked'),
            lambda s: s['memberships'][-1].update(status='revoked'),
            lambda s: s['grants'].append({**copy.deepcopy(s['grants'][-1]), 'ref': ref('deny'), 'decision': 'denied'}))
        for change in changes:
            self.record = copy.deepcopy(original)
            change(self.record['state'])
            self.sync()
            with self.subTest(change=changes.index(change)), self.assertRaises(ContractError):
                await self.plans.admit_start(self.start(), task_inspection=self.inspection())
        self.record = original
        self.sync()
        self.assertEqual(len(self.plan_js.messages), 1)

    async def test_enrollment_current_authority_after_task_read(self):
        await self.reserve()
        handle = self.owner.handle
        async def read_then_revoke(raw):
            stored = await handle(raw)
            self.record['state']['memberships'][0]['status'] = 'revoked'
            self.sync()
            return stored
        with patch.object(self.owner, 'handle', side_effect=read_then_revoke):
            with self.assertRaisesRegex(ContractError, '^execution_task_authority_unavailable$'):
                await self.enroll()
        self.assertFalse(self.plan_js.messages)

    async def test_read_revocation_during_ledger_read_prevents_disclosure(self):
        await self.reserve()
        await self.enroll()
        current = self.plan_ledger.current
        async def read_then_revoke():
            snapshot = await current()
            grant = next(g for g in self.record['state']['grants'] if g['contractId'] == 'execution-plan-read')
            grant['status'] = 'revoked'
            self.sync()
            return snapshot
        with patch.object(self.plan_ledger, 'current', side_effect=read_then_revoke):
            with self.assertRaisesRegex(ContractError, '^execution_plan_not_authorized$'):
                await self.plans.handle(self.request('execution-plan-read', {'planRef': self.plan['ref']}))

    async def test_signed_namespace_version_and_original_substitution_refuses(self):
        await self.reserve()
        await self.enroll()
        admission = await self.plans.admit_start(self.start(), task_inspection=self.inspection())
        for changes in ({'scope': {**self.scope, 'projectId': 'other-project'}},
                {'taskId': 'another-task'}, {'attemptId': 'another-attempt'}, {'runId': 'another-run'},
                {'delegationRef': self.plan['delegationRef']}, {'expectedVersion': 2}):
            # expectedVersion is specified by start(), so build the envelope directly.
            env = strict_loads(self.start())
            env['operation'].update(changes)
            env['ingressAttestation']['claims']['operation'] = copy.deepcopy(env['operation'])
            env['ingressAttestation']['signature'] = sign_claims(env['ingressAttestation']['claims'], SEED)
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                await self.plans.admit_start(canonical_bytes(env), task_inspection=self.inspection(),
                    retained_binding=admission.binding)
        changed = self.start(traceId='different-trace')
        with self.assertRaisesRegex(ContractError, '^execution_original_conflict$'):
            await self.plans.admit_start(changed, task_inspection=self.inspection(), retained_binding=admission.binding)
        with self.assertRaisesRegex(ContractError, '^execution_task_inspection_required$'):
            await self.plans.admit_start(self.start(), task_inspection=None)

    async def test_signed_stale_task_reference_and_profile_substitution_refuses(self):
        await self.reserve()
        original = copy.deepcopy(self.plan)
        for mutate in (lambda p: p['taskRef'].update(revision=1),
                lambda p: p.update(assignmentEpoch=2), lambda p: p.update(attemptId='another-attempt'),
                lambda p: p.update(repositoryRevision='another-revision'),
                lambda p: p.update(taskInputRef=ref('another-input')),
                lambda p: p.update(executionGrantRef=ref('another-grant')),
                lambda p: p.update(callerIdentityRef=ref('administrator')),
                lambda p: p['profile']['recipe'].update(path='../task.py'),
                lambda p: p['profile']['recipe'].update(path='task/./main.py'),
                lambda p: p['profile'].update(workspaceRef=ref('another-workspace'))):
            self.plan = copy.deepcopy(original)
            mutate(self.plan)
            with self.subTest(mutation=mutate), self.assertRaises(ContractError):
                await self.enroll()
            self.assertFalse(self.plan_js.messages)
        self.plan = original

    async def test_lost_append_ack_replay_reuses_retained_plan(self):
        await self.reserve()
        request = self.request('execution-plan-enroll', {'plan': self.plan, 'previousRef': None})
        self.plan_js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.plans.handle(request, task_inspection=self.inspection())
        self.assertEqual(len(self.plan_js.messages), 1)
        self.plans = self.make_owner()
        self.addAsyncCleanup(self.plans.close)
        view = await self.plans.handle(request, task_inspection=self.inspection())
        self.assertEqual(strict_loads(view.definition), self.plan)
        self.assertEqual(len(self.plan_js.messages), 1)

    async def test_history_requires_exact_original_plan_digest(self):
        await self.reserve()
        await self.enroll()
        value = strict_loads(self.plan_js.messages[0].data)
        value['state']['plan']['repositoryRevision'] = 'substituted-after-enrollment'
        self.plan_js.messages[0].data = canonical_bytes(value)
        with self.assertRaisesRegex(ContractError, '^execution_plan_history_invalid$'):
            await self.plans.handle(self.request('execution-plan-read', {'planRef': self.plan['ref']}))

    def test_closed_profile_and_nonroot_uid_501(self):
        self.profile['isolation']['workerUID'] = 501
        validate('approved-execution-profile', self.profile)
        owner = self.make_owner()
        self.addAsyncCleanup(owner.close)
        original = copy.deepcopy(self.profile)
        for mutate in (lambda p: p['isolation'].update(workerUID=0), lambda p: p.update(image='python:latest'),
                lambda p: p['isolation'].update(privileged=True), lambda p: p['isolation'].update(homeMounted=True),
                lambda p: p['isolation'].update(dockerSocketMounted=True), lambda p: p['isolation'].update(hostPID=True),
                lambda p: p.update(argv=['sh']), lambda p: p.update(env={'TOKEN': 'private'}),
                lambda p: p['network'].update(destinationRefs=[ref('widened')]),
                lambda p: p['recipe'].update(path='../task.py'), lambda p: p['recipe'].update(path='task/./main.py'),
                lambda p: p['limits'].update(offlineSeconds=61)):
            self.profile = copy.deepcopy(original)
            mutate(self.profile)
            with self.subTest(mutation=mutate), self.assertRaises(ContractError):
                self.make_owner()
