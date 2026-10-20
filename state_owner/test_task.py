"""Task reads use real retained identity authority at the offline broker boundary."""
import copy
import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity import test_service as identity_support
from identity.test_authority import fixture, ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.task import TaskOwner
from state_owner.test_ledger import CREATED, FakeJetStream, record


class TaskOwnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        identity_support.ServiceTests.setUp(self)
        patch('state_owner.task.datetime', _Clock).start()
        self.record['state']['grants'][0].update(contractId='task-inspect', resourceId='task-one')
        self.js.messages[0].data = canonical_bytes(self.record)
        self.scope = copy.deepcopy(self.record['state']['grants'][0]['scope'])
        self.binding = OwnerBinding('hub-one', 'task', 'task-one', 'task', canonical_bytes(self.scope))
        self.task_js = FakeJetStream(self.policy)
        self.task_js.config.subjects = [owner_subject(self.binding)]
        self.original = record('imported-task')
        self.original['operation']['scope'] = self.scope
        self.original['state'] = {'taskId': 'task-one', 'status': 'reserved', 'assignmentEpoch': 3,
            'reservation': {'taskId': 'task-one', 'delegationId': 'delegation-original',
                'attemptId': 'attempt-original', 'executorHubId': 'remote-hub', 'grantRef': ref('execution-grant'),
                'repositoryRevision': 'original-revision', 'assignmentEpoch': 3},
            'legacyId': 'W01ABC', 'parentKey': 'W00PARENT', 'body': 'Original task body',
            'originPeer': 'original-peer', 'flags': {'acceptanceUnknown': True},
            'audit': [{'sequence': 7, 'actor': 'original-actor'}]}
        self.task_js.messages = [SimpleNamespace(subject=owner_subject(self.binding), seq=1,
            data=canonical_bytes(self.original))]
        self.ledger = OwnerLedger(self.task_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 1))
        self.owner = TaskOwner(self.service.reader, self.ledger)

    def request(self, *, scope=None, task_id='task-one'):
        envelope = fixture()[1]
        envelope.update(contractId='task-inspect', destinationServiceId='task-owner', payload={'taskId': task_id})
        envelope['operation'].update(scope=scope or self.scope, grantRef=ref('grant'),
            payloadDigest=payload_digest(envelope['payload']))
        claims = envelope['ingressAttestation']['claims']
        claims.update(contractId='task-inspect', operation=copy.deepcopy(envelope['operation']),
            audience={'hubId': 'hub-one', 'serviceId': 'task-owner'})
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(envelope)

    async def test_inspect_preserves_original_identity_reservation_and_intent_without_writes(self):
        before = self.task_js.messages[0].data
        stored = await self.owner.handle(self.request())
        self.assertEqual(stored.record, before)
        self.assertEqual(stored.sequence, 1)
        self.assertEqual(strict_loads(stored.record)['state'], self.original['state'])
        self.assertEqual(self.task_js.messages[0].data, before)
        self.assertEqual(len(self.task_js.messages), 1)
        self.assertNotIn('W01ABC', repr(self.owner))

    async def test_revocation_during_source_read_prevents_disclosure(self):
        current = self.ledger.current
        async def read_then_revoke():
            snapshot = await current()
            self.record['state']['grants'][0]['status'] = 'revoked'
            self.js.messages[0].data = canonical_bytes(self.record)
            return snapshot
        with patch.object(self.ledger, 'current', side_effect=read_then_revoke):
            with self.assertRaisesRegex(ContractError, '^task_access_refused$'):
                await self.owner.handle(self.request())

    async def test_wrong_scope_and_target_cannot_read_source(self):
        with patch.object(self.ledger, 'current', wraps=self.ledger.current) as current:
            with self.assertRaisesRegex(ContractError, '^task_access_refused$'):
                await self.owner.handle(self.request(scope={**self.scope, 'projectId': 'other-project'}))
            with self.assertRaisesRegex(ContractError, '^task_binding_mismatch$'):
                await self.owner.handle(self.request(task_id='another-task'))
            current.assert_not_called()

    async def test_gap_and_recreated_source_refuse_instead_of_empty_task(self):
        self.task_js.deleted = 1
        with self.assertRaisesRegex(ContractError, '^owner_history_gap$'):
            await self.owner.handle(self.request())
        self.task_js.deleted = 0
        from datetime import timedelta
        self.task_js.created += timedelta(seconds=1)
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.owner.handle(self.request())

    async def test_reserved_state_requires_reservation_matching_task_and_epoch(self):
        for mutation in (lambda s: s.update(reservation=None),
                lambda s: s['reservation'].update(taskId='another-task'),
                lambda s: s['reservation'].update(assignmentEpoch=4),
                lambda s: s.update(status={}), lambda s: s.update(reservation=[])):
            value = copy.deepcopy(self.original)
            mutation(value['state'])
            self.task_js.messages[0].data = canonical_bytes(value)
            with self.assertRaisesRegex(ContractError, '^task_state_invalid$'):
                await self.owner.handle(self.request())

    async def test_absent_task_history_is_recovery_required_at_enrolled_floor(self):
        self.task_js.messages = []
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.owner.handle(self.request())


class TaskReservationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        TaskOwnerTests.setUp(self)
        self.record['state']['grants'].append({**copy.deepcopy(self.record['state']['grants'][0]),
            'ref': ref('reserve-grant'), 'contractId': 'task-reserve'})
        self.js.messages[0].data = canonical_bytes(self.record)
        self.original['effects'] = []
        self.original['state'].update(status='ready', assignmentEpoch=0, reservation=None,
            originHubId='hub-one', taskInputRef=ref('task-input'), flags={})
        self.reset_task()
        self.ledger = self.new_ledger()
        self.owner = TaskOwner(self.service.reader, self.ledger)
        self.cancel = ref('reserve-cancellation')

    def new_ledger(self):
        return OwnerLedger(self.task_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 1),
            require_completion_budget=True)

    def reset_task(self):
        self.task_js.messages = [SimpleNamespace(subject=owner_subject(self.binding), seq=1,
            data=canonical_bytes(self.original))]

    def possession(self, *, operation='reserve-one', now=None, **changes):
        from datetime import timedelta
        from identity.test_authority import NOW
        now = now or NOW
        references = self.owner.reservation_references(operation)
        payload = {'taskId': 'task-one', 'delegationId': references['delegationRef']['id'], 'attemptId': 'attempt-new',
            'executorHubId': 'executor-hub', 'grantRef': references['executionGrantRef'],
            'repositoryRevision': 'retained-source-revision', 'assignmentEpoch': 1}
        payload.update(changes)
        claims = {'purpose': 'agentmux-client-possession-v1', 'profileId': 'profile-one', 'hubId': 'hub-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport'), 'grantRef': ref('reserve-grant'),
            'operationId': operation, 'expectedVersion': len(self.task_js.messages), 'contractId': 'task-reserve',
            'payload': payload, 'approvalRefs': [], 'issuedAt': now.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (now+timedelta(seconds=30)).isoformat().replace('+00:00', 'Z')}
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})

    async def admitted(self, raw=None, *, owner=None):
        owner = owner or self.owner
        raw = raw or self.possession()
        prepared = await owner.prepare_reservation(raw, self.cancel)
        admitted = await self.service.ingress.admit(raw, cancellation_ref=self.cancel,
            reservation_context=prepared)
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return raw, prepared, admitted.envelope

    async def test_first_reservation_commits_new_embedded_reference_and_complete_intent(self):
        raw = self.possession()
        prepared = await self.owner.prepare_reservation(raw, self.cancel)
        self.assertEqual(len(self.task_js.messages), 1)
        self.assertNotIn('delegation-new', repr(prepared))
        admitted = await self.service.ingress.admit(raw, cancellation_ref=self.cancel, reservation_context=prepared)
        result = await self.owner.handle(admitted.envelope, reservation_context=prepared)
        self.assertEqual(result.sequence, 2)
        value = strict_loads(result.record)
        references = self.owner.reservation_references('reserve-one')
        reference = references['delegationRef']
        self.assertEqual(value['operation']['delegationRef'], reference)
        self.assertEqual(value['state']['delegation']['ref'], reference)
        self.assertEqual(value['state']['assignmentEpoch'], 1)
        self.assertEqual(value['state']['legacyId'], 'W01ABC')
        self.assertEqual(value['state']['parentKey'], 'W00PARENT')
        self.assertEqual(value['state']['audit'], self.original['state']['audit'])
        offer = value['effects'][0]['payload']
        self.assertEqual(offer['taskInputRef'], self.original['state']['taskInputRef'])
        self.assertEqual(offer['acceptBefore'], value['operation']['deadline'])
        self.assertEqual(value['state']['delegation']['phase'], 'offer-intent-committed')
        self.assertEqual(value['effects'][0]['recovery'], 'query-before-retry')
        self.assertEqual(value['effects'][0]['grantRef'], references['executionGrantRef'])
        self.assertEqual(value['operation']['grantRef'], ref('reserve-grant'))
        grant = value['state']['executionGrant']
        self.assertEqual(grant['ref'], references['executionGrantRef'])
        self.assertEqual(grant['requesterGrantRef'], ref('reserve-grant'))
        self.assertEqual(grant['taskId'], 'task-one')
        self.assertEqual(grant['executorHubId'], 'executor-hub')
        self.assertEqual(grant['attemptId'], 'attempt-new')
        self.assertEqual(grant['scope'], self.scope)
        self.assertEqual(grant['assignmentEpoch'], 1)
        self.assertEqual(grant['repositoryRevision'], 'retained-source-revision')
        self.assertEqual(grant['sourceTaskRef'], ref('task-one'))
        self.assertEqual(grant['issuedBy'], value['operation']['effectiveActorRef'])
        self.assertEqual(grant['expiresAt'], value['operation']['deadline'])

    async def test_two_authorized_reservations_select_one_original_attempt(self):
        _, first, first_envelope = await self.admitted()
        _, second, second_envelope = await self.admitted(self.possession(operation='second-reserve',
            attemptId='second-attempt'))
        outcomes = await asyncio.gather(
            self.owner.handle(first_envelope, reservation_context=first),
            self.owner.handle(second_envelope, reservation_context=second), return_exceptions=True)
        self.assertEqual(sum(not isinstance(value, Exception) for value in outcomes), 1)
        self.assertEqual(len(self.task_js.messages), 2)
        retained = strict_loads(self.task_js.messages[1].data)
        self.assertEqual(len(retained['effects']), 1)
        self.assertIn(retained['state']['reservation']['attemptId'], ('attempt-new', 'second-attempt'))

    async def test_reference_namespace_separates_tasks_scopes_and_operations(self):
        from state_owner.task import reservation_references
        variants = (self.binding,
            OwnerBinding('hub-one', 'task', 'another-task', 'task', canonical_bytes(self.scope)),
            OwnerBinding('hub-one', 'task', 'task-one', 'task', canonical_bytes({**self.scope, 'projectId': 'other-project'})))
        references = [reservation_references(binding, 'reserve-one') for binding in variants]
        references.append(self.owner.reservation_references('another-operation'))
        self.assertEqual(len({value['executionGrantRef']['id'] for value in references}), 4)
        self.assertEqual(len({value['delegationRef']['id'] for value in references}), 4)
        for value in references:
            self.assertNotEqual(value['executionGrantRef'], value['delegationRef'])
            self.assertEqual(value['executionGrantRef']['revision'], 1)
        own = self.owner.reservation_references('reserve-one')
        invalid = ({'grantRef': ref('nonexistent-grant')}, {'grantRef': ref('reserve-grant')},
            {'grantRef': {**own['executionGrantRef'], 'revision': 2}},
            {'grantRef': {**own['executionGrantRef'], 'ownerHubId': 'other-hub'}},
            {'grantRef': references[1]['executionGrantRef']},
            {'delegationId': references[1]['delegationRef']['id']})
        with patch.object(self.ledger, 'current', wraps=self.ledger.current) as current:
            for changed in invalid:
                with self.assertRaisesRegex(ContractError, '^task_reservation_namespace_invalid$'):
                    await self.owner.prepare_reservation(self.possession(**changed), self.cancel)
            current.assert_not_called()
        self.assertEqual(len(self.task_js.messages), 1)

    async def test_embedded_grant_binding_tampering_is_not_valid_task_state(self):
        _, prepared, envelope = await self.admitted()
        stored = await self.owner.handle(envelope, reservation_context=prepared)
        pristine = strict_loads(stored.record)
        changes = ({'ref': ref('reserve-grant')}, {'executorHubId': 'another-executor'},
            {'attemptId': 'another-attempt'}, {'taskId': 'another-task'}, {'assignmentEpoch': 2},
            {'repositoryRevision': 'another-revision'}, {'scope': {**self.scope, 'projectId': 'other-project'}},
            {'sourceTaskRef': {**ref('task-one'), 'revision': 2}}, {'issuedBy': ref('another-actor')})
        for changed in changes:
            value = copy.deepcopy(pristine)
            value['state']['executionGrant'].update(changed)
            self.task_js.messages[1].data = canonical_bytes(value)
            with self.assertRaisesRegex(ContractError, '^task_execution_grant_invalid$'):
                await self.owner.handle(TaskOwnerTests.request(self))
        self.assertEqual(len(self.task_js.messages), 2)

    async def test_requester_grant_in_business_namespace_still_cannot_substitute(self):
        execution = self.owner.reservation_references('reserve-one')['executionGrantRef']
        self.record['state']['grants'][-1]['ref'] = execution
        self.js.messages[0].data = canonical_bytes(self.record)
        request = strict_loads(self.possession())
        request['claims']['grantRef'] = execution
        request['signature'] = sign_claims(request['claims'], bytes(reversed(SEED)))
        with patch.object(self.ledger, 'current', wraps=self.ledger.current) as current:
            with self.assertRaisesRegex(ContractError, '^task_reservation_namespace_invalid$'):
                await self.owner.prepare_reservation(canonical_bytes(request), self.cancel)
            current.assert_not_called()
        self.assertEqual(len(self.task_js.messages), 1)

    async def test_embedded_grant_creation_revision_is_not_assignment_epoch(self):
        self.original['state']['assignmentEpoch'] = 6
        self.reset_task()
        _, prepared, envelope = await self.admitted(self.possession(assignmentEpoch=7))
        stored = await self.owner.handle(envelope, reservation_context=prepared)
        state = strict_loads(stored.record)['state']
        self.assertEqual(state['executionGrant']['assignmentEpoch'], 7)
        self.assertEqual(state['executionGrant']['ref']['revision'], 1)
        self.assertEqual(state['delegation']['ref']['revision'], 1)

    async def test_shorter_authority_caps_grant_and_offer_and_replay_keeps_original(self):
        from datetime import datetime, timedelta
        from identity.test_authority import NOW
        end = NOW+timedelta(seconds=10)
        self.record['state']['grants'][-1]['expiresAt'] = end.isoformat().replace('+00:00', 'Z')
        self.js.messages[0].data = canonical_bytes(self.record)
        _, prepared, envelope = await self.admitted()
        original = await self.owner.handle(envelope, reservation_context=prepared)
        value = strict_loads(original.record)
        self.assertEqual(datetime.fromisoformat(value['state']['executionGrant']['expiresAt']), end)
        self.assertEqual(value['state']['delegation']['offer']['acceptBefore'], value['state']['executionGrant']['expiresAt'])
        self.assertEqual(value['effects'][0]['payload']['acceptBefore'], value['state']['executionGrant']['expiresAt'])
        self.assertGreater(datetime.fromisoformat(value['operation']['deadline']), end)
        grant = self.record['state']['grants'][-1]
        grant['ref']['revision'] = 2
        grant['expiresAt'] = (NOW+timedelta(minutes=2)).isoformat().replace('+00:00', 'Z')
        self.js.messages[0].data = canonical_bytes(self.record)
        later = NOW+timedelta(seconds=40)
        with patch('identity.test_service.NOW', later):
            request = strict_loads(self.possession(now=later))
            request['claims']['grantRef'] = copy.deepcopy(grant['ref'])
            request['signature'] = sign_claims(request['claims'], bytes(reversed(SEED)))
            _, retry, envelope = await self.admitted(canonical_bytes(request))
            replay = await self.owner.handle(envelope, reservation_context=retry)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record, original.record)
        self.assertEqual(len(self.task_js.messages), 2)

    async def test_bulk_capacity_refusal_preserves_ready_task_without_creating_offer(self):
        from state_owner.retention import Retention, RECORD_CHARGE
        self.policy = Retention(3*RECORD_CHARGE, RECORD_CHARGE)
        self.task_js.config = self.policy.stream_config(stream='OWNER', subject=owner_subject(self.binding))
        second = copy.deepcopy(self.original)
        second.update(recordId='second-import', entityVersion=2, previousRevision=1)
        second['operation'].update(operationId='second-import', expectedVersion=1)
        self.task_js.messages.append(SimpleNamespace(subject=owner_subject(self.binding), seq=2,
            data=canonical_bytes(second)))
        self.ledger = self.new_ledger()
        self.owner = TaskOwner(self.service.reader, self.ledger)
        _, prepared, envelope = await self.admitted()
        with self.assertRaisesRegex(ContractError, '^owner_capacity_reserved$'):
            await self.owner.handle(envelope, reservation_context=prepared)
        self.assertEqual(len(self.task_js.messages), 2)
        self.assertEqual(strict_loads(self.task_js.messages[-1].data)['state']['status'], 'ready')

    async def test_lost_ack_restart_and_fresh_admission_return_original_pair(self):
        from datetime import timedelta
        from identity.test_authority import NOW
        _, prepared, envelope = await self.admitted()
        self.task_js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.owner.handle(envelope, reservation_context=prepared)
        original = self.task_js.messages[1].data
        restarted = TaskOwner(self.service.reader, self.new_ledger())
        later = NOW+timedelta(seconds=40)
        with patch('identity.test_service.NOW', later):
            _, retry, envelope = await self.admitted(self.possession(now=later), owner=restarted)
            result = await restarted.handle(envelope, reservation_context=retry)
        self.assertTrue(result.replayed)
        self.assertEqual(result.record, original)
        self.assertEqual(result.sequence, 2)
        self.assertEqual(len(self.task_js.messages), 2)

    async def test_old_preparation_cannot_use_later_admitted_possession_deadline(self):
        from datetime import timedelta
        from identity.test_authority import NOW
        first = self.possession()
        prepared = await self.owner.prepare_reservation(first, self.cancel)
        claims = strict_loads(first)['claims']
        claims['expiresAt'] = (NOW+timedelta(seconds=50)).isoformat().replace('+00:00', 'Z')
        later = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        _, new_preparation, envelope = await self.admitted(later)
        with patch('identity.test_service.NOW', NOW+timedelta(seconds=40)):
            with self.assertRaisesRegex(ContractError, '^task_reservation_preparation_invalid$'):
                await self.owner.handle(envelope, reservation_context=prepared)
            self.assertEqual(len(self.task_js.messages), 1)
            # The independently admitted fresh preparation is still valid.
            result = await self.owner.handle(envelope, reservation_context=new_preparation)
            self.assertEqual(result.sequence, 2)

    async def test_changed_trace_cannot_use_otherwise_identical_preparation(self):
        _, prepared, raw = await self.admitted()
        envelope = strict_loads(raw)
        envelope['operation']['traceId'] = 'different-trace'
        claims = envelope['ingressAttestation']['claims']
        claims['operation'] = copy.deepcopy(envelope['operation'])
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        with self.assertRaisesRegex(ContractError, '^task_reservation_preparation_invalid$'):
            await self.owner.handle(canonical_bytes(envelope), reservation_context=prepared)
        self.assertEqual(len(self.task_js.messages), 1)

    async def test_changed_payload_same_operation_and_new_reservation_cannot_replace_winner(self):
        _, prepared, envelope = await self.admitted()
        await self.owner.handle(envelope, reservation_context=prepared)
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.owner.prepare_reservation(self.possession(repositoryRevision='changed'), self.cancel)
        with self.assertRaisesRegex(ContractError, '^task_already_reserved_or_not_ready$'):
            await self.owner.prepare_reservation(self.possession(operation='another-reservation'), self.cancel)
        self.assertEqual(len(self.task_js.messages), 2)

    async def test_forged_preparation_and_changed_request_or_cancellation_refuse(self):
        from state_owner.task import PreparedTaskReservation
        raw, prepared, envelope = await self.admitted()
        forged = object.__new__(PreparedTaskReservation)
        with self.assertRaisesRegex(ContractError, '^task_reservation_preparation_invalid$'):
            await self.service.ingress.admit(raw, cancellation_ref=self.cancel, reservation_context=forged)
        with self.assertRaisesRegex(ContractError, '^task_reservation_preparation_invalid$'):
            await self.owner.handle(envelope, reservation_context=forged)
        for request, cancellation in ((self.possession(operation='changed'), self.cancel), (raw, ref('other-cancel'))):
            with self.assertRaisesRegex(ContractError, '^task_reservation_preparation_invalid$'):
                await prepared.validate_ingress(self.service.reader, request, cancellation)
        self.assertEqual(len(self.task_js.messages), 1)

    async def test_stale_preparation_and_append_race_create_no_offer(self):
        raw, prepared, envelope = await self.admitted()
        competing = copy.deepcopy(self.original)
        competing.update(recordId='another-import-record', entityVersion=2, previousRevision=1)
        competing['operation'].update(operationId='competing-change', expectedVersion=1)
        self.task_js.race = competing
        with self.assertRaisesRegex(ContractError, '^owner_revision_conflict$'):
            await self.owner.handle(envelope, reservation_context=prepared)
        retained = strict_loads(self.task_js.messages[-1].data)
        self.assertEqual(retained['state']['status'], 'ready')
        self.assertNotIn('executionGrant', retained['state'])
        self.assertNotIn('delegation', retained['state'])
        self.assertEqual(retained['effects'], [])
        with self.assertRaisesRegex(ContractError, '^task_reservation_preparation_stale$'):
            await self.service.ingress.admit(raw, cancellation_ref=self.cancel, reservation_context=prepared)
        self.assertEqual(len(self.task_js.messages), 2)

    async def test_current_authority_revocation_before_append_refuses(self):
        _, prepared, envelope = await self.admitted()
        authorize = self.owner._authorize
        calls = 0
        async def revoke_before_commit(*args):
            nonlocal calls
            calls += 1
            if calls==2:
                self.record['state']['grants'][-1]['status'] = 'revoked'
                self.js.messages[0].data = canonical_bytes(self.record)
            return await authorize(*args)
        with patch.object(self.owner, '_authorize', side_effect=revoke_before_commit):
            with self.assertRaisesRegex(ContractError, '^task_access_refused$'):
                await self.owner.handle(envelope, reservation_context=prepared)
        self.assertEqual(len(self.task_js.messages), 1)

    async def test_pending_import_obligations_and_historical_identity_reuse_refuse(self):
        pristine = copy.deepcopy(self.original)
        cases = ((lambda r: r.update(effects=record()['effects']), 'task_reservation_obligations_unavailable'),
            (lambda r: r['state'].update(flags={'acceptanceUnknown': True}), 'task_reservation_obligations_unavailable'),
            (lambda r: r['state'].update(pendingReceipt={'id': 'receipt'}), 'task_reservation_obligations_unavailable'),
            (lambda r: r['operation'].update(delegationRef=self.owner.reservation_references('reserve-one')['delegationRef']),
                'task_delegation_identity_reused'))
        for mutate, code in cases:
            self.original = copy.deepcopy(pristine)
            mutate(self.original)
            self.reset_task()
            with self.assertRaisesRegex(ContractError, '^'+code+'$'):
                await self.owner.prepare_reservation(self.possession(), self.cancel)
            self.assertEqual(len(self.task_js.messages), 1)

