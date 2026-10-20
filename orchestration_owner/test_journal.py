import base64
import asyncio
import copy
from datetime import timedelta
import threading
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity import test_service as service_tests
from identity.test_authority import NOW, SEED, ref
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import CREATED, FakeJetStream

from .commands import OrchestrationPolicyBinding, prepare_command
from .domain_adapter import OrchestrationObservation
from .journal import OrchestrationOperationJournal
from .domain_adapter import OrchestrationDomainAdapter
from .owner import OrchestrationOwner
from .phase_signer import OrchestrationPhaseSigner
from .worker import OrchestrationWorker
from .service import OrchestrationCommandService
from .client import verify_receipt
from identity.local_browser_session import LocalBrowserContext, _CONTEXT_BRAND

OWNER_SEED = bytes([71]) * 32


class OrchestrationJournalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        service_tests.ServiceTests.setUp(self)
        patch('identity.authority._utc_now', return_value=NOW).start()
        patch('orchestration_owner.journal.datetime', service_tests._Clock).start()
        patch('orchestration_owner.phase_signer.datetime', service_tests._Clock).start()
        self.scope = {'organizationId': 'org-one', 'projectId': 'project-one',
                      'workspaceId': None}
        state = self.record['state']
        member = copy.deepcopy(state['memberships'][0])
        member.update(ref=ref('orchestration-member'), scope=self.scope)
        state['memberships'].append(member)
        state['identities'].append({'ref': ref('orchestration-owner'),
            'principalId': 'orchestration-owner-one', 'kind': 'service',
            'status': 'active', 'externalIdentity': None})
        owner_member = copy.deepcopy(member)
        owner_member.update(ref=ref('orchestration-owner-member'),
                            identityRef=ref('orchestration-owner'))
        state['memberships'].append(owner_member)
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('orchestration-owner-transport'),
            identityRef=ref('orchestration-owner'),
            publicKey=base64.urlsafe_b64encode(
                bytes(SigningKey(OWNER_SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        for name in ('orchestration-command', 'orchestration-dispatch',
                     'orchestration-complete', 'orchestration-outcome-query'):
            grant = copy.deepcopy(state['grants'][0])
            grant.update(ref=ref(name), scope=self.scope, contractId=name,
                         resourceId='orchestration-one')
            if name in ('orchestration-dispatch', 'orchestration-complete'):
                grant.update(callerRef=ref('orchestration-owner'),
                             actorRef=ref('orchestration-owner'))
            state['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)
        self.resource = {**ref('orchestration-one'), 'revision': 7}
        self.policy_binding = OrchestrationPolicyBinding(self.resource, self.scope,
            '/tmp/project-one', 'orchestrator-project-one')
        self.binding = OwnerBinding('hub-one', 'orchestration-operations',
            'orchestration-one', 'attempt', canonical_bytes(self.scope))
        self.journal_js = FakeJetStream(self.policy)
        self.journal_js.config = self.policy.stream_config(
            stream='OWNER', subject=owner_subject(self.binding))
        self.journal = self.open()

    def open(self):
        ledger = OwnerLedger(self.journal_js, stream='OWNER',
            subject=owner_subject(self.binding), binding=self.binding,
            retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        return OrchestrationOperationJournal(ledger, self.service.reader,
            owner_service_identity_ref=ref('orchestration-owner'),
            policy_binding=self.policy_binding)

    def signer(self, journal=None):
        journal = self.journal if journal is None else journal
        return OrchestrationPhaseSigner(journal, self.service.ingress,
            transport_ref=ref('orchestration-owner-transport'),
            grants={name: ref(name) for name in
                ('orchestration-dispatch', 'orchestration-complete')},
            signing_seed=OWNER_SEED)

    def context(self, scope=None):
        authority = {'id': self.record['entityId'],
            'ownerHubId': self.record['ownerHubId'],
            'revision': self.record['entityVersion']}
        return LocalBrowserContext(canonical_bytes(ref('human')),
            canonical_bytes(self.scope if scope is None else scope),
            canonical_bytes(authority), self.js.messages[0].seq,
            '2026-10-09T12:10:00Z', _CONTEXT_BRAND)

    async def admit(self, contract, operation, expected, payload, *, owner=False):
        claims = copy.deepcopy(self.claims)
        claims.update(contractId=contract, operationId=operation,
            expectedVersion=expected, grantRef=ref(contract), payload=payload)
        if owner:
            claims['transportRef'] = ref('orchestration-owner-transport')
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, OWNER_SEED if owner
                                     else bytes(reversed(SEED)))})
        admitted = await self.service.ingress.admit(request,
                                                    cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed',
                         admitted.decision.reason)
        return admitted.envelope

    async def prepare(self, operation='original-one', expected_sequence=0):
        payload = {'resourceRef': self.resource, 'environmentRef': None,
            'input': {'command': 'run-start', 'request': 'one'}}
        raw = await self.admit('orchestration-command', operation, 7, payload)
        effect = prepare_command(payload, self.policy_binding)
        stored = await self.journal.prepare(raw,
            expected_sequence=expected_sequence, effect=effect, actor='human',
            provenance='orchestrator-project-one')
        return raw, effect, stored

    async def phase(self, contract, operation, observation_id=None):
        snapshot = await self.journal._ledger.current()
        state = strict_loads(snapshot.latest.record)['state']
        original = state['original']['operation']
        claim = next(row for row in snapshot.records
                     if strict_loads(row.record)['recordId'] == state['claimId'])
        payload = {'resourceRef': state['resourceRef'],
            'journalRef': {'id': self.binding.entity_id,
                'ownerHubId': self.binding.hub_id, 'revision': snapshot.sequence},
            'claimRef': self.journal._ref(claim),
            'originalOperationId': original['operationId'],
            'originalPayloadDigest': original['payloadDigest'],
            'candidateDigest': state['candidateDigest']}
        if observation_id is not None:
            payload['observationId'] = observation_id
        return await self.admit(contract, operation, snapshot.sequence, payload,
                                owner=True)

    async def test_retains_one_dispatch_and_completion_for_exact_original(self):
        raw, _, claim = await self.prepare()
        dispatch = await self.phase('orchestration-dispatch', 'dispatch-one')
        await self.journal.advance(dispatch, expected_sequence=1)
        observation = OrchestrationObservation('applied', canonical_bytes({
            'command': 'run-start', 'outcome': 'applied', 'exitCode': 0,
            'result': {'runId': 'abc123'}}))
        observation_id = self.journal._observe(self.journal._ref(claim), observation)
        complete = await self.phase('orchestration-complete', 'complete-one',
                                    observation_id)
        await self.journal.advance(complete, expected_sequence=2)
        operation = strict_loads(raw)['operation']
        outcome = await self.open().outcome(operation['operationId'],
                                            operation['payloadDigest'])
        self.assertEqual((outcome.phase, outcome.outcome), ('finished', 'applied'))
        self.assertEqual(strict_loads(outcome.result)['result']['runId'], 'abc123')
        replay = await self.journal.advance(complete, expected_sequence=2)
        self.assertTrue(replay.replayed)
        self.assertEqual(len(self.journal_js.messages), 3)

    async def test_missing_private_observation_cannot_complete(self):
        await self.prepare()
        dispatch = await self.phase('orchestration-dispatch', 'dispatch-one')
        await self.journal.advance(dispatch, expected_sequence=1)
        complete = await self.phase('orchestration-complete', 'complete-one',
                                    'missing-observation')
        with self.assertRaisesRegex(Exception, 'orchestration_observation_unavailable'):
            await self.journal.advance(complete, expected_sequence=2)
        self.assertEqual(len(self.journal_js.messages), 2)

    async def test_uncertain_result_stays_pending_and_blocks_a_new_command(self):
        raw, _, claim = await self.prepare()
        dispatch = await self.phase('orchestration-dispatch', 'dispatch-one')
        await self.journal.advance(dispatch, expected_sequence=1)
        observation = OrchestrationObservation('uncertain', canonical_bytes({
            'command': 'run-start', 'outcome': 'uncertain', 'exitCode': None,
            'result': None}))
        observed = self.journal._observe(self.journal._ref(claim), observation)
        complete = await self.phase('orchestration-complete', 'complete-one', observed)
        await self.journal.advance(complete, expected_sequence=2)
        with self.assertRaisesRegex(Exception, 'orchestration_journal_busy'):
            await self.prepare('other-command', expected_sequence=3)
        adapter = OrchestrationDomainAdapter(self.policy_binding)
        owner = OrchestrationOwner(self.journal, self.signer(),
                                   OrchestrationWorker(adapter))
        recovered = OrchestrationObservation('applied', canonical_bytes({
            'command': 'run-start', 'outcome': 'applied', 'exitCode': 0,
            'result': {'runId': 'abc123'}}))
        receipt = await owner.reconcile(raw, recovered)
        self.assertEqual(receipt['outcome'], 'applied')
        await self.prepare('other-command', expected_sequence=4)
        await owner.close()

    async def test_phase_signer_uses_fresh_enrolled_service_operations(self):
        await self.prepare()
        prototype = strict_loads(await self.phase('orchestration-dispatch',
                                                  'prototype'))['payload']
        first = await self.signer().admit('orchestration-dispatch',
            expected_sequence=1, payload=prototype, cancellation_ref=ref('cancel'))
        second = await self.signer().admit('orchestration-dispatch',
            expected_sequence=1, payload=prototype, cancellation_ref=ref('cancel'))
        first_operation = strict_loads(first.envelope)['operation']
        self.assertEqual(first_operation['caller']['authenticatedIdentityRef'],
                         ref('orchestration-owner'))
        self.assertNotEqual(first_operation['operationId'],
                            strict_loads(second.envelope)['operation']['operationId'])

    async def test_owner_dispatches_once_and_replays_retained_result(self):
        payload = {'resourceRef': self.resource, 'environmentRef': None,
            'input': {'command': 'run-start', 'request': 'one'}}
        raw = await self.admit('orchestration-command', 'owner-original', 7, payload)
        adapter = OrchestrationDomainAdapter(self.policy_binding)
        worker = OrchestrationWorker(adapter)
        owner = OrchestrationOwner(self.journal, self.signer(), worker)
        observation = OrchestrationObservation('applied', canonical_bytes({
            'command': 'run-start', 'outcome': 'applied', 'exitCode': 0,
            'result': {'runId': 'abc123'}}))
        with patch.object(adapter, 'perform', return_value=observation) as perform:
            first = await owner.apply(raw)
            second = await owner.apply(raw)
        self.assertEqual(first, second)
        self.assertEqual(first['result']['result']['runId'], 'abc123')
        self.assertEqual(perform.call_count, 1)
        self.assertEqual(len(self.journal_js.messages), 3)
        await owner.close()

    async def test_service_waits_for_history_and_returns_request_bound_signed_receipt(self):
        payload = {'resourceRef': self.resource, 'environmentRef': None,
            'input': {'command': 'run-start', 'request': 'one'}}
        claims = copy.deepcopy(self.claims)
        claims.update(contractId='orchestration-command', operationId='service-original',
            expectedVersion=7, grantRef=ref('orchestration-command'), payload=payload)
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        adapter = OrchestrationDomainAdapter(self.policy_binding)
        owner = OrchestrationOwner(self.journal, self.signer(),
                                   OrchestrationWorker(adapter))
        service = OrchestrationCommandService(owner, self.service.ingress,
            issuer_ref=ref('issuer'), signing_seed=SEED)
        observation = OrchestrationObservation('applied', canonical_bytes({
            'command': 'run-start', 'outcome': 'applied', 'exitCode': 0,
            'result': {'runId': 'abc123'}}))
        with self.assertRaisesRegex(Exception, 'orchestration_service_unavailable'):
            await service.handle(request)
        await service.start()
        with patch.object(adapter, 'perform', return_value=observation):
            response = await service.handle(request)
        public_key = base64.urlsafe_b64encode(
            bytes(SigningKey(SEED).verify_key)).decode().rstrip('=')
        receipt = verify_receipt(response, request, public_key=public_key,
                                 issuer_ref=ref('issuer'))
        self.assertEqual(receipt['actorRef'], ref('human'))
        self.assertEqual(receipt['resourceRef'], self.resource)
        self.assertEqual(receipt['originalPayloadDigest'],
                         strict_loads(self.journal_js.messages[0].data)
                         ['state']['original']['operation']['payloadDigest'])
        changed = strict_loads(request)
        changed['claims']['operationId'] = 'changed-request'
        with self.assertRaisesRegex(Exception, 'orchestration_receipt_binding'):
            verify_receipt(response, canonical_bytes(changed), public_key=public_key,
                           issuer_ref=ref('issuer'))
        await service.close()

    async def test_local_browser_restarts_and_replays_without_persisting_context_brand(self):
        adapter = OrchestrationDomainAdapter(self.policy_binding)
        owner = OrchestrationOwner(self.journal, self.signer(),
                                   OrchestrationWorker(adapter))
        service = OrchestrationCommandService(owner, self.service.ingress,
            issuer_ref=ref('issuer'), signing_seed=SEED)
        await service.start()
        command = {'command': 'run-start', 'request': 'one'}
        observed = OrchestrationObservation('applied', canonical_bytes({
            'command': 'run-start', 'outcome': 'applied', 'exitCode': 0,
            'result': {'runId': 'abc123'}}))
        with patch.object(adapter, 'perform', return_value=observed) as perform:
            first = await service.handle_local_browser(self.context(), command,
                operation_id='browser_' + 'a' * 32)
        await service.close()
        retained = strict_loads(self.journal_js.messages[0].data)['state']
        self.assertEqual(retained['localAdmission']['callerRef'], ref('human'))
        self.assertNotIn('brand', canonical_bytes(retained).decode())

        restarted_journal = self.open()
        restarted_adapter = OrchestrationDomainAdapter(self.policy_binding)
        restarted = OrchestrationCommandService(OrchestrationOwner(restarted_journal,
            self.signer(restarted_journal), OrchestrationWorker(restarted_adapter)),
            self.service.ingress, issuer_ref=ref('issuer'), signing_seed=SEED)
        await restarted.start()
        with patch.object(restarted_adapter, 'perform') as repeated:
            second = await restarted.handle_local_browser(self.context(), command,
                operation_id='browser_' + 'a' * 32)
        self.assertEqual(first, second)
        self.assertEqual(perform.call_count, 1)
        repeated.assert_not_called()
        await restarted.close()

    async def test_local_browser_scope_mismatch_is_refused_before_retention(self):
        adapter = OrchestrationDomainAdapter(self.policy_binding)
        service = OrchestrationCommandService(OrchestrationOwner(self.journal,
            self.signer(), OrchestrationWorker(adapter)), self.service.ingress,
            issuer_ref=ref('issuer'), signing_seed=SEED)
        await service.start()
        changed = {**self.scope, 'projectId': 'project-two'}
        with self.assertRaisesRegex(Exception, 'orchestration_not_authorized'):
            await service.handle_local_browser(self.context(changed),
                {'command': 'run-start', 'request': 'one'},
                operation_id='browser_' + 'b' * 32)
        self.assertEqual(self.journal_js.messages, [])
        await service.close()

    async def test_local_browser_revocation_before_dispatch_retains_not_dispatched(self):
        adapter = OrchestrationDomainAdapter(self.policy_binding)
        owner = OrchestrationOwner(self.journal, self.signer(),
                                   OrchestrationWorker(adapter))
        service = OrchestrationCommandService(owner, self.service.ingress,
            issuer_ref=ref('issuer'), signing_seed=SEED)
        await service.start()
        original = service._local_authority
        calls = 0
        async def revoked(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls >= 4:
                raise ContractError('orchestration_not_authorized')
            return await original(*args, **kwargs)
        with patch.object(service, '_local_authority', side_effect=revoked), \
                patch.object(adapter, 'perform') as perform:
            with self.assertRaisesRegex(ContractError, 'orchestration_not_authorized'):
                await service.handle_local_browser(self.context(),
                    {'command': 'run-start', 'request': 'one'},
                    operation_id='browser_' + 'c' * 32)
        perform.assert_not_called()
        latest = strict_loads(self.journal_js.messages[-1].data)['state']
        self.assertEqual(latest['observation']['outcome'], 'not-dispatched')
        await service.close()

    async def browser_service(self, *, policy=None):
        journal = self.open() if policy is None else OrchestrationOperationJournal(
            self.open()._ledger, self.service.reader,
            owner_service_identity_ref=ref('orchestration-owner'), policy_binding=policy)
        adapter = OrchestrationDomainAdapter(self.policy_binding if policy is None else policy)
        service = OrchestrationCommandService(OrchestrationOwner(journal,
            self.signer(journal), OrchestrationWorker(adapter)), self.service.ingress,
            issuer_ref=ref('issuer'), signing_seed=SEED)
        await service.start()
        self.addAsyncCleanup(service.close)
        return service, adapter

    async def completed_browser(self, *, context=None):
        service, adapter = await self.browser_service()
        observation = OrchestrationObservation('applied', canonical_bytes({
            'command': 'run-start', 'outcome': 'applied', 'exitCode': 0,
            'result': {'runId': 'abc123'}}))
        command = {'command': 'run-start', 'request': 'one'}
        operation = 'browser_' + 'e' * 32
        with patch.object(adapter, 'perform', return_value=observation):
            receipt = await service.handle_local_browser(
                self.context() if context is None else context, command, operation_id=operation)
        return service, adapter, command, operation, receipt

    async def test_browser_replay_preserves_every_retained_record_with_fresh_context(self):
        service, adapter, command, operation, receipt = await self.completed_browser()
        records = [row.data for row in self.journal_js.messages]
        context = self.context()
        fresh = LocalBrowserContext(canonical_bytes(context.caller_ref),
            canonical_bytes(context.scope), canonical_bytes(context.authority_ref),
            context.authority_sequence, '2026-10-09T12:20:00Z', _CONTEXT_BRAND)
        with patch.object(adapter, 'perform') as perform:
            replay = await service.handle_local_browser(fresh, command, operation_id=operation)
        self.assertEqual(replay, receipt)
        perform.assert_not_called()
        self.assertEqual([row.data for row in self.journal_js.messages], records)

    async def test_browser_changed_input_and_grant_conflict_without_mutation(self):
        service, adapter, command, operation, _ = await self.completed_browser()
        records = [row.data for row in self.journal_js.messages]
        with patch.object(adapter, 'perform') as perform:
            with self.assertRaisesRegex(ContractError, 'owner_operation_conflict'):
                await service.handle_local_browser(self.context(),
                    dict(command, request='changed'), operation_id=operation)
            for grant in self.record['state']['grants']:
                if grant['ref'] == ref('orchestration-command'):
                    grant['ref'] = ref('replacement-browser-grant')
            self.js.messages[0].data = canonical_bytes(self.record)
            with self.assertRaisesRegex(ContractError, 'owner_operation_conflict'):
                await service.handle_local_browser(self.context(), command, operation_id=operation)
            perform.assert_not_called()
        self.assertEqual([row.data for row in self.journal_js.messages], records)

    async def test_browser_changed_authorized_caller_cannot_replay_original(self):
        service, adapter, command, operation, _ = await self.completed_browser()
        records = [row.data for row in self.journal_js.messages]
        state = self.record['state']
        human = copy.deepcopy(next(row for row in state['identities'] if row['ref'] == ref('human')))
        human.update(ref=ref('other-human'), principalId='other-human')
        state['identities'].append(human)
        member = copy.deepcopy(next(row for row in state['memberships']
            if row['identityRef'] == ref('human') and row['scope'] == self.scope))
        member.update(ref=ref('other-member'), identityRef=human['ref'])
        state['memberships'].append(member)
        grant = copy.deepcopy(next(row for row in state['grants']
            if row['ref'] == ref('orchestration-command')))
        grant.update(ref=ref('other-browser-grant'), callerRef=human['ref'], actorRef=human['ref'])
        state['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)
        context = self.context()
        other = LocalBrowserContext(canonical_bytes(human['ref']),
            canonical_bytes(context.scope), canonical_bytes(context.authority_ref),
            context.authority_sequence, context.valid_until, _CONTEXT_BRAND)
        with patch.object(adapter, 'perform') as perform:
            with self.assertRaisesRegex(ContractError, 'owner_operation_conflict'):
                await service.handle_local_browser(other, command, operation_id=operation)
            perform.assert_not_called()
        self.assertEqual([row.data for row in self.journal_js.messages], records)

    async def test_browser_revoked_current_grant_cannot_read_completed_receipt(self):
        service, adapter, command, operation, _ = await self.completed_browser()
        records = [row.data for row in self.journal_js.messages]
        for grant in self.record['state']['grants']:
            if grant['ref'] == ref('orchestration-command'):
                grant['status'] = 'revoked'
        self.js.messages[0].data = canonical_bytes(self.record)
        with patch.object(adapter, 'perform') as perform:
            with self.assertRaises(ContractError):
                await service.handle_local_browser(self.context(), command, operation_id=operation)
            perform.assert_not_called()
        self.assertEqual([row.data for row in self.journal_js.messages], records)

    async def test_browser_fresh_context_cannot_extend_original_deadline(self):
        context = self.context()
        short = LocalBrowserContext(canonical_bytes(context.caller_ref),
            canonical_bytes(context.scope), canonical_bytes(context.authority_ref),
            context.authority_sequence, (NOW + timedelta(seconds=1)).isoformat(), _CONTEXT_BRAND)
        service, adapter, command, operation, _ = await self.completed_browser(context=short)
        records = [row.data for row in self.journal_js.messages]
        with patch('identity.authority._utc_now', return_value=NOW + timedelta(seconds=2)), \
                patch.object(adapter, 'perform') as perform:
            with self.assertRaisesRegex(ContractError, 'orchestration_not_authorized'):
                await service.handle_local_browser(self.context(), command, operation_id=operation)
            perform.assert_not_called()
        self.assertEqual([row.data for row in self.journal_js.messages], records)

    async def test_browser_concurrent_retry_joins_after_original_waiter_cancelled(self):
        service, adapter = await self.browser_service()
        entered, release = asyncio.Event(), threading.Event()
        loop = asyncio.get_running_loop()
        def perform(*args, **kwargs):
            loop.call_soon_threadsafe(entered.set)
            if not release.wait(15):
                raise RuntimeError('test effect was not released')
            return OrchestrationObservation('applied', canonical_bytes({
                'command': 'run-start', 'outcome': 'applied', 'exitCode': 0,
                'result': {'runId': 'abc123'}}))
        command = {'command': 'run-start', 'request': 'one'}
        operation = 'browser_' + 'f' * 32
        first = retry = None
        try:
            with patch.object(adapter, 'perform', side_effect=perform) as effect:
                first = asyncio.create_task(service.handle_local_browser(
                    self.context(), command, operation_id=operation))
                await asyncio.wait_for(entered.wait(), 5)
                original = self.journal_js.messages[0].data
                retry = asyncio.create_task(service.handle_local_browser(
                    self.context(), command, operation_id=operation))
                await asyncio.sleep(0)
                first.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await first
                self.assertFalse(retry.done())
                self.assertTrue(service._active)
                release.set()
                receipt = await asyncio.wait_for(retry, 5)
                self.assertEqual(receipt['outcome'], 'applied')
                self.assertEqual(effect.call_count, 1)
                self.assertEqual(self.journal_js.messages[0].data, original)
                self.assertEqual(len(self.journal_js.messages), 3)
        finally:
            release.set()
            await asyncio.gather(*(task for task in (first, retry) if task is not None),
                                 return_exceptions=True)
            await service.close()

    async def test_browser_uncertain_original_refuses_retry_without_redispatch(self):
        service, adapter = await self.browser_service()
        command = {'command': 'run-start', 'request': 'one'}
        operation = 'browser_' + '9' * 32
        observation = OrchestrationObservation('uncertain', canonical_bytes({
            'command': 'run-start', 'outcome': 'uncertain', 'exitCode': None, 'result': None}))
        with patch.object(adapter, 'perform', return_value=observation) as perform:
            with self.assertRaisesRegex(ContractError, 'orchestration_outcome_uncertain'):
                await service.handle_local_browser(self.context(), command, operation_id=operation)
            records = [row.data for row in self.journal_js.messages]
            self.assertEqual(strict_loads(records[-1])['state']['phase'], 'uncertain')
            with self.assertRaisesRegex(ContractError, 'orchestration_outcome_uncertain'):
                await service.handle_local_browser(self.context(), command, operation_id=operation)
            self.assertEqual(perform.call_count, 1)
            self.assertEqual([row.data for row in self.journal_js.messages], records)

    async def test_browser_cannot_adopt_signed_operation_identity(self):
        operation = 'browser_' + '8' * 32
        await self.prepare(operation=operation)
        service, adapter = await self.browser_service()
        records = [row.data for row in self.journal_js.messages]
        with patch.object(adapter, 'perform') as perform:
            with self.assertRaisesRegex(ContractError, 'owner_operation_conflict'):
                await service.handle_local_browser(self.context(),
                    {'command': 'run-start', 'request': 'one'}, operation_id=operation)
            perform.assert_not_called()
        self.assertEqual([row.data for row in self.journal_js.messages], records)

    async def test_browser_replay_refuses_changed_scope_and_resource_revision(self):
        service, adapter, command, operation, _ = await self.completed_browser()
        records = [row.data for row in self.journal_js.messages]
        with patch.object(adapter, 'perform') as perform:
            with self.assertRaises(ContractError):
                await service.handle_local_browser(
                    self.context(dict(self.scope, projectId='other-project')),
                    command, operation_id=operation)
            perform.assert_not_called()
        changed = OrchestrationPolicyBinding(dict(self.resource, revision=8),
            self.scope, '/tmp/project-one', 'orchestrator-project-one')
        restarted, other_adapter = await self.browser_service(policy=changed)
        with patch.object(other_adapter, 'perform') as perform:
            with self.assertRaises(ContractError):
                await restarted.handle_local_browser(self.context(), command, operation_id=operation)
            perform.assert_not_called()
        self.assertEqual([row.data for row in self.journal_js.messages], records)


if __name__ == '__main__':
    unittest.main(verbosity=2)
