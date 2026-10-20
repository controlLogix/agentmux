"""Original execution journals, signed replay, and current permission checks."""
import asyncio
import copy
from datetime import datetime, timezone
import hashlib

from nacl.signing import SigningKey

from agentmux_contracts import (
    ContractError, canonical_bytes, payload_digest, strict_loads, verify_envelope,
)
from identity.test_authority import ref, SEED
from . import test_retained as support


class RetainedJournalTests(support.RetainedExecutionTests):
    def signed_operation(self, **changes):
        original = strict_loads(self.original_start)
        return self.request('capability-process-start', original['payload'],
            caller='human', expected=original['operation']['expectedVersion'],
            operation=original['operation']['operationId'], **changes)

    def assert_signed(self, raw):
        envelope = strict_loads(raw)
        claims = verify_envelope(envelope, bytes(SigningKey(SEED).verify_key),
            {'hubId': 'hub-one', 'serviceId': 'process-owner'}, datetime.now(timezone.utc))
        self.assertEqual(claims['operation'], envelope['operation'])
        self.assertEqual(envelope['operation']['payloadDigest'], payload_digest(envelope['payload']))
        return envelope

    async def original_snapshot(self):
        state = self.credentials._history(await self.credential_ledger.current())
        record = state['record']
        with self.credentials._store.access(record['generationRef']) as directory:
            private = tuple(self.credentials._store.read(directory, name)
                for name in ('assignment.json', 'credential.json', 'delivery.json', 'acknowledged.json'))
        return {
            'execution': tuple(message.data for message in self.execution_js.messages),
            'credentials': tuple(message.data for message in self.credential_js.messages),
            'private': tuple(None if value is None else hashlib.sha256(value).digest() for value in private),
            'generation': record['generationRef'],
            'commands': tuple(self.commands), 'execCount': self.engine.exec_fixed.await_count,
        }

    async def assert_original_unchanged(self, original):
        current = await self.original_snapshot()
        # Private material must not appear in assertion failure output.
        self.assertTrue(current == original, 'The call changed the retained execution or private generation')

    async def test_first_journal_precedes_real_credential_preparation(self):
        execution = await self.retained_owner()
        entered, release = asyncio.Event(), asyncio.Event()
        real_prepare = self.credentials.prepare
        captured = {}

        async def held_prepare(raw, admission, **kwargs):
            captured.update(raw=raw, binding=admission.binding)
            entered.set()
            await release.wait()
            return await real_prepare(raw, admission, **kwargs)

        self.credentials.prepare = held_prepare
        original = asyncio.create_task(execution.start(self.original_start, task_inspection=self.inspection()))
        barrier = asyncio.create_task(entered.wait())
        try:
            done, _ = await asyncio.wait((original, barrier), timeout=10,
                return_when=asyncio.FIRST_COMPLETED)
            if original in done:
                await original
            self.assertIn(barrier, done, 'The original did not reach credential preparation')
            self.assertEqual(len(self.execution_js.messages), 1)
            first_bytes = self.execution_js.messages[0].data
            first = strict_loads(first_bytes)
            binding = strict_loads(captured['binding'])
            self.assertEqual(first['state']['executionBinding'], binding)
            self.assertEqual(first['operation'], binding['originalOperation'])
            self.assertEqual(first['state']['originalEnvelope'], self.assert_signed(self.original_start))
            self.assertEqual(first['state']['credentialPrepare'], strict_loads(captured['raw']))
            self.assertEqual(first['state']['executionPhase'], 'start-intent')
            self.assertEqual(first['state']['step'], 'credential-prepare-intent')
            self.assertIsNone(first['state']['enrollment'])
            self.assertIsNone(first['state']['resourceRef'])
            self.assertEqual(first['operation']['expectedVersion'], binding['executorRef']['revision'])
            self.assertEqual(first['previousRevision'], 0)
            self.assertEqual(first['entityVersion'], 1)
            self.assertEqual(binding['attemptId'], self.plan['attemptId'])
            self.assertEqual(binding['runRef']['id'], self.execution_ledger._binding.entity_id)
            self.assertEqual(first['effects'], [{
                'effectId': 'container-'+binding['runRef']['id'].removeprefix('execution-'),
                'contractId': 'execution-container-prepare', 'payloadDigest': payload_digest(binding),
                'grantRef': binding['originalOperation']['grantRef'],
                'recovery': 'query-before-retry', 'payload': binding,
            }])
            self.assertFalse(self.credential_js.messages)
            self.assertEqual(self.commands, [])
            self.engine.exec_fixed.assert_not_awaited()
        finally:
            release.set()
            barrier.cancel()
            await asyncio.gather(barrier, return_exceptions=True)
            await original
            self.credentials.prepare = real_prepare
        self.assertTrue(self.execution_js.messages[0].data == first_bytes,
            'Credential preparation rewrote the first durable record')
        self.assertEqual(len(self.credential_js.messages), 1)
        last = strict_loads(self.execution_js.messages[-1].data)
        self.assertEqual(last['entityVersion'], 2)
        self.assertEqual(last['state']['executionBinding']['originalOperation']['expectedVersion'],
            binding['executorRef']['revision'])
        self.assertEqual(last['state']['executionBinding'], binding)
        self.assertEqual(last['effects'], [])

    async def test_equal_replay_and_valid_signed_conflicts_keep_original_bytes(self):
        execution = await self.retained_owner()
        result = await execution.start(self.original_start, task_inspection=self.inspection())
        original = await self.original_snapshot()
        self.assertEqual(await execution.start(self.original_start, task_inspection=self.inspection()), result)
        await self.assert_original_unchanged(original)
        changed_payload = copy.deepcopy(strict_loads(self.original_start)['payload'])
        changed_payload['input']['planRef']['revision'] += 1
        candidates = (
            self.signed_operation(traceId='another-valid-trace'),
            self.request('capability-process-start', changed_payload, caller='human', expected=1,
                operation=strict_loads(self.original_start)['operation']['operationId']),
            self.request('capability-process-start', strict_loads(self.original_start)['payload'],
                caller='human', expected=2,
                operation=strict_loads(self.original_start)['operation']['operationId']),
        )
        for index, raw in enumerate(candidates):
            with self.subTest(signed_conflict=index):
                envelope = self.assert_signed(raw)
                self.assertEqual(envelope['operation']['operationId'],
                    strict_loads(self.original_start)['operation']['operationId'])
                with self.assertRaisesRegex(ContractError, '^execution_original_conflict$'):
                    await execution.start(raw, task_inspection=self.inspection())
                await self.assert_original_unchanged(original)

    async def test_current_start_reservation_and_task_read_revocation_refuse_replay(self):
        execution = await self.retained_owner()
        await execution.start(self.original_start, task_inspection=self.inspection())
        original = await self.original_snapshot()
        for contract in ('capability-process-start', 'task-reserve', 'task-inspect'):
            grant = next(item for item in self.record['state']['grants']
                if item['contractId'] == contract
                and item['actorRef'] == ref('human' if contract != 'task-inspect' else 'administrator'))
            old = grant['status']
            try:
                grant['status'] = 'revoked'
                self.sync()
                with self.subTest(revoked_contract=contract), self.assertRaises(ContractError):
                    await execution.start(self.original_start, task_inspection=self.inspection())
                await self.assert_original_unchanged(original)
            finally:
                grant['status'] = old
                self.sync()

    async def test_actual_plan_revocation_refuses_replay_and_dispatch(self):
        execution = await self.retained_owner()
        await execution.start(self.original_start, task_inspection=self.inspection())
        original = await self.original_snapshot()
        revoked = await self.plans.handle(self.request('execution-plan-revoke', {'planRef': self.plan['ref']}))
        self.assertEqual(revoked.status, 'revoked')
        for method in (execution.start, execution.dispatch):
            with self.subTest(method=method.__name__), self.assertRaisesRegex(
                    ContractError, '^execution_plan_not_approved$'):
                await method(self.original_start, task_inspection=self.inspection())
            await self.assert_original_unchanged(original)

    async def test_signed_other_actor_and_project_cannot_observe_or_enroll_original(self):
        execution = await self.retained_owner()
        await execution.start(self.original_start, task_inspection=self.inspection())
        original = await self.original_snapshot()
        for changes in ({'caller': 'human'}, {'scope': {**self.scope, 'projectId': 'other-project'}},
                {'scope': {**self.scope, 'organizationId': 'other-organization'}}):
            raw = self.request('execution-run-observe', {'runRef': self.run['runRef']},
                expected=len(self.execution_js.messages), **changes)
            self.assert_signed(raw)
            for method in (execution.query, execution.enrollment):
                with self.subTest(changes=changes, method=method.__name__), self.assertRaises(ContractError):
                    await method(raw)
                await self.assert_original_unchanged(original)

    async def test_current_observer_revocation_blocks_disclosure_without_changing_original(self):
        execution = await self.retained_owner()
        await execution.start(self.original_start, task_inspection=self.inspection())
        raw = await self.observe_command()
        self.assert_signed(raw)
        original = await self.original_snapshot()
        grant = next(item for item in self.record['state']['grants']
            if item['ref'] == ref('execution-run-observe-grant'))
        try:
            grant['status'] = 'revoked'
            self.sync()
            for method in (execution.query, execution.enrollment):
                with self.subTest(method=method.__name__), self.assertRaisesRegex(
                        ContractError, '^execution_not_authorized$'):
                    await method(raw)
                await self.assert_original_unchanged(original)
        finally:
            grant['status'] = 'active'
            self.sync()

    async def test_replay_cannot_bypass_newly_required_native_terminal_gate(self):
        execution = await self.retained_owner()
        await execution.start(self.original_start, task_inspection=self.inspection())
        original = await self.original_snapshot()

        async def terminal_authorizer(session_id, actor, scope):
            self.fail('An envelope without a terminal session reached the session authorizer')

        self.plans._ingress.require_terminal_sessions(terminal_authorizer)
        with self.assertRaisesRegex(ContractError, '^oidc_terminal_session_required$'):
            await execution.start(self.original_start, task_inspection=self.inspection())
        await self.assert_original_unchanged(original)

    async def test_cancel_without_required_terminal_session_preserves_original(self):
        execution = await self.retained_owner()
        await execution.start(self.original_start, task_inspection=self.inspection())
        original = await self.original_snapshot()

        async def terminal_authorizer(session_id, actor, scope):
            self.fail('An envelope without a terminal session reached the session authorizer')

        self.plans._ingress.require_terminal_sessions(terminal_authorizer)
        raw = self.cancel_command()
        self.assert_signed(raw)
        with self.assertRaisesRegex(ContractError, '^oidc_terminal_session_required$'):
            await execution.cancel(raw)
        await self.assert_original_unchanged(original)

    async def test_signed_terminal_start_and_cancel_pass_exact_actor_and_scope(self):
        execution = await self.retained_owner()
        self.original_start = self.signed_operation(terminalSessionId='terminal-original')
        original_envelope = self.assert_signed(self.original_start)
        checked = []

        async def terminal_authorizer(session_id, actor, scope):
            checked.append((session_id, canonical_bytes(actor), canonical_bytes(scope)))

        self.plans._ingress.require_terminal_sessions(terminal_authorizer)
        result = strict_loads(await execution.start(self.original_start, task_inspection=self.inspection()))
        self.assertEqual(result['step'], 'pending-enrollment')
        expected = ('terminal-original', canonical_bytes(ref('human')), canonical_bytes(self.scope))
        self.assertTrue(checked, 'The human start did not check the selected terminal session')
        self.assertTrue(all(item == expected for item in checked), 'The start changed terminal session arguments')
        first_bytes = self.execution_js.messages[0].data
        first = strict_loads(first_bytes)
        self.assertEqual(first['operation'], original_envelope['operation'])
        self.assertEqual(first['state']['originalEnvelope'], original_envelope)
        before_cancel = await self.original_snapshot()
        checked.clear()
        raw = self.request('capability-process-cancel', {
            'resourceRef': ref('executor'), 'input': {'runRef': self.run['runRef']}},
            caller='human', expected=1, operation='terminal-cancel', terminalSessionId='terminal-original')
        cancel_envelope = self.assert_signed(raw)
        cancelled = strict_loads(await execution.cancel(raw))
        self.assertEqual(cancelled['status'], 'terminal')
        self.assertTrue(checked, 'The human cancel did not check the selected terminal session')
        self.assertTrue(all(item == expected for item in checked), 'The cancel changed terminal session arguments')
        self.assertTrue(self.execution_js.messages[0].data == first_bytes, 'Cancel rewrote the original start')
        cancel_record = strict_loads(self.execution_js.messages[2].data)
        self.assertEqual(cancel_record['operation'], cancel_envelope['operation'])
        self.assertEqual(cancel_record['state']['executionBinding'], first['state']['executionBinding'])
        after_cancel = await self.original_snapshot()
        self.assertTrue(after_cancel['private'] == before_cancel['private'], 'Cancel changed private credential material')
        self.assertTrue(after_cancel['credentials'] == before_cancel['credentials'], 'Cancel changed credential history')
        self.assertEqual(self.commands, [])

    async def test_current_terminal_refusal_blocks_replay_and_cancel(self):
        execution = await self.retained_owner()
        self.original_start = self.signed_operation(terminalSessionId='terminal-original')
        active = True
        checked = []

        async def terminal_authorizer(session_id, actor, scope):
            checked.append((session_id, canonical_bytes(actor), canonical_bytes(scope)))
            if not active:
                raise ContractError('oidc_terminal_session_inactive')

        self.plans._ingress.require_terminal_sessions(terminal_authorizer)
        await execution.start(self.original_start, task_inspection=self.inspection())
        original = await self.original_snapshot()
        active = False
        checked.clear()
        with self.assertRaisesRegex(ContractError, '^oidc_terminal_session_inactive$'):
            await execution.start(self.original_start, task_inspection=self.inspection())
        await self.assert_original_unchanged(original)
        raw = self.request('capability-process-cancel', {
            'resourceRef': ref('executor'), 'input': {'runRef': self.run['runRef']}},
            caller='human', expected=1, operation='refused-terminal-cancel', terminalSessionId='terminal-original')
        self.assert_signed(raw)
        with self.assertRaisesRegex(ContractError, '^oidc_terminal_session_inactive$'):
            await execution.cancel(raw)
        await self.assert_original_unchanged(original)
        expected = ('terminal-original', canonical_bytes(ref('human')), canonical_bytes(self.scope))
        self.assertEqual(checked, [expected, expected])


for _name in dir(support.RetainedExecutionTests):
    if _name.startswith('test_') and _name not in vars(RetainedJournalTests):
        setattr(RetainedJournalTests, _name, None)
