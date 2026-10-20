"""Strict capacity across all pending definitions, replay and competing appends."""
import asyncio
from pathlib import Path
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
import test_definition_commands as support

CHARGE = 131072


class DefinitionBudgetTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.DefinitionCommandTests.setUp
    asyncSetUp = support.DefinitionCommandTests.asyncSetUp
    new_owner = support.DefinitionCommandTests.new_owner
    authority_message = support.DefinitionCommandTests.authority_message
    resign = support.DefinitionCommandTests.resign
    execute = support.DefinitionCommandTests.execute
    effect_request = support.DefinitionCommandTests.effect_request

    def new_ledger(self):
        identity = StreamIdentity(self.js.created, 0)
        if not hasattr(self, 'history'):
            self.history = OwnerHistory(Path(self.tmp.name).resolve() / 'history.sqlite', self.binding,
                                        stream_identity=identity)
            self.addCleanup(self.history.close)
        return OwnerLedger(self.js, stream='OWNER', subject=owner_subject(self.binding), binding=self.binding,
            retention=self.policy, stream_identity=identity, history=self.history, require_completion_budget=True)

    def capacity(self, slots):
        self.assertEqual(self.js.messages, [])
        self.policy = Retention(slots * CHARGE, CHARGE)
        self.js.config = self.policy.stream_config(stream='OWNER', subject=owner_subject(self.binding))
        self.ledger = self.new_ledger()
        self.owner = self.new_owner()

    def grant(self, payload, contract):
        self.authority_record['state']['grants'][0].update(contractId=contract, resourceId=payload['definitionId'],
            definitionTarget={'scope': payload['scope'], 'name': payload['name']})

    async def create(self, number):
        self.env['contractId'] = 'definition-save'
        self.env['operation'].update(operationId='create-' + str(number), expectedVersion=0)
        self.env['payload'] = {'definitionId': 'definition-' + str(number), 'scope': 'repo',
            'name': 'worker-' + str(number), 'expectedChecksum': None, 'definition': {'description': 'Review changes'}}
        self.grant(self.env['payload'], self.env['contractId'])
        self.resign()
        return await self.execute()

    async def finish(self, original, *, retry=False, attempt=None):
        contract = 'definition-effect-retry' if retry else 'definition-effect-complete'
        self.grant(original['effects'][0]['payload'], contract)
        self.effect_request(contract, original=original, attempt=attempt)
        return await self.execute()

    async def test_all_earlier_pending_definitions_keep_their_completion_capacity(self):
        self.capacity(6)
        with patch.object(self.ledger, 'append', wraps=self.ledger.append) as append:
            for number in range(3):
                await self.create(number)
            originals = [strict_loads(message.data) for message in self.js.messages]
            with self.assertRaisesRegex(ContractError, '^owner_capacity_reserved$'):
                await self.create(3)
            self.assertEqual(len(self.js.messages), 3)
            self.assertFalse((self.repo / '.agentmux/agents/worker-3.md').exists())
            # This is a new receiver with no private effect observations. Its
            # durable catalog must still reserve every earlier pending attempt.
            self.owner = self.new_owner()
            for original in originals:
                result = await self.finish(original)
                self.assertEqual(result.status, 'reconciliation-required')
            self.assertEqual([call.kwargs['completion_records'] for call in append.await_args_list],
                             [1, 2, 3, 4, 2, 1, 0])
        self.assertEqual(len(self.js.messages), 6)
        self.assertEqual(strict_loads(self.js.messages[-1].data)['effects'], [])
        self.assertTrue(self.ledger.completion_budget_required)

    async def test_reconciliation_and_fresh_retry_each_admit_their_own_remaining_write(self):
        self.capacity(4)
        with patch.object(self.ledger, 'append', wraps=self.ledger.append) as append:
            await self.create(0)
            original = strict_loads(self.js.messages[0].data)
            self.owner = self.new_owner()
            self.assertEqual((await self.finish(original)).status, 'reconciliation-required')
            retry = await self.finish(original, retry=True)
            self.assertEqual(retry.status, 'retry-authorized')
            self.effect_request('definition-effect-complete', attempt=retry.attempt_operation_id, original=original)
            result = await self.execute()
            self.assertEqual(result.status, 'reconciliation-required')
            self.assertEqual([call.kwargs['completion_records'] for call in append.await_args_list], [1, 0, 1, 0])
            with self.assertRaisesRegex(ContractError, '^owner_capacity_exhausted$'):
                await self.finish(original, retry=True, attempt=retry.attempt_operation_id)
        self.assertEqual(len(self.js.messages), 4)

    async def test_lost_ack_and_exact_replay_need_no_new_reserve_at_full_capacity(self):
        self.capacity(2)
        self.js.lose_ack = True
        with patch.object(self.ledger, 'append', wraps=self.ledger.append) as append:
            receipt = await self.create(0)
            original = strict_loads(self.js.messages[0].data)
            save = canonical_bytes(self.env)
            self.assertTrue(receipt.replayed)
            self.js.lose_ack = True
            result = await self.finish(original)
            complete = canonical_bytes(self.env)
            self.assertEqual(result.status, 'applied')
            self.assertTrue(result.replayed)
            self.assertTrue((await self.owner.execute(complete)).replayed)
            self.grant(original['effects'][0]['payload'], 'definition-save')
            with patch('definition_commands.apply_exact_source', side_effect=AssertionError('replayed effect')):
                self.assertTrue((await self.owner.execute(save)).replayed)
            self.assertEqual([call.kwargs['completion_records'] for call in append.await_args_list], [1, 0])
        self.assertEqual(len(self.js.messages), 2)

    async def test_competing_candidates_keep_their_count_with_the_same_sequence_check(self):
        self.capacity(4)
        self.env['operation']['operationId'] = 'race-one'
        self.resign()
        first = canonical_bytes(self.env)
        self.env['operation']['operationId'] = 'race-two'
        self.resign()
        second = canonical_bytes(self.env)
        other = self.new_owner()
        append = self.ledger.append
        entered, release, calls = 0, asyncio.Event(), []
        async def compete(record, **options):
            nonlocal entered
            calls.append((options['expected_sequence'], options['completion_records']))
            entered += 1
            if entered == 2:
                release.set()
            await asyncio.wait_for(release.wait(), 3)
            return await append(record, **options)
        with patch.object(self.ledger, 'append', compete):
            results = await asyncio.gather(self.owner.execute(first), other.execute(second), return_exceptions=True)
        self.assertEqual(calls, [(0, 1), (0, 1)])
        failures = [result for result in results if isinstance(result, Exception)]
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ContractError)
        self.assertEqual(failures[0].code, 'owner_revision_conflict')
        self.assertEqual(len(self.js.messages), 1)
        self.assertTrue(self.path.exists())

    async def test_superseding_version_retires_only_the_obsolete_attempt(self):
        self.capacity(3)
        with patch.object(self.ledger, 'append', wraps=self.ledger.append) as append:
            await self.execute()
            original = strict_loads(self.js.messages[0].data)
            self.env['operation'].update(operationId='replace-one', expectedVersion=1)
            self.env['payload']['expectedChecksum'] = original['state']['definitions'][0]['checksum']
            self.resign()
            await self.execute()
            current = strict_loads(self.js.messages[1].data)
            self.assertEqual((await self.finish(current)).status, 'applied')
            self.assertEqual([call.kwargs['completion_records'] for call in append.await_args_list], [1, 1, 0])
        self.grant(original['effects'][0]['payload'], 'definition-effect-query')
        self.effect_request('definition-effect-query', original=original)
        self.assertEqual((await self.execute()).status, 'superseded')
        self.assertEqual(len(self.js.messages), 3)

    async def test_readonly_admission_detaches_indexed_head_before_file_worker(self):
        await self.create(0)
        original = strict_loads(self.js.messages[0].data)
        entry = original['state']['definitions'][0]
        path = self.repo / '.agentmux/agents/worker-0.md'
        before = self.service._file_identity(path.stat())
        self.env['operation'].update(operationId='preview-next-revision', expectedVersion=1)
        self.env['payload']['expectedChecksum'] = entry['checksum']
        self.resign()
        proposal = await self.owner._admission.prepare(canonical_bytes(self.env))
        self.assertEqual(proposal.decision.outcome, 'allowed')
        self.assertEqual(proposal.preparation.aggregate_version, 1)
        self.assertEqual(proposal.preparation.change.candidate.version, 2)
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(before, self.service._file_identity(path.stat()))

    async def test_authority_is_rechecked_after_reserve_outcome_reads(self):
        from definition_budget import completion_records
        await self.create(0)
        original = strict_loads(self.js.messages[0].data)
        await self.finish(original)
        async def revoke(*args, **kwargs):
            count = await completion_records(*args, **kwargs)
            self.authority_record['state']['grants'][0]['status'] = 'revoked'
            return count
        with patch('definition_commands.completion_records', revoke):
            with self.assertRaisesRegex(ContractError, '^definition_not_authorized$'):
                await self.create(1)
        self.assertEqual(len(self.js.messages), 2)
        self.assertFalse((self.repo / '.agentmux/agents/worker-1.md').exists())
