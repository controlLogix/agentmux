"""Reserved future records under competing conditional owner admissions.

The fixture's toy domain owes one terminal record per outstanding ID. Production
owners must supply their own conservative bounds from complete retained state.
"""
import asyncio
import copy
from pathlib import Path
import tempfile
import unittest

from agentmux_contracts import ContractError, strict_loads
from state_owner.ledger import OwnerLedger, StreamIdentity
from state_owner.history import OwnerHistory
from state_owner.retention import RECORD_CHARGE, Retention
from state_owner.test_ledger import BINDING, CREATED, SUBJECT, FakeJetStream, record


class CompletionReserveTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.policy = Retention(8 * RECORD_CHARGE, RECORD_CHARGE)
        self.js = FakeJetStream(self.policy)
        self.owner = self.new_owner()

    def new_owner(self, **changes):
        options = dict(require_completion_budget=True)
        options.update(changes)
        return OwnerLedger(self.js, stream='OWNER', subject=SUBJECT, binding=BINDING,
                           retention=self.policy, stream_identity=StreamIdentity(CREATED, 0), **options)

    def proposal(self, operation, sequence, outstanding, *, new=()):
        value = record(operation, sequence, sequence - 1)
        effect = value['effects'][0]
        value['effects'] = [dict(copy.deepcopy(effect), effectId=identity) for identity in new]
        value['state']['outstanding'] = list(outstanding)
        return value

    async def append(self, operation, sequence, outstanding, **options):
        proposal = self.proposal(operation, sequence, outstanding, new=options.pop('new', ()))
        return await self.owner.append(proposal, expected_sequence=sequence - 1,
                                        completion_records=len(outstanding), **options)

    async def fill_with_three_obligations(self):
        pending = ('obligation-a', 'obligation-b', 'obligation-c')
        await self.append('accept', 1, pending, new=pending)
        for sequence in range(2, 6):
            await self.append('progress-' + str(sequence), sequence, pending)
        return pending

    async def test_strict_composition_requires_bound_on_every_new_append(self):
        self.assertTrue(self.owner.completion_budget_required)
        for admission in ('bulk', 'completion', 'reconciliation'):
            with self.assertRaisesRegex(ContractError, '^owner_completion_budget_required$'):
                await self.owner.append(self.proposal('missing-' + admission, 1, ()),
                                        expected_sequence=0, admission=admission)
        self.assertEqual(self.js.messages, [])
        self.assertFalse(self.new_owner(require_completion_budget=False).completion_budget_required)
        with self.assertRaisesRegex(ContractError, '^owner_configuration_invalid$'):
            self.new_owner(require_completion_budget='yes')

    async def test_strict_scan_capacity_cannot_undercut_reserved_completion_horizon(self):
        for bounds in ({'max_history_records': 1}, {'max_history_bytes': 65_536}):
            with self.assertRaisesRegex(ContractError, '^owner_history_capacity$'):
                self.new_owner(**bounds)
        exact = self.new_owner(max_history_records=8, max_history_bytes=8 * 65_536)
        self.assertTrue(exact.completion_budget_required)
        self.assertEqual(self.js.messages, [])

    async def test_invalid_bounds_never_publish(self):
        for count in (-1, True, 1.0, '1', 9_007_199_254_740_992):
            with self.assertRaisesRegex(ContractError, '^owner_completion_budget_invalid$'):
                await self.owner.append(self.proposal('bad-bound', 1, ()),
                                        expected_sequence=0, completion_records=count)
        self.assertEqual(self.js.messages, [])

    async def test_bulk_cannot_consume_three_outstanding_completions(self):
        pending = await self.fill_with_three_obligations()
        # Six used slots pass the former fixed-reserve rule, but leave only two
        # slots for three already accepted obligations.
        with self.assertRaisesRegex(ContractError, '^owner_capacity_reserved$'):
            await self.append('more-progress', 6, pending)
        self.assertEqual(len(self.js.messages), 5)
        for sequence, remaining in ((6, pending[1:]), (7, pending[2:]), (8, ())):
            await self.append('finish-' + str(sequence), sequence, remaining, admission='completion')
        self.assertEqual(len(self.js.messages), 8)
        self.assertEqual(strict_loads(self.js.messages[0].data)['state']['outstanding'], list(pending))
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state']['outstanding'], [])

    async def test_completion_and_reconciliation_cannot_spend_other_obligations_slots(self):
        pending = await self.fill_with_three_obligations()
        for admission in ('completion', 'reconciliation'):
            with self.assertRaisesRegex(ContractError, '^owner_capacity_exhausted$'):
                await self.append('no-release-' + admission, 6, pending, admission=admission)
        # One reconciliation record consumes its own previously reserved slot.
        await self.append('reconcile', 6, pending[1:], admission='reconciliation')
        self.assertEqual(len(self.js.messages), 6)

    async def test_competing_acceptors_share_state_sequence_and_cannot_oversubscribe(self):
        initial = ('obligation-original',)
        await self.append('initial', 1, initial, new=initial)
        await self.append('progress', 2, initial)
        groups = [('a-one', 'a-two', 'a-three'), ('b-one', 'b-two', 'b-three')]
        proposals = [self.proposal('accept-' + str(index), 3, initial + group, new=group)
                     for index, group in enumerate(groups)]
        results = await asyncio.gather(*(owner.append(proposal, expected_sequence=2, completion_records=4)
            for owner, proposal in zip((self.owner, self.new_owner()), proposals)), return_exceptions=True)
        self.assertEqual(sum(not isinstance(result, Exception) for result in results), 1)
        loser = next(result for result in results if isinstance(result, Exception))
        self.assertIsInstance(loser, ContractError)
        self.assertEqual(loser.code, 'owner_revision_conflict')
        pending = tuple(strict_loads(self.js.messages[-1].data)['state']['outstanding'])
        losing = next(group for group in groups if group[0] not in pending)
        with self.assertRaisesRegex(ContractError, '^owner_capacity_reserved$'):
            await self.append('retry-loser', 4, pending + losing, new=losing)
        for sequence in range(4, 8):
            pending = pending[1:]
            await self.append('finish-' + str(sequence), sequence, pending, admission='completion')
        self.assertEqual(pending, ())
        self.assertEqual(len(self.js.messages), 7)

    async def test_lost_ack_and_restart_do_not_consume_a_second_completion_slot(self):
        pending = await self.fill_with_three_obligations()
        proposal = self.proposal('finish-once', 6, pending[1:])
        self.js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.owner.append(proposal, expected_sequence=5, admission='completion', completion_records=2)
        self.owner = self.new_owner()
        # A retained replay spends no record and needs no new admission budget.
        replay = await self.owner.append(proposal, expected_sequence=5, admission='completion')
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.sequence, 6)
        self.assertEqual(len(self.js.messages), 6)
        for sequence, remaining in ((7, pending[2:]), (8, ())):
            await self.append('finish-' + str(sequence), sequence, remaining, admission='completion')
        self.assertEqual(len(self.js.messages), 8)

    async def test_indexed_recovery_derives_remaining_bound_from_retained_state(self):
        pending = await self.fill_with_three_obligations()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        index = OwnerHistory(Path(folder.name).resolve() / 'history.sqlite', BINDING,
                             stream_identity=StreamIdentity(CREATED, 0))
        self.addCleanup(index.close)
        self.owner = self.new_owner(history=index)
        while not (await self.owner.prepare_history(batch_size=2)).ready:
            pass
        snapshot = await self.owner.current()
        recovered = tuple(strict_loads(snapshot.latest.record)['state']['outstanding'])
        self.assertEqual(recovered, pending)
        with self.assertRaisesRegex(ContractError, '^owner_capacity_reserved$'):
            await self.append('indexed-progress', 6, recovered)
        for sequence in range(6, 9):
            recovered = recovered[1:]
            await self.append('indexed-finish-' + str(sequence), sequence, recovered, admission='completion')
        self.assertEqual((await self.owner.current()).sequence, 8)
