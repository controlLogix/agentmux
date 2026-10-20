"""Offline indexed-owner controls; no live broker or automatic recovery effects."""
from pathlib import Path
from datetime import timedelta
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes

from state_owner.checkpoints import export_checkpoint, load_checkpoint
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerLedger, StreamIdentity
from state_owner.retention import Retention
from state_owner.test_ledger import BINDING, CREATED, SUBJECT, FakeJetStream, record


class IndexedLedgerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owner-index-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.policy = Retention(1024 * 131_072, 8 * 131_072)
        self.js = FakeJetStream(self.policy)
        self.index = self.new_index('history.sqlite')
        self.owner = self.make_owner(self.index)

    def new_index(self, name):
        result = OwnerHistory(self.directory / name, BINDING, stream_identity=StreamIdentity(CREATED, 0))
        self.addCleanup(result.close)
        return result

    def make_owner(self, history):
        return OwnerLedger(self.js, stream='OWNER', subject=SUBJECT, binding=BINDING,
                           retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
                           max_history_records=1, max_history_bytes=65_536, history=history)

    def seed_source(self, count):
        for seq in range(1, count + 1):
            self.js.messages.append(SimpleNamespace(subject=SUBJECT, seq=seq,
                data=canonical_bytes(record('source-' + str(seq), seq, seq - 1))))

    async def test_pages_pass_old_scan_bound_and_preserve_completion_and_outcomes(self):
        self.seed_source(140)
        with self.assertRaisesRegex(ContractError, '^owner_history_recovery_required$'):
            await self.owner.current()
        self.assertEqual(self.index.verified_cursor, 128)
        progress = await self.owner.prepare_history(batch_size=16)
        self.assertTrue(progress.ready)
        snapshot = await self.owner.current()
        self.assertEqual(snapshot.sequence, 140)
        self.assertEqual(len(snapshot.records), 140)
        self.assertEqual(snapshot.latest.sequence, 140)
        first = record('source-1')
        prior = await self.owner.outcome('source-1', first['operation']['payloadDigest'])
        self.assertTrue(prior.replayed)
        self.assertEqual(prior.sequence, 1)
        final = await self.owner.append(record('completion', 141, 140), expected_sequence=140,
                                        admission='completion')
        self.assertEqual(final.sequence, 141)
        self.assertEqual(self.index.verified_cursor, 141)

    async def test_reopen_verifies_source_in_pages_and_detects_corrupt_prefix(self):
        self.seed_source(4)
        await self.owner.prepare_history()
        self.index.close()
        reopened = self.new_index('history.sqlite')
        self.assertEqual(reopened.verified_cursor, 0)
        owner = self.make_owner(reopened)
        progress = await owner.prepare_history(batch_size=2)
        self.assertFalse(progress.ready)
        self.js.messages[2].data = canonical_bytes(record('different-source', 3, 2))
        with self.assertRaisesRegex(ContractError, '^owner_history_cache_invalid$'):
            await owner.prepare_history(batch_size=2)

    async def test_current_does_not_rescan_verified_prefix(self):
        self.seed_source(5)
        await self.owner.prepare_history()
        original = self.js.get_msg
        calls = []
        async def counted(*args, **kwargs):
            calls.append(kwargs.get('seq'))
            return await original(*args, **kwargs)
        self.js.get_msg = counted
        self.assertEqual((await self.owner.current()).sequence, 5)
        self.assertEqual(calls, [None])
        first = record('source-1')
        await self.owner.outcome('source-1', first['operation']['payloadDigest'])
        self.assertEqual(calls[-2:], [None, 1])

    async def test_checkpoint_prefix_is_checked_at_live_source_before_suffix(self):
        self.seed_source(6)
        await self.owner.prepare_history()
        identity = StreamIdentity(CREATED, 0)
        manifest = self.directory / 'manifest.json'
        digest = export_checkpoint(manifest, self.index, BINDING, identity, through=4)
        restored = load_checkpoint(manifest, expected_digest=digest, binding=BINDING,
                                   stream_identity=identity, history_path=self.directory / 'restored.sqlite')
        self.addCleanup(restored.history.close)
        self.assertTrue(restored.reconciliation_required)
        owner = self.make_owner(restored.history)
        original = self.js.get_msg
        seen = []
        async def counted(*args, **kwargs):
            seen.append(kwargs.get('seq'))
            return await original(*args, **kwargs)
        self.js.get_msg = counted
        self.assertTrue((await owner.prepare_history()).ready)
        self.assertEqual(seen, [4, 5, 6])
        self.assertEqual((await owner.current()).sequence, 6)

    async def test_checkpoint_head_mismatch_is_not_adopted(self):
        self.seed_source(2)
        await self.owner.prepare_history()
        identity = StreamIdentity(CREATED, 0)
        manifest = self.directory / 'manifest.json'
        digest = export_checkpoint(manifest, self.index, BINDING, identity)
        restored = load_checkpoint(manifest, expected_digest=digest, binding=BINDING,
                                   stream_identity=identity, history_path=self.directory / 'restored.sqlite')
        self.addCleanup(restored.history.close)
        self.js.messages[1].data = canonical_bytes(record('wrong-head', 2, 1))
        with self.assertRaisesRegex(ContractError, '^owner_history_corrupt$'):
            await self.make_owner(restored.history).current()

    async def test_index_configuration_covers_completion_reserve(self):
        small = OwnerHistory(self.directory / 'small.sqlite', BINDING, max_records=1023,
                             stream_identity=StreamIdentity(CREATED, 0))
        self.addCleanup(small.close)
        with self.assertRaisesRegex(ContractError, '^owner_history_capacity$'):
            self.make_owner(small)

    async def test_verified_history_cannot_cross_stream_creation_epochs(self):
        other = OwnerHistory(self.directory / 'other-epoch.sqlite', BINDING,
                             stream_identity=StreamIdentity(CREATED + timedelta(seconds=1), 0))
        self.addCleanup(other.close)
        with self.assertRaisesRegex(ContractError, '^owner_history_configuration$'):
            self.make_owner(other)

    async def test_partial_cache_preserves_stronger_trusted_revision_floor(self):
        self.seed_source(2)
        partial = OwnerHistory(self.directory / 'partial.sqlite', BINDING,
                               stream_identity=StreamIdentity(CREATED, 3))
        self.addCleanup(partial.close)
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.make_owner(partial).current()

    async def test_retained_inventory_floor_refuses_source_rollback_before_replay(self):
        self.seed_source(1)
        trusted = self.owner.require_recovery_identity(StreamIdentity(CREATED, 2))
        self.assertEqual(trusted.minimum_sequence, 2)
        self.assertEqual(self.owner.require_recovery_identity(StreamIdentity(CREATED, 0)), trusted)
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.owner.prepare_history()
        self.assertEqual(self.index.verified_cursor, 0)
        self.assertEqual(self.js.messages[0].seq, 1)

    async def test_recovery_floor_cannot_relabel_source_epoch(self):
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            self.owner.require_recovery_identity(StreamIdentity(CREATED + timedelta(seconds=1), 2))
        self.assertEqual(self.owner.require_recovery_identity(StreamIdentity(CREATED, 0)).minimum_sequence, 0)

    async def test_cache_failure_after_ack_keeps_committed_outcome(self):
        with patch.object(self.index, 'append_verified', side_effect=ContractError('owner_history_cache_invalid')):
            stored = await self.owner.append(record(), expected_sequence=0)
        self.assertEqual(stored.sequence, 1)
        self.assertEqual(self.index.verified_cursor, 0)
        result = await self.owner.outcome('operation-one', record()['operation']['payloadDigest'])
        self.assertTrue(result.replayed)
        self.assertEqual(self.index.verified_cursor, 1)
        self.assertEqual(len(self.js.messages), 1)

    async def test_indexed_lost_ack_recovers_same_intent(self):
        self.js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.owner.append(record(), expected_sequence=0)
        replay = await self.owner.append(record(), expected_sequence=0)
        self.assertTrue(replay.replayed)
        self.assertEqual(len(self.js.messages), 1)

    async def test_history_larger_than_old_64mib_limit_keeps_completion_usable(self):
        self.policy = Retention(2048 * 131_072, 8 * 131_072)
        self.js = FakeJetStream(self.policy)
        self.owner = self.make_owner(self.index)
        for seq in range(1, 1101):
            item = record('large-' + str(seq), seq, seq - 1)
            item['state']['padding'] = 'x' * 62000
            self.js.messages.append(SimpleNamespace(subject=SUBJECT, seq=seq,
                                                     data=canonical_bytes(item)))
        self.assertGreater(sum(len(m.data) for m in self.js.messages), 67_108_864)
        while not (await self.owner.prepare_history(batch_size=32)).ready:
            pass
        self.assertGreater(self.index.total_bytes, 67_108_864)
        self.assertEqual((await self.owner.current()).sequence, 1100)
        first = record('large-1')
        self.assertEqual((await self.owner.outcome('large-1', first['operation']['payloadDigest'])).sequence, 1)
        completed = await self.owner.append(record('large-completion', 1101, 1100),
                                            expected_sequence=1100, admission='completion')
        self.assertEqual(completed.sequence, 1101)


if __name__ == '__main__':
    unittest.main()
