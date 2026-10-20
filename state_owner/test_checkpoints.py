"""Offline checkpoint tests; no broker or application backup qualification."""
from datetime import datetime, timezone, timedelta
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from state_owner.checkpoints import export_checkpoint, load_checkpoint
from state_owner.history import OwnerHistory
from state_owner.ledger import StoredRecord, StreamIdentity, OwnerBinding
from state_owner.test_ledger import BINDING, record


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.source = StreamIdentity(datetime(2026, 1, 1, tzinfo=timezone.utc), 0)
        self.history = OwnerHistory(self.root / 'source.db', BINDING, stream_identity=self.source)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.history.close)
        self.path = self.root / 'manifest.json'

    def populate(self, count=3, size=20):
        for number in range(1, count + 1):
            value = record('operation-' + str(number), number, number - 1)
            value['state']['large'] = 'a' * size
            self.history.verify_source(StoredRecord(canonical_bytes(value), number))

    def export(self):
        return export_checkpoint(self.path, self.history, BINDING, self.source,
                                 shard_bytes=128 * 1024)

    def load(self, digest, **changes):
        args = dict(expected_digest=digest, binding=BINDING, stream_identity=self.source,
                    history_path=self.root / 'restored.db')
        args.update(changes)
        result = load_checkpoint(self.path, **args)
        self.addCleanup(result.history.close)
        return result

    def test_multipart_over_sdk_parser_limit_preserves_outcomes(self):
        self.populate(25, 50000)
        digest = self.export()
        manifest = strict_loads(self.path.read_bytes())
        self.assertGreater(manifest['recordBytes'], 1048576)
        self.assertGreater(len(manifest['shards']), 1)
        result = self.load(digest, stream_identity=StreamIdentity(self.source.created, 20))
        self.assertTrue(result.reconciliation_required)
        self.assertEqual(result.cursor, 25)
        for expected, restored in zip(self.history.records(25), result.history.records(25)):
            self.assertEqual(expected, restored)
        original = strict_loads(self.history.record(1).record)
        outcome = result.history.outcome('operation-1', original['operation']['payloadDigest'])
        self.assertEqual(outcome.record, self.history.record(1).record)
        self.assertNotIn('operation', repr(result))

    def test_missing_and_corrupt_shards_fail(self):
        self.populate()
        digest = self.export()
        manifest = strict_loads(self.path.read_bytes())
        shard = self.root / manifest['shards'][0]['name']
        shard.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ContractError, '^checkpoint_restore_failed$'):
            self.load(digest)
        shard.unlink()
        with self.assertRaisesRegex(ContractError, '^checkpoint_restore_failed$'):
            self.load(digest, history_path=self.root / 'another.db')

    def test_wrong_binding_source_and_digest_fail(self):
        self.populate()
        digest = self.export()
        other = OwnerBinding('other-hub', BINDING.owner_domain, BINDING.entity_id,
                             BINDING.entity_kind, BINDING.scope)
        for changes in ({'binding': other},
                        {'stream_identity': StreamIdentity(self.source.created + timedelta(seconds=1), 0)},
                        {'stream_identity': StreamIdentity(self.source.created, 4)},
                        {'expected_digest': 'sha256:' + '0' * 64}):
            with self.assertRaisesRegex(ContractError, '^checkpoint_restore_failed$'):
                self.load(digest, **changes)

    def test_manifest_interruption_has_no_accepted_backup(self):
        self.populate()
        from state_owner import checkpoints
        publish = checkpoints._publish
        def fail_manifest(directory, name, raw):
            if name == self.path.name:
                raise OSError('private detail')
            return publish(directory, name, raw)
        with patch.object(checkpoints, '_publish', side_effect=fail_manifest):
            with self.assertRaisesRegex(ContractError, '^checkpoint_export_uncertain$'):
                self.export()
        self.assertFalse(self.path.exists())
        self.assertTrue(list(self.root.glob('part-*')))
        self.assertFalse(list(self.root.glob('.checkpoint-*')))

    def test_no_replace_and_symlink_rejection(self):
        self.populate()
        digest = self.export()
        with self.assertRaisesRegex(ContractError, '^checkpoint_export_uncertain$'):
            self.export()
        self.assertEqual(digest, 'sha256:' + hashlib.sha256(self.path.read_bytes()).hexdigest())
        manifest = strict_loads(self.path.read_bytes())
        shard = self.root / manifest['shards'][0]['name']
        moved = self.root / 'saved'
        shard.rename(moved)
        shard.symlink_to(moved)
        with self.assertRaisesRegex(ContractError, '^checkpoint_restore_failed$'):
            self.load(digest)

    def test_prefix_export_and_failed_cache_starts_unverified(self):
        self.populate()
        digest = export_checkpoint(self.path, self.history, BINDING, self.source, through=2)
        loaded = self.load(digest)
        self.assertEqual(len(loaded.history.records(2)), 2)
        loaded.history.close()
        with OwnerHistory(self.root / 'restored.db', BINDING, stream_identity=self.source) as reopened:
            self.assertEqual(reopened.cursor, 2)
            self.assertEqual(reopened.verified_cursor, 0)
        with self.assertRaisesRegex(ContractError, '^checkpoint_export_uncertain$'):
            export_checkpoint(self.root / 'bad.json', self.history, BINDING,
                              self.source, through=4)

    def test_source_epoch_cannot_be_relabelled_on_export(self):
        self.populate()
        newer = StreamIdentity(self.source.created + timedelta(seconds=1), 0)
        with self.assertRaisesRegex(ContractError, '^checkpoint_export_uncertain$'):
            export_checkpoint(self.path, self.history, BINDING, newer)
        self.assertFalse(self.path.exists())
        self.assertFalse(list(self.root.glob('part-*')))

    def test_export_preserves_cache_floor_and_refuses_older_prefix(self):
        self.history.close()
        self.source = StreamIdentity(self.source.created, 2)
        self.history = OwnerHistory(self.root / 'source.db', BINDING, stream_identity=self.source)
        self.addCleanup(self.history.close)
        self.populate()
        lower = StreamIdentity(self.source.created, 0)
        with self.assertRaisesRegex(ContractError, '^checkpoint_export_uncertain$'):
            export_checkpoint(self.path, self.history, BINDING, lower, through=1)
        self.assertFalse(self.path.exists())
        digest = export_checkpoint(self.path, self.history, BINDING, lower)
        manifest = strict_loads(self.path.read_bytes())
        self.assertEqual(manifest['source']['minimumSequence'], 2)
        restored = self.load(digest, stream_identity=lower)
        self.assertEqual(restored.history.source_identity.minimum_sequence, 2)

    def test_load_keeps_higher_supplied_floor(self):
        self.populate()
        digest = self.export()
        restored = self.load(digest, stream_identity=StreamIdentity(self.source.created, 3))
        self.assertEqual(restored.history.source_identity.minimum_sequence, 3)


class CheckpointCapacityTests(unittest.TestCase):
    def test_fifty_gibibytes_choose_bounded_larger_shards(self):
        from state_owner.checkpoints import _shard_size, MAX_SHARD_BYTES, DEFAULT_SHARD_BYTES
        selected = _shard_size(50 * 1024 ** 3, 1_000_000, DEFAULT_SHARD_BYTES)
        self.assertGreater(selected, DEFAULT_SHARD_BYTES)
        self.assertLessEqual(selected, MAX_SHARD_BYTES)
        with self.assertRaises(ValueError):
            _shard_size(1024 ** 4, 1_000_000, DEFAULT_SHARD_BYTES)

    def test_checkpoint_cadence_counts_active_changes(self):
        from state_owner.checkpoints import CheckpointCadence
        cadence = CheckpointCadence(now=100)
        self.assertFalse(cadence.due(0, 2000))
        self.assertFalse(cadence.due(1, 2000))
        self.assertFalse(cadence.due(1, 2899))
        self.assertTrue(cadence.due(1, 2900))
        cadence.completed(1, 2900)
        self.assertFalse(cadence.due(1, 4000))
        self.assertTrue(cadence.due(10001, 4001))
        cadence.completed(9999, 4002)
        self.assertTrue(cadence.due(10001, 4901))
        cadence.completed(10001, 4902)
        self.assertFalse(cadence.due(10001, 5902))
        with self.assertRaisesRegex(ContractError, 'checkpoint_cadence_invalid'):
            cadence.due(10000, 5903)
        with self.assertRaisesRegex(ContractError, 'checkpoint_cadence_invalid'):
            cadence.due(10002, float('nan'))
