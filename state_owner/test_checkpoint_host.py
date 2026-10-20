"""Local checkpoint custody, failure recovery and original worker ownership."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import state_owner.checkpoints as checkpoint_module

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from state_owner.checkpoint_host import CheckpointHost
from state_owner.checkpoints import CheckpointReceipt, export_checkpoint, load_checkpoint, _publish, _digest
from state_owner.history import OwnerHistory
from state_owner.ledger import StoredRecord, StreamIdentity
from state_owner.test_ledger import BINDING, CREATED, record


class CheckpointHostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = StreamIdentity(CREATED, 0)
        self.ref = {'id': 'checkpoint-one', 'ownerHubId': BINDING.hub_id, 'revision': 1}
        self.history = OwnerHistory(self.root / 'source.sqlite', BINDING, stream_identity=self.source)
        self.addCleanup(self.history.close)
        self.host = self.new_host()

    def new_host(self, **changes):
        options = dict(stream='OWNER', commit_ref=self.ref, binding=BINDING, stream_identity=self.source)
        options.update(changes)
        return CheckpointHost(self.root / 'checkpoint', **options)

    def generation(self, cursor):
        while self.history.verified_cursor < cursor:
            sequence = self.history.verified_cursor + 1
            value = record('operation-' + str(sequence), sequence, sequence - 1)
            self.history.verify_source(StoredRecord(canonical_bytes(value), sequence))
        path = self.root / ('checkpoint.' + str(cursor) + '.' + os.urandom(16).hex() + '.json')
        digest = export_checkpoint(path, self.history, BINDING, self.source, through=cursor)
        return CheckpointReceipt(str(path), digest, cursor)

    def test_complete_commit_restart_idempotent_and_fenced_restore(self):
        receipt = self.generation(3)
        self.assertIsNone(self.host.latest())
        entry = self.host.commit(receipt)
        self.assertEqual(entry.stream_identity, StreamIdentity(CREATED, 3))
        self.assertEqual(self.new_host().latest(), entry)
        self.assertEqual(self.new_host().commit(receipt), entry)
        self.assertEqual(len(list(self.root.glob('checkpoint-inventory-*'))), 1)
        restored = self.new_host().restore(self.root / 'restored.sqlite')
        try:
            self.assertTrue(restored.reconciliation_required)
            self.assertEqual(restored.history.source_identity.minimum_sequence, 3)
            self.assertEqual(restored.history.record(1), self.history.record(1))
        finally:
            restored.history.close()

    def test_missing_inventory_does_not_trust_uncommitted_exports(self):
        self.generation(3)
        self.assertIsNone(self.new_host().latest())
        self.assertIsNone(self.new_host(stream_identity=StreamIdentity(CREATED, 2)).latest())

    def test_exact_metadata_and_entire_chain_required_before_receipt(self):
        receipt = self.generation(2)
        for value in (replace(receipt, cursor=1), replace(receipt, digest='sha256:' + '0' * 64),
                      replace(receipt, manifest_path=str(self.root / 'another.json'))):
            with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_commit_uncertain$'):
                self.host.commit(value)
        manifest = strict_loads(Path(receipt.manifest_path).read_bytes())
        part = self.root / manifest['shards'][0]['name']
        part.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_commit_uncertain$'):
            self.host.commit(receipt)
        self.assertEqual(list(self.root.glob('checkpoint-inventory-*')), [])

    def test_inventory_binds_stream_owner_creation_and_exact_commit_reference(self):
        self.host.commit(self.generation(2))
        for host in (self.new_host(stream='ANOTHER'), self.new_host(binding=replace(BINDING, entity_id='another')),
                     self.new_host(stream_identity=StreamIdentity(CREATED.replace(year=2025), 0))):
            with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_unavailable$'):
                host.latest()
        self.assertIsNone(self.new_host(commit_ref={**self.ref, 'revision': 2}).latest())

    def test_lower_commit_and_deleted_observed_floor_refused(self):
        old, new = self.generation(1), self.generation(3)
        self.host.commit(old)
        self.host.commit(new)
        with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_commit_uncertain$'):
            self.new_host().commit(old)
        for path in self.root.glob('checkpoint-inventory-*'):
            if strict_loads(path.read_bytes())['cursor'] == 3:
                path.unlink()
        with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_unavailable$'):
            self.host.latest()

    def test_historic_receipt_does_not_lower_new_enrollment_floor_or_restore(self):
        receipt = self.generation(1)
        self.host.commit(receipt)
        newer = self.new_host(stream_identity=StreamIdentity(CREATED, 3))
        self.assertEqual(newer.latest().receipt, receipt)
        self.assertEqual(asyncio.run(newer.recovery_identity()), StreamIdentity(CREATED, 3))
        with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_restore_failed$'):
            newer.restore(self.root / 'too-old.sqlite')

    def test_lost_receipt_ack_reconciles_same_generation_without_overwrite(self):
        receipt = self.generation(2)
        def lose_ack(*args, **kwargs):
            _publish(*args, **kwargs)
            raise OSError('private path')
        with patch('state_owner.checkpoint_host._publish', side_effect=lose_ack):
            with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_commit_uncertain$'):
                self.host.commit(receipt)
        self.assertEqual(self.new_host().latest().receipt, receipt)
        self.assertEqual(self.new_host().commit(receipt).receipt, receipt)

    def test_root_replacement_and_private_file_mode_refused(self):
        receipt = self.generation(1)
        Path(receipt.manifest_path).chmod(0o644)
        with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_commit_uncertain$'):
            self.host.commit(receipt)
        Path(receipt.manifest_path).chmod(0o600)
        with patch.object(self.host, '_root_identity', (-1, -1)):
            with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_unavailable$'):
                self.host.latest()

    def test_corrupt_inventory_and_native_admission_failure_refuse_resolution(self):
        self.host.commit(self.generation(1))
        with patch('state_owner.checkpoint_host._native_guard', side_effect=ValueError('private detail')):
            with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_unavailable$'):
                self.host.latest()
        path = next(self.root.glob('checkpoint-inventory-*'))
        path.write_bytes(b'{}')
        with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_unavailable$'):
            self.new_host().latest()

    def test_two_hosts_exclude_competing_commits_and_never_acknowledge_an_older_floor(self):
        older, newer = self.generation(1), self.generation(3)
        other = self.new_host()
        entered, release = threading.Event(), threading.Event()
        original = self.host._verify
        def paused(receipt, directory):
            entered.set()
            if not release.wait(3):
                raise AssertionError('worker not released')
            return original(receipt, directory)
        with patch.object(self.host, '_verify', paused), ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.host.commit, older)
            try:
                self.assertTrue(entered.wait(3))
                with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_commit_uncertain$'):
                    other.commit(newer)
                self.assertEqual(list(self.root.glob('checkpoint-inventory-*')), [])
            finally:
                release.set()
            self.assertEqual(future.result(timeout=3).receipt, older)
        self.assertEqual(other.commit(newer).receipt, newer)
        with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_commit_uncertain$'):
            self.host.commit(older)
        self.assertEqual(self.new_host().latest().receipt, newer)

    def test_final_scan_refuses_newer_receipt_even_from_a_writer_bypassing_exclusion(self):
        older, newer = self.generation(1), self.generation(3)
        def publish_both(directory, name, raw, **options):
            _publish(directory, name, raw, **options)
            newer_raw = self.host._encode(newer)
            newer_name = self.host._namespace + _digest(newer_raw).split(':')[1] + '.json'
            _publish(directory, newer_name, newer_raw, **options)
        with patch('state_owner.checkpoint_host._publish', side_effect=publish_both):
            with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_commit_uncertain$'):
                self.host.commit(older)
        self.assertEqual(self.new_host().latest().receipt, newer)

    def test_restore_cleanup_failures_close_unreturned_cache_and_hide_raw_errors(self):
        self.host.commit(self.generation(2))
        for closing in ('directory', 'lock'):
            result, target = [], []
            original_open, original_acquire, original_close = self.host._open, self.host._acquire, os.close
            def opened():
                fd = original_open()
                if closing == 'directory' and not target:
                    target.append(fd)
                return fd
            def acquired(directory):
                fd = original_acquire(directory)
                if closing == 'lock':
                    target.append(fd)
                return fd
            def restored(*args, **kwargs):
                value = load_checkpoint(*args, **kwargs)
                result.append(value)
                return value
            def close(fd):
                original_close(fd)
                if target and fd == target[0]:
                    target.clear()
                    raise OSError('private descriptor cleanup detail')
            with patch.object(self.host, '_open', opened), patch.object(self.host, '_acquire', acquired), \
                    patch('state_owner.checkpoint_host.load_checkpoint', side_effect=restored), \
                    patch('state_owner.checkpoint_host.os.close', side_effect=close):
                with self.assertRaisesRegex(ContractError, '^checkpoint_inventory_restore_failed$'):
                    self.host.restore(self.root / (closing + '-restored.sqlite'))
            self.assertEqual(len(result), 1)
            self.assertTrue(result[0].history._closed)
        self.assertEqual(self.new_host().latest().receipt.cursor, 2)

    def test_restore_validator_descriptor_failure_also_closes_unreturned_cache(self):
        receipt = self.generation(2)
        source, created = [], []
        original_directory = checkpoint_module._directory
        original_close, original_fenced = os.close, checkpoint_module.FencedHistory
        def directory(path):
            result = original_directory(path)
            if str(path) == receipt.manifest_path:
                source.append(result[0])
            return result
        def fenced(*args):
            value = original_fenced(*args)
            created.append(value)
            return value
        def close(fd):
            original_close(fd)
            if source and fd == source[0]:
                source.clear()
                raise OSError('private source descriptor detail')
        with patch('state_owner.checkpoints._directory', side_effect=directory), \
                patch('state_owner.checkpoints.FencedHistory', side_effect=fenced), \
                patch('state_owner.checkpoints.os.close', side_effect=close):
            with self.assertRaisesRegex(ContractError, '^checkpoint_restore_failed$'):
                load_checkpoint(receipt.manifest_path, expected_digest=receipt.digest, binding=BINDING,
                    stream_identity=self.source, history_path=self.root / 'validator-restored.sqlite')
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].history._closed)


class AsyncCheckpointHostTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancellation_joins_original_commit_and_floor_survives_restart(self):
        support = CheckpointHostTests()
        support.setUp()
        self.addCleanup(support.doCleanups)
        receipt = support.generation(2)
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        original = support.host.commit
        def blocked(value):
            entered.set()
            if not release.wait(3):
                raise AssertionError('worker not released')
            try:
                return original(value)
            finally:
                finished.set()
        with patch.object(support.host, 'commit', blocked):
            task = asyncio.create_task(support.host.committed(receipt))
            while not entered.is_set():
                await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(finished.is_set())
        self.assertEqual(await support.new_host().recovery_identity(), StreamIdentity(CREATED, 2))
        self.assertEqual((await support.host.resolve()).receipt, receipt)
