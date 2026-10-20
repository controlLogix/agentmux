"""Offline encrypted backups; no broker, off-volume or recovery-time claims."""
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import state_owner.backup as backup_module

from nacl.secret import SecretBox
from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from state_owner.artifacts import OwnerArtifacts
from state_owner.backup import export_backup, restore_backup
from state_owner.history import OwnerHistory
from state_owner.ledger import StoredRecord, StreamIdentity
from state_owner.test_artifacts import Store, JS
from state_owner.test_recovery import history


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class BackupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.destination = self.root / 'backup'
        self.destination.mkdir(mode=0o700)
        self.binding, self.snapshot = history()
        self.source = StreamIdentity(datetime(2026, 10, 16, tzinfo=timezone.utc), 0)
        self.owner = OwnerHistory(self.root / 'owner.db', self.binding, stream_identity=self.source)
        self.addCleanup(self.owner.close)
        self.store = Store()
        self.artifacts = OwnerArtifacts(self.store, JS(self.store), bucket='bucket',
            owner_hub_id='hub-one', store_ref={'id': 'ref-one', 'ownerHubId': 'hub-one', 'revision': 1},
            max_bytes=1024)
        self.payload = b'artifact bytes\x00\xff private'
        self.reference = await self.artifacts.upload(self.payload, media_type='application/octet-stream')
        for index, stored in enumerate(self.snapshot.records):
            value = strict_loads(stored.record)
            # The retained first record still requires bytes absent from latest state.
            value['artifacts'] = [self.reference] if index == 0 else []
            self.owner.verify_source(StoredRecord(canonical_bytes(value), stored.sequence))
        self.key = b'k' * 32  # Public fixture key, never a deployment key.
        self.restores = 0

    async def export(self, **changes):
        config = dict(key=self.key, retrieve_artifact=self.artifacts.retrieve)
        config.update(changes)
        return await export_backup(self.destination, self.owner, self.binding, self.source, **config)

    def restore(self, receipt, **changes):
        self.restores += 1
        config = dict(expected_digest=receipt.digest, key=self.key, binding=self.binding,
                      stream_identity=self.source, history_path=self.root / f'restored-{self.restores}.db')
        config.update(changes)
        result = restore_backup(self.destination, receipt.manifest_name, **config)
        self.addCleanup(result.close)
        return result

    def manifest(self, receipt):
        return strict_loads(SecretBox(self.key).decrypt((self.destination / receipt.manifest_name).read_bytes()))

    def change_manifest(self, receipt, change):
        value = self.manifest(receipt)
        change(value)
        encrypted = bytes(SecretBox(self.key).encrypt(canonical_bytes(value)))
        (self.destination / receipt.manifest_name).write_bytes(encrypted)
        return replace(receipt, digest=digest(encrypted))

    def published_tops(self):
        tops = []
        for path in self.destination.iterdir():
            raw = SecretBox(self.key).decrypt(path.read_bytes())
            try:
                value = strict_loads(raw)
            except ContractError:
                continue
            if isinstance(value, dict) and value.get('format') == 'amx-owner-encrypted-backup-v1':
                tops.append(path)
        return tops

    async def test_artifact_reader_round_trip_preserves_all_history(self):
        receipt = await self.export()
        result = self.restore(receipt)
        self.assertTrue(result.reconciliation_required)
        self.assertEqual(result.cursor, 2)
        self.assertEqual(result.retrieve(self.reference), self.payload)
        self.assertEqual(list(result.history.records(2)), list(self.owner.records(2)))
        first = strict_loads(self.owner.record(1).record)
        self.assertEqual(result.history.outcome(first['operation']['operationId'], first['operation']['payloadDigest']).record,
                         self.owner.record(1).record)
        self.assertNotIn('private', repr(result))
        for path in self.destination.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(b'secret-value', path.read_bytes())
            self.assertNotIn(self.payload, path.read_bytes())
        with self.assertRaises(ContractError):
            result.retrieve({**self.reference, 'mediaType': 'text/plain'})

    async def test_wrong_key_digest_binding_epoch_floor(self):
        receipt = await self.export()
        cases = ({'key': b'x' * 32}, {'expected_digest': 'sha256:' + '0' * 64},
                 {'binding': replace(self.binding, hub_id='other-hub')},
                 {'stream_identity': StreamIdentity(self.source.created + timedelta(seconds=1), 0)},
                 {'stream_identity': StreamIdentity(self.source.created, 3)},
                 {'max_total_bytes': 10}, {'max_artifacts': 0})
        for case in cases:
            with self.assertRaisesRegex(ContractError, '^owner_backup_restore_failed$'):
                self.restore(receipt, **case)

    async def test_repeated_exports_preserve_independent_immutable_generations(self):
        first = await self.export()
        first_bytes = (self.destination / first.manifest_name).read_bytes()
        first_parts = {entry['name'] for entry in self.manifest(first)['components']}
        value = strict_loads(self.owner.record(2).record)
        value.update(entityVersion=3, previousRevision=2, recordId='record-generation-3')
        value['operation']['operationId'] = 'operation-generation-3'
        value['operation']['expectedVersion'] = 2
        self.owner.verify_source(StoredRecord(canonical_bytes(value), 3))

        second = await self.export()
        second_parts = {entry['name'] for entry in self.manifest(second)['components']}
        self.assertNotEqual(first.manifest_name, second.manifest_name)
        self.assertTrue(first_parts.isdisjoint(second_parts))
        self.assertEqual((self.destination / first.manifest_name).read_bytes(), first_bytes)
        self.assertEqual(self.restore(first).cursor, 2)
        self.assertEqual(self.restore(second).cursor, 3)

    async def test_missing_truncated_swapped_parts_fail(self):
        receipt = await self.export()
        components = self.manifest(receipt)['components']
        path = self.destination / components[-1]['name']
        original = path.read_bytes()
        for bad in (original[:-1], (self.destination / components[0]['name']).read_bytes()):
            path.write_bytes(bad)
            with self.assertRaises(ContractError):
                self.restore(receipt)
        path.unlink()
        with self.assertRaises(ContractError):
            self.restore(receipt)

    async def test_artifact_omission_and_traversal_fail_even_with_new_top_digest(self):
        receipt = await self.export()
        missing = self.change_manifest(receipt, lambda m: m.update(components=[e for e in m['components'] if e['kind'] != 'artifact']))
        with self.assertRaises(ContractError):
            self.restore(missing)
        # A failed post-load inventory check must close the restored cache lock.
        with OwnerHistory(self.root / 'restored-1.db', self.binding, stream_identity=self.source):
            pass
        traversal = self.change_manifest(missing, lambda m: m['components'][0].update(name='../outside'))
        with self.assertRaises(ContractError):
            self.restore(traversal)

    async def test_failed_artifact_and_capacity_never_publish_top(self):
        async def missing(_):
            raise RuntimeError('private store details')
        for config in ({'retrieve_artifact': missing}, {'max_artifacts': 0}, {'max_total_bytes': 10}):
            with self.assertRaisesRegex(ContractError, '^owner_backup_export_uncertain$'):
                await self.export(**config)
            self.assertEqual(self.published_tops(), [])

    async def test_cancelled_export_cleans_plaintext_staging(self):
        stages = []
        real_temporary = tempfile.TemporaryDirectory
        def track(*args, **kwargs):
            result = real_temporary(*args, **kwargs)
            stages.append(Path(result.name))
            return result
        async def cancelled(_):
            raise asyncio.CancelledError()
        with patch('state_owner.backup.tempfile.TemporaryDirectory', side_effect=track):
            with self.assertRaises(asyncio.CancelledError):
                await self.export(retrieve_artifact=cancelled)
        self.assertTrue(stages)
        self.assertTrue(all(not path.exists() for path in stages))
        self.assertEqual(self.published_tops(), [])

    async def test_cancelled_export_joins_authorized_reader_cleanup(self):
        entered, cleaning, release, cleaned = (asyncio.Event() for _ in range(4))
        owner_thread = threading.get_ident()
        async def read(reference):
            self.assertEqual(threading.get_ident(), owner_thread)
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                await release.wait()
                cleaned.set()
        task = asyncio.create_task(self.export(retrieve_artifact=read))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            task.cancel()
            await asyncio.wait_for(cleaning.wait(), 2)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(cleaned.is_set())
            self.assertEqual(self.published_tops(), [])
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_file_worker_keeps_loop_responsive_and_joins_on_cancel(self):
        from state_owner import backup
        entered = asyncio.Event()
        release, exited = threading.Event(), threading.Event()
        loop = asyncio.get_running_loop()
        diagnostics = []
        old_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _, context: diagnostics.append(context.get('message')))
        publish = backup._publish
        stages = []
        real_temporary = tempfile.TemporaryDirectory
        def staging(*args, **kwargs):
            result = real_temporary(*args, **kwargs)
            stages.append(Path(result.name))
            return result
        def blocked(*args):
            loop.call_soon_threadsafe(entered.set)
            try:
                if not release.wait(5):
                    raise TimeoutError()
                return publish(*args)
            finally:
                exited.set()
        with patch.object(backup, '_publish', side_effect=blocked), patch.object(
                backup.tempfile, 'TemporaryDirectory', side_effect=staging):
            task = asyncio.create_task(self.export())
            try:
                await asyncio.wait_for(entered.wait(), 2)
                for _ in range(2):
                    task.cancel()
                    await asyncio.sleep(0)
                    self.assertFalse(task.done())
                    self.assertEqual(self.owner.verified_cursor, 2)
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertTrue(exited.is_set())
                self.assertTrue(stages)
                self.assertTrue(all(not path.exists() for path in stages))
            finally:
                release.set()
                await asyncio.gather(task, return_exceptions=True)
                loop.set_exception_handler(old_handler)
        self.assertEqual(diagnostics, [])

    async def test_fixed_prefix_and_exact_deduplication(self):
        value = strict_loads(self.owner.record(2).record)
        value.update(entityVersion=3, previousRevision=2, recordId='record-3', artifacts=[self.reference])
        value['operation']['operationId'] = 'operation-3'
        value['operation']['expectedVersion'] = 2
        self.owner.verify_source(StoredRecord(canonical_bytes(value), 3))
        calls = []
        async def retrieve(ref):
            calls.append(ref)
            value = strict_loads(self.owner.record(3).record)
            value.update(entityVersion=4, previousRevision=3, recordId='record-4')
            value['operation']['operationId'] = 'operation-4'
            value['operation']['expectedVersion'] = 3
            self.owner.verify_source(StoredRecord(canonical_bytes(value), 4))
            return await self.artifacts.retrieve(ref)
        receipt = await self.export(retrieve_artifact=retrieve)
        self.assertEqual(len(calls), 1)
        self.assertEqual(receipt.cursor, 3)
        self.assertEqual(self.restore(receipt).cursor, 3)

    async def test_conflicting_reference_identity_is_rejected(self):
        value = strict_loads(self.owner.record(2).record)
        value.update(entityVersion=3, previousRevision=2, recordId='record-3',
                     artifacts=[{**self.reference, 'mediaType': 'text/plain'}])
        value['operation']['operationId'] = 'operation-3'
        self.owner.verify_source(StoredRecord(canonical_bytes(value), 3))
        with self.assertRaises(ContractError):
            await self.export()
        self.assertEqual(list(self.destination.iterdir()), [])

    async def test_local_retrieval_rechecks_ciphertext_and_uses_absolute_directory(self):
        receipt = await self.export()
        old_cwd = os.getcwd()
        try:
            os.chdir(self.root)
            result = restore_backup('backup', receipt.manifest_name, expected_digest=receipt.digest,
                key=self.key, binding=self.binding, stream_identity=self.source,
                history_path=self.root / 'relative-restored.db')
            self.addCleanup(result.close)
            os.chdir(self.root.parent)
            self.assertEqual(result.retrieve(self.reference), self.payload)
        finally:
            os.chdir(old_cwd)
        entry = next(e for e in self.manifest(receipt)['components'] if e['kind'] == 'artifact')
        (self.destination / entry['name']).write_bytes(b'corrupt')
        with self.assertRaisesRegex(ContractError, '^owner_backup_artifact_unavailable$'):
            result.retrieve(self.reference)

    async def test_staging_cleanup_failure_closes_restored_history(self):
        receipt = await self.export()
        real_temporary = tempfile.TemporaryDirectory
        class FailingCleanup:
            def __enter__(self):
                self.temporary = real_temporary()
                return self.temporary.__enter__()
            def __exit__(self, *args):
                self.temporary.__exit__(*args)
                raise OSError('private cleanup failure')
        with patch('state_owner.backup.tempfile.TemporaryDirectory', return_value=FailingCleanup()):
            with self.assertRaisesRegex(ContractError, '^owner_backup_restore_failed$'):
                self.restore(receipt)
        with OwnerHistory(self.root / 'restored-1.db', self.binding, stream_identity=self.source):
            pass

    async def test_source_directory_close_failure_closes_unreturned_restored_history(self):
        receipt = await self.export()
        original_directory, original_close = backup_module._directory, os.close
        original_fenced = backup_module.FencedBackup
        source, results = [], []
        def directory(path):
            result = original_directory(path)
            if Path(path) == self.destination / receipt.manifest_name:
                source.append(result[0])
            return result
        def fenced(*args):
            result = original_fenced(*args)
            results.append(result)
            return result
        def close(fd):
            original_close(fd)
            if source and fd == source[0]:
                source.clear()
                raise OSError('private source cleanup detail')
        with patch('state_owner.backup._directory', side_effect=directory), \
                patch('state_owner.backup.FencedBackup', side_effect=fenced), \
                patch('state_owner.backup.os.close', side_effect=close):
            with self.assertRaisesRegex(ContractError, '^owner_backup_restore_failed$'):
                self.restore(receipt)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].history._closed)
        self.assertIsNone(results[0]._box)
        with self.assertRaisesRegex(ContractError, '^owner_backup_artifact_unavailable$'):
            results[0].retrieve(self.reference)
        # The failed result did not retain the SQLite cache lock.
        with OwnerHistory(self.root / 'restored-1.db', self.binding, stream_identity=self.source):
            pass

    async def test_staging_and_restored_plaintext_cannot_be_in_destination(self):
        receipt = await self.export()
        with self.assertRaises(ContractError):
            self.restore(receipt, history_path=self.destination / 'bad.db')
        real_temporary = tempfile.TemporaryDirectory
        def inside(*args, **kwargs):
            return real_temporary(*args, **kwargs, dir=self.destination)
        with patch('state_owner.backup.tempfile.TemporaryDirectory', side_effect=inside):
            with self.assertRaises(ContractError):
                await self.export()
            with self.assertRaises(ContractError):
                self.restore(receipt)
        self.assertEqual(len(self.published_tops()), 1)


if __name__ == '__main__':
    unittest.main()
