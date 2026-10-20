"""Single-owner backup lifecycle with real private inventory, keys and restore."""
import asyncio
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from nacl.secret import SecretBox

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from state_owner.artifacts import OwnerArtifacts
from state_owner.backup_host import BackupHost
from state_owner.backup_lifecycle import OwnerBackupLifecycle
from state_owner.history import OwnerHistory
from state_owner.ledger import StoredRecord, StreamIdentity
from state_owner.test_artifacts import Store, JS
from state_owner.test_recovery import history


class BackupLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binding, snapshot = history()
        self.identity = StreamIdentity(datetime(2026, 10, 16, tzinfo=timezone.utc), 0)
        self.history = OwnerHistory(self.root / 'source.sqlite', self.binding, stream_identity=self.identity)
        self.addCleanup(self.history.close)
        directories = [self.root / name for name in ('backup', 'inventory', 'keys')]
        for directory in directories:
            directory.mkdir(mode=0o700)
        self.host = BackupHost(*directories, destination_id='protected-one',
                               binding=self.binding, stream_identity=self.identity)
        self.host.enroll_key('backup-one')
        store = Store()
        self.artifacts = OwnerArtifacts(store, JS(store), bucket='bucket', owner_hub_id='hub-one',
            store_ref={'id': 'ref-one', 'ownerHubId': 'hub-one', 'revision': 1}, max_bytes=1024)
        self.reference = await self.artifacts.upload(b'retained artifact', media_type='text/plain')
        for index, item in enumerate(snapshot.records):
            value = strict_loads(item.record)
            value['artifacts'] = [self.reference] if index == 0 else []
            self.history.verify_source(StoredRecord(canonical_bytes(value), item.sequence))
        self.now = 1000.0
        self.services = []
        self.addAsyncCleanup(self.close_services)

    async def close_services(self):
        for service in self.services:
            if not service._closed:
                await service.close()

    def service(self, **changes):
        arguments = dict(key_id='backup-one', retrieve_artifact=self.artifacts.retrieve,
                         clock=lambda: self.now)
        arguments.update(changes)
        service = OwnerBackupLifecycle(self.history, self.binding, self.identity, self.host, **arguments)
        self.services.append(service)
        return service

    async def test_hourly_export_daily_real_restore_and_durable_inventory(self):
        from state_owner import backup_lifecycle
        service = self.service()
        owner_thread = threading.get_ident()
        key_threads, restore_threads = [], []
        load_key, restore = self.host.load_key, backup_lifecycle.restore_backup
        def key_read(key_id):
            key_threads.append(threading.get_ident())
            return load_key(key_id)
        def sample(*args, **kwargs):
            restore_threads.append(threading.get_ident())
            return restore(*args, **kwargs)
        with patch.object(self.host, 'load_key', side_effect=key_read), patch.object(
                backup_lifecycle, 'restore_backup', side_effect=sample):
            first = await service.run_due()
            self.assertEqual(first, self.host.latest())
            self.assertEqual(len(restore_threads), 1)
            first_files = set(self.host.backup_directory.iterdir())
            self.now = 1300.0
            self.assertEqual(await service.run_due(), first)
            self.assertEqual(set(self.host.backup_directory.iterdir()), first_files)
            self.now = 4600.0
            second = await service.run_due()
            self.assertNotEqual(first.receipt.manifest_name, second.receipt.manifest_name)
            self.assertEqual(len(restore_threads), 1)
            self.now = 87400.0
            latest = await service.run_due()
            self.assertEqual(latest.completed_at, self.now)
            self.assertEqual(len(restore_threads), 2)
        # The explicit test read above is on this thread; lifecycle I/O is not.
        self.assertTrue(any(thread != owner_thread for thread in key_threads))
        self.assertTrue(all(thread != owner_thread for thread in restore_threads))
        self.assertEqual(self.history.verified_cursor, 2)
        self.assertEqual(latest.source_identity.minimum_sequence, 2)

    async def test_restart_uses_inventory_and_resamples_without_early_export(self):
        from state_owner.backup import restore_backup
        first = self.service()
        entry = await first.run_due()
        await first.close()
        self.now += 100
        replacement = self.service()
        with patch('state_owner.backup_lifecycle.restore_backup', wraps=restore_backup) as sample:
            await replacement.start()
            self.assertEqual(self.host.latest(), entry)
            self.assertEqual(sample.call_count, 1)
        await replacement.close()
        self.assertTrue(replacement._loop_task.done())

    async def test_timer_failure_reaches_owner_health_and_shutdown(self):
        service = self.service()
        with patch('state_owner.backup_lifecycle.POLL_SECONDS', .001):
            await service.start()
            self.now += 3600
            with patch.object(self.host, 'commit', side_effect=OSError('private destination')):
                with self.assertRaisesRegex(ContractError, '^owner_backup_host_unavailable$'):
                    await asyncio.wait_for(asyncio.shield(service._loop_task), 2)
            with self.assertRaisesRegex(ContractError, '^owner_backup_host_unavailable$'):
                service.check()
            with self.assertRaises(ContractError):
                await service.close()
        self.assertTrue(service._loop_task.done())

    async def test_restart_sample_detects_missing_artifact_bytes_in_recent_bundle(self):
        first = self.service()
        entry = await first.run_due()
        await first.close()
        encrypted = (self.host.backup_directory / entry.receipt.manifest_name).read_bytes()
        manifest = strict_loads(SecretBox(self.host.load_key(entry.key_id)).decrypt(encrypted))
        artifact = next(part for part in manifest['components'] if part['kind'] == 'artifact')
        (self.host.backup_directory / artifact['name']).unlink()
        self.now += 100
        replacement = self.service()
        with self.assertRaisesRegex(ContractError, '^owner_backup_restore_failed$'):
            await replacement.start()
        with self.assertRaisesRegex(ContractError, '^owner_backup_restore_failed$'):
            replacement.check()
        with self.assertRaises(ContractError):
            await replacement.close()
        self.assertEqual(self.host.latest(), entry)

    async def test_missing_key_never_creates_one(self):
        service = self.service(key_id='not-enrolled')
        with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
            await service.start()
        with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
            service.check()
        with self.assertRaises(ContractError):
            await service.close()
        self.assertIsNone(self.host.latest())
        self.assertFalse((self.root / 'keys' / 'key-not-enrolled.key').exists())

    async def test_empty_owner_still_requires_enrolled_key_at_startup(self):
        empty = OwnerHistory(self.root / 'empty.sqlite', self.binding, stream_identity=self.identity)
        self.addCleanup(empty.close)
        service = OwnerBackupLifecycle(empty, self.binding, self.identity, self.host,
            key_id='not-enrolled', retrieve_artifact=self.artifacts.retrieve, clock=lambda: self.now)
        self.services.append(service)
        with self.assertRaisesRegex(ContractError, '^backup_key_unavailable$'):
            await service.start()
        with self.assertRaises(ContractError):
            await service.close()
        self.assertEqual(empty.verified_cursor, 0)
        self.assertIsNone(self.host.latest())

    async def test_stronger_trusted_floor_forces_backup_before_hourly_deadline(self):
        from state_owner.backup import export_backup
        prefix = OwnerHistory(self.root / 'prefix.sqlite', self.binding, stream_identity=self.identity)
        self.addCleanup(prefix.close)
        prefix.verify_source(self.history.record(1))
        receipt = await export_backup(self.host.backup_directory, prefix, self.binding, self.identity,
            key=self.host.load_key('backup-one'), retrieve_artifact=self.artifacts.retrieve)
        self.host.commit(receipt, key_id='backup-one', completed_at=self.now)
        stronger = StreamIdentity(self.identity.created, 2)
        service = OwnerBackupLifecycle(self.history, self.binding, stronger, self.host,
            key_id='backup-one', retrieve_artifact=self.artifacts.retrieve, clock=lambda: self.now)
        self.services.append(service)
        self.now += 1
        latest = await service.run_due()
        self.assertEqual(latest.receipt.cursor, 2)
        self.assertNotEqual(latest.receipt.manifest_name, receipt.manifest_name)

    async def test_inventory_watermark_refuses_rolled_back_and_empty_live_owners(self):
        original = self.service()
        retained = await original.run_due()
        await original.close()
        original_files = set(self.host.backup_directory.iterdir())
        for cursor in (0, 1):
            weaker = OwnerHistory(self.root / f'rollback-{cursor}.sqlite', self.binding,
                                  stream_identity=self.identity)
            self.addCleanup(weaker.close)
            if cursor:
                weaker.verify_source(self.history.record(1))
            service = OwnerBackupLifecycle(weaker, self.binding, self.identity, self.host,
                key_id='backup-one', retrieve_artifact=self.artifacts.retrieve, clock=lambda: self.now)
            self.services.append(service)
            identity = await service.recovery_identity()
            self.assertEqual(identity.minimum_sequence, 2)
            with patch('state_owner.backup_lifecycle.export_backup') as export, patch(
                    'state_owner.backup_lifecycle.restore_backup') as sample:
                with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
                    await service.start()
                with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
                    service.check()
                self.assertIsNone(service._loop_task)
                self.now += 3600
                with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
                    await service.run_due()
                export.assert_not_called()
                sample.assert_not_called()
            with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
                await service.close()
            self.assertEqual(self.host.latest(), retained)
            self.assertEqual(set(self.host.backup_directory.iterdir()), original_files)

    async def test_observed_inventory_floor_survives_later_weaker_inventory_lookup(self):
        service = self.service()
        entry = await service.run_due()
        self.assertEqual((await service.recovery_identity()).minimum_sequence, 2)
        with patch.object(self.host, 'latest', return_value=None):
            self.assertEqual((await service.recovery_identity()).minimum_sequence, 2)
        self.assertEqual(self.host.latest(), entry)

    async def test_newer_inventory_during_export_is_checked_before_sampling(self):
        from state_owner.backup import export_backup
        previous = self.service()
        older = await previous.run_due()
        await previous.close()
        higher = OwnerHistory(self.root / 'higher.sqlite', self.binding, stream_identity=self.identity)
        self.addCleanup(higher.close)
        for item in self.history.records(2):
            higher.verify_source(item)
        value = strict_loads(self.history.record(2).record)
        value.update(entityVersion=3, previousRevision=2, recordId='record-higher')
        value['operation']['operationId'] = 'operation-higher'
        value['operation']['expectedVersion'] = 2
        higher.verify_source(StoredRecord(canonical_bytes(value), 3))
        receipt = await export_backup(self.host.backup_directory, higher, self.binding, self.identity,
            key=self.host.load_key('backup-one'), retrieve_artifact=self.artifacts.retrieve)
        newest = self.host.commit(receipt, key_id='backup-one', completed_at=self.now)
        latest = self.host.latest
        calls = 0
        def before_and_after_publication():
            nonlocal calls
            calls += 1
            return older if calls == 1 else latest()
        service = self.service()
        self.now += 3600
        with patch.object(self.host, 'latest', side_effect=before_and_after_publication), patch(
                'state_owner.backup_lifecycle.restore_backup') as sample:
            with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
                await service.run_due()
            sample.assert_not_called()
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            service.check()
        self.assertEqual((await service.recovery_identity()).minimum_sequence, 3)
        self.assertEqual(self.host.latest(), newest)

    async def test_inventory_failure_is_reported_and_never_marks_a_backup_complete(self):
        service = self.service()
        with patch.object(self.host, 'commit', side_effect=OSError('private path')):
            with self.assertRaisesRegex(ContractError, '^owner_backup_host_unavailable$'):
                await service.start()
        with self.assertRaisesRegex(ContractError, '^owner_backup_host_unavailable$'):
            service.check()
        with self.assertRaises(ContractError):
            await service.close()
        self.assertIsNone(self.host.latest())
        self.assertIsNone(service._last_sample)

    async def test_close_joins_original_start_and_reader_before_shared_cache_closure(self):
        entered, release, reader_done = (asyncio.Event() for _ in range(3))
        async def read(reference):
            entered.set()
            try:
                await release.wait()
                return await self.artifacts.retrieve(reference)
            finally:
                reader_done.set()
        service = self.service(retrieve_artifact=read)
        starting = asyncio.create_task(service.start())
        closing = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            closing = asyncio.create_task(service.close())
            await asyncio.sleep(0)
            closing.cancel()
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            self.assertFalse(service._startup.done())
            self.assertEqual(self.history.verified_cursor, 2)
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await closing
            with self.assertRaisesRegex(ContractError, '^owner_backup_lifecycle_closed$'):
                await starting
            self.assertTrue(reader_done.is_set())
            self.assertTrue(service._closing.done())
            self.assertEqual(self.history.verified_cursor, 2)
        finally:
            release.set()
            await asyncio.gather(*(task for task in (starting, closing) if task is not None),
                                 return_exceptions=True)

    async def test_selected_key_rotation_forces_a_new_generation(self):
        first = self.service()
        entry = await first.run_due()
        await first.close()
        self.host.enroll_key('backup-two')
        replacement = self.service(key_id='backup-two')
        rotated = await replacement.run_due()
        self.assertEqual(rotated.key_id, 'backup-two')
        self.assertNotEqual(entry.receipt.manifest_name, rotated.receipt.manifest_name)
        self.assertEqual(len(self.host.load_key('backup-one')), 32)

    async def test_wall_clock_rollback_refuses_to_hide_an_overdue_backup(self):
        service = self.service()
        await service.run_due()
        self.now -= 1
        with self.assertRaisesRegex(ContractError, '^owner_backup_clock_invalid$'):
            await service.run_due()

    async def test_wall_clock_rollback_after_inventory_commit_refuses_sample_success(self):
        service = self.service()
        commit = self.host.commit
        def clock_rollback(*args, **kwargs):
            entry = commit(*args, **kwargs)
            self.now -= 1
            return entry
        with patch.object(self.host, 'commit', side_effect=clock_rollback):
            with self.assertRaisesRegex(ContractError, '^owner_backup_clock_invalid$'):
                await service.run_due()
        self.assertIsNotNone(self.host.latest())
        self.assertIsNone(service._last_sample)
