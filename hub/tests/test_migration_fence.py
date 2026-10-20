"""STATE-01 legacy writer fence checks on disposable hub databases."""
import asyncio
import concurrent.futures
import os
from pathlib import Path
import sqlite3
import shutil
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from types import SimpleNamespace

from agentmux_contracts import canonical_bytes, payload_digest, sign_claims
from hub.fed.runtime import Federation
from hub.migration_recovery import LegacyWriterRecoveryGuard
from hub.authority_switch_recovery_client import EnrolledAuthoritySwitchRecovery
from hub.server import Hub
from hub.store import APP_ID, MIGRATIONS, HubError, Store
from identity.test_authority import fixture, ref, SEED, NOW
from identity.test_service import ServiceTests as _IdentityServiceTests, _Clock
from state_owner.authority_switch import (AuthoritySwitchHost, AuthoritySwitchOwner,
    authority_switch_id)
from state_owner.authority_switch_service import VerifiedEnrolledRecovery
from state_owner.ledger import StoredRecord
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import CREATED, FakeJetStream


SOURCE_REF = {'id': 'legacy-source', 'ownerHubId': 'hub-one', 'revision': 1}


class DurableWriterFenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='agentmux-fence-')
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(os.path.realpath(self.directory.name), 'hub.db')
        self.store = Store(self.path)
        self.addCleanup(lambda: self.store.db.close())
        self.store.repo_add('alpha')

    def test_fence_keeps_reads_refuses_writes_and_survives_restart(self):
        fence = self.store.fence_legacy_writer()
        self.assertEqual(self.store.status()['repos'], ['alpha'])
        with self.assertRaisesRegex(HubError, '^legacy writer is fenced for migration$'):
            self.store.repo_add('beta')
        with self.assertRaisesRegex(HubError, '^legacy writer is fenced for migration$'):
            self.store.event('migration', 'source', 'unexpected-write')
        self.store.db.close()
        self.store = Store(self.path)
        self.assertEqual(self.store.migration_fence_status(), fence)
        with self.assertRaisesRegex(HubError, '^legacy writer is fenced for migration$'):
            self.store.team_add('alpha', 'blocked')
        with self.assertRaisesRegex(HubError, '^legacy writer is fenced for migration$'):
            self.store.post('virtual:operator', 'virtual:operator', 'note', 'blocked')
        with self.assertRaisesRegex(HubError, '^legacy writer is fenced for migration$'):
            self.store.work_create('virtual:operator', 'alpha', 'role:alpha/worker', 'blocked')
        with self.assertRaisesRegex(HubError, '^legacy migration recovery refused$'):
            self.store.recover_legacy_writer('f'+'0'*32)
        recovered = self.store.recover_legacy_writer(fence['fenceId'])
        self.assertEqual((recovered['state'], recovered['generation']), ('open', 1))
        self.store.repo_add('beta')
        next_fence = self.store.fence_legacy_writer()
        self.assertEqual(next_fence['generation'], 2)
        self.assertNotEqual(next_fence['fenceId'], fence['fenceId'])

    def test_fenced_restart_reuses_existing_plugin_tables_without_creating_missing_ones(self):
        sql = 'CREATE TABLE IF NOT EXISTS p_example_items (id TEXT PRIMARY KEY) STRICT'
        self.store.db.execute(sql)
        self.store.fence_legacy_writer()
        runtime = Federation.__new__(Federation)
        runtime.hub = SimpleNamespace(store=self.store)
        runtime.plugin_adapters = {'example': SimpleNamespace(
            name='example', tables=(sql,))}
        runtime._init_db()
        runtime.plugin_adapters['example'] = SimpleNamespace(name='example', tables=(
            'CREATE TABLE IF NOT EXISTS p_example_missing (id TEXT PRIMARY KEY) STRICT',))
        with self.assertRaisesRegex(HubError,
                '^fenced legacy database is missing a required plugin table$'):
            runtime._init_db()


class SerializedCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='agentmux-fence-capture-')
        self.addCleanup(self.directory.cleanup)
        self.hub = Hub.__new__(Hub)
        self.hub.dbx = concurrent.futures.ThreadPoolExecutor(max_workers=1,
            thread_name_prefix='hubdb-fence-test')
        self.hub.store = await asyncio.get_running_loop().run_in_executor(
            self.hub.dbx, Store, os.path.join(os.path.realpath(self.directory.name), 'hub.db'))
        self.addAsyncCleanup(self.cleanup)
        await self.hub.db(self.hub.store.repo_add, 'alpha')
        self.capture_root = os.path.join(os.path.realpath(self.directory.name), 'hub')
        self.context = patch('hub.server.HUBDIR', self.capture_root)
        self.context.start()
        self.addCleanup(self.context.stop)

    async def cleanup(self):
        await self.hub.db(self.hub.store.db.close)
        self.hub.dbx.shutdown(wait=True)

    async def test_unchanged_capture_fences_then_replays_same_fence(self):
        baseline = await self.hub.capture_legacy_migration_baseline(
            source_ref=SOURCE_REF, application_version='test')
        result = await self.hub.fence_legacy_writer_and_capture(source_ref=SOURCE_REF,
            application_version='test',
            expected_digest=baseline['inventory']['comparisonDigest'])
        self.assertEqual(result['capture']['inventory']['comparisonDigest'],
            baseline['inventory']['comparisonDigest'])
        self.assertTrue(Path(baseline['path']).is_file())
        self.assertTrue(Path(result['capture']['path']).is_file())
        await self.hub.db(self.hub.store.checkpoint)
        repeated = await self.hub.fence_legacy_writer_and_capture(source_ref=SOURCE_REF,
            application_version='test',
            expected_digest=baseline['inventory']['comparisonDigest'])
        self.assertEqual(repeated['fence'], result['fence'])
        with self.assertRaisesRegex(HubError, '^legacy writer is fenced for migration$'):
            await self.hub.db(self.hub.store.repo_add, 'late')

    async def test_invalid_comparison_digest_does_not_fence(self):
        with self.assertRaisesRegex(HubError,
                '^legacy migration comparison digest is invalid$'):
            await self.hub.fence_legacy_writer_and_capture(source_ref=SOURCE_REF,
                application_version='test', expected_digest='wrong')
        self.assertIsNone(await self.hub.legacy_writer_fence_status())

    async def test_comparison_digest_binds_source_and_application_version(self):
        baseline = await self.hub.capture_legacy_migration_baseline(
            source_ref=SOURCE_REF, application_version='test')
        for source_ref, application_version in (
                ({**SOURCE_REF, 'id': 'other-source'}, 'test'),
                (SOURCE_REF, 'other-version')):
            with self.subTest(source_ref=source_ref, application_version=application_version):
                with self.assertRaisesRegex(HubError,
                        '^legacy source changed before migration fence$'):
                    await self.hub.fence_legacy_writer_and_capture(source_ref=source_ref,
                        application_version=application_version,
                        expected_digest=baseline['inventory']['comparisonDigest'])
                fence = await self.hub.legacy_writer_fence_status()
                await self.hub.recover_legacy_writer(fence['fenceId'])

    async def test_non_fence_fed_state_row_remains_in_comparison(self):
        with self.hub.store.tx():
            self.hub.store.db.execute("INSERT INTO fed_state(k,v) VALUES (?,?)",
                ('application-marker', 'migration.legacy-writer-fence'))
        baseline = await self.hub.capture_legacy_migration_baseline(
            source_ref=SOURCE_REF, application_version='test')
        with self.hub.store.tx():
            self.hub.store.db.execute("UPDATE fed_state SET v='changed' WHERE k='application-marker'")
        with self.assertRaisesRegex(HubError,
                '^legacy source changed before migration fence$'):
            await self.hub.fence_legacy_writer_and_capture(source_ref=SOURCE_REF,
                application_version='test',
                expected_digest=baseline['inventory']['comparisonDigest'])
        fence = await self.hub.legacy_writer_fence_status()
        await self.hub.recover_legacy_writer(fence['fenceId'])

    async def test_migration_control_verbs_require_operator(self):
        with self.assertRaisesRegex(HubError, '^operator-only verb;'):
            await self.hub.dispatch('migration_status', {}, 'alpha-worker-one')

    async def test_inflight_write_completes_but_queued_write_is_refused_after_fence(self):
        baseline = await self.hub.capture_legacy_migration_baseline(
            source_ref=SOURCE_REF, application_version='test')
        started, release = threading.Event(), threading.Event()

        def in_flight():
            with self.hub.store.tx():
                self.hub.store.db.execute(
                    "INSERT INTO repo_aliases(alias,repo) VALUES ('before-fence','alpha')")
                started.set()
                release.wait(5)

        running = asyncio.create_task(self.hub.db(in_flight))
        self.assertTrue(await asyncio.to_thread(started.wait, 2))
        fencing = asyncio.create_task(self.hub.fence_legacy_writer_and_capture(
            source_ref=SOURCE_REF, application_version='test',
            expected_digest=baseline['inventory']['comparisonDigest']))
        await asyncio.sleep(0)
        queued = asyncio.create_task(self.hub.db(self.hub.store.repo_add, 'after_fence'))
        release.set()
        await running
        with self.assertRaisesRegex(HubError,
                '^legacy source changed before migration fence$'):
            await fencing
        with self.assertRaisesRegex(HubError, '^legacy writer is fenced for migration$'):
            await queued
        self.assertEqual(self.hub.store.q('SELECT alias FROM repo_aliases'),
            [{'alias': 'before-fence'}])
        self.assertIsNone(self.hub.store.q1("SELECT 1 FROM repos WHERE repo='after_fence'"))
        fence = await self.hub.legacy_writer_fence_status()
        await self.hub.recover_legacy_writer(fence['fenceId'])
        await self.hub.db(self.hub.store.repo_add, 'after_recovery')


class RetainedAuthorityRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _IdentityServiceTests.setUp(self)
        patch('state_owner.authority_switch.datetime', _Clock).start()
        patch('hub.migration_recovery.datetime', _Clock).start()
        self.directory = tempfile.TemporaryDirectory(prefix='agentmux-retained-fence-')
        self.addCleanup(self.directory.cleanup)
        self.hubs = []

    async def asyncTearDown(self):
        for hub in reversed(self.hubs):
            await self.close_hub(hub)

    async def close_hub(self, hub):
        await hub.db(hub.store.db.close)
        hub.dbx.shutdown(wait=True)

    def envelope(self, action, *, expected):
        _, envelope = fixture()
        payload = {'action': action, 'switchId': self.switch_id,
            'source': self.source}
        envelope.update(contractId='authority-switch',
            destinationServiceId='authority-switch-owner', payload=payload)
        envelope['operation'].update(operationId=action.replace('-', '_'),
            expectedVersion=expected, scope=self.scope, grantRef=ref('grant'),
            taskId=None, runId=None, attemptId=None, delegationRef=None,
            payloadDigest=payload_digest(payload))
        claims = envelope['ingressAttestation']['claims']
        claims.update(contractId='authority-switch',
            operation=envelope['operation'],
            audience={'hubId': 'hub-one', 'serviceId': 'authority-switch-owner'})
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(envelope)

    async def configured(self, *, target_open=False, restored_old=False):
        root = Path(self.directory.name).resolve()
        path = root / ('hub-'+str(len(self.hubs))+'.db')
        old_path = root / ('old-'+str(len(self.hubs))+'.db')
        store = Store(str(path))
        store.repo_add('alpha')
        if restored_old:
            store.backup(str(old_path))
        fence = store.fence_legacy_writer()
        self.scope = {'organizationId': 'org-one', 'projectId': None,
            'workspaceId': None}
        self.source = {'sourceRef': SOURCE_REF, 'applicationVersion': 'test',
            'comparisonDigest': 'sha256:'+'a'*64, 'fenceId': fence['fenceId'],
            'fenceGeneration': fence['generation']}
        self.switch_id = authority_switch_id(self.source)
        self.record['state']['memberships'][0]['scope'] = self.scope
        self.record['state']['grants'][0].update(scope=self.scope,
            contractId='authority-switch', resourceId=self.switch_id,
            status='active')
        self.js.messages[0].data = canonical_bytes(self.record)
        binding = OwnerBinding('hub-one', 'authority-switch', self.switch_id,
            'authority-switch', canonical_bytes(self.scope))
        switch_js = FakeJetStream(self.policy)
        switch_js.config.subjects = [owner_subject(binding)]
        switch_js.messages = []
        ledger = OwnerLedger(switch_js, stream='OWNER', subject=owner_subject(binding),
            binding=binding, retention=self.policy,
            stream_identity=StreamIdentity(CREATED, 0))
        owner = AuthoritySwitchOwner(self.service.reader, ledger)
        await owner.handle(self.envelope('record-source-fence', expected=0))
        permit = None
        if target_open:
            await owner.handle(self.envelope('open-target-admission', expected=1))
        else:
            permit = await owner.handle(self.envelope('request-recovery', expected=1))
        store.db.close()
        guard = LegacyWriterRecoveryGuard(owner, source=self.source,
            switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2))
        guarded = Store(str(old_path if restored_old else path),
            migration_recovery=guard)
        hub = Hub.__new__(Hub)
        hub.dbx = concurrent.futures.ThreadPoolExecutor(max_workers=1,
            thread_name_prefix='hubdb-retained-fence-test')
        hub.store = guarded
        hub._authority_switch_recovery = guard
        self.hubs.append(hub)
        return hub, permit, switch_js

    async def test_authorized_pre_cutover_recovery_uses_owner_permit(self):
        hub, permit, _ = await self.configured()
        with self.assertRaisesRegex(HubError, '^legacy migration recovery refused$'):
            await hub.db(hub.store.recover_legacy_writer, self.source['fenceId'])
        recovered = await hub.recover_legacy_writer(self.source['fenceId'], permit)
        self.assertEqual(recovered['state'], 'open')
        await hub.db(hub.store.repo_add, 'after_recovery')

    async def test_retained_selection_guard_closes_writer_without_owner_credentials(self):
        hub, _, switch_js = await self.configured(target_open=True)
        path = hub.store.path
        await self.close_hub(hub)
        self.hubs.remove(hub)
        binding = OwnerBinding('hub-one', 'authority-switch', self.switch_id,
            'authority-switch', canonical_bytes(self.scope))
        custody = (Path(self.directory.name) / 'switch-custody').resolve()
        custody.mkdir(mode=0o700)
        host = AuthoritySwitchHost(custody, binding=binding,
            stream_identity=StreamIdentity(CREATED, 0))
        for sequence, message in enumerate(switch_js.messages, 1):
            host.observe(StoredRecord(message.data, sequence))
        guard = LegacyWriterRecoveryGuard.closed(source=self.source,
            switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2),
            host=host)
        store = Store(path, migration_recovery=guard)
        try:
            os.chmod(path, 0o600)
            for suffix in ('-wal', '-shm', '-journal'):
                if os.path.exists(path + suffix):
                    os.chmod(path + suffix, 0o600)
            joined_guard = LegacyWriterRecoveryGuard.closed(source=self.source,
                switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2),
                host=host)
            joined = Store.open_existing(path, application_id=APP_ID,
                user_version=len(MIGRATIONS), owner_uid=os.getuid(),
                migration_recovery=joined_guard)
            joined.db.close()
            with self.assertRaisesRegex(HubError, '^legacy migration authority unavailable$'):
                Store(path)
            with self.assertRaisesRegex(HubError, '^legacy migration authority unavailable$'):
                store.repo_add('refused')
            with self.assertRaisesRegex(HubError, '^legacy migration recovery refused$'):
                await guard.authorize(store, store.migration_fence_status(),
                    self.source['fenceId'], object())
        finally:
            store.db.close()
        anchors = list(Path(path).parent.glob('.agentmux-authority-switch-*.json'))
        self.assertEqual(len(anchors), 1)
        self.assertEqual(anchors[0].stat().st_mode & 0o777, 0o600)
        competing = str((Path(self.directory.name) / 'competing.db').resolve())
        shutil.copy2(path, competing)
        ordinary = Store(competing)
        competing_guard = LegacyWriterRecoveryGuard.closed(source=self.source,
            switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2),
            host=host)
        try:
            with self.assertRaisesRegex(HubError,
                    '^legacy migration authority unavailable$'):
                Store(competing, migration_recovery=competing_guard)
        finally:
            ordinary.db.close()
        previous_umask = os.umask(0o777)
        try:
            activated = Store(competing, migration_recovery=competing_guard)
        finally:
            os.umask(previous_umask)
        activated.db.close()
        competing_anchors = list(Path(competing).parent.glob(
            '.agentmux-authority-switch-*.json'))
        self.assertEqual(len(competing_anchors), 2)
        self.assertTrue(all(anchor.stat().st_mode & 0o777 == 0o600
                            for anchor in competing_anchors))
        with patch.dict(os.environ, {'AGENTMUX_HOME': str(Path(self.directory.name) / 'other-home')}), \
                self.assertRaisesRegex(HubError, '^legacy migration authority unavailable$'):
            Store(path)
        moved = str(Path(self.directory.name) / 'moved.db')
        shutil.copy2(path, moved)
        os.replace(path, path + '.original')
        os.symlink(moved, path)
        with self.assertRaisesRegex(HubError, '^legacy migration authority unavailable$'):
            Store(path)

    async def test_token_expiry_at_transaction_commit_rolls_back_fence_open(self):
        hub, permit, _ = await self.configured()
        path = hub.store.path
        owner = hub._authority_switch_recovery._owner
        await self.close_hub(hub)
        self.hubs.remove(hub)
        guard = LegacyWriterRecoveryGuard(owner, source=self.source,
            switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2))
        os.chmod(path, 0o600)
        for suffix in ('-wal', '-shm', '-journal'):
            if os.path.exists(path+suffix):
                os.chmod(path+suffix, 0o600)
        hub = Hub.__new__(Hub)
        hub.dbx = concurrent.futures.ThreadPoolExecutor(max_workers=1,
            thread_name_prefix='hubdb-retained-fence-expiry-test')
        hub.store = Store.open_existing(path, application_id=APP_ID,
            user_version=len(MIGRATIONS), owner_uid=os.getuid(),
            migration_recovery=guard)
        hub._authority_switch_recovery = guard
        self.hubs.append(hub)
        custody = hub.store._selected_custody
        held = len(custody.rows)
        fence = await hub.db(hub.store.migration_fence_status)
        token = await guard.authorize(hub.store, fence,
            self.source['fenceId'], permit)
        with patch.object(guard, '_allows_recovery', side_effect=(True, True, False)):
            with self.assertRaisesRegex(HubError,
                    '^legacy migration recovery refused$'):
                await hub.db(hub.store.recover_legacy_writer,
                    self.source['fenceId'], token)
        self.assertEqual((await hub.db(hub.store.migration_fence_status))['state'],
            'fenced')
        self.assertTrue(await hub.db(hub.store.migration_authority_closed))
        self.assertGreaterEqual(len(custody.rows), held)
        await hub.db(hub.store.check_existing)

    async def test_enrolled_recovery_retries_after_expired_local_use_on_guarded_store(self):
        hub, _, switch_js = await self.configured()
        path = hub.store.path
        await self.close_hub(hub)
        self.hubs.remove(hub)
        binding = OwnerBinding('hub-one', 'authority-switch', self.switch_id,
            'authority-switch', canonical_bytes(self.scope))
        custody = (Path(self.directory.name) / 'retry-custody').resolve()
        custody.mkdir(mode=0o700)
        host = AuthoritySwitchHost(custody, binding=binding,
            stream_identity=StreamIdentity(CREATED, 0))
        for sequence, message in enumerate(switch_js.messages, 1):
            host.observe(StoredRecord(message.data, sequence))
        closed = LegacyWriterRecoveryGuard.closed(source=self.source,
            switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2),
            host=host)
        caller = object.__new__(EnrolledAuthoritySwitchRecovery)
        caller._public = canonical_bytes({'switchId': self.switch_id,
            'source': self.source,
            'streamIdentity': {'created': CREATED.isoformat().replace('+00:00', 'Z'),
                               'minimumSequence': 2},
            'custodyDirectory': str(custody)})
        guard = closed.with_enrolled_recovery(caller)
        os.chmod(path, 0o600)
        for suffix in ('-wal', '-shm', '-journal'):
            if os.path.exists(path + suffix):
                os.chmod(path + suffix, 0o600)
        store = Store.open_existing(path, application_id=APP_ID,
            user_version=len(MIGRATIONS), owner_uid=os.getuid(),
            migration_recovery=guard)
        try:
            class RetryClock(_Clock):
                current = NOW

                @classmethod
                def now(cls, tz=None):
                    return cls.current

            def authorization(seconds):
                value = object.__new__(VerifiedEnrolledRecovery)
                object.__setattr__(value, '_valid_until',
                    RetryClock.current + timedelta(seconds=seconds))
                return value
            first, second = authorization(.02), authorization(5)
            with (patch('hub.migration_recovery.datetime', RetryClock),
                    patch.object(EnrolledAuthoritySwitchRecovery, 'authorize',
                        side_effect=(first, second))):
                fence = store.migration_fence_status()
                expired = await guard.authorize(store, fence, self.source['fenceId'])
                RetryClock.current = NOW + timedelta(seconds=1)
                with self.assertRaisesRegex(HubError,
                        '^legacy migration recovery refused$'):
                    store.recover_legacy_writer(self.source['fenceId'], expired)
                self.assertEqual(store.migration_fence_status()['state'], 'fenced')
                fresh = await guard.authorize(store, fence, self.source['fenceId'])
                self.assertEqual(store.recover_legacy_writer(
                    self.source['fenceId'], fresh)['state'], 'open')
        finally:
            store.db.close()

    async def test_successful_recovery_reconciles_exact_open_row_after_restart(self):
        hub, permit, _ = await self.configured()
        path = hub.store.path
        owner = hub._authority_switch_recovery._owner
        await hub.recover_legacy_writer(self.source['fenceId'], permit)
        await self.close_hub(hub)
        self.hubs.remove(hub)

        guard = LegacyWriterRecoveryGuard(owner, source=self.source,
            switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2))
        restarted = Hub.__new__(Hub)
        restarted.dbx = concurrent.futures.ThreadPoolExecutor(max_workers=1,
            thread_name_prefix='hubdb-retained-fence-restart-test')
        os.chmod(path, 0o600)
        for suffix in ('-wal', '-shm', '-journal'):
            if os.path.exists(path+suffix):
                os.chmod(path+suffix, 0o600)
        restarted.store = Store.open_existing(path, application_id=APP_ID,
            user_version=len(MIGRATIONS), owner_uid=os.getuid(),
            migration_recovery=guard)
        restarted._authority_switch_recovery = guard
        self.hubs.append(restarted)
        custody = restarted.store._selected_custody
        held = len(custody.rows)
        self.assertGreater(held, 1)
        self.assertTrue(await restarted.db(
            restarted.store.migration_authority_closed))
        replayed = await owner.handle(self.envelope('request-recovery', expected=1))
        recovered = await restarted.recover_legacy_writer(
            self.source['fenceId'], replayed)
        self.assertEqual(recovered['state'], 'open')
        await restarted.db(restarted.store.repo_add, 'after_restart')
        self.assertGreaterEqual(len(custody.rows), held)
        await restarted.db(restarted.store.check_existing)
        original = path+'.original'
        os.rename(path, original)
        shutil.copyfile(original, path)
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(HubError,
                '^selected hub database is unavailable$'):
            await restarted.db(restarted.store.check_existing)

    async def test_configured_startup_refuses_old_schema_without_migrating_it(self):
        hub, _permit, _ = await self.configured(target_open=True)
        path = hub.store.path
        owner = hub._authority_switch_recovery._owner
        await self.close_hub(hub)
        self.hubs.remove(hub)
        connection = sqlite3.connect(path)
        current = connection.execute('PRAGMA user_version').fetchone()[0]
        connection.execute(f'PRAGMA user_version = {current-1}')
        connection.close()
        guard = LegacyWriterRecoveryGuard(owner, source=self.source,
            switch_id=self.switch_id, stream_identity=StreamIdentity(CREATED, 2))
        with self.assertRaisesRegex(HubError,
                '^configured legacy database requires reconciliation$'):
            Store(path, migration_recovery=guard)
        connection = sqlite3.connect(Path(path).as_uri()+'?mode=ro', uri=True)
        try:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0],
                current-1)
        finally:
            connection.close()

    async def test_revoked_stale_and_missing_retained_authority_fail_closed(self):
        for failure in ('revoked', 'stale', 'missing'):
            with self.subTest(failure=failure):
                hub, permit, switch_js = await self.configured()
                if failure == 'revoked':
                    self.record['state']['grants'][0]['status'] = 'revoked'
                    self.js.messages[0].data = canonical_bytes(self.record)
                elif failure == 'missing':
                    switch_js.messages = []
                clock = _Clock
                if failure == 'stale':
                    class ExpiredClock(_Clock):
                        @classmethod
                        def now(cls, tz=None):
                            from datetime import timedelta
                            return NOW+timedelta(minutes=20)
                    clock = ExpiredClock
                with patch('hub.migration_recovery.datetime', clock):
                    with self.assertRaisesRegex(HubError,
                            '^legacy migration recovery refused$'):
                        await hub.recover_legacy_writer(self.source['fenceId'], permit)
                with self.assertRaisesRegex(HubError,
                        '^legacy migration authority unavailable$'):
                    await hub.db(hub.store.repo_add, 'blocked_'+failure)

    async def test_restored_database_without_local_fence_stays_closed_after_target_open(self):
        hub, permit, _ = await self.configured(target_open=True, restored_old=True)
        self.assertIsNone(await hub.db(hub.store.migration_fence_status))
        self.assertIsNone(permit)
        with self.assertRaisesRegex(HubError,
                '^legacy migration authority unavailable$'):
            await hub.db(hub.store.repo_add, 'bypass')
        runtime = Federation.__new__(Federation)
        runtime.hub = hub
        runtime.plugin_adapters = {'example': SimpleNamespace(name='example', tables=(
            'CREATE TABLE IF NOT EXISTS p_example_missing (id TEXT PRIMARY KEY) STRICT',))}
        with self.assertRaisesRegex(HubError,
                '^fenced legacy database is missing a required plugin table$'):
            runtime._init_db()
        self.assertIsNone(await hub.db(hub.store.q1,
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='p_example_missing'"))
        with self.assertRaisesRegex(HubError, '^legacy migration recovery refused$'):
            await hub.recover_legacy_writer(self.source['fenceId'], permit)


if __name__ == '__main__':
    unittest.main()
