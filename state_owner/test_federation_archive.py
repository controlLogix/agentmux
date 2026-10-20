"""Exact legacy federation evidence and current-authority import boundaries."""
import copy
from datetime import timedelta
import hashlib
import sqlite3
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads, validate
from hub.fed import ledger as legacy
from identity import test_service as identity_support
from identity.test_authority import NOW, SEED, ref
from identity.test_service import _Clock
from state_owner.federation_archive import (TABLES, FederationArchiveImporter,
    FederationArchiveSource, federation_archive_identity, prepare_federation_import,
    validate_federation_archive)
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import CREATED, FakeJetStream
from state_owner import test_task_migration as migration_support


SCOPE = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}


def populate(store):
    """Use the existing legacy operations, including all unresolved states."""
    store.db.execute('DELETE FROM fed_outbox')
    store.db.execute('DELETE FROM fed_seen')
    for name in ('withdrawn', 'sent', 'failed', 'pending'):
        legacy.outbox_add(store, name, 'am.msg', {'id': name, 'body': 'Original\nbody', 'null': None})
        seq = store.q1('SELECT seq FROM fed_outbox WHERE msg_id=?', (name,))['seq']
        if name == 'withdrawn':
            legacy.outbox_withdraw(store)
        elif name == 'sent':
            legacy.outbox_sent(store, seq)
        elif name == 'failed':
            legacy.outbox_failed(store, seq, 'Delivery unresolved')
    legacy.mark_seen(store, 'SEEN-old')
    legacy.mark_seen(store, 'seen-new')
    legacy.audit(store, 'in', 'work', 'old-peer', 'raw-rid', 'am.work.v3', 'original-envelope',
        b'{ "original": true }', 'held', {'reason': 'Needs current approval'})
    legacy.audit(store, 'local', 'control', None, None, None, None, b'opaque original', 'recorded')
    for decision in ('held', 'approved', 'denied'):
        qid = legacy.quarantine_add(store, {'id': 'env-'+decision, 'grant_id': 'historical-grant',
            'data': {'body': 'Original source'}}, 'am.work.v3', 'work', 'old-peer', 'Policy required')
        if decision != 'held':
            legacy.quarantine_decide(store, qid, decision, 'historical-actor')
    legacy.state_set(store, 'positions', {'old-peer': 42, 'unresolved': ['original-envelope']})
    legacy.state_set(store, 'enrollment', {'peer': 'old-peer', 'status': 'historical', 'policy': 'old-policy'})


class FederationSourceTests(unittest.TestCase):
    def setUp(self):
        self.legacy = migration_support.TaskMigrationTests()
        self.legacy.setUp()
        self.addCleanup(self.legacy.doCleanups)
        populate(self.legacy.store)
        self.snapshot = self.legacy.capture()
        self.source = FederationArchiveSource(self.snapshot, source_owner_organization_id='org-one')
        self.identity = federation_archive_identity(ref('legacy-source'), target_hub_id='hub-one', scope=SCOPE)
        self.binding = OwnerBinding('hub-one', 'federation-archive', self.identity['archiveId'],
            'federation-archive', canonical_bytes(SCOPE))

    def test_actual_rows_counts_order_json_nulls_hashes_and_policy_gap(self):
        payload = prepare_federation_import(self.source, binding=self.binding)
        archive = payload['sourceArchive']
        for table, (key, _) in TABLES.items():
            expected = self.legacy.store.q('SELECT * FROM '+table+' ORDER BY '+key+' COLLATE BINARY')
            family = archive['families'][table]
            self.assertTrue(family['present'])
            self.assertEqual(family['count'], len(expected))
            self.assertEqual([m['row'] for m in family['rows']], expected)
            self.assertEqual(len({m['memberId'] for m in family['rows']}), len(expected))
        audit = archive['families']['fed_audit']['rows'][0]['row']
        self.assertEqual(audit['sha'], hashlib.sha256(b'{ "original": true }').hexdigest())
        self.assertEqual(audit['size'], len(b'{ "original": true }'))
        self.assertEqual(archive['historicalHoldingPolicy'], 'unknown')
        self.assertTrue(archive['policyRevalidationRequired'])

    def test_stable_archive_and_member_ids_exclude_capture_revision_and_digest(self):
        first = prepare_federation_import(self.source, binding=self.binding)
        self.legacy.store.db.execute("UPDATE fed_state SET v='changed source' WHERE k='positions'")
        later = self.legacy.capture('later.db')
        source = FederationArchiveSource(later, source_owner_organization_id='org-one')
        second = prepare_federation_import(source, binding=self.binding)
        self.assertNotEqual(first['captureDigest'], second['captureDigest'])
        self.assertEqual(first['archiveId'], second['archiveId'])
        for table in TABLES:
            self.assertEqual([r['memberId'] for r in first['sourceArchive']['families'][table]['rows']],
                [r['memberId'] for r in second['sourceArchive']['families'][table]['rows']])
        self.assertEqual(self.identity, federation_archive_identity(ref('legacy-source') | {'revision': 2},
            target_hub_id='hub-one', scope=SCOPE))
        self.assertNotEqual(self.identity, federation_archive_identity(ref('other-source'),
            target_hub_id='hub-one', scope=SCOPE))

    def test_other_organization_and_project_scope_refuse_before_source_read(self):
        with patch.object(self.snapshot, '_check_file', wraps=self.snapshot._check_file) as check:
            for scope in (SCOPE | {'organizationId': 'other-org'}, SCOPE | {'projectId': 'project-one'}):
                binding = OwnerBinding('hub-one', 'federation-archive', self.identity['archiveId'],
                    'federation-archive', canonical_bytes(scope))
                with self.assertRaises(ContractError):
                    prepare_federation_import(self.source, binding=binding)
            check.assert_not_called()

    def test_empty_all_families_have_explicit_complete_manifest(self):
        for table in TABLES:
            self.legacy.store.db.execute('DELETE FROM '+table)
        source = FederationArchiveSource(self.legacy.capture('empty.db'), source_owner_organization_id='org-one')
        families = prepare_federation_import(source, binding=self.binding)['sourceArchive']['families']
        self.assertEqual(families, {table: {'present': True, 'count': 0, 'rows': []} for table in TABLES})

    def test_unknown_column_missing_table_changed_file_and_oversize_refuse(self):
        self.legacy.store.db.execute('ALTER TABLE fed_state ADD COLUMN unreviewed TEXT')
        source = FederationArchiveSource(self.legacy.capture('extra.db'), source_owner_organization_id='org-one')
        with self.assertRaisesRegex(ContractError, '^federation_archive_source_invalid$'):
            prepare_federation_import(source, binding=self.binding)
        self.legacy.store.db.execute('DROP TABLE fed_state')
        source = FederationArchiveSource(self.legacy.capture('missing.db'), source_owner_organization_id='org-one')
        with self.assertRaisesRegex(ContractError, '^federation_archive_source_invalid$'):
            prepare_federation_import(source, binding=self.binding)
        with (self.legacy.root/'capture.db').open('ab') as output:
            output.write(b'changed')
        with self.assertRaisesRegex(ContractError, '^task_migration_snapshot_changed$'):
            prepare_federation_import(self.source, binding=self.binding)

    def test_protected_json_escaped_source_refuses_without_redaction_or_capture_change(self):
        self.legacy.store.db.execute("UPDATE fed_state SET v=? WHERE k='positions'", ('{"\\u0067hp_'+'z'*36+'":"ordinary"}',))
        snapshot = self.legacy.capture('protected.db')
        original = (self.legacy.root/'protected.db').read_bytes()
        source = FederationArchiveSource(snapshot, source_owner_organization_id='org-one')
        with self.assertRaisesRegex(ContractError, '^task_import_protected_source$'):
            prepare_federation_import(source, binding=self.binding)
        self.assertEqual((self.legacy.root/'protected.db').read_bytes(), original)

    def test_oversize_source_retains_capture_and_restores_sqlite_limit(self):
        legacy.state_set(self.legacy.store, 'large', 'x'*70000)
        snapshot = self.legacy.capture('large.db')
        original = (self.legacy.root/'large.db').read_bytes()
        limit = snapshot._db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        with self.assertRaises(ContractError):
            prepare_federation_import(FederationArchiveSource(snapshot, source_owner_organization_id='org-one'),
                binding=self.binding)
        self.assertEqual(snapshot._db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), limit)
        self.assertEqual((self.legacy.root/'large.db').read_bytes(), original)

    def test_older_schema_preserves_explicit_absent_families_without_migration(self):
        from hub.store import Store, MIGRATIONS
        from state_owner.task_migration import capture_tasks
        for version in (1, 2, 3):
            with self.subTest(version=version), patch('hub.store.MIGRATIONS', MIGRATIONS[:version]):
                store = Store(str(self.legacy.root/('old-'+str(version)+'.db')))
            self.addCleanup(store.db.close)
            snapshot = capture_tasks(store, self.legacy.root/('old-capture-'+str(version)+'.db'),
                source_ref=ref('legacy-source'), application_version='legacy-v'+str(version))
            self.addCleanup(snapshot.close)
            source = FederationArchiveSource(snapshot, source_owner_organization_id='org-one')
            archive = prepare_federation_import(source, binding=self.binding)['sourceArchive']
            self.assertEqual(archive['schemaVersion'], version)
            self.assertEqual(archive['families'],
                {table: {'present': False, 'count': 0, 'rows': []} for table in TABLES})
            self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0], version)

    def test_current_schema_import_keeps_federation_rows_and_refuses_future_version(self):
        payload = prepare_federation_import(self.source, binding=self.binding)
        archive = payload['sourceArchive']
        self.assertEqual(archive['schemaVersion'], 6)
        for table, (key, _) in TABLES.items():
            expected = self.legacy.store.q('SELECT * FROM '+table+' ORDER BY '+key+' COLLATE BINARY')
            self.assertEqual([member['row'] for member in archive['families'][table]['rows']], expected)
        unsupported = copy.deepcopy(payload)
        unsupported['sourceArchive']['schemaVersion'] = 7
        with self.assertRaisesRegex(ContractError, '^schema_invalid$'):
            validate('federation-ledger-import', unsupported)

    def test_missing_parent_has_fixed_diagnostic_and_keeps_original_capture(self):
        root = self.legacy.root
        moved = root.with_name(root.name+'-temporarily-moved')
        root.rename(moved)
        try:
            with self.assertRaisesRegex(ContractError, '^federation_archive_source_unavailable$') as raised:
                prepare_federation_import(self.source, binding=self.binding)
            self.assertNotIn(str(root), str(raised.exception))
            self.assertIsNone(raised.exception.__cause__)
            self.assertTrue(raised.exception.__suppress_context__)
            self.assertTrue((moved/'capture.db').is_file())
        finally:
            moved.rename(root)
        self.assertEqual(prepare_federation_import(self.source, binding=self.binding)['archiveId'],
            self.identity['archiveId'])

    def test_large_nocase_family_refuses_before_unbounded_binary_sort(self):
        db = self.legacy.store.db
        db.execute('DROP TABLE fed_state')
        db.execute('CREATE TABLE fed_state(k TEXT PRIMARY KEY COLLATE NOCASE,v TEXT NOT NULL) STRICT')
        db.executemany('INSERT INTO fed_state VALUES (?,?)',
            ((f'key-{number:05d}', 'original') for number in range(8000)))
        snapshot = self.legacy.capture('large-family.db')
        source = FederationArchiveSource(snapshot, source_owner_organization_id='org-one')
        original = (self.legacy.root/'large-family.db').read_bytes()
        with self.assertRaisesRegex(ContractError, '^federation_archive_artifact_required$'):
            prepare_federation_import(source, binding=self.binding)
        # The temporary progress callback must not constrain the borrowed
        # snapshot after refusal. This query takes more than its read budget.
        self.assertEqual(snapshot._db.execute('SELECT count(*) FROM fed_state').fetchone()[0], 8000)
        self.assertEqual(snapshot._db.execute('WITH RECURSIVE n(x) AS '
            '(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2000) SELECT sum(x) FROM n').fetchone()[0], 2001000)
        self.assertEqual((self.legacy.root/'large-family.db').read_bytes(), original)

    def test_instruction_and_elapsed_budgets_restore_borrowed_connection(self):
        db = self.snapshot._db
        limit = db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        for target, value in (('MAX_READ_INSTRUCTIONS', 100), ('MAX_READ_SECONDS', 0)):
            with self.subTest(target=target), patch('state_owner.federation_archive.'+target, value):
                with self.assertRaisesRegex(ContractError, '^federation_archive_source_unavailable$'):
                    prepare_federation_import(self.source, binding=self.binding)
            self.assertEqual(db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), limit)
            self.assertEqual(db.execute('WITH RECURSIVE n(x) AS '
                '(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2000) SELECT sum(x) FROM n').fetchone()[0], 2001000)
            self.assertEqual(prepare_federation_import(self.source, binding=self.binding)['archiveId'],
                self.identity['archiveId'])


class FederationImportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        identity_support.ServiceTests.setUp(self)
        patch('state_owner.federation_archive.datetime', _Clock).start()
        source_test = FederationSourceTests()
        source_test.setUp()
        self.addCleanup(source_test.doCleanups)
        self.source_test = source_test
        self.source, self.binding, self.identity = source_test.source, source_test.binding, source_test.identity
        for row in self.record['state']['memberships']:
            row['scope'] = copy.deepcopy(SCOPE)
        grant = self.record['state']['grants'][0]
        grant.update(contractId='federation-ledger-import', resourceId=self.binding.entity_id,
            scope=copy.deepcopy(SCOPE), ref=ref('archive-grant'))
        self.sync_identity()
        self.archive_js = FakeJetStream(self.policy)
        self.archive_js.config.subjects = [owner_subject(self.binding)]
        self.new_importer()

    def sync_identity(self):
        self.js.messages[0].data = canonical_bytes(self.record)

    def new_importer(self, source=None):
        self.ledger = OwnerLedger(self.archive_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        self.importer = FederationArchiveImporter(self.service.reader, self.ledger, source=source or self.source)

    def request(self, payload=None, *, grant='archive-grant'):
        if payload is None:
            payload = prepare_federation_import(self.source, binding=self.binding)
        claims = {'purpose': 'agentmux-client-possession-v1', 'profileId': 'profile-one', 'hubId': 'hub-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport'), 'grantRef': ref(grant),
            'operationId': self.identity['operationId'], 'expectedVersion': 0,
            'contractId': 'federation-ledger-import', 'payload': payload, 'approvalRefs': [],
            'issuedAt': NOW.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (NOW+timedelta(seconds=30)).isoformat().replace('+00:00', 'Z')}
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})

    async def admitted(self, payload=None):
        result = await self.service.ingress.admit(self.request(payload), cancellation_ref=ref('archive-cancel'))
        self.assertEqual(result.decision.outcome, 'allowed')
        return result.envelope

    async def test_complete_import_recreation_repeat_and_zero_effects(self):
        payload = prepare_federation_import(self.source, binding=self.binding)
        first = await self.importer.handle(await self.admitted(payload))
        self.new_importer()
        again = await self.importer.handle(await self.admitted(payload))
        self.assertTrue(again.replayed)
        self.assertEqual(first.record, again.record)
        self.assertEqual(len(self.archive_js.messages), 1)
        record = validate_federation_archive(first.record, self.binding, authority_id='authority-one')
        self.assertEqual(record['state']['payload'], payload)
        self.assertEqual(record['state']['status'], 'reconciliation_required')
        self.assertTrue(record['state']['captureComplete'])
        self.assertTrue(record['state']['writerTransferRequired'])
        self.assertFalse(record['effects'] or record['artifacts'])
        self.assertEqual(self.source_test.legacy.store.q1("SELECT sent FROM fed_outbox WHERE msg_id='withdrawn'")['sent'], 'withdrawn')

    async def test_lost_reply_returns_original_after_owner_recreation(self):
        raw = await self.admitted()
        self.archive_js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.importer.handle(raw)
        self.archive_js.lose_ack = False
        self.new_importer()
        again = await self.importer.handle(await self.admitted())
        self.assertTrue(again.replayed)
        self.assertEqual(len(self.archive_js.messages), 1)
        self.assertEqual(again.record, self.archive_js.messages[0].data)

    async def test_changed_capture_conflicts_without_second_record(self):
        first = await self.importer.handle(await self.admitted())
        legacy.state_set(self.source_test.legacy.store, 'positions', {'old-peer': 43})
        source = FederationArchiveSource(self.source_test.legacy.capture('later.db'), source_owner_organization_id='org-one')
        payload = prepare_federation_import(source, binding=self.binding)
        self.new_importer(source)
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.importer.handle(await self.admitted(payload))
        self.assertEqual([m.data for m in self.archive_js.messages], [first.record])

    async def test_revoked_authority_refuses_before_private_source_read(self):
        raw = await self.admitted()
        self.record['state']['grants'][0]['status'] = 'revoked'
        self.sync_identity()
        with patch.object(self.source, 'read', wraps=self.source.read) as read:
            with self.assertRaises(ContractError):
                await self.importer.handle(raw)
            read.assert_not_called()
        self.assertFalse(self.archive_js.messages)

    async def test_changed_source_claim_and_member_tampering_refuse_before_append(self):
        pristine = prepare_federation_import(self.source, binding=self.binding)
        for mutate in (lambda p: p.update(captureDigest='sha256:'+'0'*64),
                lambda p: p['sourceArchive']['families']['fed_seen'].update(count=0),
                lambda p: p['sourceArchive']['families']['fed_outbox']['rows'][0]['row'].update(sent=None),
                lambda p: p.update(sourceRef=ref('different-source'))):
            payload = copy.deepcopy(pristine)
            mutate(payload)
            with self.assertRaises(ContractError):
                await self.importer.handle(await self.admitted(payload))
        self.assertFalse(self.archive_js.messages)

    async def test_revocation_during_target_read_prevents_append(self):
        current = self.ledger.current
        async def revoke():
            value = await current()
            self.record['state']['grants'][0]['status'] = 'revoked'
            self.sync_identity()
            return value
        raw = await self.admitted()
        with patch.object(self.ledger, 'current', side_effect=revoke):
            with self.assertRaises(ContractError):
                await self.importer.handle(raw)
        self.assertFalse(self.archive_js.messages)

    async def test_protected_and_oversize_selected_source_refuse_before_any_append(self):
        raw = await self.admitted()
        for index, value in enumerate(('ghp_'+'z'*36, 'x'*70000)):
            legacy.state_set(self.source_test.legacy.store, 'positions', value)
            snapshot = self.source_test.legacy.capture('unavailable-'+str(index)+'.db')
            path = self.source_test.legacy.root/('unavailable-'+str(index)+'.db')
            original = path.read_bytes()
            self.new_importer(FederationArchiveSource(snapshot, source_owner_organization_id='org-one'))
            with patch.object(self.ledger, 'append', wraps=self.ledger.append) as append:
                with self.assertRaises(ContractError):
                    await self.importer.handle(raw)
                append.assert_not_called()
            self.assertEqual(path.read_bytes(), original)
        self.assertFalse(self.archive_js.messages)

    async def test_revocation_after_commit_suppresses_result_without_losing_record(self):
        raw = await self.admitted()
        append = self.ledger.append
        async def append_and_revoke(*args, **kwargs):
            stored = await append(*args, **kwargs)
            self.record['state']['grants'][0]['status'] = 'revoked'
            self.sync_identity()
            return stored
        with patch.object(self.ledger, 'append', side_effect=append_and_revoke):
            with self.assertRaises(ContractError):
                await self.importer.handle(raw)
        self.assertEqual(len(self.archive_js.messages), 1)
        validate_federation_archive(self.archive_js.messages[0].data, self.binding, authority_id='authority-one')

    async def test_replay_refuses_unrecognized_later_record_after_owner_recreation(self):
        first = await self.importer.handle(await self.admitted())
        later = strict_loads(first.record)
        later.update(recordId='unrecognized-later-write', entityVersion=2, previousRevision=1)
        later['operation'].update(operationId='unrecognized-later-write', expectedVersion=1)
        later['authorizationDecision']['operationId'] = 'unrecognized-later-write'
        # OwnerLedger can validate the generic retained chain without knowing
        # that this archive domain allows only one complete initial record.
        await self.ledger.append(later, expected_sequence=1, completion_records=0)
        self.new_importer()
        with self.assertRaisesRegex(ContractError, '^federation_archive_record_invalid$'):
            await self.importer.handle(await self.admitted())
        self.assertEqual(len(self.archive_js.messages), 2)
        self.assertEqual(self.archive_js.messages[0].data, first.record)


class FederationFixtureReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def test_owned_ready_marker_precedes_provisioner_client_without_filtering_errors(self):
        import tempfile
        from pathlib import Path
        from state_owner.test_task_live import LiveFederationArchiveTests, LiveTaskTests
        fixture = LiveFederationArchiveTests('test_tls_complete_archive_lost_reply_recreation_repeat_and_conflict')
        with tempfile.TemporaryDirectory() as directory:
            fixture.directory = Path(directory)
            log = fixture.directory/'server.private.log'
            log.write_bytes(b'Owned broker is starting\n')
            connection = object()
            with patch.object(LiveTaskTests, 'connect', new=AsyncMock(return_value=connection)) as connect:
                with self.assertRaisesRegex(OSError, '^archive_fixture_broker_not_ready$'):
                    await fixture.connect('provisioner')
                connect.assert_not_awaited()
                self.assertIs(await fixture.connect('identity'), connection)
                log.write_bytes(log.read_bytes()+b'Server is ready\n')
                self.assertIs(await fixture.connect('provisioner'), connection)
                self.assertEqual([call.args for call in connect.await_args_list], [('identity',), ('provisioner',)])
