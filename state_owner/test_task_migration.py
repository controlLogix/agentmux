"""Actual legacy SQLite capture, unchanged obligations and private readback."""
import json
from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.store import Store, MIGRATIONS
from identity.test_authority import ref
from state_owner.ledger import OwnerBinding
from state_owner.task_migration import capture_tasks, TaskMigrationSnapshot, task_import_identity, prepare_task_import


class TaskMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='amx-task-migration-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.store = Store(str(self.root/'hub.db'))
        self.addCleanup(self.store.db.close)
        self.store.repo_add('alpha')
        self.parent = self.store.work_create('virtual:operator', 'alpha', 'role:alpha/worker',
            'Parent', body='Original parent\nbody', task_key='AMUX-48')
        self.child = self.store.work_create('virtual:operator', 'alpha', 'role:alpha/worker',
            'Child', body=None, requirements={'capabilities': ['python']}, parent_id=self.parent['id'])
        self.store.db.execute("UPDATE work_items SET origin_peer='remote', claimed_by='nats:federated', "
            "state='claimed', lease_until='2000-01-01T00:00:00Z', fed_flags=? WHERE id=?",
            ('{ "executor": {"peer":"remote","node":"node-one","execution_id":"old-exec","grant_id":"old-grant"}, "acceptanceUnknown":true }', self.parent['id']))
        self.store.db.execute("UPDATE work_items SET origin_peer='remote',state='blocked', "
            "blocked_reason='awaiting origin grant',fed_flags=? WHERE id=?",
            ('{"origin_id":"REMOTE-W01", "execution_id":"pending-exec", "result_pending":true, "result_id":"stable-return"}', self.child['id']))
        self.store.db.execute('INSERT INTO claims VALUES (?,?,?,?,?,?)',
            ('alpha', 'src/file.py', 'old-holder', self.parent['id'], '2000-01-01T00:00:00Z', '2026-10-09T00:00:00Z'))
        self.store.db.execute("INSERT INTO fed_seen VALUES ('seen-original','2026-10-09T00:00:00Z')")
        self.store.db.execute("INSERT INTO fed_outbox(msg_id,subject,payload,created,attempts,last_error) "
            "VALUES ('old-envelope','am.msg','{}','2026-10-09T00:00:00Z',3,'old failure')")
        self.store.db.execute('CREATE TABLE p_private_items(id TEXT PRIMARY KEY, raw BLOB) STRICT')
        self.store.db.execute('INSERT INTO p_private_items VALUES (?,?)', ('unknown-plugin', bytes([0,255,7])))

    def capture(self, name='capture.db'):
        snapshot = capture_tasks(self.store, self.root/name, source_ref=ref('legacy-source'),
            application_version='legacy-current')
        self.addCleanup(snapshot.close)
        return snapshot

    def test_exact_task_rows_links_json_nulls_audit_and_unresolved_work(self):
        before = self.store.q1('SELECT * FROM work_items WHERE id=?', (self.parent['id'],))
        snapshot = self.capture()
        self.assertEqual(snapshot.task_ids(), tuple(sorted((self.parent['id'], self.child['id']))))
        parent = strict_loads(snapshot.task(self.parent['id']))
        child = strict_loads(snapshot.task(self.child['id']))
        self.assertEqual(parent['work'], before)
        self.assertEqual(child['work'], self.store.q1('SELECT * FROM work_items WHERE id=?', (self.child['id'],)))
        self.assertEqual(child['work']['parent_id'], self.parent['id'])
        self.assertIsNone(child['work']['body'])
        self.assertEqual(parent['events'], self.store.q(
            "SELECT * FROM events WHERE entity='work' AND entity_id=? ORDER BY seq", (self.parent['id'],)))
        self.assertEqual(parent['claims'], self.store.q('SELECT * FROM claims WHERE work_id=? ORDER BY repo,path',
            (self.parent['id'],)))
        self.assertEqual(parent['work']['state'], 'claimed')
        self.assertEqual(json.loads(parent['work']['fed_flags'])['executor']['grant_id'], 'old-grant')
        self.assertEqual(child['work']['blocked_reason'], 'awaiting origin grant')
        self.assertTrue(json.loads(child['work']['fed_flags'])['result_pending'])
        self.assertEqual(self.store.q1('SELECT * FROM work_items WHERE id=?', (self.parent['id'],)), before)

    def test_full_database_retains_other_owner_tables_and_original_pending_deliveries(self):
        snapshot = self.capture()
        inventory = snapshot.inventory()
        self.assertFalse(inventory['writerAuthorityTransferred'])
        tables = {table['name']: table['rows'] for table in inventory['tables']}
        for name in ('work_items', 'fed_seen', 'fed_outbox', 'fed_audit', 'fed_quarantine',
                'fed_state', 'nats_outbox', 'messages', 'deliveries', 'p_private_items'):
            self.assertIn(name, tables)
        with closing(sqlite3.connect((self.root/'capture.db').as_uri()+'?mode=ro', uri=True)) as db:
            self.assertEqual(db.execute('SELECT raw FROM p_private_items').fetchone()[0], bytes([0,255,7]))
            self.assertEqual(db.execute('SELECT msg_id,sent,attempts,last_error FROM fed_outbox').fetchone(),
                ('old-envelope', None, 3, 'old failure'))
            self.assertEqual(db.execute('SELECT msg_id FROM fed_seen').fetchone()[0], 'seen-original')
        self.assertEqual(inventory['schemaVersion'], len(MIGRATIONS))

    def test_reopen_and_repeated_readback_preserve_bytes_after_source_changes(self):
        snapshot = self.capture()
        raw = snapshot.task(self.parent['id'])
        inventory = snapshot.inventory()
        self.store.db.execute("UPDATE work_items SET title='New live writer title' WHERE id=?", (self.parent['id'],))
        snapshot.close()
        reopened = TaskMigrationSnapshot(self.root/'capture.db', digest=inventory['databaseDigest'],
            source_ref=inventory['sourceRef'], application_version=inventory['applicationVersion'])
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.task(self.parent['id']), raw)
        self.assertEqual(reopened.task(self.parent['id']), raw)
        later = self.capture('later.db')
        self.assertNotEqual(later.task(self.parent['id']), raw)
        self.assertNotEqual(later.inventory()['databaseDigest'], inventory['databaseDigest'])
        self.assertEqual(self.store.work(self.parent['id'])['title'], 'New live writer title')

    def test_collision_and_interrupted_copy_never_replace_completed_snapshot(self):
        snapshot = self.capture()
        original = (self.root/'capture.db').read_bytes()
        with self.assertRaisesRegex(ContractError, '^task_migration_capture_unavailable$'):
            self.capture()
        self.assertEqual((self.root/'capture.db').read_bytes(), original)
        backup = self.store.backup
        def interrupted(path):
            backup(path)
            raise OSError('private injected interruption')
        with patch.object(self.store, 'backup', side_effect=interrupted):
            with self.assertRaises(ContractError):
                self.capture('interrupted.db')
        self.assertFalse((self.root/'interrupted.db').exists())
        self.assertFalse(list(self.root.glob('.task-capture-*')))
        self.assertEqual(snapshot.task_ids(), tuple(sorted((self.parent['id'], self.child['id']))))

    def test_changed_file_wrong_digest_symlink_and_active_transaction_refuse(self):
        snapshot = self.capture()
        inventory = snapshot.inventory()
        with self.assertRaisesRegex(ContractError, '^task_migration_snapshot_invalid$'):
            TaskMigrationSnapshot(self.root/'capture.db', digest='sha256:'+'0'*64,
                source_ref=ref('legacy-source'), application_version='legacy-current')
        (self.root/'link.db').symlink_to(self.root/'capture.db')
        with self.assertRaises(ContractError):
            TaskMigrationSnapshot(self.root/'link.db', digest=inventory['databaseDigest'],
                source_ref=ref('legacy-source'), application_version='legacy-current')
        with self.store.tx():
            with self.assertRaises(ContractError):
                self.capture('transaction.db')
        with (self.root/'capture.db').open('ab') as output:
            output.write(b'x')
        with self.assertRaisesRegex(ContractError, '^task_migration_snapshot_changed$'):
            snapshot.task_ids()

    def test_identity_preserves_original_tokens_without_using_them_as_target_ids(self):
        options = dict(target_hub_id='hub-one', scope={'organizationId':'org-one','projectId':None,'workspaceId':None})
        first = task_import_identity(ref('legacy-source'), 'W01ABC', **options)
        self.assertRegex(first['taskId'], '^legacy_[0-9a-f]{64}$')
        self.assertEqual(first, task_import_identity(ref('legacy-source')|{'revision':2}, 'W01ABC', **options))
        self.assertNotEqual(first, task_import_identity(ref('other-source'), 'W01ABC', **options))
        self.assertNotEqual(first, task_import_identity(ref('legacy-source'), 'w01abc', **options))
        self.assertNotEqual(first, task_import_identity(ref('legacy-source'), 'W01ABC',
            **(options|{'target_hub_id':'other-hub'})))
        self.assertNotEqual(first, task_import_identity(ref('legacy-source'), 'W01ABC',
            **(options|{'scope':options['scope']|{'projectId':'other-project'}})))

    def test_actual_older_store_schema_is_read_without_running_migrations(self):
        for version in range(1, len(MIGRATIONS)+1):
            with self.subTest(version=version), patch('hub.store.MIGRATIONS', MIGRATIONS[:version]):
                old = Store(str(self.root/('old-'+str(version)+'.db')))
            self.addCleanup(old.db.close)
            old.repo_add('alpha')
            work = old.work_create('virtual:operator', 'alpha', 'role:alpha/worker', 'Old schema')
            captured = capture_tasks(old, self.root/('old-capture-'+str(version)+'.db'),
                source_ref=ref('old-source'), application_version='legacy-v'+str(version))
            self.addCleanup(captured.close)
            self.assertEqual(captured.inventory()['schemaVersion'], version)
            row = strict_loads(captured.task(work['id']))['work']
            self.assertEqual('origin' in row, version >= 3)
            self.assertEqual('origin_peer' in row, version >= 4)
            self.assertEqual('fed_flags' in row, version >= 4)
            self.assertEqual(old.db.execute('PRAGMA user_version').fetchone()[0], version)

    def test_foreign_key_gap_refuses_publication_and_keeps_original_source(self):
        self.store.db.execute('PRAGMA foreign_keys=OFF')
        self.store.db.execute("UPDATE work_items SET parent_id='absent-parent' WHERE id=?", (self.child['id'],))
        with self.assertRaises(ContractError):
            self.capture('broken.db')
        self.assertFalse((self.root/'broken.db').exists())
        self.assertEqual(self.store.q1('SELECT parent_id FROM work_items WHERE id=?',
            (self.child['id'],))['parent_id'], 'absent-parent')

    def target(self, legacy_id):
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        identity = task_import_identity(ref('legacy-source'), legacy_id, target_hub_id='hub-one', scope=scope)
        return OwnerBinding('hub-one', 'task', identity['taskId'], 'task', canonical_bytes(scope))

    def test_target_preparation_preserves_source_and_maps_parent_without_permission(self):
        snapshot = self.capture()
        binding = self.target(self.child['id'])
        payload = prepare_task_import(snapshot, self.child['id'], binding=binding, source_repository='alpha')
        source = strict_loads(snapshot.task(self.child['id']))
        self.assertEqual(payload['sourceRecord'], source)
        self.assertEqual(payload['sourceTaskDigest'], payload_digest(source))
        self.assertEqual(payload['captureDigest'], snapshot.inventory()['databaseDigest'])
        self.assertEqual(payload['legacyId'], self.child['id'])
        self.assertEqual(payload['parentTaskId'], self.target(self.parent['id']).entity_id)
        with self.assertRaisesRegex(ContractError, '^task_import_binding_mismatch$'):
            prepare_task_import(snapshot, self.child['id'], binding=self.target(self.parent['id']), source_repository='alpha')

    def test_cross_repository_parent_and_oversize_source_refuse_without_losing_capture(self):
        self.store.repo_add('beta')
        self.store.db.execute("UPDATE work_items SET repo='beta' WHERE id=?", (self.parent['id'],))
        snapshot = self.capture()
        with self.assertRaisesRegex(ContractError, '^task_import_parent_scope_unavailable$'):
            prepare_task_import(snapshot, self.child['id'], binding=self.target(self.child['id']), source_repository='alpha')
        self.store.db.execute('UPDATE work_items SET body=? WHERE id=?', ('x'*65536, self.child['id']))
        self.store.db.execute("UPDATE work_items SET repo='alpha' WHERE id=?", (self.parent['id'],))
        large = self.capture('large.db')
        with self.assertRaisesRegex(ContractError, '^task_import_artifact_required$'):
            prepare_task_import(large, self.child['id'], binding=self.target(self.child['id']), source_repository='alpha')
        self.assertEqual(len(strict_loads(large.task(self.child['id']))['work']['body']), 65536)

    def test_sqlite_open_uses_hashed_descriptor_during_parent_swap_and_restoration(self):
        snapshot = self.capture()
        inventory = snapshot.inventory()
        original_row = strict_loads(snapshot.task(self.parent['id']))['work']
        snapshot.close()
        replacement = self.root.with_name(self.root.name+'-replacement')
        held = self.root.with_name(self.root.name+'-held')
        replacement.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, replacement)
        shutil.copyfile(self.root/'capture.db', replacement/'capture.db')
        (replacement/'capture.db').chmod(0o600)
        connect = sqlite3.connect
        with closing(connect(replacement/'capture.db')) as db:
            db.execute("UPDATE work_items SET title='Unhashed replacement' WHERE id=?", (self.parent['id'],))
            db.commit()
        opened = []
        def swap_at_open(*args, **kwargs):
            opened.append(args[0])
            os.rename(self.root, held)
            os.rename(replacement, self.root)
            try:
                return connect(*args, **kwargs)
            finally:
                os.rename(self.root, replacement)
                os.rename(held, self.root)
        with patch('state_owner.task_migration.sqlite3.connect', side_effect=swap_at_open):
            admitted = TaskMigrationSnapshot(self.root/'capture.db', digest=inventory['databaseDigest'],
                source_ref=inventory['sourceRef'], application_version=inventory['applicationVersion'])
        self.addCleanup(admitted.close)
        self.assertTrue(opened[0].startswith('file:/dev/fd/'))
        self.assertEqual(strict_loads(admitted.task(self.parent['id']))['work'], original_row)
        self.assertEqual(admitted.inventory()['databaseDigest'], inventory['databaseDigest'])
        self.assertEqual(self.store.q1('SELECT * FROM work_items WHERE id=?', (self.parent['id'],)), original_row)

    def test_backup_write_uses_allocated_descriptor_without_overwriting_swapped_database(self):
        replacement = self.root.with_name(self.root.name+'-write-replacement')
        held = self.root.with_name(self.root.name+'-write-held')
        replacement.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, replacement)
        connect = sqlite3.connect
        destinations = []
        def swap_at_destination_open(*args, **kwargs):
            if '?mode=rw' not in str(args[0]):
                return connect(*args, **kwargs)
            destinations.append(args[0])
            temporary = next(self.root.glob('.task-capture-*')).name
            foreign = replacement/temporary
            with closing(connect(foreign)) as db:
                db.execute('CREATE TABLE unrelated(v TEXT)')
                db.execute("INSERT INTO unrelated VALUES ('Keep original data')")
                db.commit()
            os.rename(self.root, held)
            os.rename(replacement, self.root)
            try:
                return connect(*args, **kwargs)
            finally:
                os.rename(self.root, replacement)
                os.rename(held, self.root)
        with patch('state_owner.task_migration.sqlite3.connect', side_effect=swap_at_destination_open):
            snapshot = self.capture()
        self.assertEqual(len(destinations), 1)
        self.assertTrue(destinations[0].startswith('file:/dev/fd/'))
        foreign = next(replacement.glob('.task-capture-*'))
        with closing(connect(foreign)) as db:
            self.assertEqual(db.execute('SELECT v FROM unrelated').fetchone()[0], 'Keep original data')
            self.assertIsNone(db.execute("SELECT name FROM sqlite_schema WHERE name='work_items'").fetchone())
        self.assertEqual(strict_loads(snapshot.task(self.parent['id']))['work']['title'], 'Parent')

    def test_failed_capture_does_not_unlink_substituted_temporary_file(self):
        replaced = []
        def substitute_then_fail(_destination):
            path = next(self.root.glob('.task-capture-*'))
            path.rename(self.root/'retained-owned-temp')
            path.write_bytes(b'Unrelated replacement')
            replaced.append(path)
            raise OSError('private injected substitution')
        with patch.object(self.store, 'backup', side_effect=substitute_then_fail):
            with self.assertRaises(ContractError):
                self.capture('failed.db')
        self.assertEqual(replaced[0].read_bytes(), b'Unrelated replacement')
        self.assertTrue((self.root/'retained-owned-temp').exists())
        self.assertFalse((self.root/'failed.db').exists())

    def test_store_backup_keeps_legacy_path_and_borrowed_connection_ownership(self):
        path = self.root/'legacy-path.db'
        self.store.backup(str(path))
        with closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute('SELECT title FROM work_items WHERE id=?',
                (self.parent['id'],)).fetchone()[0], 'Parent')
        with closing(sqlite3.connect(':memory:')) as destination:
            self.store.backup(destination)
            self.assertEqual(destination.execute('SELECT title FROM work_items WHERE id=?',
                (self.parent['id'],)).fetchone()[0], 'Parent')
            destination.execute('CREATE TABLE caller_still_owns_connection(v TEXT)')
