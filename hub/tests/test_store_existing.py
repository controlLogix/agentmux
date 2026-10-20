"""Selected database opening preserves existing data and refuses migration."""
import os
from pathlib import Path
import sqlite3
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hub.store import APP_ID, MIGRATIONS, HubError, Store


class ExistingStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name).resolve() / 'hub.db')
        store = Store(self.path)
        store.db.execute('CREATE TABLE future_records (id TEXT PRIMARY KEY, value BLOB)')
        store.db.execute('INSERT INTO future_records VALUES (?,?)', ('original', b'unknown\x00bytes'))
        store.db.close()
        os.chmod(self.path, 0o600)
        self.inputs = dict(application_id=APP_ID, user_version=len(MIGRATIONS), owner_uid=os.getuid())

    def open(self, path=None, **changes):
        return Store.open_existing(path or self.path, **dict(self.inputs, **changes))

    def test_existing_store_keeps_records_and_uses_existing_transactions_without_migration(self):
        with patch.object(Store, '_migrate', side_effect=AssertionError('must not migrate')):
            store = self.open()
        try:
            self.assertEqual(store.q('SELECT * FROM future_records'),
                [{'id': 'original', 'value': b'unknown\x00bytes'}])
            with store.tx():
                store.event('board', 'SH-1', 'observed', 'peer:nick')
            self.assertEqual(store.q1('SELECT entity_id, actor FROM events'),
                {'entity_id': 'SH-1', 'actor': 'peer:nick'})
            self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0], len(MIGRATIONS))
        finally:
            store.db.close()
        self.assertFalse((Path(self.path).parent / 'backups').exists())

    def test_database_authority_lock_allows_ordinary_join_before_activation(self):
        store = self.open()
        try:
            joined = self.open()
            joined.db.close()
        finally:
            store.db.close()
        reopened = self.open()
        reopened.db.close()

    def test_missing_database_or_parent_is_not_created(self):
        for path in (self.path + '.missing', str(Path(self.path).parent / 'missing' / 'hub.db')):
            with self.subTest(path=path):
                with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
                    self.open(path)
                self.assertFalse(Path(path).exists())
                if Path(path).parent.name == 'missing':
                    self.assertFalse(Path(path).parent.exists())

    def test_old_or_foreign_schema_refuses_without_upgrading_or_erasing_records(self):
        for pragma, changed in (('user_version', len(MIGRATIONS) - 1), ('application_id', 1234)):
            with self.subTest(pragma=pragma):
                connection = sqlite3.connect(self.path)
                connection.execute(f'PRAGMA {pragma} = {changed}')
                connection.close()
                with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
                    self.open()
                connection = sqlite3.connect(self.path)
                try:
                    self.assertEqual(connection.execute(f'PRAGMA {pragma}').fetchone()[0], changed)
                    self.assertEqual(connection.execute('SELECT value FROM future_records').fetchone()[0],
                        b'unknown\x00bytes')
                    connection.execute(f'PRAGMA {pragma} = {self.inputs[pragma]}')
                finally:
                    connection.close()

    def test_link_shared_file_wrong_owner_and_invalid_schema_pins_refuse_privately(self):
        link = self.path + '.link'
        os.symlink(self.path, link)
        with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
            self.open(link)
        for changes in ({'owner_uid': os.getuid() + 1}, {'application_id': 0},
                        {'user_version': len(MIGRATIONS) - 1}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
                    self.open(**changes)
        os.chmod(self.path, 0o644)
        with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
            self.open()

    def test_default_store_still_creates_and_migrates_new_database(self):
        path = str(Path(self.directory.name).resolve() / 'ordinary' / 'hub.db')
        store = Store(path)
        try:
            self.assertEqual(store.db.execute('PRAGMA application_id').fetchone()[0], APP_ID)
            self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0], len(MIGRATIONS))
        finally:
            store.db.close()

    def test_main_hardlink_and_unprotected_sidecars_refuse_before_sqlite_open(self):
        link = self.path + '.hardlink'
        os.link(self.path, link)
        with patch('hub.store.sqlite3.connect', side_effect=AssertionError('must refuse before connect')):
            with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
                self.open()
        os.unlink(link)
        for suffix in ('-wal', '-shm', '-journal'):
            side = Path(self.path + suffix)
            for kind in ('shared', 'symlink', 'hardlink'):
                with self.subTest(suffix=suffix, kind=kind):
                    if kind == 'symlink':
                        side.symlink_to(self.path)
                    elif kind == 'hardlink':
                        os.link(self.path, side)
                    else:
                        side.write_bytes(b'private sidecar')
                        side.chmod(0o644)
                    try:
                        with patch('hub.store.sqlite3.connect', side_effect=AssertionError('must refuse before connect')):
                            with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
                                self.open()
                    finally:
                        side.unlink()

    def test_native_acl_refuses_even_with_private_mode_bits(self):
        subprocess.run(['/bin/chmod', '+a', 'everyone allow read', self.path], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
                self.open()
        finally:
            subprocess.run(['/bin/chmod', '-N', self.path], check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_observed_database_replacement_refuses_before_schema_access(self):
        connect = sqlite3.connect
        original = self.path + '.original'
        def replaced(*args, **kwargs):
            os.rename(self.path, original)
            shutil.copyfile(original, self.path)
            os.chmod(self.path, 0o600)
            return connect(*args, **kwargs)
        with patch('hub.store.sqlite3.connect', side_effect=replaced):
            with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
                self.open()

    def test_held_custody_lives_until_sqlite_close_and_rechecks_main_and_sidecar(self):
        store = self.open()
        custody = store._selected_custody
        self.assertGreater(len(custody.rows), 1)
        side = Path(self.path + '-wal')
        self.assertTrue(side.exists())
        store.check_existing()
        side.chmod(0o644)
        with self.assertRaisesRegex(HubError, '^selected hub database is unavailable$'):
            store.check_existing()
        side.chmod(0o600)
        store.db.close()
        self.assertEqual(custody.rows, [])

    def test_native_custody_recheck_preserves_sqlite_wal_writer_lock(self):
        store = self.open()
        probe = '''import sqlite3,sys
connection=sqlite3.connect(sys.argv[1],timeout=0,isolation_level=None)
try:
    connection.execute('BEGIN IMMEDIATE')
except sqlite3.OperationalError as error:
    sys.exit(0 if str(error)=='database is locked' else 2)
else:
    connection.execute('ROLLBACK')
    sys.exit(1)
finally:
    connection.close()
'''
        try:
            store.db.execute('BEGIN IMMEDIATE')
            for recheck in (False, True):
                if recheck:
                    store.check_existing()
                result = subprocess.run([sys.executable, '-c', probe, self.path], timeout=3,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode, 0)
        finally:
            store.db.execute('ROLLBACK')
            store.db.close()
