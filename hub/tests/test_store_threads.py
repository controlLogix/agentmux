"""One store connection shared by an owner's event loop and its executor thread (AMUX-740)."""
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from hub.store import APP_ID, MIGRATIONS, HubError, Store


class SharedConnectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name).resolve() / 'hub.db')
        store = Store(self.path)
        store.repo_add('agentmux')
        store.db.close()
        os.chmod(self.path, 0o600)

    def stores(self):
        default = Store(self.path)
        existing = Store.open_existing(self.path, application_id=APP_ID,
            user_version=len(MIGRATIONS), owner_uid=os.getuid())
        for store in (default, existing):
            self.addCleanup(store.db.close)
        return {'default': default, 'existing': existing}

    def test_identical_queries_on_two_threads_never_miss_a_present_row(self):
        # Before AMUX-740 one thread reset the other's cached statement between
        # execute and fetch: about 4,000 misses a second on each thread.
        for name, store in self.stores().items():
            with self.subTest(store=name):
                misses, errors, stop = [0, 0], [], time.monotonic() + 1.0
                def check(index):
                    while time.monotonic() < stop:
                        try:
                            one = store.q1('SELECT repo FROM repos WHERE repo=?', ('agentmux',))
                            rows = store.q('SELECT repo FROM repos WHERE repo=?', ('agentmux',))
                        except Exception as error:
                            errors.append(type(error).__name__)
                            continue
                        misses[index] += (one != {'repo': 'agentmux'}) + (rows != [{'repo': 'agentmux'}])
                threads = [threading.Thread(target=check, args=(index,), daemon=True) for index in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(10)
                self.assertFalse(any(thread.is_alive() for thread in threads))
                self.assertEqual((misses, errors), ([0, 0], []))

    def test_transaction_on_another_thread_waits_instead_of_joining(self):
        # Before AMUX-740 the second thread saw in_transaction, treated its block as
        # nested, and its write was rolled back with the first thread's.
        for name, store in self.stores().items():
            with self.subTest(store=name):
                entered, finished, outcome = threading.Event(), threading.Event(), []
                def first():
                    try:
                        with store.tx():
                            store.db.execute("INSERT INTO repos (repo, created) VALUES ('first', 'now')")
                            entered.set()
                            outcome.append(finished.wait(0.5))
                            raise RuntimeError('roll back the first transaction')
                    except RuntimeError:
                        pass
                def second():
                    entered.wait(5)
                    with store.tx():
                        store.db.execute("INSERT INTO repos (repo, created) VALUES ('second', 'now')")
                    finished.set()
                threads = [threading.Thread(target=first, daemon=True), threading.Thread(target=second, daemon=True)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(10)
                self.assertFalse(any(thread.is_alive() for thread in threads))
                self.assertEqual(outcome, [False])
                self.assertTrue(finished.is_set())
                self.assertEqual(store.q("SELECT repo FROM repos WHERE repo IN ('first', 'second')"),
                                 [{'repo': 'second'}])
                with store.tx():
                    store.db.execute("DELETE FROM repos WHERE repo='second'")

    def test_refused_transaction_releases_the_store_lock(self):
        for name, store in self.stores().items():
            with self.subTest(store=name):
                fence = store.fence_legacy_writer()
                with self.assertRaisesRegex(HubError, 'fenced for migration'):
                    with store.tx():
                        pass
                result = []
                self.assertEqual(self.read_elsewhere(store), [{'repo': 'agentmux'}])
                store.recover_legacy_writer(fence['fenceId'])

    def read_elsewhere(self, store, wait=5):
        result = []
        reader = threading.Thread(target=lambda: result.append(
            store.q1('SELECT repo FROM repos WHERE repo=?', ('agentmux',))), daemon=True)
        reader.start()
        reader.join(wait)
        return result

    def test_busy_begin_releases_the_store_lock(self):
        for name, store in self.stores().items():
            with self.subTest(store=name):
                other = sqlite3.connect(self.path, isolation_level=None)
                self.addCleanup(other.close)
                other.execute('BEGIN IMMEDIATE')
                store.db.execute('PRAGMA busy_timeout = 50')
                with self.assertRaisesRegex(sqlite3.OperationalError, 'locked'):
                    with store.tx():
                        pass
                other.execute('ROLLBACK')
                self.assertEqual(self.read_elsewhere(store), [{'repo': 'agentmux'}])

    def test_reader_waits_for_a_nested_transaction_to_end(self):
        for name, store in self.stores().items():
            with self.subTest(store=name):
                with store.tx():
                    with store.tx():
                        store.db.execute("INSERT INTO repos (repo, created) VALUES ('nested', 'now')")
                    self.assertEqual(self.read_elsewhere(store, wait=0.3), [])
                    store.db.execute("DELETE FROM repos WHERE repo='nested'")
                self.assertEqual(self.read_elsewhere(store), [{'repo': 'agentmux'}])


if __name__ == '__main__':
    unittest.main()
