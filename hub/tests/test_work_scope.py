"""Repository filters preserve existing work transactions and agent capacity."""
import tempfile
import unittest
from pathlib import Path

from hub.store import Store


class WorkScope(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(str(Path(self.directory.name) / 'hub.db'))
        self.addCleanup(self.store.db.close)
        for repository in ('alpha', 'beta'):
            self.store.repo_add(repository, groups=('shared',))
        self.agent = self.store.register('alpha', 'worker', 'one', 'codex', {'max_active': 1})
        self.store.set_state(self.agent, 'ready')

    def create(self, repository, *, priority=100):
        return self.store.work_create('operator', repository, 'role:group:shared/worker',
                                      repository + ' task', priority=priority)

    def claim_both(self):
        rows = [self.create(repository) for repository in ('alpha', 'beta')]
        for row in rows:
            self.assertEqual(self.store.claim(self.agent, work_id=row['id'])['claimed']['id'], row['id'])
            self.store.claim_path(self.agent, row['repo'], 'file.py', work_id=row['id'])
        return rows

    def test_scoped_claim_keeps_group_eligibility_and_first_claim_priority(self):
        foreign = self.create('beta', priority=1)
        local = self.create('alpha', priority=2)
        self.assertEqual([row['id'] for row in self.store.claimable(self.agent)], [foreign['id'], local['id']])
        self.assertEqual([row['id'] for row in self.store.claimable(self.agent, repository='alpha')], [local['id']])
        self.assertEqual(self.store.claim(self.agent, repository='alpha')['claimed']['id'], local['id'])
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')

    def test_scoped_claim_preserves_global_capacity_without_foreign_rows(self):
        foreign = self.create('beta')
        self.store.claim(self.agent, work_id=foreign['id'])
        local = self.create('alpha')
        result = self.store.claim(self.agent, repository='alpha')
        self.assertIsNone(result['claimed'])
        self.assertIn('max_active', result['reason'])
        self.assertEqual(result['active'], [])
        self.assertEqual(self.store.work(local['id'])['state'], 'ready')

    def test_scoped_explicit_claim_cannot_select_another_repository(self):
        foreign = self.create('beta')
        self.assertIsNone(self.store.claim(self.agent, work_id=foreign['id'], repository='alpha')['claimed'])
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')

    def test_scoped_return_preserves_other_work_and_path_claims(self):
        local, foreign = self.claim_both()
        with self.store.tx():
            returned = self.store._return_leases(self.agent, 'agent dead', repository='alpha')
        self.assertEqual(returned, [{'id': local['id'], 'state': 'ready'}])
        self.assertEqual(self.store.work(foreign['id'])['state'], 'claimed')
        self.assertEqual([row['repo'] for row in self.store.q('SELECT repo FROM claims')], ['beta'])
        with self.store.tx():
            self.store._return_leases(self.agent, 'agent dead')
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')
        self.assertEqual(self.store.q('SELECT * FROM claims'), [])

    def test_scoped_heartbeat_renews_only_selected_work_and_touches_agent(self):
        local, foreign = self.claim_both()
        with self.store.tx():
            self.store.db.execute("UPDATE work_items SET lease_until='2000-01-01T00:00:00Z'")
            self.store.db.execute("UPDATE agents SET last_seen='2000-01-01T00:00:00Z'")
        self.assertEqual(self.store.heartbeat(self.agent, 200, repository='alpha'), 1)
        self.assertGreater(self.store.work(local['id'])['lease_until'], '2000-01-01T00:00:00Z')
        self.assertEqual(self.store.work(foreign['id'])['lease_until'], '2000-01-01T00:00:00Z')
        self.assertGreater(self.store.agent(self.agent)['last_seen'], '2000-01-01T00:00:00Z')
        self.assertEqual(self.store.heartbeat(self.agent, 200), 2)
        self.assertGreater(self.store.work(foreign['id'])['lease_until'], '2000-01-01T00:00:00Z')

    def test_scoped_sweep_preserves_other_expired_work_and_path_claims(self):
        local, foreign = self.claim_both()
        with self.store.tx():
            self.store.db.execute("UPDATE work_items SET lease_until='2000-01-01T00:00:00Z'")
            self.store.db.execute("UPDATE claims SET lease_until='2000-01-01T00:00:00Z'")
        self.assertEqual(self.store.sweep_leases(repository='alpha'), [{'id': local['id'], 'state': 'ready'}])
        self.assertEqual(self.store.work(foreign['id'])['state'], 'claimed')
        self.assertEqual([row['repo'] for row in self.store.q('SELECT repo FROM claims')], ['beta'])
        self.assertEqual(self.store.sweep_leases(), [{'id': foreign['id'], 'state': 'ready'}])
        self.assertEqual(self.store.q('SELECT * FROM claims'), [])

    def test_scoped_return_stays_inside_the_callers_outer_transaction(self):
        local, foreign = self.claim_both()
        with self.assertRaisesRegex(RuntimeError, 'abort'):
            with self.store.tx():
                self.store._return_leases(self.agent, 'reregistered', repository='alpha')
                raise RuntimeError('abort')
        for row in (local, foreign):
            self.assertEqual(self.store.work(row['id'])['state'], 'claimed')
        self.assertEqual(len(self.store.q('SELECT * FROM claims')), 2)
