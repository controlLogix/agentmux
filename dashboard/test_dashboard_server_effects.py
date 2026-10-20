"""The concrete owner reuses board behavior but supplies enrolled attribution."""
import sqlite3
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from dashboard_server_effects import DashboardServerEffects


class DashboardServerEffectsTests(unittest.TestCase):
    def setUp(self):
        self.effects = DashboardServerEffects('127.0.0.1')

    def test_transactional_board_write_supplies_actor_outside_body(self):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        with patch('server.Handler.board_write', return_value={'ok': True}) as write:
            result = self.effects.apply_transactional(db, '/api/board/config',
                'config', {'name': 'orchestratorEnabled', 'value': False}, 'user-one')
        self.assertEqual(result, {'ok': True})
        called = write.call_args.args
        self.assertIs(called[1], db)
        self.assertEqual(called[2], 'config')
        self.assertEqual(called[3], {'name': 'orchestratorEnabled',
                                    'value': False, 'actor': 'user-one'})

    def test_run_review_binds_path_id_and_enrolled_actor(self):
        with patch('dashboard_server_effects.runsview.write_approval') as write:
            result = self.effects.apply_external('/api/runs/abcdef/review', 'run-review',
                {'decision': 'approved', 'note': 'read'}, 'user-one')
        self.assertEqual(result, {'ok': True})
        write.assert_called_once_with('abcdef', 'user-one', 'read', 'approved')
        with self.assertRaisesRegex(ContractError, 'dashboard_effect_target_mismatch'):
            self.effects.apply_external('/api/runs/not-a-run/review', 'run-review',
                {'decision': 'approved'}, 'user-one')


if __name__ == '__main__':
    unittest.main()
