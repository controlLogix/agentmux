import sqlite3
import unittest

import ccboard
import ccstore


def ref(name):
    return {'id': name, 'ownerHubId': 'hub-one', 'revision': 1}


def policy(project, *, environment=None, enabled=True):
    return {'resourceRef': ref('orchestration-' + project),
            'scope': {'organizationId': 'org-one', 'projectId': project,
                      'workspaceId': None},
            'environmentRef': None if environment is None else ref(environment),
            'enabled': enabled, 'agent': '', 'workScope': 'goal', 'notify': True,
            'notifyCommand': ''}


class ScopedOrchestrationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        for statement in ccstore.SCHEMA:
            self.db.execute(statement)
        for statement in ccboard.NEW_TABLES:
            self.db.execute(statement)
        ccboard.migrate(self.db)
        self.addCleanup(self.db.close)

    def test_multiple_projects_and_optional_environments_are_retained_separately(self):
        values = [policy('project-one'), policy('project-two', environment='env-two')]
        self.assertEqual(ccboard.set_orchestration_policies(
            self.db, values, 'human-one'), values)
        self.assertEqual(ccboard.orchestration_policies(self.db), values)
        history = ccboard.history(self.db)
        self.assertTrue(any(row['event'] == 'config' and
            row['detail'] == {'name': 'orchestratorPolicies', 'count': 2}
            for row in history))

    def test_legacy_global_switch_does_not_become_scoped_authority(self):
        ccboard.set_config(self.db, 'orchestratorEnabled', True, 'historic-operator')
        ccboard.set_config(self.db, 'orchestratorAgent', 'ccc-orchestrator',
                           'historic-operator')
        self.assertEqual(ccboard.orchestration_policies(self.db), [])

    def test_duplicate_scope_and_environment_is_refused(self):
        with self.assertRaisesRegex(ccboard.Invalid, 'duplicate'):
            ccboard.set_orchestration_policies(self.db,
                [policy('project-one'), policy('project-one')], 'human-one')

    def test_policy_rejects_missing_project_and_caller_selected_extra_fields(self):
        missing = policy('project-one')
        missing['scope']['projectId'] = None
        forged = policy('project-one')
        forged['actor'] = 'forged'
        for value in (missing, forged):
            with self.subTest(value=value), self.assertRaises(ccboard.Invalid):
                ccboard.set_orchestration_policies(self.db, [value], 'human-one')

    def test_corrupt_retained_policy_fails_closed(self):
        self.db.execute('INSERT INTO board_config(name,value) VALUES (?,?)',
                        ('orchestratorPolicies', '[{"enabled":true}]'))
        with self.assertRaisesRegex(ccboard.Invalid, 'invalid retained'):
            ccboard.orchestration_policies(self.db)


if __name__ == '__main__':
    unittest.main(verbosity=2)
