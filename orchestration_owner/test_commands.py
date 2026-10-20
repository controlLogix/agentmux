import unittest

from agentmux_contracts import ContractError, canonical_bytes
from .commands import OrchestrationPolicyBinding, prepare_command


def ref(name, revision=1):
    return {'id': name, 'ownerHubId': 'hub-one', 'revision': revision}


class OrchestrationCommandTests(unittest.TestCase):
    def setUp(self):
        self.scope = {'organizationId': 'org-one', 'projectId': 'project-one',
                      'workspaceId': None}
        self.binding = OrchestrationPolicyBinding(ref('orchestration-one'), self.scope,
            '/private/project', 'ccc-orchestrator')

    def payload(self, value, *, environment=None):
        return {'resourceRef': ref('orchestration-one'), 'environmentRef': environment,
                'input': value}

    def test_project_only_policy_omits_environment_without_weakening_project_scope(self):
        prepared = prepare_command(self.payload(
            {'command': 'run-start', 'request': 'implement AMUX-50'}), self.binding)
        self.assertEqual(prepared.command, 'run-start')
        self.assertIsNone(prepared.private_input().get('environmentRef'))
        self.assertTrue(prepared.candidate_digest.startswith('sha256:'))
        self.assertNotIn('/private/project', repr(self.binding))

    def test_optional_environment_must_match_selected_profile_exactly(self):
        selected = OrchestrationPolicyBinding(ref('orchestration-one'), self.scope,
            '/private/project', 'ccc-orchestrator', ref('environment-one'))
        valid = self.payload({'command': 'orchestrator-stop'}, environment=ref('environment-one'))
        self.assertEqual(prepare_command(valid, selected).command, 'orchestrator-stop')
        for environment in (None, ref('environment-two')):
            with self.subTest(environment=environment), self.assertRaisesRegex(
                    ContractError, 'orchestration_scope_mismatch'):
                prepare_command(self.payload({'command': 'orchestrator-stop'},
                                              environment=environment), selected)

    def test_closed_commands_reject_added_authority_and_force_fields(self):
        cases = [
            {'command': 'run-complete', 'runId': 'abc123', 'force': True},
            {'command': 'run-start', 'request': 'one', 'actor': 'forged'},
            {'command': 'orchestrator-start', 'request': 'one', 'agent': 'chosen-by-caller'},
            {'command': 'claim-for', 'resource': 'src/a.py', 'holder': 'worker', 'ttl': 60,
             'note': '', 'task': None, 'dependsOn': [], 'projectId': 'other'},
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaisesRegex(
                    ContractError, 'orchestration_command_invalid'):
                prepare_command(self.payload(value), self.binding)

    def test_assignment_and_claim_inputs_keep_existing_domain_guards(self):
        valid = {'command': 'run-assign', 'runId': 'abc123', 'worker': 'worker-a',
                 'reviewer': 'reviewer-a', 'task': 'AMUX-50', 'brief': None}
        self.assertEqual(prepare_command(self.payload(valid), self.binding).private_input(), valid)
        invalid = [
            dict(valid, reviewer='worker-a'),
            dict(valid, runId='../bad'),
            {'command': 'claim-for', 'resource': '../orchestrator.warrant',
             'holder': 'worker-a', 'ttl': 60, 'note': '', 'task': None, 'dependsOn': []},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ContractError):
                prepare_command(self.payload(value), self.binding)

    def test_canonical_candidate_binds_resource_and_command(self):
        payload = self.payload({'command': 'release-for', 'resource': 'taskmgmt/run.py',
                                'holder': 'worker-a'})
        prepared = prepare_command(payload, self.binding)
        self.assertEqual(prepared.candidate, canonical_bytes(payload))
        changed = self.payload({'command': 'release-for', 'resource': 'taskmgmt/coordination.py',
                                'holder': 'worker-a'})
        self.assertNotEqual(prepare_command(changed, self.binding).candidate_digest,
                            prepared.candidate_digest)

    def test_scope_requires_a_real_project(self):
        for project in (None, '', 'BAD PROJECT'):
            scope = dict(self.scope, projectId=project)
            with self.subTest(project=project), self.assertRaisesRegex(
                    ContractError, 'orchestration_policy_invalid'):
                OrchestrationPolicyBinding(ref('orchestration-one'), scope,
                    '/private/project', 'ccc-orchestrator')


if __name__ == '__main__':
    unittest.main(verbosity=2)
