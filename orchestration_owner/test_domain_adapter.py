import importlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from .commands import OrchestrationPolicyBinding, prepare_command
from .domain_adapter import OrchestrationDomainAdapter


def ref(name):
    return {'id': name, 'ownerHubId': 'hub-one', 'revision': 1}


class OrchestrationDomainAdapterTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='orchestration-domain-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.previous_cwd = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.previous_cwd)
        self.saved = {name: os.environ.get(name) for name in
                      ('AGENTMUX_HOME', 'AGENTMUX_AGENT', 'AGENTMUX_TRUST_IDENTITY')}
        os.environ['AGENTMUX_HOME'] = str(self.root / 'home')
        os.environ['AGENTMUX_AGENT'] = 'forged-pane-label'
        os.environ.pop('AGENTMUX_TRUST_IDENTITY', None)
        self.addCleanup(self.restore)
        import coordination
        import run
        importlib.reload(coordination)
        importlib.reload(run)
        self.binding = OrchestrationPolicyBinding(ref('orchestration-one'), {
            'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None},
            str(self.root), 'orchestrator-project-one')
        self.adapter = OrchestrationDomainAdapter(self.binding)

    def restore(self):
        for name, value in self.saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def effect(self, value):
        return prepare_command({'resourceRef': ref('orchestration-one'),
            'environmentRef': None, 'input': value}, self.binding)

    def test_owner_actor_not_environment_label_is_retained(self):
        result = self.adapter.perform(self.effect({'command': 'run-start',
            'request': 'bounded work'}), actor='human-one',
            provenance='orchestrator-project-one')
        self.assertEqual(result.outcome, 'applied')
        run_id = result.private_copy()['result']['runId']
        events = [json.loads(line) for line in
                  (Path(os.environ['AGENTMUX_HOME']) / 'runs' / run_id / 'events.jsonl')
                  .read_text().splitlines()]
        self.assertEqual((events[0]['by'], events[0]['via']),
                         ('human-one', 'orchestrator-project-one'))

    def test_exact_effect_cannot_be_reused_for_a_different_verb(self):
        import coordination
        effect = self.effect({'command': 'run-start', 'request': 'one'})
        with coordination._owner_effect(effect, actor='human-one',
                                        provenance='orchestrator-project-one'):
            with self.assertRaisesRegex(coordination.IdentityError,
                                        "cannot perform 'complete'"):
                coordination.orchestrator_identity('complete')

    def test_selected_repository_is_checked_before_any_effect(self):
        other = Path(tempfile.mkdtemp(prefix='orchestration-other-')).resolve()
        self.addCleanup(shutil.rmtree, other, ignore_errors=True)
        os.chdir(other)
        with self.assertRaisesRegex(ContractError, 'orchestration_environment_mismatch'):
            self.adapter.perform(self.effect({'command': 'run-start', 'request': 'one'}),
                actor='human-one', provenance='orchestrator-project-one')
        self.assertFalse((Path(os.environ['AGENTMUX_HOME']) / 'runs').exists())

    def test_process_start_uses_fixed_selected_agent_without_legacy_warrant(self):
        os.environ['AGENTMUX_ORCHESTRATOR_WARRANT'] = 'legacy-secret'
        completed = subprocess.CompletedProcess([], 0, 'spawned', '')
        with patch('orchestration_owner.domain_adapter.subprocess.run',
                   return_value=completed) as execute:
            result = self.adapter.perform(self.effect({'command': 'orchestrator-start',
                'request': 'one'}), actor='human-one',
                provenance='orchestrator-project-one')
        self.assertEqual(result.outcome, 'applied')
        argv = execute.call_args.args[0]
        self.assertEqual(argv[2:], ['spawn', 'orchestrator-project-one', '--cwd',
            str(self.root), '--agentdef', 'orchestrator-project-one', '--role', 'lead'])
        self.assertNotIn('AGENTMUX_ORCHESTRATOR_WARRANT', execute.call_args.kwargs['env'])
        self.assertEqual(execute.call_args.kwargs['env']['AGENTMUX_OWNER_REQUEST'], 'one')

    def test_unconfirmed_spawn_cleanup_is_an_uncertain_effect(self):
        completed = subprocess.CompletedProcess([], 75, '', 'termination unconfirmed')
        with patch('orchestration_owner.domain_adapter.subprocess.run',
                   return_value=completed):
            with self.assertRaisesRegex(ContractError, 'orchestration_effect_uncertain'):
                self.adapter.perform(self.effect({'command': 'orchestrator-start',
                    'request': 'one'}), actor='human-one',
                    provenance='orchestrator-project-one')

    def test_process_stop_targets_only_the_selected_scoped_session(self):
        with patch.object(self.adapter, '_kill_selected', return_value=True) as kill:
            result = self.adapter.perform(self.effect({'command': 'orchestrator-stop'}),
                actor='human-one', provenance='orchestrator-project-one')
        self.assertEqual(result.outcome, 'applied')
        kill.assert_called_once_with('orchestrator-project-one')

    def test_kill_passes_exact_process_generation_to_existing_safe_kill(self):
        rows = ('9|1700000000|$4|1699999999|%7|701\n'
                '9|1700000000|$4|1699999999|%8|702\n')
        calls = [subprocess.CompletedProcess([], 0, rows, ''),
                 subprocess.CompletedProcess([], 0, "killed 'worker-one'\n", '')]
        with patch('orchestration_owner.domain_adapter.subprocess.run',
                   side_effect=calls) as execute:
            self.assertTrue(self.adapter._kill_selected('worker-one'))
        self.assertEqual(execute.call_count, 2)
        kill_argv = execute.call_args_list[1].args[0]
        self.assertEqual(kill_argv[2:], ['kill', 'worker-one'])
        self.assertEqual(execute.call_args_list[1].kwargs['env']
            ['AGENTMUX_KILL_EXPECTED_TARGET'], rows.rstrip())
        self.assertEqual(execute.call_args_list[1].kwargs['env']
            ['AGENTMUX_OWNER_TERMINATION'], '1')

    def test_process_inspection_error_is_not_treated_as_absence(self):
        failed = subprocess.CompletedProcess([], 1, '', 'permission denied')
        with patch('orchestration_owner.domain_adapter.subprocess.run',
                   return_value=failed):
            with self.assertRaisesRegex(ContractError,
                                        'orchestration_process_identity_unavailable'):
                self.adapter._snapshot('worker-one')

    def test_teardown_releases_and_closes_only_agents_in_the_completed_run(self):
        import run
        import coordination
        run_id = 'abc123'
        directory = run.run_dir(run_id)
        directory.mkdir(parents=True)
        run.complete_path(run_id).write_text('complete\n', encoding='utf-8')
        run.events_path(run_id).write_text('\n'.join((
            json.dumps({'event': 'start', 'detail': 'one'}),
            json.dumps({'event': 'assign', 'job': run_id + '/1',
                        'worker': 'worker-one', 'reviewer': 'reviewer-one'}))) + '\n',
            encoding='utf-8')
        claims = [
            {'resource': 'src/one.py', 'holder': 'worker-one'},
            {'resource': 'src/two.py', 'holder': 'unrelated-agent'}]
        with patch.object(coordination, 'all_claims', return_value=claims), \
                patch.object(coordination, 'cmd_release', return_value=0) as release, \
                patch.object(coordination, 'journal') as journal, \
                patch.object(self.adapter, '_kill_selected', return_value=True) as kill:
            self.assertEqual(self.adapter._teardown(run_id), 0)
        self.assertEqual([call.args[0].holder for call in release.call_args_list],
                         ['worker-one'])
        self.assertEqual([call.args[0] for call in kill.call_args_list],
                         ['worker-one', 'reviewer-one'])
        journal.assert_called_once()

    def test_run_from_another_orchestration_scope_is_refused(self):
        import run
        run_id = 'abc123'
        run.run_dir(run_id).mkdir(parents=True)
        other = dict(self.adapter._owner_binding())
        other['scope'] = dict(other['scope'], projectId='project-two')
        self.adapter._run_binding_path(run_id).write_bytes(
            json.dumps(other, separators=(',', ':'), sort_keys=True).encode())
        with self.assertRaisesRegex(ContractError, 'orchestration_scope_mismatch'):
            self.adapter.perform(self.effect({'command': 'run-complete',
                'runId': run_id}), actor='human-one',
                provenance='orchestrator-project-one')

    def test_claim_refuses_absent_delegated_holder(self):
        command = {'command': 'claim-for', 'resource': 'src/one.py',
                   'holder': 'worker-one', 'ttl': 300, 'note': '',
                   'task': None, 'dependsOn': []}
        with patch('coordination.live_agents', return_value=[]):
            with self.assertRaisesRegex(ContractError,
                                        'orchestration_holder_unavailable'):
                self.adapter.perform(self.effect(command), actor='human-one',
                    provenance='orchestrator-project-one')

    def test_forced_teardown_release_keeps_replacement_holder_and_scope(self):
        from argparse import Namespace
        import coordination
        args = Namespace(resource='src/one.py', holder='worker-one', ttl=300,
            note='', task='', depends_on=[], owner_binding=self.adapter._owner_binding())
        with patch.object(coordination, 'journal', return_value='test'), \
                patch.object(coordination, 'broadcast', return_value=0):
            self.assertEqual(coordination.cmd_claim(args), 0)
            path = coordination.claim_path(args.resource, args.owner_binding)
            replacement = json.loads(path.read_text())
            replacement['holder'] = 'replacement-worker'
            path.write_text(json.dumps(replacement))
            released = coordination.cmd_release(Namespace(resource=args.resource,
                holder='worker-one', force=True, expected_holder='worker-one',
                owner_binding=args.owner_binding))
        self.assertEqual(released, 1)
        self.assertEqual(json.loads(path.read_text())['holder'], 'replacement-worker')

    def test_same_resource_has_independent_claims_per_project_scope(self):
        from argparse import Namespace
        import coordination
        first = self.adapter._owner_binding()
        second = {**first, 'scope': {**first['scope'], 'projectId': 'project-two'}}
        def claim(binding, holder):
            return coordination.cmd_claim(Namespace(resource='src/one.py', holder=holder,
                ttl=300, note='', task='', depends_on=[], owner_binding=binding))
        with patch.object(coordination, 'journal', return_value='test'), \
                patch.object(coordination, 'broadcast', return_value=0):
            self.assertEqual(claim(first, 'worker-one'), 0)
            self.assertEqual(claim(second, 'worker-two'), 0)
        self.assertNotEqual(coordination.claim_path('src/one.py', first),
                            coordination.claim_path('src/one.py', second))
        self.assertEqual(len(coordination.all_claims()), 2)

    def test_renewal_cannot_overwrite_holder_that_replaced_observed_generation(self):
        from argparse import Namespace
        import coordination
        binding = self.adapter._owner_binding()
        args = Namespace(resource='src/one.py', holder='worker-one', ttl=300,
            note='', task='', depends_on=[], owner_binding=binding)
        with patch.object(coordination, 'journal', return_value='test'), \
                patch.object(coordination, 'broadcast', return_value=0):
            self.assertEqual(coordination.cmd_claim(args), 0)
            path = coordination.claim_path(args.resource, binding)
            original_take = coordination.take_generation
            def replace_before_lock(resource, selected):
                changed = json.loads(selected.read_text())
                changed['holder'] = 'worker-two'
                temporary = selected.with_name('.replacement.tmp')
                temporary.write_text(json.dumps(changed))
                os.replace(temporary, selected)
                return original_take(resource, selected)
            with patch.object(coordination, 'take_generation',
                              side_effect=replace_before_lock):
                renewed = coordination.cmd_claim(args)
        self.assertEqual(renewed, 1)
        self.assertEqual(json.loads(path.read_text())['holder'], 'worker-two')

    def test_concurrent_legacy_output_capture_does_not_mix_run_results(self):
        import run
        for run_id in ('abc123', 'def456'):
            run.run_dir(run_id).mkdir(parents=True)
            self.adapter._run_binding_path(run_id).write_bytes(
                json.dumps(self.adapter._owner_binding(), separators=(',', ':'),
                           sort_keys=True).encode())
        effects = [self.effect({'command': 'run-assign', 'runId': run_id,
                    'worker': 'worker-' + str(index),
                    'reviewer': 'reviewer-' + str(index), 'task': None, 'brief': None})
                   for index, run_id in enumerate(('abc123', 'def456'), 1)]
        def printed(command):
            time.sleep(.01)
            print(command['runId'] + '/1')
            return 0
        with patch.object(self.adapter, '_perform', side_effect=printed):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda effect: self.adapter.perform(effect,
                    actor='human-one', provenance='orchestrator-project-one'), effects))
        self.assertEqual([result.private_copy()['result']['jobId'] for result in results],
                         ['abc123/1', 'def456/1'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
