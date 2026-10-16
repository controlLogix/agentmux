"""Pure collector controls. No tool, subprocess, service or installer is run."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


go = load('cohort_go_controls', 'native_go.py')
compose = load('cohort_compose_controls', 'native_compose.py')


class PureCohortControls(unittest.TestCase):
    def test_descriptor_research_selection_requires_actual_named_terminal(self):
        package = go.MODULE + '/runtime'
        name = 'TestDarwinUnlinkedDescriptorResearch'
        for rows in ([dict(Package=package, Action='pass')],
                     [dict(Package=package, Test='TestOther', Action=action) for action in ('run', 'pass')]
                     + [dict(Package=package, Action='pass')],
                     [dict(Package=package, Test=name, Action='run'), dict(Package=package, Action='pass')]):
            self.assertEqual(go.admit_required_events('\n'.join(map(json.dumps, rows)), 0, package, (name,))['status'], 'failed')
        root = Path(__file__).resolve().parents[2] / 'platform/runtime'
        diagnostic = (root / 'snapshot_darwin_descriptor_research_test.go').read_text()
        default = (root / 'snapshot_darwin_test.go').read_text()
        self.assertTrue(diagnostic.startswith('//go:build darwin && agentmux_darwin_descriptor_research\n'))
        self.assertNotIn('func ' + name + '(', default)
        self.assertIn('func TestMain(', default)
        self.assertIn('func TestDarwinProductRemainsFailClosed(', default)

    def setUp(self):
        # Any accidental tool execution fails the control before launch.
        self.guards = [mock.patch.object(go.subprocess, name, side_effect=AssertionError('subprocess forbidden'))
                       for name in ('Popen', 'run', 'check_output', 'check_call', 'call')]
        for guard in self.guards:
            guard.start()
            self.addCleanup(guard.stop)
        self.package = go.MODULE + '/launcher'
        self.names = ('TestOne', 'TestTwo')

    def rows(self):
        return ([{'Package': self.package, 'Action': 'start'}]
                + [dict(Package=self.package, Action=action, Test=name)
                   for name in self.names for action in ('run', 'pass')]
                + [{'Package': self.package, 'Action': 'pass'}])

    def admit(self, rows=None, code=0, stderr=''):
        raw = '\n'.join(json.dumps(row) for row in (self.rows() if rows is None else rows))
        return go.admit_cohort_events(raw, stderr, code, self.package, self.names)

    def sdk_provenance(self, host, selected, observed, version):
        # Execute the actual, unchanged guard block with an in-memory command
        # recorder. No xcrun or other subprocess is launched.
        tree = ast.parse(Path(compose.__file__).read_text())
        qualify = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'qualify')
        blocks = [n for n in ast.walk(qualify) if isinstance(n, ast.If)
                  and any(isinstance(s, ast.Assign) and any(isinstance(t, ast.Subscript)
                          and ast.unparse(t) == "report['nativeSDK']" for t in s.targets) for s in n.body)]
        self.assertEqual(len(blocks), 1)
        invoke = mock.Mock(side_effect=[observed, version])
        scope = {'host': host, 'selected': {'sdkRoot': selected}, 'report': {},
                 'successful': lambda value: value, 'invoke': invoke, 're': compose.re}
        exec(compile(ast.Module(body=blocks, type_ignores=[]), compose.__file__, 'exec'), scope)
        return scope['report'], invoke.call_args_list

    def test_selected_canonical_sdk265_is_queried_explicitly(self):
        sdk = '/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk'
        report, calls = self.sdk_provenance(('darwin', 'arm64'), sdk, sdk, '26.5')
        self.assertEqual(report['nativeSDK'], {'path': sdk, 'version': '26.5'})
        self.assertEqual(calls, [mock.call(['/usr/bin/xcrun', '--sdk', sdk, '--show-sdk-path'], 'sdk-path'),
                                 mock.call(['/usr/bin/xcrun', '--sdk', sdk, '--show-sdk-version'], 'sdk-version')])

    def test_observed_sdk_path_mismatch_is_refused(self):
        with self.assertRaisesRegex(ValueError, '^actual_sdk_differs_from_enrollment$'):
            self.sdk_provenance(('darwin', 'arm64'), '/sdk/MacOSX26.5.sdk', '/sdk/MacOSX27.sdk', '27.0')

    def test_observed_sdk_version_must_remain_numeric(self):
        for version in ('', 'unknown', '26.5\nprivate', '26.5-beta'):
            with self.assertRaisesRegex(ValueError, '^actual_sdk_differs_from_enrollment$'):
                self.sdk_provenance(('darwin', 'arm64'), '/sdk/MacOSX26.5.sdk', '/sdk/MacOSX26.5.sdk', version)

    def test_linux_sdk_query_absent_and_explicit_sdk27_still_supported(self):
        report, calls = self.sdk_provenance(('linux', 'amd64'), '', '', '')
        self.assertEqual(report, {})
        self.assertEqual(calls, [])
        sdk = '/sdk/MacOSX27.sdk'
        report, calls = self.sdk_provenance(('darwin', 'arm64'), sdk, sdk, '27.0')
        self.assertEqual(report['nativeSDK'], {'path': sdk, 'version': '27.0'})
        self.assertEqual(calls[0], mock.call(['/usr/bin/xcrun', '--sdk', sdk, '--show-sdk-path'], 'sdk-path'))

    def test_exact_complete_names_pass(self):
        result = self.admit()
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(len(result['namedResults']), 4)

    def test_missing_skip_failure_and_nonzero_refused(self):
        for action in ('skip', 'fail'):
            rows = self.rows(); rows[2]['Action'] = action
            self.assertEqual(self.admit(rows)['status'], 'failed')
        self.assertEqual(self.admit(self.rows()[:3] + self.rows()[-1:])['status'], 'failed')
        self.assertEqual(self.admit(code=1)['status'], 'failed')

    def test_unexpected_duplicate_and_unjoined_tests_refused(self):
        for extra in ([dict(Package=self.package, Action=a, Test='TestExtra') for a in ('run', 'pass')],
                      self.rows()[1:3], [dict(Package=self.package, Action='run', Test='TestOne/unjoined')]):
            self.assertEqual(self.admit(self.rows()[:-1] + extra + self.rows()[-1:])['status'], 'failed')

    def test_complete_subtests_pass_but_orphan_does_not(self):
        extra = [dict(Package=self.package, Action=a, Test='TestOne/child') for a in ('run', 'pass')]
        self.assertEqual(self.admit(self.rows()[:2] + extra + self.rows()[2:])['status'], 'passed')
        extra = [dict(Package=self.package, Action=a, Test='TestForeign/child') for a in ('run', 'pass')]
        self.assertEqual(self.admit(self.rows()[:-1] + extra + self.rows()[-1:])['status'], 'failed')

    def test_child_cannot_start_after_parent_terminal(self):
        extra = [dict(Package=self.package, Action=a, Test='TestOne/child') for a in ('run', 'pass')]
        result = self.admit(self.rows()[:-1] + extra + self.rows()[-1:])
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['topLevelOwnershipAndJoinOrderVerified'])

    def test_parent_cannot_finish_with_active_descendant(self):
        event = lambda name, action: dict(Package=self.package, Test=name, Action=action)
        rows = [self.rows()[0], event('TestOne', 'run'), event('TestOne/child', 'run'),
                event('TestOne', 'pass'), event('TestOne/child', 'pass'), *self.rows()[3:]]
        result = self.admit(rows)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['topLevelOwnershipAndJoinOrderVerified'])

    def test_slash_prefix_sequences_do_not_prove_nested_parentage(self):
        # Historical review: these sequences were wrongly rejected as nested
        # parent violations. Go JSON also permits them as opaque sibling names.
        event = lambda name, action: dict(Package=self.package, Test=name, Action=action)
        for order in (
            [('TestOne', 'run'), ('TestOne/child', 'run'), ('TestOne/child', 'pass'),
             ('TestOne/child/grandchild', 'run'), ('TestOne/child/grandchild', 'pass'), ('TestOne', 'pass')],
            [('TestOne', 'run'), ('TestOne/child', 'run'), ('TestOne/child/grandchild', 'run'),
             ('TestOne/child', 'pass'), ('TestOne/child/grandchild', 'pass'), ('TestOne', 'pass')]):
            result = self.admit([self.rows()[0], *(event(*item) for item in order), *self.rows()[3:]])
            self.assertEqual(result['status'], 'passed')
            self.assertTrue(result['topLevelOwnershipAndJoinOrderVerified'])
            self.assertEqual(result['parentageScope'], 'top-level-ownership')
            self.assertFalse(result['nestedParentageVerified'])

    def test_actual_contained_path_slash_siblings_are_opaque(self):
        package = go.MODULE + '/kernel/assembly'
        event = lambda name, action: dict(Package=package, Test=name, Action=action)
        rows = [dict(Package=package, Action='start'), event('TestContainedPaths', 'run')]
        for suffix in ('..', '../outside', '/bin/sh', 'bin/../bin/boot'):
            rows += [event('TestContainedPaths/' + suffix, action) for action in ('run', 'pass')]
        rows += [event('TestContainedPaths', 'pass'), dict(Package=package, Action='pass')]
        result = go.admit_cohort_events('\n'.join(map(json.dumps, rows)), '', 0, package, ('TestContainedPaths',))
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['parentageScope'], 'top-level-ownership')
        self.assertFalse(result['nestedParentageVerified'])
        self.assertTrue(result['parentageLimits'])
        self.assertTrue(result['topLevelOwnershipAndJoinOrderVerified'])
        self.assertNotIn('hierarchyOrderValid', result)

    def test_subtest_lifecycle_requires_active_top_owner(self):
        event = lambda name, action: dict(Package=self.package, Test=name, Action=action)
        for action in ('run', 'pause', 'cont', 'pass', 'fail', 'skip'):
            rows = self.rows()[:-1] + [event('TestOne/opaque/name', action), self.rows()[-1]]
            result = self.admit(rows)
            self.assertEqual(result['status'], 'failed')
            self.assertFalse(result['topLevelOwnershipAndJoinOrderVerified'])
        rows = [self.rows()[0], event('TestOne/opaque/name', 'run'), *self.rows()[1:]]
        self.assertFalse(self.admit(rows)['topLevelOwnershipAndJoinOrderVerified'])

    def test_package_terminal_cannot_leave_active_owned_names(self):
        rows = [self.rows()[0], self.rows()[1],
                dict(Package=self.package, Test='TestOne/opaque//name', Action='run'), self.rows()[-1]]
        result = self.admit(rows)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['topLevelOwnershipAndJoinOrderVerified'])

    def test_valid_parallel_siblings_and_nested_slash_names_pass(self):
        event = lambda name, action: dict(Package=self.package, Test=name, Action=action)
        order = [('TestOne', 'run'), ('TestOne', 'pause'), ('TestTwo', 'run'),
                 ('TestTwo/slash/name', 'run'), ('TestTwo/slash/name', 'pause'),
                 ('TestTwo/other', 'run'), ('TestTwo/other', 'pause'),
                 ('TestTwo/slash/name', 'cont'), ('TestTwo/other', 'cont'),
                 ('TestTwo/other', 'pass'), ('TestTwo/slash/name', 'pass'), ('TestTwo', 'pass'),
                 ('TestOne', 'cont'), ('TestOne/child', 'run'),
                 ('TestOne/child/grandchild', 'run'), ('TestOne/child/grandchild', 'pass'),
                 ('TestOne/child', 'pass'), ('TestOne', 'pass')]
        result = self.admit([self.rows()[0], *(event(*item) for item in order), self.rows()[-1]])
        self.assertEqual(result['status'], 'passed')
        self.assertTrue(result['topLevelOwnershipAndJoinOrderVerified'])

    def test_bad_package_boundaries_and_race_refused(self):
        for rows in (self.rows()[1:], self.rows()[:-1], self.rows() + [self.rows()[0]],
                     self.rows() + [dict(Package=self.package, Action='output', Output='late')]):
            self.assertEqual(self.admit(rows)['status'], 'failed')
        self.assertEqual(self.admit(stderr='WARNING: DATA RACE')['status'], 'failed')

    def test_malformed_duplicate_fields_and_foreign_package_refused(self):
        for raw in ('[]', 'null', 'not json', '{"Package":"x","Package":"y","Action":"start"}'):
            self.assertEqual(go.admit_cohort_events(raw, '', 0, self.package, self.names)['status'], 'failed')
        rows = self.rows(); rows[1]['Package'] = 'foreign'
        self.assertEqual(self.admit(rows)['status'], 'failed')

    def test_fixed_cohort_names_and_anchoring(self):
        self.assertEqual([len(v[3]) for v in go.DARWIN_COHORTS.values()], [4, 2, 6, 6, 1, 2, 1, 3, 1, 7, 2, 3, 1])
        for package, tags, budget, names in go.DARWIN_COHORTS.values():
            self.assertTrue(go.cohort_pattern(names).startswith('^('))
            self.assertTrue(go.cohort_pattern(names).endswith(')$'))
        for names in ((), ('TestOne', 'TestOne'), ('TestOne.*',)):
            with self.assertRaises(ValueError): go.cohort_pattern(names)

    def test_actual_source_inventory_contains_every_frozen_name_once(self):
        # Read source only; no Go inventory/build is executed.
        root = Path(__file__).resolve().parents[2] / 'platform'
        for cohort, (package, tags, budget, names) in go.DARWIN_COHORTS.items():
            files = {
                'darwin-frontend-budget': ['main_frontend_budget_common_test.go'],
                'darwin-frontend-receipt': ['main_child_exit_darwin_test.go'],
                'darwin-signed-role-lifecycle': ['startup_session_lifecycle_darwin_test.go', 'session_cleanup_lifecycle_darwin_test.go'],
                'darwin-installed-cli': ['installed_cli_compose_scenarios_darwin_test.go'],
                'darwin-installed-cli-port': ['installed_cli_compose_port_darwin_test.go'],
                'darwin-creator-history': ['bootstrap_history_darwin_test.go', 'host_history_policy_darwin_test.go'],
                'darwin-startup-owner': ['installed_cli_compose_startup_owner_darwin_test.go'],
                'darwin-runtime-rollback': ['supervisor_rollback_darwin_test.go'],
                'darwin-normal-self': ['normal_admission_darwin_test.go'],
                'darwin-normal-identity': ['protected_normal_darwin_test.go'],
                'darwin-normal-parent': ['runtime_parent_normal_darwin_test.go'],
                'darwin-live-role-recovery': ['signed_role_live_process_darwin_test.go'],
                'darwin-installed-cli-slow-consumer': ['installed_cli_compose_slow_consumer_darwin_test.go'],
            }[cohort]
            raw = json.dumps({'ImportPath': go.MODULE + '/' + package[2:], 'TestGoFiles': files})
            result = go.validate_cohort_inventory(raw, root, cohort)
            self.assertEqual(result['requiredTests'], list(names))

    def test_missing_duplicate_or_unsafe_inventory_refused(self):
        cohort = 'darwin-frontend-budget'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); directory = root / 'cmd/agentmux-runtime'; directory.mkdir(parents=True)
            path = directory / 'controls_test.go'
            names = go.DARWIN_COHORTS[cohort][3]
            text = '\n'.join('func ' + n + '(t *testing.T) {}' for n in names)
            record = {'ImportPath': go.MODULE + '/cmd/agentmux-runtime', 'TestGoFiles': [path.name]}
            for body in (text.replace(names[0], 'TestMissing'), text + '\nfunc ' + names[0] + '(t *testing.T) {}'):
                path.write_text(body)
                with self.assertRaises(ValueError): go.validate_cohort_inventory(json.dumps(record), root, cohort)
            record['TestGoFiles'] = ['../outside.go']
            with self.assertRaises(ValueError): go.validate_cohort_inventory(json.dumps(record), root, cohort)

    def test_environment_is_whitelisted_and_authorizations_scoped(self):
        base = {'HOME': '/private/home', 'AGENTMUX_TEST_NATS': '/tools/nats', 'CGO_ENABLED': '1',
                'SECRET': 'never', 'DYLD_INSERT_LIBRARIES': 'never', 'AMX_DARWIN_INSTALL_AUTHORIZED': '1',
                'AMX_DARWIN_CLI_BUILD_AUTHORIZED': '1', 'DOCKER_CONFIG': '/private/docker',
                'AMX_BOOTSTRAP_DOCKER_AUTHORIZED': '1', 'AMX_BOOTSTRAP_SELECTION_FILE': '/private/selection',
                'AMX_BOOTSTRAP_SELECTION_SHA256': 'a' * 64}
        env = compose.cohort_environment(base, 'darwin-frontend-budget', {}, Path('/private/out'), 'b' * 64)
        self.assertEqual(set(env), {'HOME', 'AGENTMUX_TEST_NATS', 'CGO_ENABLED'})
        member = {'path': '/protected/child', 'sha256': 'c' * 64}
        groups = {'frontendReceiptChild': {'members': {'agentmux-frontend-receipt-fixture': member}}}
        env = compose.cohort_environment(base, 'darwin-frontend-receipt', groups, Path('/private/out'), 'b' * 64)
        self.assertEqual(env['AMX_DARWIN_FRONTEND_RECEIPT_SHA256'], 'sha256:' + 'c' * 64)
        self.assertNotIn('DOCKER_CONFIG', env)
        self.assertNotIn('AMX_DARWIN_INSTALL_AUTHORIZED', env)

    def test_signed_environment_uses_distinct_cli_and_role_plans(self):
        ref = lambda p: {'path': p, 'sha256': 'a' * 64}
        groups = {'signedRelease': {'plan': ref('/prepared'), 'policy': ref('/policy'), 'cliInstallPlan': ref('/cli')}}
        base = {k: 'selected' for k in ('DOCKER_CONFIG', 'AMX_BOOTSTRAP_DOCKER_AUTHORIZED', 'AMX_BOOTSTRAP_SELECTION_FILE', 'AMX_BOOTSTRAP_SELECTION_SHA256')}
        env = compose.cohort_environment(base, 'darwin-installed-cli', groups, Path('/out'), 'b' * 64)
        self.assertEqual(env['AMX_DARWIN_CLI_INSTALL_PLAN'], '/cli')
        self.assertEqual(env['AMX_DARWIN_ROLE_RELEASE_PLAN'], '/prepared')
        env = compose.cohort_environment({}, 'darwin-signed-role-lifecycle', groups, Path('/out'), 'b' * 64)
        self.assertEqual(env['AMX_DARWIN_LIFECYCLE_NATS_SHA256'], 'sha256:' + 'b' * 64)
        self.assertNotIn('AMX_DARWIN_CLI_INSTALL_PLAN', env)

    def test_live_recovery_and_slow_consumer_exact_selection_and_groups(self):
        expected = {
            'darwin-live-role-recovery': (900, (
                'TestSignedDarwinLiveRolesLateSnapshotDegradationAndWholeGroupRecovery',
                'TestSignedDarwinLiveTLSBrokerRecoveryPreservesOwnedRoles',
                'TestSignedDarwinLiveTLSBrokerReconnectExhaustionIsBounded')),
            'darwin-installed-cli-slow-consumer': (1200, (
                'TestInstalledCLIDarwinRealComposeSlowConsumerIsolationAndRecovery',)),
        }
        for cohort, (budget, names) in expected.items():
            self.assertEqual(go.DARWIN_COHORTS[cohort], ('./launcher', 'agentmux_bootstrap_docker', budget, names))
            self.assertEqual(compose.cohort_groups(cohort), ('signedRelease',))
            for missing in names:
                rows = [dict(Package=self.package, Action='start')]
                rows += [dict(Package=self.package, Test=name, Action=action)
                         for name in names if name != missing for action in ('run', 'pass')]
                rows += [dict(Package=self.package, Action='pass')]
                self.assertEqual(go.admit_cohort_events('\n'.join(map(json.dumps, rows)), '', 0,
                                                       self.package, names)['status'], 'failed')

    def test_live_recovery_environment_matches_lifecycle_without_cli_or_engine(self):
        ref = lambda p: {'path': p, 'sha256': 'a' * 64}
        groups = {'signedRelease': {'plan': ref('/prepared'), 'policy': ref('/policy'), 'cliInstallPlan': ref('/cli')}}
        base = {'AGENTMUX_TEST_NATS': '/tools/nats', 'CGO_ENABLED': '1', 'SECRET': 'forbidden',
                'DOCKER_CONFIG': '/forbidden', 'AMX_DARWIN_CLI_INSTALL_PLAN': '/forbidden'}
        actual = compose.cohort_environment(base, 'darwin-live-role-recovery', groups, Path('/out'), 'b' * 64)
        self.assertEqual(actual, compose.cohort_environment(base, 'darwin-signed-role-lifecycle', groups, Path('/out'), 'b' * 64))
        self.assertEqual(set(actual), {'AGENTMUX_TEST_NATS', 'CGO_ENABLED', 'AMX_DARWIN_ROLE_RELEASE_PLAN',
                                      'AMX_DARWIN_REVIEWED_ROLE_RELEASE_PLAN', 'AMX_DARWIN_ROLE_RELEASE_POLICY',
                                      'AMX_DARWIN_REVIEWED_ROLE_RELEASE_POLICY', 'AMX_DARWIN_LIFECYCLE_NATS_SHA256',
                                      'AGENTMUX_TEST_LIFECYCLE_OUTPUT'})
        self.assertEqual(actual['AMX_DARWIN_LIFECYCLE_NATS_SHA256'], 'sha256:' + 'b' * 64)
        self.assertEqual(actual['AGENTMUX_TEST_LIFECYCLE_OUTPUT'], '/out')
        self.assertNotIn('darwin-live-role-recovery', compose.DOCKER_COHORTS)

    def test_slow_consumer_uses_existing_cli_engine_pipeline_and_limits(self):
        ref = lambda p: {'path': p, 'sha256': 'a' * 64}
        groups = {'signedRelease': {'plan': ref('/prepared'), 'policy': ref('/policy'), 'cliInstallPlan': ref('/cli')}}
        base = {k: 'selected' for k in ('AGENTMUX_TEST_NATS', 'DOCKER_CONFIG', 'AMX_BOOTSTRAP_DOCKER_AUTHORIZED',
                                      'AMX_BOOTSTRAP_SELECTION_FILE', 'AMX_BOOTSTRAP_SELECTION_SHA256')}
        self.assertIn('darwin-installed-cli-slow-consumer', compose.DOCKER_COHORTS)
        actual = compose.cohort_environment(base, 'darwin-installed-cli-slow-consumer', groups, Path('/out'), 'b' * 64)
        self.assertEqual(actual, compose.cohort_environment(base, 'darwin-installed-cli', groups, Path('/out'), 'b' * 64))
        self.assertNotIn('AGENTMUX_TEST_LIFECYCLE_OUTPUT', actual)
        self.assertEqual(actual['AMX_DARWIN_CLI_INSTALL_PLAN'], '/cli')
        source = Path(compose.__file__).read_text()
        self.assertIn('Only the named cohort passed; omitted cohorts and full P02 remain unqualified.', source)
        self.assertIn("phaseAccepted=False", source)

    def test_frozen_extensions_never_select_diagnostic_parent_tests(self):
        expected = {
            'darwin-creator-history': ('./launcher', 'agentmux_darwin_install', ('frontendReceiptChild',), 2),
            'darwin-startup-owner': ('./launcher', 'agentmux_bootstrap_docker', ('signedRelease',), 1),
            'darwin-runtime-rollback': ('./runtime', 'agentmux_bootstrap_docker,agentmux_darwin_runtime_fixture', ('runtimeFixture',), 3),
        }
        for cohort, (package, tags, groups, count) in expected.items():
            actual = go.DARWIN_COHORTS[cohort]
            self.assertEqual(actual[:2], (package, tags))
            self.assertEqual(len(actual[3]), count)
            self.assertEqual(compose.cohort_groups(cohort), groups)
        for package, tags, budget, names in go.DARWIN_COHORTS.values():
            self.assertNotIn('candidate', tags)
            self.assertTrue(all('RuntimeCandidateParent' not in n for n in names))

    def test_final_normal_cohorts_have_exact_names_tags_and_groups(self):
        package = './internal/darwinfixtureidentity'
        expected = {
            'darwin-normal-self': ('agentmux_bootstrap_docker,agentmux_darwin_identity_normal_probe', (),
                                   ('TestNormalAdmissionSelfSDK265',)),
            'darwin-normal-identity': ('agentmux_bootstrap_docker,agentmux_darwin_identity_protected_normal',
                                       ('cooperativeIdentity',), tuple('TestProtectedNormal' + suffix for suffix in (
                                           'LoaderAdmission', 'FastCompletion', 'WrongDigest', 'InvalidArguments',
                                           'ReparentedRoles', 'HostRefusals', 'RoleRosterRefusals'))),
            'darwin-normal-parent': ('agentmux_bootstrap_docker,agentmux_darwin_identity_protected_normal,agentmux_darwin_runtime_fixture',
                                     ('runtimeFixture',), ('TestRuntimeNormalParentEOFStopsActualChild',
                                                          'TestRuntimeNormalParentInheritedLeasesLastUntilOwnedReap')),
        }
        for cohort, (tags, groups, names) in expected.items():
            actual = go.DARWIN_COHORTS[cohort]
            self.assertEqual(actual, (package, tags, 180, names))
            self.assertEqual(compose.cohort_groups(cohort), groups)
            self.assertNotIn(cohort, compose.DOCKER_COHORTS)
            self.assertTrue(all(tag.startswith('agentmux_') for tag in tags.split(',')))
            self.assertNotIn('candidate', tags)

    def test_normal_self_requires_no_artifact_and_drops_fixture_inputs(self):
        bundle = {'schemaVersion': '2.0.0', 'target': 'darwin-arm64', 'currentTupleSHA256': 'a' * 64, 'groups': {}}
        self.assertEqual(compose.validate_cohort_bundle(bundle, 'darwin-normal-self', 'a' * 64), {})
        base = {'HOME': '/private/home', 'CGO_ENABLED': '1', 'AGENTMUX_IDENTITY_FIXTURE_PATH': 'unreviewed',
                'AGENTMUX_RUNTIME_FIXTURE_AUTHORIZED': '1', 'AMX_DARWIN_CLI_BUILD_AUTHORIZED': '1'}
        env = compose.cohort_environment(base, 'darwin-normal-self', {}, Path('/out'), 'b' * 64)
        self.assertEqual(env, {'HOME': '/private/home', 'CGO_ENABLED': '1'})
        for cohort in ('darwin-normal-identity', 'darwin-normal-parent'):
            with self.assertRaises(ValueError): compose.validate_cohort_bundle(bundle, cohort, 'a' * 64)

    def test_normal_identity_adds_only_its_two_pinned_inputs(self):
        groups = {'cooperativeIdentity': {'members': {'fixture': {'path': '/protected/fixture', 'sha256': 'd' * 64}}}}
        base = {'CGO_ENABLED': '1', 'AGENTMUX_RUNTIME_FIXTURE_PATH': 'unreviewed',
                'AGENTMUX_IDENTITY_FIXTURE_DIGEST': 'unreviewed', 'AMX_DARWIN_INSTALL_AUTHORIZED': '1'}
        env = compose.cohort_environment(base, 'darwin-normal-identity', groups, Path('/out'), 'b' * 64)
        self.assertEqual(env, {'CGO_ENABLED': '1', 'AGENTMUX_IDENTITY_FIXTURE_PATH': '/protected/fixture',
                               'AGENTMUX_IDENTITY_FIXTURE_DIGEST': 'sha256:' + 'd' * 64})

    def test_normal_parent_adds_only_its_three_runtime_inputs(self):
        groups = {'runtimeFixture': {'members': {'runtime-fixture': {'path': '/protected/runtime-fixture', 'sha256': 'e' * 64}}}}
        base = {'CGO_ENABLED': '1', 'AGENTMUX_IDENTITY_FIXTURE_PATH': 'unreviewed',
                'AGENTMUX_RUNTIME_FIXTURE_DIGEST': 'unreviewed', 'DOCKER_CONFIG': '/forbidden'}
        env = compose.cohort_environment(base, 'darwin-normal-parent', groups, Path('/out'), 'b' * 64)
        self.assertEqual(env, {'CGO_ENABLED': '1', 'AGENTMUX_RUNTIME_FIXTURE_AUTHORIZED': '1',
                               'AGENTMUX_RUNTIME_FIXTURE_PATH': '/protected/runtime-fixture',
                               'AGENTMUX_RUNTIME_FIXTURE_DIGEST': 'sha256:' + 'e' * 64})

    def test_runtime_fixture_environment_has_only_its_three_authorizations(self):
        groups = {'runtimeFixture': {'members': {'runtime-fixture': {'path': '/protected/runtime-fixture', 'sha256': 'd' * 64}}}}
        base = {'AGENTMUX_IDENTITY_FIXTURE_PATH': 'forbidden', 'AMX_DARWIN_FRONTEND_RECEIPT_AUTHORIZED': '1',
                'AMX_DARWIN_CLI_BUILD_AUTHORIZED': '1', 'GOFLAGS': '', 'CGO_ENABLED': '1'}
        env = compose.cohort_environment(base, 'darwin-runtime-rollback', groups, Path('/out'), 'b' * 64)
        self.assertEqual(set(env) - {'GOFLAGS', 'CGO_ENABLED'}, {
            'AGENTMUX_RUNTIME_FIXTURE_AUTHORIZED', 'AGENTMUX_RUNTIME_FIXTURE_PATH', 'AGENTMUX_RUNTIME_FIXTURE_DIGEST'})
        self.assertEqual(env['AGENTMUX_RUNTIME_FIXTURE_DIGEST'], 'sha256:' + 'd' * 64)
        self.assertEqual(env['AGENTMUX_RUNTIME_FIXTURE_PATH'], '/protected/runtime-fixture')

    def test_creator_history_reuses_receipt_child_without_docker_authorization(self):
        groups = {'frontendReceiptChild': {'members': {'agentmux-frontend-receipt-fixture': {'path': '/protected/receipt', 'sha256': 'e' * 64}}}}
        env = compose.cohort_environment({'DOCKER_CONFIG': '/forbidden', 'AMX_BOOTSTRAP_DOCKER_AUTHORIZED': '1'},
                                         'darwin-creator-history', groups, Path('/out'), 'b' * 64)
        self.assertEqual(set(env), {'AMX_DARWIN_FRONTEND_RECEIPT_AUTHORIZED',
                                   'AMX_DARWIN_FRONTEND_RECEIPT_FIXTURE', 'AMX_DARWIN_FRONTEND_RECEIPT_SHA256'})

    def test_startup_owner_uses_same_engine_pipeline_and_signed_cli_inputs(self):
        self.assertEqual(set(compose.DOCKER_COHORTS), {'darwin-installed-cli', 'darwin-installed-cli-port', 'darwin-startup-owner',
                                                     'darwin-installed-cli-slow-consumer'})
        ref = lambda p: {'path': p, 'sha256': 'a' * 64}
        groups = {'signedRelease': {'plan': ref('/prepared'), 'policy': ref('/policy'), 'cliInstallPlan': ref('/cli')}}
        base = {k: 'selected' for k in ('DOCKER_CONFIG', 'AMX_BOOTSTRAP_DOCKER_AUTHORIZED', 'AMX_BOOTSTRAP_SELECTION_FILE', 'AMX_BOOTSTRAP_SELECTION_SHA256')}
        env = compose.cohort_environment(base, 'darwin-startup-owner', groups, Path('/out'), 'b' * 64)
        self.assertEqual(env['DOCKER_CONFIG'], 'selected')
        self.assertEqual(env['AMX_DARWIN_CLI_INSTALL_PLAN'], '/cli')
        self.assertEqual(env['AMX_DARWIN_ROLE_RELEASE_POLICY'], '/policy')
        self.assertNotIn('AGENTMUX_RUNTIME_FIXTURE_AUTHORIZED', env)

    def test_bundle_scope_tuple_and_purpose_cannot_be_swapped(self):
        bundle = {'schemaVersion': '2.0.0', 'target': 'darwin-arm64', 'currentTupleSHA256': 'a' * 64, 'groups': {}}
        self.assertEqual(compose.validate_cohort_bundle(bundle, 'darwin-frontend-budget', 'a' * 64), {})
        for cohort, pin in (('darwin-frontend-receipt', 'a' * 64), ('darwin-frontend-budget', 'b' * 64)):
            with self.assertRaises(ValueError): compose.validate_cohort_bundle(bundle, cohort, pin)
        for extra in ('environment', 'installer', 'unknownGroup'):
            wrong = copy.deepcopy(bundle); wrong[extra] = {}
            with self.assertRaises(ValueError): compose.validate_cohort_bundle(wrong, 'darwin-frontend-budget', 'a' * 64)
        wrong = copy.deepcopy(bundle); wrong['groups'] = {'frontendReceiptChild': {'purpose': 'signedRelease'}}
        with self.assertRaises(ValueError): compose.validate_cohort_bundle(wrong, 'darwin-frontend-receipt', 'a' * 64)

    def test_private_reference_requires_exact_pin_and_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            p = Path(temporary) / 'ref.json'; p.write_text('{"kind":"review"}'); p.chmod(0o600)
            ref = {'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
            self.assertEqual(compose.pinned_reference(ref), {'kind': 'review'})
            p.chmod(0o644)
            with self.assertRaises(ValueError): compose.pinned_reference(ref)
            p.chmod(0o600); ref['sha256'] = '0' * 64
            with self.assertRaises(ValueError): compose.pinned_reference(ref)

    def test_legacy_selectors_and_safe_files_unchanged(self):
        self.assertEqual(len(compose.NAMES), 4)
        self.assertEqual(len(go.DARWIN_INSTALL_NAMES), 4)
        self.assertEqual(len(go.DARWIN_HOST_NAMES), 3)
        self.assertNotIn('darwin-occupied-port-result.json', compose.SAFE_FILES)
        self.assertNotIn('agentmux-frontend-receipt-fixture', compose.SAFE_FILES)

    def test_existing_self_test_invocations_keep_their_paths(self):
        # Do not execute the legacy suite here: some runner controls have their
        # own mocked subprocess fixtures. Only test argument routing.
        with mock.patch.object(unittest.TextTestRunner, 'run', return_value=SimpleNamespace(wasSuccessful=lambda: True)):
            self.assertEqual(compose.main(['--self-test']), 0)
            self.assertEqual(go.main(['--self-test']), 0)

    def test_cohort_and_install_mode_cannot_be_combined(self):
        with mock.patch.object(sys, 'stderr'), self.assertRaises(SystemExit) as caught:
            compose.main(['--darwin-cohort', 'darwin-frontend-budget', '--allow-protected-fixture-install'])
        self.assertEqual(caught.exception.code, 2)

    def test_three_artifact_groups_are_independent_and_pinned(self):
        pin = 'a' * 64
        root = '/Library/Application Support/Agentmux/Protected/releases/' + 'b' * 64
        rosters = {
            'frontendReceiptChild': ['agentmux-frontend-receipt-fixture'],
            'cooperativeIdentity': ['fixture', 'bin/boot', 'bin/kernel-lifecycle', 'bin/internal-communication', 'bin/exported-status'],
            'signedRelease': ['release-manifest.json', 'protected-assembly.json', 'release-authorization.json',
                              'release-authorization.sig', 'bin/boot', 'bin/kernel-lifecycle', 'bin/internal-communication',
                              'bin/exported-status', 'agentmux-runtime'],
            'runtimeFixture': ['runtime-fixture', 'bin/boot', 'bin/kernel-lifecycle', 'bin/internal-communication', 'bin/exported-status'],
        }
        references, contents, groups = {}, {}, {}
        def ref(name, record):
            path = '/private/' + name
            references[path] = record
            return {'path': path, 'sha256': 'c' * 64}
        for purpose, names in rosters.items():
            artifact_purpose = compose.RUNTIME_FIXTURE_PURPOSE if purpose == 'runtimeFixture' else purpose
            members = {}
            for name in names:
                # Separate releases prevent coincidental equal bytes conferring a shared purpose.
                directory = root[:-64] + hashlib.sha256(purpose.encode()).hexdigest()
                path = directory + '/' + name
                raw = (purpose if purpose == 'runtimeFixture' else purpose + name).encode(); contents[path] = raw
                members[name] = {'path': path, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
            directory = str(Path(next(iter(members.values()))['path']).parent)
            policy = {'packageDirectory': directory}
            plan = {'releaseDirectory': directory, 'publicTrust': policy}
            if purpose == 'runtimeFixture': plan['purpose'] = compose.RUNTIME_FIXTURE_PURPOSE
            g = {'purpose': artifact_purpose, 'members': members, 'plan': ref(purpose + '-plan', plan), 'policy': None, 'cliInstallPlan': None}
            for field, kind in (('installationReceipt', 'installation'), ('candidateMatch', 'candidateMatch')):
                g[field] = ref(purpose + field, {'schemaVersion': '1.0.0', 'kind': kind, 'purpose': artifact_purpose,
                    'status': 'passed', 'currentTupleSHA256': pin, 'members': members,
                    'evidence': ref(purpose + kind + '-raw', {'original': 'retained'})})
            if purpose == 'signedRelease':
                g['policy'] = ref('policy', policy)
                m = members['agentmux-runtime']
                g['cliInstallPlan'] = ref('cli', {'destination': m['path'], 'digest': 'sha256:' + m['sha256'], 'bytes': m['bytes']})
            groups[purpose] = g
        bundle = {'schemaVersion': '2.0.0', 'target': 'darwin-arm64', 'currentTupleSHA256': pin, 'groups': groups}
        def info(path):
            return SimpleNamespace(st_mode=(stat.S_IFREG | 0o555 if str(path) in contents else stat.S_IFDIR | 0o755), st_uid=0, st_nlink=1)
        with mock.patch.object(compose, 'pinned_reference', side_effect=lambda r: references[r['path']]), \
             mock.patch.object(Path, 'lstat', info), \
             mock.patch.object(compose, 'read_stable_file', side_effect=lambda p, maximum: contents[str(p)]):
            self.assertEqual(set(compose.validate_cohort_bundle(bundle, 'darwin-installed-cli', pin)), set(rosters))
            self.assertEqual(set(compose.validate_cohort_bundle(bundle, 'darwin-runtime-rollback', pin)), set(rosters))
            runtime = groups['runtimeFixture']
            original_purpose = runtime['purpose']
            for wrong_purpose in ('runtimeFixture', 'cooperativeIdentity', 'signedRelease', 'frontendReceiptChild'):
                runtime['purpose'] = wrong_purpose
                with self.assertRaises(ValueError): compose.validate_cohort_bundle(bundle, 'darwin-runtime-rollback', pin)
            runtime['purpose'] = original_purpose
            plan = references[runtime['plan']['path']]
            plan['purpose'] = 'cooperativeIdentity'
            with self.assertRaises(ValueError): compose.validate_cohort_bundle(bundle, 'darwin-runtime-rollback', pin)
            plan['purpose'] = compose.RUNTIME_FIXTURE_PURPOSE
            for field in ('purpose', 'currentTupleSHA256', 'status', 'members'):
                record = references[groups['signedRelease']['candidateMatch']['path']]
                original = copy.deepcopy(record)
                record[field] = 'wrong'
                with self.assertRaises(ValueError): compose.validate_cohort_bundle(bundle, 'darwin-installed-cli', pin)
                record.clear(); record.update(original)
            wrong = copy.deepcopy(bundle)
            wrong['groups']['signedRelease']['members'] = groups['cooperativeIdentity']['members']
            with self.assertRaises(ValueError): compose.validate_cohort_bundle(wrong, 'darwin-installed-cli', pin)

    def test_cohort_runner_checkpoints_pass_failure_and_timeout_without_tools(self):
        cohort = 'darwin-frontend-budget'
        package, tags, budget, names = go.DARWIN_COHORTS[cohort]
        for outcome in ('passed', 'failed', 'timeout'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); source = root / 'source'; folder = source / 'platform/cmd/agentmux-runtime'
                folder.mkdir(parents=True)
                file = folder / 'controls_test.go'
                file.write_text('\n'.join('func ' + name + '(t *testing.T) {}' for name in names))
                home, evidence = root / 'home', root / 'evidence'; home.mkdir(); evidence.mkdir()
                args = SimpleNamespace(darwin_cohort=cohort, cohort_prerequisites=None, cohort_prerequisites_sha256=None,
                    workspace=root, evidence=evidence, candidate_commit='candidate', engine_lease=None,
                    selection=root / 'selection', selection_sha256='a' * 64, prerequisites=root / 'prereq', prerequisites_sha256='b' * 64)
                prereq = {'goExecutable': '/tools/go', 'goSHA256': 'g', 'natsSHA256': 'n', 'compilerSHA256': 'c'}
                selected = {'target': 'native-darwin'}
                report = {'sourceCommit': 'candidate', 'sourceHashes': {}, 'compilerVersion': 'clang', 'nativeSDK': {}, 'limits': []}
                executed = {file.relative_to(source).as_posix(): compose.digest(file)}
                calls = []
                def invoke(command, label, maximum):
                    calls.append((command, label, maximum))
                    out, err = root / (label + '.out'), root / (label + '.err'); err.write_text('')
                    if label == 'cohort-inventory':
                        out.write_text(json.dumps({'ImportPath': go.MODULE + '/cmd/agentmux-runtime', 'TestGoFiles': [file.name]}))
                    else:
                        rows = [{'Action': 'start', 'Package': go.MODULE + '/cmd/agentmux-runtime'}]
                        for name in names:
                            rows.extend(dict(Action=a, Package=rows[0]['Package'], Test=name) for a in ('run', 'pass'))
                        if outcome == 'failed': rows[2]['Action'] = 'fail'
                        rows.append(dict(Action='pass' if outcome == 'passed' else 'fail', Package=rows[0]['Package']))
                        out.write_text('\n'.join(map(json.dumps, rows)))
                    return {'stdout': out, 'stderr': err, 'exitCode': 0 if label == 'cohort-inventory' or outcome == 'passed' else 1,
                            'timedOut': label != 'cohort-inventory' and outcome == 'timeout'}
                with mock.patch.object(compose, 'source_hashes', return_value={}), \
                     mock.patch.object(compose, 'verify_files'), \
                     mock.patch.object(compose, 'read_pinned', side_effect=lambda p, *a: selected if p == args.selection else prereq), \
                     mock.patch.object(compose.subprocess, 'check_output', side_effect=lambda cmd, **kw: 'candidate\n' if cmd[1] == 'rev-parse' else ''):
                    if outcome == 'passed':
                        compose.run_darwin_cohort(args, report, go, selected, prereq, source, home, {}, invoke, executed)
                        self.assertEqual(report['cohort']['status'], 'passed')
                        self.assertEqual(report['cohort']['artifactValidationStatus'], 'passed')
                        self.assertFalse(report['phaseAccepted'])
                        self.assertEqual(len(report['omittedCohorts']), 12)
                        self.assertEqual(report['separatePrequalification']['runtimeCandidateParent']['status'], 'unqualified')
                        self.assertTrue(report['separatePrequalification']['runtimeCandidateParent']['historical'])
                    else:
                        with self.assertRaises(ValueError): compose.run_darwin_cohort(args, report, go, selected, prereq, source, home, {}, invoke, executed)
                        self.assertEqual(report['cohort']['testStatus'], 'failed')
                        self.assertTrue(report['effectsMayBeLive'])
                    self.assertEqual(len(calls), 2)
                    self.assertIn('-race', calls[-1][0])
                    self.assertIn('-failfast', calls[-1][0])
                    self.assertNotIn('-tags', calls[-1][0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
