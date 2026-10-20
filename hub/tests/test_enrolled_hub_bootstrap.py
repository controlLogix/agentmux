"""Offline ownership checks for explicit enrolled Hub startup."""
import asyncio
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from hub import cli
from hub.enrolled_hub_bootstrap import (
    EnrolledHubBootstrapFailure, _run_enrolled_hub, _selection_paths, _startup_arguments)
from hub.client_launch_selection import load_authority_switch_configuration, SelectionError
from hub import enrolled_hub_bootstrap as bootstrap


class OwnedSession:
    def __init__(self, selected, *, fail_start=False, fail_join=False):
        self.selected = selected
        self.fail_start = fail_start
        self.fail_join = fail_join
        self.starts = self.closes = self.joins = 0
        self.start_deadline = None

    def start(self, *, deadline):
        self.starts += 1
        self.start_deadline = deadline
        if self.fail_start:
            raise ValueError('PRIVATE_START_FAILURE')
        return self

    def close(self, *, deadline):
        self.closes += 1
        return not self.fail_join

    def join_final(self):
        self.joins += 1
        return not self.fail_join


class RetainedChild:
    def __init__(self):
        self.terminated = self.killed = self.joined = self.late_hub = False

    def poll(self):
        return 143 if self.terminated or self.killed else None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.joined = True
        return self.poll()

    def try_late_hub(self):
        self.late_hub = not (self.terminated or self.killed)


class EnrolledHubBootstrapTests(unittest.TestCase):
    def test_work_selection_is_explicit_bounded_and_reaches_bootstrap(self):
        arguments = ['--startup-deadline', '12.5', '--selection', '/private/identity',
            '--work-selection', '/private/first', '--code-selection', '/private/code',
            '--work-selection', '/private/second']
        ordinary, paths = bootstrap._work_paths(arguments)
        self.assertEqual(paths, ('/private/first', '/private/second'))
        self.assertEqual(ordinary, ['--startup-deadline', '12.5', '--selection',
            '/private/identity', '--code-selection', '/private/code'])
        with patch.object(bootstrap, '_run_enrolled_hub', return_value=0) as run:
            self.assertEqual(bootstrap.main(arguments), 0)
        self.assertEqual(run.call_args.args, (('/private/identity',),))
        self.assertEqual(run.call_args.kwargs['work_paths'], paths)
        self.assertEqual(run.call_args.kwargs['code_paths'], ('/private/code',))
        for args in (['--work-selection'], ['--work-selection', ''],
                ['--work-selection', '--selection'], ['--work-selection', '/private/work'] * 65):
            with self.subTest(args=args), self.assertRaises(EnrolledHubBootstrapFailure):
                bootstrap._work_paths(args)

    def test_failed_work_enrollment_joins_every_original_session_before_hub(self):
        sessions = []
        def create(value):
            session = OwnedSession(value)
            session.work_enrollment = Mock(side_effect=ValueError('private enrollment failure'))
            sessions.append(session)
            return session
        resolver, server = Mock(), Mock()
        with self.assertRaises(ValueError):
            _run_enrolled_hub(('identity',), work_paths=('work',),
                loader=lambda name, **_kwargs: self.selected(name, ('alpha',) if name == 'identity' else ()),
                session_factory=create, resolver_factory=resolver, server_main=server,
                authority_switch_loader=lambda *_args, **_kwargs: None)
        resolver.assert_not_called()
        server.assert_not_called()
        sessions[0].work_enrollment.assert_not_called()
        sessions[1].work_enrollment.assert_called_once()
        self.assertEqual([(s.starts, s.closes, s.joins) for s in sessions], [(1, 1, 1)] * 2)

    def test_work_path_shape_and_foreign_hub_refuse_before_sessions_start(self):
        for paths in ('work', None, ('work',) * 65):
            load, create = Mock(), Mock()
            with self.subTest(paths=paths), self.assertRaises(EnrolledHubBootstrapFailure):
                _run_enrolled_hub(('identity',), work_paths=paths,
                    loader=load, session_factory=create)
            load.assert_not_called()
            create.assert_not_called()
        create = Mock()
        with self.assertRaises(EnrolledHubBootstrapFailure):
            _run_enrolled_hub(('identity',), work_paths=('work',),
                loader=lambda name, **_kwargs: self.selected(name,
                    ('alpha',) if name == 'identity' else (),
                    hub_id='hub-one' if name == 'identity' else 'hub-two'),
                session_factory=create)
        create.assert_not_called()

    def test_code_selection_is_explicit_and_owned_until_hub_returns(self):
        ordinary, paths = bootstrap._code_paths(['--selection', '/private/identity',
            '--code-selection', '/private/code'])
        self.assertEqual(ordinary, ['--selection', '/private/identity'])
        self.assertEqual(paths, ('/private/code',))
        for args in (['--code-selection'], ['--code-selection', '--selection'],
                ['--code-selection', '/private/code'] * 65):
            with self.assertRaises(EnrolledHubBootstrapFailure):
                bootstrap._code_paths(args)
        sessions = []
        def create(value):
            session = OwnedSession(value)
            session.code_enrollment = Mock(return_value={'codeCommands': {}})
            sessions.append(session)
            return session
        observed = {}
        def server(**kwargs):
            self.assertEqual([(s.starts, s.closes) for s in sessions], [(1, 0), (1, 0)])
            observed.update(kwargs)
            return 0
        result = _run_enrolled_hub(('identity',), code_paths=('code',),
            loader=lambda name, **_kwargs: self.selected(name, ('alpha',) if name == 'identity' else ()),
            session_factory=create, resolver_factory=lambda *_args, **_kwargs: object(), server_main=server,
            authority_switch_loader=lambda *_args, **_kwargs: None)
        self.assertEqual(result, 0)
        self.assertEqual(observed['code_sessions'], (sessions[1],))
        sessions[0].code_enrollment.assert_not_called()
        sessions[1].code_enrollment.assert_called_once()
        self.assertEqual([(s.closes, s.joins) for s in sessions], [(1, 1), (1, 1)])

    def test_failed_code_enrollment_joins_original_sessions_before_hub(self):
        sessions = []
        def create(value):
            session = OwnedSession(value)
            session.code_enrollment = Mock(side_effect=ValueError('private enrollment failure'))
            sessions.append(session)
            return session
        resolver, server = Mock(), Mock()
        with self.assertRaises(ValueError):
            _run_enrolled_hub(('identity',), code_paths=('code',),
                loader=lambda name, **_kwargs: self.selected(name, ('alpha',) if name == 'identity' else ()),
                session_factory=create, resolver_factory=resolver, server_main=server,
                authority_switch_loader=lambda *_args, **_kwargs: None)
        resolver.assert_not_called()
        server.assert_not_called()
        self.assertEqual([(s.closes, s.joins) for s in sessions], [(1, 1), (1, 1)])

    def test_explicit_domain_sessions_keep_identity_routes_and_join_after_hub(self):
        selected = {name: self.selected(name, ('alpha',) if name == 'identity' else ())
            for name in ('identity', 'messages', 'knowledge', 'peer-control', 'policy', 'work')}
        sessions = []
        def create(value):
            session = OwnedSession(value)
            session.message_enrollment = Mock(return_value={'messageCommands': {}})
            session.knowledge_enrollment = Mock(return_value={'knowledgeCommands': {}})
            session.peer_control_enrollment = Mock(return_value={'peerControlCommands': {}})
            session.federation_policy_enrollment = Mock(return_value={'federationPolicyCommands': {}})
            session.work_enrollment = Mock(return_value={'workCommands': {}})
            sessions.append(session)
            return session
        observed = {}
        def resolver(routes, **_kwargs):
            self.assertEqual(routes, {'alpha': sessions[0]})
            return object()
        def server(**kwargs):
            self.assertEqual([session.starts for session in sessions], [1] * 6)
            self.assertEqual([session.closes for session in sessions], [0] * 6)
            observed.update(kwargs)
            return 0
        result = _run_enrolled_hub(('identity',), message_paths=('messages',), knowledge_paths=('knowledge',),
            peer_control_paths=('peer-control',), policy_paths=('policy',), work_paths=('work',),
            loader=lambda path, **_kwargs: selected[path], session_factory=create,
            resolver_factory=resolver, server_main=server,
            authority_switch_loader=lambda *_args, **_kwargs: None)
        self.assertEqual(result, 0)
        self.assertEqual(observed['message_sessions'], (sessions[1],))
        self.assertEqual(observed['peer_control_sessions'], (sessions[3],))
        self.assertEqual(observed['policy_sessions'], (sessions[4],))
        sessions[4].federation_policy_enrollment.assert_called_once()
        sessions[3].peer_control_enrollment.assert_called_once()
        self.assertEqual(observed['knowledge_sessions'], (sessions[2],))
        sessions[1].message_enrollment.assert_called_once()
        sessions[2].knowledge_enrollment.assert_called_once()
        sessions[1].knowledge_enrollment.assert_not_called()
        sessions[2].message_enrollment.assert_not_called()
        self.assertEqual(observed['work_sessions'], (sessions[5],))
        sessions[5].work_enrollment.assert_called_once()
        for session in sessions[:5]:
            session.work_enrollment.assert_not_called()
        self.assertEqual([(session.closes, session.joins) for session in sessions], [(1, 1)] * 6)

    def test_policy_selection_is_explicit_and_failure_joins_original_sessions(self):
        ordinary, paths = bootstrap._policy_paths(['--selection', '/private/identity',
            '--policy-selection', '/private/policy'])
        self.assertEqual(ordinary, ['--selection', '/private/identity'])
        self.assertEqual(paths, ('/private/policy',))
        for args in (['--policy-selection'], ['--policy-selection', '--selection'],
                ['--policy-selection', '/private/policy'] * 65):
            with self.assertRaises(EnrolledHubBootstrapFailure):
                bootstrap._policy_paths(args)
        sessions = []
        def create(selected):
            session = OwnedSession(selected)
            session.federation_policy_enrollment = Mock(side_effect=ValueError('private enrollment failure'))
            sessions.append(session)
            return session
        server = Mock()
        with self.assertRaises(ValueError):
            _run_enrolled_hub(('identity',), policy_paths=('policy',),
                loader=lambda name, **_kwargs: self.selected(name, ('alpha',) if name == 'identity' else ()),
                session_factory=create, server_main=server,
                authority_switch_loader=lambda *_args, **_kwargs: None)
        server.assert_not_called()
        self.assertEqual([(session.closes, session.joins) for session in sessions], [(1, 1)] * 2)

    def test_peer_control_selection_is_explicit_and_failure_joins_original_sessions(self):
        ordinary, paths = bootstrap._peer_control_paths(['--selection', '/private/identity',
            '--peer-control-selection', '/private/control'])
        self.assertEqual(ordinary, ['--selection', '/private/identity'])
        self.assertEqual(paths, ('/private/control',))
        for args in (['--peer-control-selection'], ['--peer-control-selection', '--selection'],
                ['--peer-control-selection', '/private/control'] * 65):
            with self.assertRaises(EnrolledHubBootstrapFailure):
                bootstrap._peer_control_paths(args)
        sessions = []
        def create(selected):
            session = OwnedSession(selected)
            session.peer_control_enrollment = Mock(side_effect=ValueError('private enrollment failure'))
            sessions.append(session)
            return session
        server = Mock()
        with self.assertRaises(ValueError):
            _run_enrolled_hub(('identity',), peer_control_paths=('control',),
                loader=lambda name, **_kwargs: self.selected(name, ('alpha',) if name == 'identity' else ()),
                session_factory=create, server_main=server,
                authority_switch_loader=lambda *_args, **_kwargs: None)
        server.assert_not_called()
        self.assertEqual([(session.closes, session.joins) for session in sessions], [(1, 1)] * 2)

    def test_failed_knowledge_enrollment_joins_started_sessions_without_starting_hub(self):
        sessions = []
        def create(value):
            session = OwnedSession(value)
            session.knowledge_enrollment = Mock(side_effect=ValueError('private enrollment failure'))
            sessions.append(session)
            return session
        resolver, server = Mock(), Mock()
        with self.assertRaises(ValueError):
            _run_enrolled_hub(('identity',), knowledge_paths=('knowledge',),
                loader=lambda name, **_kwargs: self.selected(name, ('alpha',) if name == 'identity' else ()),
                session_factory=create, resolver_factory=resolver, server_main=server,
                authority_switch_loader=lambda *_args, **_kwargs: None)
        self.assertEqual([(session.closes, session.joins) for session in sessions], [(1, 1)] * 2)
        resolver.assert_not_called()
        server.assert_not_called()

    def test_knowledge_selection_flag_never_becomes_an_identity_default(self):
        ordinary, knowledge = bootstrap._knowledge_paths(['--selection', '/private/identity',
            '--knowledge-selection', '/private/knowledge', '--message-selection', '/private/messages'])
        self.assertEqual(knowledge, ('/private/knowledge',))
        self.assertEqual(ordinary, ['--selection', '/private/identity', '--message-selection', '/private/messages'])
        for args in (['--knowledge-selection'], ['--knowledge-selection', '--selection'],
                ['--knowledge-selection', '/private/knowledge'] * 65):
            with self.assertRaises(EnrolledHubBootstrapFailure):
                bootstrap._knowledge_paths(args)

    def test_explicit_message_sessions_are_borrowed_by_hub_and_joined_after_it_returns(self):
        ordinary = self.selected('identity', ('alpha',))
        messages = self.selected('message-service', ())
        loaded, sessions = [], []
        def load(path, *, deadline):
            loaded.append(path)
            return ordinary if path == '/private/identity.json' else messages
        def create(selected):
            session = OwnedSession(selected)
            session.message_enrollment = Mock(return_value={'messageCommands': {}})
            sessions.append(session)
            return session
        observed = {}
        def resolver(routes, **_kwargs):
            self.assertEqual(set(routes), {'alpha'})
            self.assertIs(routes['alpha'], sessions[0])
            return object()
        def server(**kwargs):
            self.assertEqual(loaded, ['/private/identity.json', '/private/messages.json'])
            self.assertEqual([s.starts for s in sessions], [1, 1])
            self.assertEqual([s.closes for s in sessions], [0, 0])
            observed.update(kwargs)
            return 0
        result = _run_enrolled_hub(('/private/identity.json',), message_paths=('/private/messages.json',),
            loader=load, session_factory=create, resolver_factory=resolver, server_main=server,
            authority_switch_loader=lambda *_args, **_kwargs: None)
        self.assertEqual(result, 0)
        self.assertEqual(observed['message_sessions'], (sessions[1],))
        sessions[1].message_enrollment.assert_called_once()
        self.assertEqual([(s.closes, s.joins) for s in sessions], [(1, 1), (1, 1)])

    def test_message_selection_arguments_are_explicit_and_do_not_supply_identity_defaults(self):
        ordinary, messages = bootstrap._message_paths(['--startup-deadline', '10',
            '--selection', '/private/identity', '--message-selection', '/private/one',
            '--message-selection', '/private/two'])
        self.assertEqual(messages, ('/private/one', '/private/two'))
        self.assertEqual(ordinary, ['--startup-deadline', '10', '--selection', '/private/identity'])
        for args in (['--message-selection'], ['--message-selection', '--selection']):
            with self.assertRaises(EnrolledHubBootstrapFailure):
                bootstrap._message_paths(args)

    def selected(self, name, repositories, *, hub_id='hub-one'):
        return SimpleNamespace(profile_id=name, hub_id=hub_id,
            application_client=f'/private/{name}-key.json',
            application_connection=f'/private/{name}-connection.json',
            application_repositories=tuple(repositories))

    def test_all_selections_and_sessions_precede_one_resolver_and_hub(self):
        selected = [self.selected('one', ('alpha', 'shared')),
                    self.selected('two', ('beta',))]
        loaded, sessions, observed = [], [], {}
        def load(path, *, deadline):
            loaded.append(path)
            return selected[len(loaded) - 1]
        def create(value):
            self.assertEqual(loaded, ['/private/one.json', '/private/two.json'])
            session = OwnedSession(value)
            sessions.append(session)
            return session
        def resolver(routes, *, local_source_hub_id):
            self.assertTrue(all(session.starts == 1 for session in sessions))
            self.assertEqual(local_source_hub_id, 'hub-one')
            observed['routes'] = routes
            return SimpleNamespace(routes=routes)
        def server_main(*, legacy_identity):
            observed['resolver'] = legacy_identity
            return 7
        result = _run_enrolled_hub(('/private/one.json', '/private/two.json'),
            loader=load, session_factory=create, resolver_factory=resolver,
            server_main=server_main)
        self.assertEqual(result, 7)
        self.assertIs(observed['routes']['alpha'], sessions[0])
        self.assertIs(observed['routes']['shared'], sessions[0])
        self.assertIs(observed['routes']['beta'], sessions[1])
        self.assertEqual([(value.closes, value.joins) for value in sessions], [(1, 1), (1, 1)])
        self.assertTrue(all(0 < value.start_deadline - bootstrap.time.monotonic() <= 5
                            for value in sessions))

    def test_route_and_hub_validation_happen_before_session_start(self):
        cases = (
            [self.selected('one', ())],
            [self.selected('one', ('alpha',)), self.selected('two', ('alpha',))],
            [self.selected('one', ('alpha',)), self.selected('two', ('beta',), hub_id='hub-two')],
            [SimpleNamespace(profile_id='one', hub_id='hub-one', application_client=None,
                             application_connection='/private/connection',
                             application_repositories=('alpha',))],
        )
        for selections in cases:
            with self.subTest(selections=selections):
                create = Mock()
                with self.assertRaises(EnrolledHubBootstrapFailure):
                    _run_enrolled_hub(tuple(str(index) for index in range(len(selections))),
                        loader=lambda path, deadline, values=iter(selections): next(values),
                        session_factory=create, resolver_factory=Mock(), server_main=Mock())
                create.assert_not_called()

    def test_exact_authority_switch_binding_reaches_hub_and_conflicts_refuse(self):
        selected = [self.selected('one', ('alpha',)), self.selected('two', ('beta',))]
        binding = {'switchId': 'switch_' + 'a' * 64}
        authorized_guard = object()
        caller = object()
        guard = Mock()
        guard.with_enrolled_recovery.return_value = authorized_guard
        observed = {}
        def server_main(**kwargs):
            observed.update(kwargs)
            return 0
        result = _run_enrolled_hub(('one', 'two'),
            loader=lambda path, deadline, values=iter(selected): next(values),
            session_factory=OwnedSession,
            resolver_factory=lambda routes, **kwargs: object(),
            authority_switch_loader=lambda value, deadline: (binding, guard),
            authority_switch_client_factory=lambda sessions, public: caller,
            server_main=server_main)
        self.assertEqual(result, 0)
        self.assertIs(observed['authority_switch_recovery'], authorized_guard)
        guard.with_enrolled_recovery.assert_called_once_with(caller)

        for recoveries in ((None, (binding, guard)),
                           ((binding, guard), ({'switchId': 'switch_' + 'b' * 64}, object()))):
            sessions = []
            with self.subTest(recoveries=recoveries), self.assertRaises(EnrolledHubBootstrapFailure):
                values = iter(recoveries)
                _run_enrolled_hub(('one', 'two'),
                    loader=lambda path, deadline, chosen=iter(selected): next(chosen),
                    session_factory=lambda value: sessions.append(OwnedSession(value)) or sessions[-1],
                    resolver_factory=Mock(), server_main=Mock(),
                    authority_switch_loader=lambda value, deadline, chosen=values: next(chosen))
            self.assertEqual(sessions, [])

    def test_omitted_service_pin_cannot_hide_retained_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            custody = root / 'authority-switch'
            custody.mkdir(mode=0o700)
            first = SimpleNamespace(invocation=SimpleNamespace(
                application_services_selection=None, application_services_digest=None,
                host_policy=str(root / 'host-policy.json')))
            deadline = bootstrap.time.monotonic() + 1
            self.assertIsNone(load_authority_switch_configuration(first, deadline=deadline))
            (custody / ('authority-switch-' + 'a' * 64 + '-1-' + 'b' * 64 + '.json')).write_text('{}')
            with self.assertRaises(SelectionError):
                load_authority_switch_configuration(first, deadline=deadline)

    def test_start_failure_joins_every_original_session_and_never_opens_hub(self):
        selected = [self.selected('one', ('alpha',)), self.selected('two', ('beta',))]
        sessions = []
        def create(value):
            session = OwnedSession(value, fail_start=len(sessions) == 1)
            sessions.append(session)
            return session
        resolver, server = Mock(), Mock()
        with self.assertRaisesRegex(ValueError, 'PRIVATE_START_FAILURE'):
            _run_enrolled_hub(('one', 'two'),
                loader=lambda path, deadline, values=iter(selected): next(values),
                session_factory=create, resolver_factory=resolver, server_main=server)
        resolver.assert_not_called()
        server.assert_not_called()
        self.assertEqual([(value.closes, value.joins) for value in sessions], [(1, 1), (1, 1)])

    def test_resolver_or_hub_failure_joins_started_sessions(self):
        selected = self.selected('one', ('alpha',))
        for failure in ('resolver', 'hub'):
            with self.subTest(failure=failure):
                session = OwnedSession(selected)
                def resolver(routes, **kwargs):
                    if failure == 'resolver':
                        raise ValueError('PRIVATE_RESOLVER_FAILURE')
                    return object()
                def server_main(**kwargs):
                    raise ValueError('PRIVATE_HUB_FAILURE')
                with self.assertRaisesRegex(ValueError,
                        'PRIVATE_RESOLVER_FAILURE' if failure == 'resolver' else 'PRIVATE_HUB_FAILURE'):
                    _run_enrolled_hub(('one',), loader=lambda path, deadline: selected,
                        session_factory=lambda value: session, resolver_factory=resolver,
                        server_main=server_main)
                self.assertEqual((session.starts, session.closes, session.joins), (1, 1, 1))

    def test_failed_final_cleanup_changes_success_to_failure(self):
        selected = self.selected('one', ('alpha',))
        session = OwnedSession(selected, fail_join=True)
        with self.assertRaises(EnrolledHubBootstrapFailure):
            _run_enrolled_hub(('one',), loader=lambda path, deadline: selected,
                session_factory=lambda value: session,
                resolver_factory=lambda routes, **kwargs: object(),
                server_main=lambda **kwargs: 0)
        self.assertEqual((session.closes, session.joins), (1, 1))

    def test_unresolved_hub_cleanup_retains_exact_borrowed_sessions(self):
        from hub.server import HubCleanupFailure
        from types import SimpleNamespace
        for joined in (False, True):
            with self.subTest(joined=joined):
                sessions = []
                def create(value):
                    session = OwnedSession(value)
                    sessions.append(session)
                    return session
                owner = SimpleNamespace(_hub_borrowers_joined=joined)
                failure = HubCleanupFailure(owner)
                cause = RuntimeError('original cleanup failure')
                def failed_server(**kwargs):
                    raise failure from cause
                with self.assertRaises(HubCleanupFailure) as caught:
                    _run_enrolled_hub(('identity',),
                        loader=lambda name, **kwargs: self.selected(name, ('alpha',)),
                        session_factory=create, resolver_factory=lambda *args, **kwargs: object(),
                        server_main=failed_server, authority_switch_loader=lambda *args, **kwargs: None)
                self.assertIs(caught.exception, failure)
                self.assertIs(failure.owner, owner)
                self.assertIs(failure.__cause__, cause)
                self.assertEqual(failure.sessions, () if joined else tuple(sessions))
                self.assertEqual([(s.closes, s.joins) for s in sessions],
                    [(1, 1)] if joined else [(0, 0)])

    def test_closed_cli_shape_reaches_enrolled_child_without_changing_ordinary_start(self):
        ordinary, enrolled = Mock(), Mock()
        with patch.object(cli, 'start', side_effect=(ordinary, enrolled)) as start:
            self.assertIs(cli.main(['start']), ordinary)
            self.assertIs(cli.main(['start', '--selection', '/private/one.json',
                                    '--selection', '/private/two.json']), enrolled)
        self.assertEqual(start.call_args_list[0].args, ((),))
        self.assertEqual(start.call_args_list[1].args,
                         (('/private/one.json', '/private/two.json'),))
        with patch.object(cli, 'start') as start:
            with self.assertRaises(cli.Fail):
                cli.main(['start', '--selection', '/private/one.json', '--unknown'])
        start.assert_not_called()

    def test_enrolled_start_uses_dedicated_bootstrap_process(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(cli, 'ROOT', directory), \
                patch.object(cli, 'call', side_effect=[cli.Fail('not running'), {'ok': True}]), \
                patch.object(cli.subprocess, 'Popen') as popen, \
                patch.object(cli.time, 'sleep'), patch.object(cli, 'python', return_value='/python'), \
                patch('sys.stdout', new_callable=io.StringIO):
            popen.return_value.poll.return_value = None
            cli.start(('/private/one.json', '/private/two.json'))
        command = popen.call_args.args[0]
        self.assertEqual(command[:3], ['/python',
            str(Path(cli.REPO) / 'hub' / 'enrolled_hub_bootstrap.py'), '--startup-deadline'])
        self.assertGreater(float(command[3]), 0)
        self.assertEqual(command[4:], ['--selection', '/private/one.json',
                                       '--selection', '/private/two.json'])

    def test_enrolled_start_refuses_an_existing_unqualified_hub(self):
        with patch.object(cli, 'call', return_value={'ok': True}), \
                patch.object(cli.subprocess, 'Popen') as popen, \
                self.assertRaisesRegex(cli.Fail, 'existing hub'):
            cli.start(('/private/one.json',))
        popen.assert_not_called()

    def test_slow_multiselection_timeout_stops_and_joins_exact_child(self):
        child = RetainedChild()
        clock = [0.0]
        def sleep(seconds):
            clock[0] += seconds
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(cli, 'ROOT', directory), \
                patch.object(cli, 'ENROLLED_STARTUP_SECONDS', 0.4), \
                patch.object(cli, 'call', side_effect=cli.Fail('not running')), \
                patch.object(cli.subprocess, 'Popen', return_value=child) as popen, \
                patch.object(cli.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(cli.time, 'sleep', side_effect=sleep), \
                patch.object(cli, 'python', return_value='/python'), \
                self.assertRaisesRegex(cli.Fail, 'did not come up'):
            cli.start(('/private/one.json', '/private/two.json'))
        self.assertTrue(child.terminated)
        self.assertTrue(child.joined)
        self.assertFalse(child.killed)
        child.try_late_hub()
        self.assertFalse(child.late_hub)
        command = popen.call_args.args[0]
        self.assertEqual(float(command[3]), 0.4)
        self.assertEqual(command[4:], ['--selection', '/private/one.json',
                                       '--selection', '/private/two.json'])

    def test_interrupted_enrolled_wait_stops_and_joins_exact_child(self):
        child = RetainedChild()
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(cli, 'ROOT', directory), \
                patch.object(cli, 'call', side_effect=cli.Fail('not running')), \
                patch.object(cli.subprocess, 'Popen', return_value=child), \
                patch.object(cli.time, 'sleep', side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            cli.start(('/private/one.json',))
        self.assertTrue(child.terminated)
        self.assertTrue(child.joined)
        child.try_late_hub()
        self.assertFalse(child.late_hub)

    def test_bootstrap_arguments_are_repeated_selection_pairs_only(self):
        self.assertEqual(_selection_paths(['--selection', '/one', '--selection', '/two']),
                         ('/one', '/two'))
        for argv in ([], ['--selection'], ['/one'], ['--selection', '/one', '--unknown']):
            with self.subTest(argv=argv), self.assertRaises(EnrolledHubBootstrapFailure):
                _selection_paths(argv)
        self.assertEqual(_startup_arguments(
            ['--startup-deadline', '12.5', '--selection', '/one']), (('/one',), 12.5))
        for argv in (['--selection', '/one'], ['--startup-deadline', 'bad', '--selection', '/one']):
            with self.subTest(startup_argv=argv), self.assertRaises(EnrolledHubBootstrapFailure):
                _startup_arguments(argv)

    def test_public_failure_output_is_fixed(self):
        error = io.StringIO()
        with patch.object(bootstrap, '_run_enrolled_hub',
                          side_effect=ValueError('PRIVATE_FAILURE')), \
                patch('sys.stderr', error):
            self.assertEqual(bootstrap.main(['--startup-deadline',
                str(bootstrap.time.monotonic() + 5), '--selection', '/one']), 1)
        self.assertEqual(error.getvalue(), 'enrolled hub startup failed\n')

    def test_actual_resolver_accepts_bootstrap_mapping_and_verified_hub_id(self):
        from hub.client_launch_session import ApplicationClientSession
        from hub.legacy_identity_client import EnrolledLegacyIdentityResolver
        selected = self.selected('one', ('alpha',))
        session = ApplicationClientSession(selected)
        resolver = EnrolledLegacyIdentityResolver({'alpha': session},
            local_source_hub_id='hub-one')
        self.assertEqual(resolver.repositories, ('alpha',))
        self.assertEqual(resolver.local_source_hub_id, 'hub-one')

    def test_actual_session_open_boundary_accepts_capped_deadlines_inside_outer_budget(self):
        from hub.client_launch_session import ApplicationClientSession
        selected = [self.selected('one', ('alpha',)), self.selected('two', ('beta',)),
                    self.selected('work', ())]
        outer_deadline = bootstrap.time.monotonic() + 30
        loader_deadlines, open_budgets, sessions, owners = [], [], [], []
        work_enrollment = {'hubId': 'hub-one', 'profileId': 'one', 'authorityId': 'authority-one',
            'callerRef': 'operator-one', 'scope': {'repositoryId': 'alpha'}, 'workCommands': {}}

        def load(_path, *, deadline):
            loader_deadlines.append(deadline)
            return selected[len(loader_deadlines) - 1]

        async def open_client(_key, _connection, *, deadline, cleanup_deadline, **_kwargs):
            loop = asyncio.get_running_loop()
            remaining = deadline - loop.time()
            open_budgets.append((remaining, cleanup_deadline - deadline))
            if not 0 < remaining <= 5:
                raise ValueError('application_connection_deadline')
            owner = SimpleNamespace(_signer=SimpleNamespace(selection=(
                work_enrollment if _key == '/private/work-key.json' else {})), _close_task=None)
            owners.append(owner)

            async def close(**_options):
                if owner._close_task is None:
                    owner._close_task = asyncio.create_task(asyncio.sleep(0))
                await owner._close_task

            owner.close = close
            return owner

        def create(value):
            session = ApplicationClientSession(value)
            sessions.append(session)
            return session

        def server(**kwargs):
            self.assertEqual(kwargs['work_sessions'], (sessions[2],))
            self.assertEqual(sessions[2].work_enrollment(), work_enrollment)
            self.assertTrue(all(session._thread.is_alive() for session in sessions))
            return 0

        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            result = _run_enrolled_hub(('one', 'two'), work_paths=('work',), startup_deadline=outer_deadline,
                loader=load, session_factory=create,
                resolver_factory=lambda routes, **kwargs: object(), server_main=server)

        self.assertEqual(result, 0)
        self.assertEqual(loader_deadlines, [outer_deadline] * 3)
        self.assertEqual(len(open_budgets), 3)
        self.assertTrue(all(0 < remaining <= 5 and 1 <= cleanup_extension < 1.01
                            for remaining, cleanup_extension in open_budgets))
        self.assertTrue(all(not session._thread.is_alive() for session in sessions))
        self.assertTrue(all(owner._close_task.done() for owner in owners))

    def test_slow_multiselection_uses_one_deadline(self):
        selected = [self.selected('one', ('alpha',)), self.selected('two', ('beta',))]
        sessions = []
        with patch.object(bootstrap.time, 'monotonic', return_value=10):
            result = _run_enrolled_hub(('one', 'two'), startup_deadline=20,
                loader=lambda path, deadline, values=iter(selected): next(values),
                session_factory=lambda value: sessions.append(OwnedSession(value)) or sessions[-1],
                resolver_factory=lambda routes, **kwargs: object(), server_main=lambda **kwargs: 0)
        self.assertEqual(result, 0)
        self.assertEqual([session.start_deadline for session in sessions], [15, 15])


if __name__ == '__main__':
    unittest.main()
