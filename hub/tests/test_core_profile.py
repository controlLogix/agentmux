"""Closed core entrypoint and authenticated same-connection reply boundaries."""
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import canonical_bytes, strict_loads
from hub.core_profile import CoreRoute, CoreSetupRequired, core_arguments
from hub.core_endpoint import CoreConnection, _mac, _socket_identity


class CoreSurfaceTests(unittest.TestCase):
    def test_nested_startup_or_selection_cannot_escape_core_route(self):
        for arguments in (['start', '--selection', '/private/other'], ['--json', 'start'],
                ['startup'], ['mcp'], ['selected', '--repository-root', '/other', '--', 'ping'],
                ['dashboard'], ['repo', 'add', 'other'], ['work', 'unknown']):
            with self.subTest(arguments=arguments), self.assertRaises(CoreSetupRequired):
                core_arguments(arguments)

    def test_existing_work_and_operator_arguments_stay_exact(self):
        for arguments in (['start'], ['--as', 'falcon-worker-one', '--json', 'done', 'work-one',
                '--result', 'Original result', '--operation-id', 'original'],
                ['work', 'add', '--to', 'role:falcon/worker', '--title', 'Original'], ['stop']):
            self.assertIs(core_arguments(arguments), arguments)


@unittest.skipUnless(os.uname().sysname == 'Darwin', 'native private-file checks require macOS')
class CoreConnectionTests(unittest.TestCase):
    def exchange(self, *, altered=False, wrong_pid=False):
        # This transport test substitutes route admission only. It does not qualify
        # central admission or claim a Hub/owner integration result.
        with tempfile.TemporaryDirectory(prefix='a702-', dir=str(Path.home()/'.cache')) as directory:
            root = Path(directory).resolve(); (root/'hub').mkdir(mode=0o700)
            route = object.__new__(CoreRoute)
            route.home = str(root); route.socket = str(root/'hub'/'hub.sock')
            route.repository = '/approved'
            route.binding = {'repositories': {'/approved': 'falcon'}, 'profileId': 'profile-one'}
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(route.socket); os.chmod(route.socket, 0o600); listener.listen(1)
            record = {'version': 1, 'binding': route.binding, 'source': {},
                'pid': os.getpid()+100000 if wrong_pid else os.getpid(),
                'socket': _socket_identity(route.socket), 'key': 'ab'*32}
            path = root/'hub'/'selected-endpoint.json'; path.write_bytes(canonical_bytes(record));path.chmod(0o600)
            observed=[]
            def server():
                connection,_ = listener.accept()
                try:
                    raw=connection.recv(65536)
                    if not raw: return
                    request=strict_loads(raw)['core'];observed.append(request['request'])
                    body={'nonce':request['nonce'],'binding':request['binding'],'response':{'ok':True,'result':'original'}}
                    signature=_mac(record['key'],body)
                    if altered:body['response']['result']='substituted'
                    connection.sendall(canonical_bytes({'core':body,'mac':signature})+b'\n')
                finally:connection.close()
            worker=threading.Thread(target=server);worker.start()
            try:
                with patch.object(CoreRoute,'check'):
                    client=CoreConnection(route)
                    try:
                        if altered or wrong_pid:
                            with self.assertRaises(CoreSetupRequired):client.exchange({'verb':'ping'},2)
                        else:
                            self.assertEqual(client.exchange({'verb':'ping'},2),{'ok':True,'result':'original'})
                    finally:client.close()
            finally:
                worker.join(3);listener.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(observed),0 if wrong_pid else 1)

    def test_original_signed_response(self):self.exchange()
    def test_changed_response_refused(self):self.exchange(altered=True)
    def test_wrong_peer_refused_before_command(self):self.exchange(wrong_pid=True)


class CoreCleanupTests(unittest.TestCase):
    def test_outer_startup_retains_exact_owners_until_hub_borrowers_join(self):
        self.retained_startup()

    def test_outer_close_failure_is_preserved_without_repeating_consumed_cleanup(self):
        import asyncio
        for owner in ('core', 'installed', 'route', 'both'):
            for error_type in (RuntimeError, asyncio.CancelledError):
                with self.subTest(owner=owner, error_type=error_type):
                    self.retained_startup(owner, error_type)

    def retained_startup(self, failing_owner=None, error_type=RuntimeError):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from hub import server
        from hub.core_profile import run_registered_core
        hub = SimpleNamespace(_hub_borrowers_joined=False)
        failure = server.HubCleanupFailure(hub)
        failure.sessions = (object(),)
        cause = RuntimeError('original Hub cleanup')
        failure.__cause__ = cause
        original_sessions = failure.sessions
        installed, core = Mock(), Mock()
        routes = []
        def initialize(route, *args):
            route.home, route.socket = server.ROOT, server.SOCK
            route.context = SimpleNamespace(context=object())
            route.selection_path = '/selected'
            route.paths = {'identity': ['identity'], 'messages': ['messages'], 'work': ['work']}
            routes.append(route)
        with patch.object(CoreRoute, '__init__', initialize), patch.object(CoreRoute, 'close') as close_route, \
                patch('hub.core_endpoint.CoreEndpoint'), \
                patch('hub.installed_client_admission.admit_installed_client', return_value=installed), \
                patch('hub.native_core_context.NativeCoreContext', return_value=core), \
                patch('hub.enrolled_hub_bootstrap._run_enrolled_hub', side_effect=failure), \
                patch.dict(os.environ, {}):
            with self.assertRaises(server.HubCleanupFailure) as caught:
                run_registered_core('/installed/client', ['/selected', '42', 'digest', '/repo', '--', 'start'],
                    registration_reader=Mock())
            self.assertIs(caught.exception, failure)
            installed.close.assert_not_called(); core.close.assert_not_called(); close_route.assert_not_called()
            cleanup = failure.cleanup_owners[-1]
            self.assertIs(cleanup.route, routes[0])
            with self.assertRaises(server.HubCleanupFailure):
                cleanup.close()
            installed.close.assert_not_called(); core.close.assert_not_called(); close_route.assert_not_called()
            self.assertIs(failure.__cause__, cause)
            self.assertIs(failure.sessions, original_sessions)
            self.assertEqual(cleanup.startup_owners, (core, installed))
            hub._hub_borrowers_joined = True
            outer_error = error_type('original outer close')
            route_error = RuntimeError('original route close')
            if failing_owner in ('core', 'both'):
                core.close.side_effect = outer_error
            elif failing_owner == 'installed':
                installed.close.side_effect = outer_error
            if failing_owner in ('route', 'both'):
                close_route.side_effect = route_error
            if failing_owner:
                expected = route_error if failing_owner == 'route' else outer_error
                for attempt in range(2):
                    with self.assertRaises(BaseException) as closed:
                        cleanup.close()
                    self.assertIs(closed.exception, expected)
                    self.assertFalse(cleanup.closed)
                self.assertEqual(cleanup.close_failures,
                    (outer_error, route_error) if failing_owner == 'both' else (expected,))
                self.assertIs(cleanup.failure, failure)
                self.assertIs(failure.__cause__, cause)
            else:
                cleanup.close(); cleanup.close()
                self.assertTrue(cleanup.closed)
            installed.close.assert_called_once(); core.close.assert_called_once(); close_route.assert_called_once()

    def test_wrapper_success_and_joined_failure_release_outer_owners(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import Mock
        from hub import server
        from hub.core_profile import run_registered_core
        for outcome in ('success', 'ordinary', 'joined', 'cancelled'):
            with self.subTest(outcome=outcome):
                installed, core = Mock(), Mock()
                def initialize(route, *args):
                    route.home, route.socket = server.ROOT, server.SOCK
                    route.context = SimpleNamespace(context=object())
                    route.selection_path = '/selected'
                    route.paths = {'identity': ['identity'], 'messages': ['messages'], 'work': ['work']}
                failure = {'success': None, 'ordinary': RuntimeError('startup failed'),
                    'joined': server.HubCleanupFailure(SimpleNamespace(_hub_borrowers_joined=True)),
                    'cancelled': asyncio.CancelledError()}[outcome]
                with patch.object(CoreRoute, '__init__', initialize), \
                        patch.object(CoreRoute, 'close') as close_route, \
                        patch('hub.core_endpoint.CoreEndpoint'), \
                        patch('hub.installed_client_admission.admit_installed_client', return_value=installed), \
                        patch('hub.native_core_context.NativeCoreContext', return_value=core), \
                        patch('hub.enrolled_hub_bootstrap._run_enrolled_hub', side_effect=failure, return_value=0), \
                        patch('sys.stderr'), patch.dict(os.environ, {}):
                    args = ['/selected', '42', 'digest', '/repo', '--', 'start']
                    if outcome == 'cancelled':
                        with self.assertRaises(asyncio.CancelledError) as caught:
                            run_registered_core('/installed/client', args, registration_reader=Mock())
                        self.assertIs(caught.exception, failure)
                    else:
                        result = run_registered_core('/installed/client', args, registration_reader=Mock())
                        self.assertEqual(result, 0 if outcome == 'success' else 1)
                    core.close.assert_called_once()
                    installed.close.assert_called_once()
                    close_route.assert_called_once()

    def test_route_constructor_failure_closes_retained_files_and_registration(self):
        from unittest.mock import Mock
        held = Mock()
        def fail(route, *args):
            route.files.append(held)
            raise CoreSetupRequired()
        with patch.object(CoreRoute, '_initialize', fail), \
                patch('hub.core_profile.DescriptorCleanup') as cleanup:
            with self.assertRaises(CoreSetupRequired):
                CoreRoute('/installed', '/selected', 42, 'sha256:original', '/repo', Mock())
        held.close.assert_called_once()
        cleanup.return_value.close.assert_called_once_with(42)

    def test_constructor_parse_failure_closes_original_record(self):
        from unittest.mock import Mock
        record = Mock(raw=b'invalid json')
        route = object.__new__(CoreRoute)
        route.home='/private/selected'
        with patch('hub.core_endpoint.PrivateFile',return_value=record):
            with self.assertRaises(ValueError): CoreConnection(route)
        record.close.assert_called_once()

    def test_endpoint_close_preserves_replacement_but_closes_descriptor(self):
        from unittest.mock import Mock
        from hub.core_endpoint import CoreEndpoint
        endpoint=object.__new__(CoreEndpoint)
        record=Mock();record.check.side_effect=CoreSetupRequired()
        endpoint.record=record;endpoint.path='/private/original'
        with patch('hub.core_endpoint.os.unlink') as unlink:
            with self.assertRaises(CoreSetupRequired):endpoint.close()
        unlink.assert_not_called();record.close.assert_called_once()
        self.assertIsNone(endpoint.record)

    def test_callback_reuses_current_repository_resolver_and_refuses_start(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        from hub.client_launch_repository import RepositoryCoreCallback
        selected = SimpleNamespace(repository='/approved', reference=SimpleNamespace(profile_id='profile-one'))
        with patch('hub.client_launch_repository.os.getcwd',return_value='/approved'), \
                patch('dashboard.repository_profiles.discover_repository_profile',return_value=nullcontext(selected)), \
                patch('hub.client_launch_repository._core_handoff',return_value=0) as handoff:
            self.assertEqual(RepositoryCoreCallback().invoke(('agents',)),0)
            self.assertEqual(handoff.call_args.args, ('/approved',['agents']))
            self.assertIs(handoff.call_args.kwargs['discovery'], selected)
            with self.assertRaises(CoreSetupRequired): RepositoryCoreCallback().invoke(('start',))
            self.assertEqual(handoff.call_count,1)
