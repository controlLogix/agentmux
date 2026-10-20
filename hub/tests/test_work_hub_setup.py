"""Selected work clients share the actual Hub source and owned lifecycle."""
import asyncio
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError
from capability_owner.federated_work_client import FederatedWorkCommandClient, WorkBridgeIntents
from capability_owner.legacy_work_client import LegacyWorkCommandClient
from capability_owner.local_work_client import LocalWorkClient
from hub import server
from hub.client_launch_session import ApplicationClientSession
from hub.fed.runtime import Federation
from hub.tests.test_work_client_transport import material


def work_session():
    selected = material()
    session = object.__new__(ApplicationClientSession)
    enrollment = {key: selected[key] for key in
        ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope', 'workCommands')}
    session.work_enrollment = lambda: enrollment
    return session


class WorkHubSetupTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(server, 'ROOT', str(root)))
        self.enterContext(patch.object(server, 'HUBDIR', str(root / 'hub')))

    @staticmethod
    def close_hub(hub):
        if hub._work_storage_commands is not None:
            asyncio.run(hub._work_storage_commands.close(timeout=None))
        hub.dbx.submit(hub.store.db.close).result()
        hub.dbx.shutdown(wait=True)
        hub.io.shutdown(wait=True)

    def test_local_only_hub_constructs_one_source_and_binds_both_adapters(self):
        session = work_session()
        hub = server.Hub(work_sessions=(session,))
        self.addCleanup(self.close_hub, hub)
        base = hub._work_storage_commands
        self.assertIs(type(base), LegacyWorkCommandClient)
        self.assertIs(type(hub._local_work_commands), LocalWorkClient)
        self.assertIs(hub._local_work_commands._commands, base)
        self.assertIs(type(hub.fed._work_commands), FederatedWorkCommandClient)
        self.assertIs(hub.fed._work_commands._client, base)
        self.assertIs(type(hub.fed._work_intents), WorkBridgeIntents)
        self.assertIs(base._store, hub.store)
        self.assertIs(base._hub_worker, hub.dbx)
        self.assertIs(base._stop, hub.stop)
        self.assertIs(base._federation, hub.fed)
        self.assertIs(base._routes[0][0], session)
        self.assertTrue(hub.fed._qualified_work)
        self.assertFalse(hub.fed.enabled)
        self.assertIsNone(hub.fed.session)

    def test_ordinary_hub_keeps_work_selection_absent(self):
        hub = server.Hub()
        self.addCleanup(self.close_hub, hub)
        self.assertIsNone(hub._work_storage_commands)
        self.assertIsNone(hub._local_work_commands)
        self.assertFalse(hub.fed._qualified_work)
        self.assertIsNone(hub.fed._work_commands)
        self.assertIsNone(hub.fed._work_intents)

    def test_invalid_work_sessions_close_the_original_database(self):
        for selected in ((), [], (object(),), (work_session(),) * 2):
            stores = []
            original = server.Store
            def record(*args, **kwargs):
                store = original(*args, **kwargs)
                stores.append(store)
                return store
            with self.subTest(selected=type(selected).__name__), patch.object(server, 'Store', record):
                with self.assertRaises(ContractError):
                    server.Hub(work_sessions=selected)
                self.assertEqual(len(stores), 1)
                with self.assertRaisesRegex(sqlite3.ProgrammingError, 'closed'):
                    stores[0].db.execute('SELECT 1')

    def test_work_profile_must_match_other_selected_domains(self):
        client = Mock()
        from agentmux_contracts import canonical_bytes
        client._routes = [(None, canonical_bytes({
            'hubId': 'another-hub', 'profileId': 'another-profile', 'authorityId': 'another-authority'}))]
        stores = []
        original = server.Store
        def record(*args, **kwargs):
            store = original(*args, **kwargs)
            stores.append(store)
            return store
        with patch('capability_owner.legacy_messages_client.LegacyMessageCommandClient', return_value=client), \
                patch.object(server, 'Store', record):
            with self.assertRaisesRegex(ValueError, 'profiles do not match'):
                server.Hub(message_sessions=(object(),), work_sessions=(work_session(),))
        with self.assertRaisesRegex(sqlite3.ProgrammingError, 'closed'):
            stores[0].db.execute('SELECT 1')

    def test_server_entry_forwards_the_exact_sessions(self):
        selected = (work_session(),)
        hub = Mock(main=AsyncMock())
        with patch.object(server, 'Hub', return_value=hub) as factory:
            self.assertEqual(server.main(work_sessions=selected), 0)
        self.assertIs(factory.call_args.kwargs['work_sessions'], selected)
        hub.main.assert_awaited_once()

    def test_federation_refuses_unbound_or_implicitly_enabled_work(self):
        for arguments in ({'qualified_work': 'yes'}, {'work_commands': object()},
                {'qualified_work': True}, {'qualified_work': True, 'work_commands': object()}):
            with self.subTest(arguments=tuple(arguments)), self.assertRaises(server.HubError):
                Federation(object(), '/unused', lambda *_args: None, **arguments)
