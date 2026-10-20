"""A work-only selection must compose its authorized control publisher."""
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import canonical_bytes, strict_loads
from dashboard.test_application_service_host import Client
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from identity.test_work_peer_control import WorkPeerControlFixture

from .peer_control_command import PeerControlCommandOwner
from .selected_storage import SelectedStorageFailure
from .test_knowledge_host import SelectedKnowledgeCompositionFixture
from .test_peer_control_command import PeerControlCommandFixture
from .work import WorkStorageResource


class SelectedWorkPublicationTests(PeerControlCommandFixture, WorkPeerControlFixture,
        unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Reuse valid operator and publisher credentials, after the existing
        # work fixture replaces the Knowledge declaration with a Work resource.
        super().setUp()
        current = strict_loads(self.snapshot.record)
        for grant in current['state']['grants']:
            if grant['ref'] in (*self.grants.values(), ref('control-local-publisher-grant')):
                grant['resourceId'] = 'work-one'
        next(item for item in current['state']['transports'] if item['ref'] == ref('transport'))['issuerRef'] = (
            self.value['identity']['issuer']['issuerRef'])
        self.snapshot = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence + 1)
        self.selection = self.selected()

    async def asyncSetUp(self):
        # Exercise selected startup, without constructing a source or command
        # owner in advance or bypassing validation of either one.
        await SelectedKnowledgeCompositionFixture.asyncSetUp(self)

    async def test_work_only_startup_composes_operator_publication_owner(self):
        connections = []

        def control_connection(**_options):
            connection = Client(object())
            connection.flush = AsyncMock()

            async def connect(**options):
                self.assertTrue(options['user_jwt_cb']())
                self.assertEqual(len(options['signature_cb']('broker-nonce')), 88)
                self.assertFalse(options['allow_reconnect'])
                self.assertTrue(options['tls_handshake_first'])
                connection.options = options
                connection.is_connected = True

            async def subscribe_owned(session, subject, **options):
                self.assertIs(connection._agentmux_session, session)
                return await connection.subscribe(subject, **options)

            async def close():
                connection.is_connected = False

            connection.connect = connect
            connection.subscribe_owned = subscribe_owned
            connection.close = close
            connections.append(connection)
            return connection

        route = self.selection.policy['peerControl']['routes'][0]
        self.assertNotIn('knowledge', self.selection.policy['storage'])
        self.assertEqual(route['resourceRef'], ref('work-one'))
        self.assertEqual(route['operators'][0]['grants'], self.grants)
        self.assertIn('publisher', route)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients), \
                patch('hub.fed.peer_control.new_client', side_effect=control_connection):
            try:
                await self.host.start()
            except SelectedStorageFailure as error:
                # Keep the actual responsible startup failure in this private
                # regression output; public diagnostics stay unchanged.
                cause = getattr(error, '_cause', None)
                if cause is not None:
                    raise cause from error
                raise
            self.host.check_health()
            resource = next(item for item in self.host._resources if type(item) is WorkStorageResource)
            source = resource._owner._source
            self.assertEqual(len(self.host._message_stores), 1)
            self.assertEqual(len(self.host._peer_control_publishers), 1)
            self.assertEqual(len(self.host._peer_control_owners), 1)
            owner = self.host._peer_control_owners[0]
            publisher = self.host._peer_control_publishers[0]
            self.assertIs(type(owner), PeerControlCommandOwner)
            self.assertIs(owner._source, source)
            self.assertIs(resource._store, source._store)
            self.assertIs(owner._publishers[route['routeId']], publisher)
            self.assertIs(publisher._selection, self.selection)
            self.assertEqual(publisher._pin, route)
            self.assertEqual(len(self.host._work_controls), 1)
            self.assertEqual(self.host._knowledge_controls, [])
            await self.host.close(timeout=None)
            self.assertTrue(owner._closing.done())
            self.assertTrue(publisher._closing.done())
            self.assertTrue(source._closing.done())
            self.assertIsNone(source._store)
            self.assertTrue(all(not item.is_connected for item in connections))
            self.assertTrue(all(not item.is_connected for item in self.clients))
            self.assertFalse(self.identity._closed)
