"""AMUX-669 selected startup with the existing controlled broker boundary."""
import copy
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from dashboard.test_application_service_host import Client
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from identity.test_work_peer_control import WorkPeerControlFixture

from .selected_storage import SelectedStorageFailure
from .test_knowledge_host import SelectedKnowledgeCompositionFixture
from .work import WorkStorageResource
from .work_control import WorkControlOwner


class SelectedWorkControlTests(WorkPeerControlFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        record = strict_loads(self.snapshot.record)
        state = record['state']
        next(item for item in state['transports'] if item['ref'] == ref('transport'))['issuerRef'] = (
            self.value['identity']['issuer']['issuerRef'])
        state['memberships'].append({'ref': ref('work-composition-member'),
            'identityRef': ref('human'), 'scope': copy.deepcopy(self.scope), 'status': 'active'})
        self.snapshot = AuthoritySnapshot(canonical_bytes(record), self.snapshot.sequence + 1)

    async def asyncSetUp(self):
        # The selected host must open the source itself; do not prebuild an owner.
        await SelectedKnowledgeCompositionFixture.asyncSetUp(self)

    async def test_selected_startup_owns_work_control_gates_health_and_cleanup(self):
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
        self.assertNotIn('knowledge', self.selection.policy['storage'])
        self.assertNotIn('operators', self.selection.policy['peerControl']['routes'][0])
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients), \
                patch('hub.fed.peer_control.new_client', return_value=connection):
            await self.host.start()
            self.host.check_health()
            resource = next(item for item in self.host._resources if type(item) is WorkStorageResource)
            self.assertEqual(len(self.host._work_controls), 1)
            self.assertEqual(self.host._knowledge_controls, [])
            owner = self.host._work_controls[0]
            self.assertIs(type(owner), WorkControlOwner)
            self.assertIs(resource._control_owner, owner)
            self.assertIn(owner, self.host._policy_gates())
            ingress = next(iter(owner._routes.values()))
            source = resource._owner._source
            self.assertIs(ingress._store_owner, source)
            self.assertIs(resource._store, source._store)
            self.assertEqual(len(self.host._message_stores), 1)
            self.assertEqual([item.subject for item in connection.subscriptions], ['am.ctl.alice'])
            owner.begin_policy_pause()
            with self.assertRaises(ContractError):
                owner.check()
            await owner.join_policy_pause()
            owner.end_policy_pause()
            self.host.check_health()
            connection.is_connected = False
            with self.assertRaises(SelectedStorageFailure):
                self.host.check_health()
            self.assertTrue(self.host._closed)
            await self.host.close(timeout=None)
            self.assertTrue(owner._closing.done())
            self.assertTrue(ingress._closing.done())
            self.assertFalse(ingress._active)
            self.assertFalse(ingress._workers)
            self.assertFalse(connection.is_connected)
            self.assertIsNone(source._store)
            self.assertTrue(source._closing.done())
            connection.subscriptions[0].unsubscribe.assert_awaited_once()
            self.assertTrue(all(not item.is_connected for item in self.clients))
            self.assertFalse(self.identity._closed)
