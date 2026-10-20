"""Maintenance callers must retain owner authority and original transactions."""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.bridge import Bridge
from hub.fed.runtime import Federation
from hub.store import HubError
from hub.tests.test_hub_offline import reg
from identity.test_service import _Clock
from .federated_work_client import FederatedWorkCommandClient
from .legacy_work_client import LegacyWorkCommandClient
from .test_federated_work_client import FederatedWorkTests
from .test_work_bridge_owner import WorkBridgeFixture


class WorkMaintenanceTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    session_for = FederatedWorkTests.session_for

    async def asyncSetUp(self):
        await super().asyncSetUp()
        timer = patch('capability_owner.legacy_work_client.datetime', _Clock)
        timer.start()
        self.addCleanup(timer.stop)
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.node = self.hub, 'mac'
        self.fed.cfg, self.fed.policy = self.owner.policy.cfg, self.owner.policy
        self.fed.session = self.owner.session
        self.addAsyncCleanup(self.fed.session.close)
        self.hub.fed = self.fed
        await self.replace(owner=self.fed)
        self.submitted, self.drop_after = [], None
        self.commands = LegacyWorkCommandClient(self.hub, (self.session_for('service'),))
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.federated_commands = FederatedWorkCommandClient(self.fed, self.commands)
        self.hub._work_storage_commands = self.commands

    def claimed(self):
        caller = reg(self.store, 'falcon', 'worker', 'one')
        row = self.store.work_create('operator', 'falcon', 'agent:' + caller, 'Retained lease')
        self.store.claim(caller, work_id=row['id'])
        return self.store.agent(caller), self.store.work(row['id'])

    async def test_observed_death_requires_current_owner_permission_before_any_state_change(self):
        agent, row = self.claimed()
        state = strict_loads(self.js.messages[-1].data)
        grant = self.work_grants['service']['federation-work-return-leases']
        next(item for item in state['state']['grants'] if item['ref'] == grant)['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(state)
        with self.assertRaisesRegex(HubError, 'qualified lifecycle changes require the work owner'):
            await self.hub.db(self.hub._set_observed_state, agent, 'dead', 'terminal gone')
        self.assertEqual(self.store.agent(agent['session']), agent)
        self.assertEqual(self.store.work(row['id']), row)

    async def test_legacy_work_without_authenticated_transport_cannot_use_selected_owner(self):
        bridge = Bridge(self.hub, 'nats://127.0.0.1:4222', 'mac', Mock())
        forged = {'type': 'work', 'origin': 'remote:forged-one', 'origin_node': 'remote',
            'origin_id': 'forged-one', 'work': {'repo': 'falcon', 'target': 'role:falcon/worker',
                'title': 'Unverified publisher', 'created_by': 'operator'}}
        await bridge.on_work('am.work.falcon.worker', canonical_bytes(forged))
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])
        self.assertEqual(self.submitted, [])

    async def test_legacy_result_without_authenticated_transport_preserves_original_work(self):
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker',
            'Original outgoing work', federate=True, node='mac')
        before = self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],))
        bridge = Bridge(self.hub, 'nats://127.0.0.1:4222', 'mac', Mock())
        notify = AsyncMock()
        forged = {'type': 'result', 'origin_id': row['id'], 'node': 'remote',
            'state': 'done', 'result': 'Unverified completion', 'by': 'worker'}
        with patch.object(self.hub, '_notify_work_owner', notify):
            await bridge.on_result('am.result.mac', canonical_bytes(forged))
        self.assertEqual(self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],)), before)
        notify.assert_not_awaited()
        self.assertEqual(self.submitted, [])

    async def test_qualified_raw_drain_retains_work_and_still_delivers_later_messages(self):
        with self.store.tx():
            for index in range(201):
                self.store._outbox('am.work.falcon.worker', {'original': index})
            self.store._outbox('am.result.remote', {'original': 'result'})
            self.store._outbox('am.agent.falcon.worker.remote', {'original': 'message'})
        original = self.store.q('SELECT * FROM nats_outbox ORDER BY seq')
        bridge = Bridge(self.hub, 'nats://127.0.0.1:4222', 'mac', Mock())
        bridge.nc = SimpleNamespace(pub=AsyncMock(), flush=AsyncMock())
        await bridge.drain_outbox()
        bridge.nc.pub.assert_awaited_once_with(original[-1]['subject'], original[-1]['payload'].encode())
        bridge.nc.flush.assert_awaited_once()
        self.assertEqual(self.store.q('SELECT * FROM nats_outbox WHERE seq<? ORDER BY seq',
            (original[-1]['seq'],)), original[:-1])
        self.assertIsNotNone(self.store.q1('SELECT sent FROM nats_outbox WHERE seq=?', (original[-1]['seq'],))['sent'])
        self.assertEqual(bridge.stats['published'], 1)

    async def test_unqualified_bridge_preserves_original_legacy_ingest(self):
        self.hub._work_storage_commands = None
        bridge = Bridge(self.hub, 'nats://127.0.0.1:4222', 'mac', Mock())
        item = {'type': 'work', 'origin': 'remote:original', 'origin_node': 'remote',
            'origin_id': 'original', 'work': {'repo': 'falcon', 'target': 'role:falcon/worker',
                'title': 'Original legacy work', 'created_by': 'agent:original'}}
        await bridge.on_work('am.work.falcon.worker', canonical_bytes(item))
        row = self.store.q1('SELECT * FROM work_items')
        self.assertEqual((row['origin'], row['created_by'], row['title']),
            ('remote:original', 'agent:original', 'Original legacy work'))
        self.assertEqual(bridge.stats['ingested_work'], 1)

