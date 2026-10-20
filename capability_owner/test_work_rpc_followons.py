"""Actual work RPC offers and durable release follow-ons."""
import unittest
from unittest.mock import AsyncMock, patch

from hub.fed.runtime import Federation
from hub.fed import ledger
from hub.fed.policy import Policy
from hub.store import HubError
from identity.test_service import _Clock
from .local_work_client import LocalWorkClient
from .test_work_bridge_owner import WorkBridgeFixture
from . import test_work_rpc as rpc_support
from . import test_work_runtime as runtime_support
from .work_rpc import WorkRpc


class WorkRpcFollowonTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    session_for = runtime_support.WorkRuntimeTests.session_for
    caller = runtime_support.WorkRuntimeTests.caller
    packet = rpc_support.WorkRpcTests.packet
    mutations = rpc_support.WorkRpcTests.mutations
    active = rpc_support.WorkRpcTests.active

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await runtime_support.WorkRuntimeTests.setup_runtime(self)
        self.drop_before = None
        self.fed.cfg['federation'].update(enabled=True, url='nats://127.0.0.1:4222')
        for module in ('capability_owner.local_work_client', 'capability_owner.work_rpc', 'hub.server'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.local = LocalWorkClient(self.hub, self.storage)
        self.hub._work_storage_commands, self.hub._local_work_commands = self.storage, self.local
        self.hub._work_rpc = WorkRpc(self.hub, self.storage, self.local)
        self.args = {'to': 'role:falcon/worker', 'title': 'Original RPC offer'}

    async def test_actual_federated_offer_and_local_federate_retry_preserve_one_outbox(self):
        for verb, args in (('fed_work_add', self.args),
                ('work_add', {**self.args, 'federate': True})):
            with self.subTest(verb=verb):
                original = await self.packet(verb, args, operation_id=verb)
                self.assertTrue(original['ok'], original)
                recovered = await self.packet(verb, args, operation_id=verb)
                self.assertEqual(recovered, original)
        self.assertEqual(len(self.mutations('offer')), 2)
        self.assertEqual(len(ledger.outbox_pending(self.store)), 2)
        self.assertEqual(self.active(), [])

    async def test_unshared_federation_offer_refuses_before_effect(self):
        del self.fed.cfg['repos']['falcon']
        self.fed.policy = Policy(self.fed.cfg, {})
        refused = await self.packet('fed_work_add', self.args)
        self.assertFalse(refused['ok'], refused)
        self.assertEqual(self.mutations('offer'), [])
        self.assertEqual(ledger.outbox_pending(self.store), [])

    async def test_required_release_followon_failure_retains_original_for_retry(self):
        from .test_work_on_behalf import OperatorWorkClientTests
        session = self.store.register('falcon', 'worker', 'claude', 'claude', {'max_active': 1})
        self.store.db.execute("UPDATE agents SET state='ready' WHERE session=?", (session,))
        # Use real operator proof with an explicit registered effective target.
        operator_session = OperatorWorkClientTests.session_for(self)
        from .legacy_work_client import LegacyWorkCommandClient
        self.storage = LegacyWorkCommandClient(self.hub, (operator_session,))
        self.addAsyncCleanup(self.storage.close, timeout=None)
        self.storage.bind(self.fed)
        self.local = LocalWorkClient(self.hub, self.storage)
        self.hub._work_storage_commands, self.hub._local_work_commands = self.storage, self.local
        self.hub._work_rpc = WorkRpc(self.hub, self.storage, self.local)
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Original release')
        self.store.claim(session, work_id=row['id'])
        request = {'verb': 'release', 'args': {'work_id': row['id'], 'outcome': 'done'},
            'operationId': 'release-followon', 'as': session}
        import asyncio
        import json
        import os
        from types import SimpleNamespace
        from unittest.mock import Mock
        async def call():
            replies = []
            reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()))
            writer = SimpleNamespace(write=Mock(side_effect=lambda raw: replies.append(json.loads(raw))),
                drain=AsyncMock(), close=Mock(), get_extra_info=lambda name: object())
            with patch.object(self.hub, 'peer', return_value=(123, os.getuid())), \
                    patch.object(self.hub, 'identify_qualified', return_value=(None, False)):
                await asyncio.create_task(self.hub.handle_conn(reader, writer))
            return replies[0]
        with patch.object(self.fed, 'local_event', new=AsyncMock(side_effect=HubError('capture pending'))):
            uncertain = await call()
        self.assertFalse(uncertain['ok'], uncertain)
        self.assertEqual(len(self.mutations('release')), 1)
        self.assertEqual(len(self.active()), 1)
        with patch.object(self.fed, 'local_event', new=AsyncMock()) as event:
            recovered = await call()
            self.assertTrue(recovered['ok'], recovered)
            event.assert_awaited_once_with('work_released', recovered['result'], require_completion=True)
            repeated = await call()
            self.assertEqual(repeated, recovered)
            event.assert_awaited_once()
        self.assertEqual(len(self.mutations('release')), 1)
        self.assertEqual(self.active(), [])

    async def test_required_local_event_does_not_swallow_capture_failure(self):
        adapter = next(iter(self.fed.plugin_adapters.values()))
        with patch.object(type(adapter), 'on_local_event', new=AsyncMock(side_effect=HubError('pending'))):
            with self.assertRaisesRegex(HubError, 'pending'):
                await Federation.local_event(self.fed, 'work_released', {}, require_completion=True)
