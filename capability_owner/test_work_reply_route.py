"""The selected capability receiver owns its concrete signed work bridge."""
import asyncio
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, strict_loads
from identity.test_authority import ref, SEED
from .reply_service import CapabilityReplyService
from .test_reply_service import Connection
from .test_work_bridge_owner import WorkBridgeFixture


class WorkReplyRouteTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    def receiver(self, bridge):
        return CapabilityReplyService(self.service.reader, resources=(self.resource,),
            hub_id='hub-one', profile_id='profile-one', authority_id='authority-one',
            service_id='storage-owner', service_identity_ref=ref('service'),
            service_instance_id='ingress-one', signing_key_ref=ref('issuer'), signing_seed=SEED,
            request_signing_key_ref=ref('issuer'), connection=Connection(), work_bridge=bridge)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.route = self.receiver(self.endpoint)
        self.addAsyncCleanup(self.route.close)

    async def route_call(self, raw):
        response = await self.route.handle(raw,
            received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        return self.verify_reply(response, raw)

    async def test_selected_route_returns_exact_signed_original_and_closes_bridge(self):
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Original route'})
        reply = await self.route_call(raw)
        self.assertEqual(reply['outcome'], 'applied')
        self.assertEqual(reply['result'], self.store.q1('SELECT * FROM work_items'))
        self.assertEqual(await self.route_call(raw), reply)
        self.assertEqual(self.route._request_limit, 1048576)
        await self.route.close()
        self.assertTrue(self.endpoint._closed)
        self.assertFalse(self.endpoint._workers)

    async def test_route_refuses_unbound_bridge_and_missing_work_route(self):
        original = self.endpoint._instance
        self.endpoint._instance = 'another-instance'
        try:
            with self.assertRaises(ContractError):
                self.receiver(self.endpoint)
        finally:
            self.endpoint._instance = original
        receiver = self.receiver(None)
        self.addAsyncCleanup(receiver.close)
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Must refuse'})
        with self.assertRaises(ContractError):
            await receiver.handle(raw, received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])

    async def test_policy_pause_joins_original_bridge_effect_before_resuming(self):
        entered, release = threading.Event(), threading.Event()
        original = self.resource._effect
        def held(*args, **kwargs):
            entered.set()
            if not release.wait(3):
                raise TimeoutError('Original work was not released')
            return original(*args, **kwargs)
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Owned work'})
        pending = joining = None
        try:
            with patch.object(self.resource, '_effect', side_effect=held):
                pending = asyncio.create_task(self.route_call(raw))
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                self.route.begin_policy_pause()
                joining = asyncio.create_task(self.route.join_policy_pause())
                await asyncio.sleep(0)
                self.assertFalse(joining.done())
                with self.assertRaises(ContractError):
                    await self.route_call(raw)
                release.set()
                self.assertEqual((await pending)['outcome'], 'applied')
                await joining
                self.assertFalse(self.endpoint._workers)
                self.route.end_policy_pause()
        finally:
            release.set()
            for owned in (pending, joining):
                if owned is not None:
                    await asyncio.gather(owned, return_exceptions=True)
