"""Adoption source preflight precedes its unchanged caller proof lifetime."""
import asyncio
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError
from hub import server
from .test_work_source import SelectedWorkSourceFixture
from . import test_hub_work_maintenance as maintenance_fixture
from . import test_hub_lifecycle_disclosure as disclosure_fixture


class PreflightFallback(Exception):
    pass


class AdoptPreflightTests(SelectedWorkSourceFixture, unittest.IsolatedAsyncioTestCase):
    def configure_channels(self, **kwargs):
        maintenance_fixture.HubWorkMaintenanceTests.configure_channels(self, include_second=False, **kwargs)

    async def asyncSetUp(self):
        await maintenance_fixture.HubWorkMaintenanceTests.asyncSetUp(self)
        self.arguments = {'legacy': 'preflight-pane', 'repo': 'falcon', 'role': 'worker',
            'agent': 'preflight', 'cli': 'shell'}
        self.request = {'verb': 'adopt', 'args': self.arguments, 'operationId': 'preflight-original'}
        self.writer = SimpleNamespace(get_extra_info=lambda key: object())
        self.enterContext(patch.object(self.hub, 'peer', return_value=(123, server.os.getuid())))
        self.enterContext(patch.object(self.hub, 'identify_qualified', return_value=(None, False)))
        self.enterContext(patch.object(self.hub, 'resolve_role', return_value={}))
        self.enterContext(patch.object(self.hub.tp, 'handle', return_value=('%94', 23904)))
        self.binding = self.hub._work_source_binding

    async def dispatch(self, proof, *, arguments=None, caller='operator'):
        token = self.hub._authenticated_caller_context.set(proof)
        try:
            return await self.hub.dispatch('adopt', self.arguments if arguments is None else arguments, caller)
        finally:
            self.hub._authenticated_caller_context.reset(token)

    async def test_actual_adoption_preflights_before_identity_once_and_preserves_receipt(self):
        events = []
        verify, identity = self.binding.verify, self.hub._caller_identity
        async def verified():
            events.append('verify-enter')
            await verify()
            events.append('verify-return')
        async def classified(*args, **kwargs):
            events.append('identity')
            return await identity(*args, **kwargs)
        with patch.object(self.binding, 'verify', side_effect=verified), \
                patch.object(self.hub, '_caller_identity', side_effect=classified):
            proof = await self.hub.authenticate_caller(self.request, self.writer, False)
            admitted = self.hub._authenticated_callers[proof]
            self.assertIs(admitted.work_source_preflight, self.binding)
            self.assertGreater(admitted.expires_monotonic, time.monotonic())
            self.assertLessEqual(admitted.expires_monotonic - time.monotonic(), 5)
            result = await self.dispatch(proof)
        self.assertEqual(events, ['verify-enter', 'verify-return', 'identity'])
        row = await self.hub.db(self.hub.store.agent, result['session'])
        self.assertEqual((row['generation'], row['state'], row['handle']), (1, 'ready', '%94'))
        self.assertTrue(any(r['contractId'] == 'federation-work-register' for r in self.submitted))

    async def test_changed_arguments_caller_task_and_direct_calls_keep_dispatch_preflight(self):
        for kind in ('arguments', 'caller', 'task', 'direct'):
            with self.subTest(kind=kind):
                proof = None if kind == 'direct' else await self.hub.authenticate_caller(self.request, self.writer, False)
                with patch.object(self.binding, 'verify', side_effect=PreflightFallback) as verify:
                    with self.assertRaises(PreflightFallback):
                        if kind == 'task':
                            task = asyncio.create_task(self.dispatch(proof))
                            await asyncio.wait_for(task, 3)
                        else:
                            await self.dispatch(proof,
                                arguments={**self.arguments, 'agent': 'changed'} if kind == 'arguments' else None,
                                caller='different' if kind == 'caller' else 'operator')
                    verify.assert_awaited_once()
        self.assertFalse(any(r['contractId'] == 'federation-work-register' for r in self.submitted))

    async def test_expired_original_proof_keeps_dispatch_preflight(self):
        proof = await self.hub.authenticate_caller(self.request, self.writer, False)
        deadline = self.hub._authenticated_callers[proof].expires_monotonic
        expired = asyncio.Event()
        timer = asyncio.get_running_loop().call_later(max(0, deadline - time.monotonic()) + .02, expired.set)
        try:
            await asyncio.wait_for(expired.wait(), 6)
        finally:
            timer.cancel()
        with patch.object(self.binding, 'verify', side_effect=PreflightFallback) as verify:
            with self.assertRaises(PreflightFallback):
                await self.dispatch(proof)
            verify.assert_awaited_once()

    async def test_source_mode_changed_during_authentication_refuses_proof(self):
        identity = self.hub._caller_identity
        original_url = self.hub.cfg.get('nats_url')
        async def changed(*args, **kwargs):
            result = await identity(*args, **kwargs)
            self.hub.cfg['nats_url'] = 'nats://changed.invalid'
            return result
        try:
            with patch.object(self.hub, '_caller_identity', side_effect=changed):
                with self.assertRaises(ContractError):
                    await self.hub.authenticate_caller(self.request, self.writer, False)
            self.assertEqual(len(self.hub._authenticated_callers), 0)
        finally:
            if original_url is None:
                self.hub.cfg.pop('nats_url', None)
            else:
                self.hub.cfg['nats_url'] = original_url

    async def test_wrong_uid_refuses_before_source_preflight(self):
        with patch.object(self.hub, 'peer', return_value=(123, server.os.getuid() + 1)), \
                patch.object(self.binding, 'verify', wraps=self.binding.verify) as verify:
            with self.assertRaisesRegex(server.HubError, 'wrong uid'):
                await self.hub.authenticate_caller(self.request, self.writer, False)
            verify.assert_not_awaited()

    async def test_cancelled_authentication_joins_original_source_verification(self):
        entered, release = asyncio.Event(), asyncio.Event()
        prove = self.binding._prove_current
        workers = []
        async def held(*args, **kwargs):
            workers.append(asyncio.current_task())
            result = await prove(*args, **kwargs)
            entered.set()
            await release.wait()
            return result
        with patch.object(self.binding, '_prove_current', side_effect=held):
            task = asyncio.create_task(self.hub.authenticate_caller(self.request, self.writer, False))
            try:
                await asyncio.wait_for(entered.wait(), 3)
                task.cancel()
                delivered = asyncio.Event()
                asyncio.get_running_loop().call_soon(delivered.set)
                await delivered.wait()
                self.assertFalse(task.done())
                self.assertTrue(any(not worker.done() for worker in workers))
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(asyncio.shield(task), 5)
                self.assertTrue(all(worker.done() for worker in workers))
                self.assertEqual(len(self.hub._authenticated_callers), 0)
            finally:
                release.set()
                if not task.done():
                    task.cancel()
                await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 8)

    async def test_remote_register_grant_revoked_after_preflight_prevents_effect(self):
        identity = self.hub._caller_identity
        async def revoked(*args, **kwargs):
            result = await identity(*args, **kwargs)
            disclosure_fixture.HubLifecycleDisclosureTests.revoke(self, 'register')
            return result
        with patch.object(self.hub, '_caller_identity', side_effect=revoked):
            proof = await self.hub.authenticate_caller(self.request, self.writer, False)
        with self.assertRaises(ContractError):
            await self.dispatch(proof)
        self.assertIsNone(await self.hub.db(self.hub.store.agent, 'falcon-worker-preflight'))
