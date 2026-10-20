"""Scoped readiness under actual signed actor authority and original validity."""
import asyncio
from datetime import timedelta
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from hub.tests.test_hub_offline import reg
from identity.test_authority import NOW, ref
from identity.test_service import _Clock
from .legacy_work_client import LegacyWorkCommandClient
from .test_work_bridge_owner import WorkBridgeFixture
from . import test_work_bridge_owner as owner_tests
from . import test_legacy_work_client as client_tests
from .work_legacy import LegacyWorkActor


class WorkReadinessTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def readiness(self, session, *, identity='human', operation='readiness'):
        return (await self.work_call(self.work_request('read',
            {'query': {'kind': 'readiness', 'session': session}}, identity=identity,
            operation=operation)))['value']

    def target(self, repo='falcon', name='target', maximum=2):
        return reg(self.store, repo, 'worker', name,
            snap={'capabilities': ['python'], 'max_active': maximum})

    async def test_operator_and_service_read_exact_local_target_without_federation(self):
        target = self.target()
        ready = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Ready')
        active = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Active')
        self.store.claim(target, work_id=active['id'], repository='falcon')
        for identity in ('human', 'service'):
            result = await self.readiness(target, identity=identity, operation='read-' + identity)
            self.assertEqual(set(result), {'claimable', 'active', 'capacity'})
            self.assertEqual([x['id'] for x in result['claimable']], [ready['id']])
            self.assertEqual([x['id'] for x in result['active']], [active['id']])
            self.assertEqual(result['capacity'], {'atCapacity': False, 'available': 1})
            self.assertNotIn('token_sha', canonical_bytes(result).decode())
        self.assertIsNone(self.resource.repository_id)
        self.assertFalse(hasattr(self.local, 'policy'))

    async def test_agent_self_only_and_native_select_cannot_bypass_checked_permission(self):
        target = await owner_tests.WorkBridgeOwnerTests._agent_owner(self)
        other = self.target(name='other')
        self.assertEqual((await self.readiness(target))['capacity']['available'], 3)
        with self.assertRaises(ContractError):
            await self.readiness(other, operation='other-agent')
        with self.assertRaises(ContractError):
            self.resource._select({'kind': 'readiness', 'session': target}, target)
        # The existing generic query still has its original shape and behavior.
        self.assertEqual(self.resource._select({'kind': 'list', 'state': None}, 'operator'), [])

    async def test_service_identity_cannot_use_an_operator_enrollment_label(self):
        target = self.target()
        service = self.work_actors[1]
        actors = (self.work_actors[0], LegacyWorkActor(service.identity_ref, service.transport_ref,
            'operator', service.grants))
        await self.replace(actors=actors)
        with self.assertRaises(ContractError):
            await self.readiness(target, identity='service')

    async def test_cross_home_group_eligibility_and_global_capacity_hide_foreign_rows(self):
        self.store.repo_add('falcon', groups=['shared'])
        self.store.repo_add('other', groups=['shared'])
        target = self.target(repo='other', maximum=1)
        allowed = self.store.work_create('virtual:operator', 'falcon', 'role:group:shared/worker', 'Allowed')
        self.store.work_create('virtual:operator', 'falcon', 'role:*/worker', 'Missing capability',
            requirements={'capabilities': ['missing']})
        hidden = self.store.work_create('virtual:operator', 'other', 'role:other/worker', 'Private other work')
        self.store.claim(target, work_id=hidden['id'], repository='other')
        result = await self.readiness(target, identity='service')
        self.assertEqual(result['claimable'], self.store.claimable(target, repository='falcon'))
        self.assertEqual([x['id'] for x in result['claimable']], [allowed['id']])
        self.assertEqual(result['active'], [])
        self.assertEqual(result['capacity'], {'atCapacity': True, 'available': 0})
        self.assertNotIn(hidden['id'], canonical_bytes(result).decode())
        self.assertNotIn(hidden['title'], canonical_bytes(result).decode())

    async def test_shared_owner_keeps_same_scope_and_projection(self):
        target = self.target()
        await self.replace(owner=self.owner)
        self.assertIsNotNone(self.resource.repository_id)
        result = await self.readiness(target, identity='service')
        self.assertEqual(result, {'claimable': [], 'active': [],
            'capacity': {'atCapacity': False, 'available': 2}})

    async def test_missing_dead_and_unbounded_query_refuse(self):
        target = self.target()
        self.store.set_state(target, 'dead')
        for session in (target, 'missing'):
            with self.subTest(session=session), self.assertRaises(ContractError):
                await self.readiness(session, operation='bad-' + session)
        payload = {'resourceRef': ref('task-one'), 'input': {'query':
            {'kind': 'readiness', 'session': '*'}}}
        with self.assertRaises(ContractError):
            validate('federation-work-read', payload)

    async def test_revoked_read_grant_refuses(self):
        target = self.target()
        raw = self.work_request('read', {'query': {'kind': 'readiness', 'session': target}})
        current = strict_loads(self.js.messages[-1].data)
        next(x for x in current['state']['grants'] if
            x['ref'] == self.work_grants['human']['federation-work-read'])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.work_call(raw)

    async def test_read_grant_from_another_scope_refuses(self):
        target = self.target()
        current = strict_loads(self.js.messages[-1].data)
        grant = next(x for x in current['state']['grants'] if
            x['ref'] == self.work_grants['human']['federation-work-read'])
        grant['scope'] = {**grant['scope'], 'projectId': 'another-project'}
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.readiness(target)

    async def test_read_grant_revoked_after_load_refuses(self):
        target = self.target()
        select = self.resource._select
        def revoked(*args, **kwargs):
            result = select(*args, **kwargs)
            current = strict_loads(self.js.messages[-1].data)
            next(x for x in current['state']['grants'] if
                x['ref'] == self.work_grants['human']['federation-work-read'])['status'] = 'revoked'
            self.js.messages[-1].data = canonical_bytes(current)
            return result
        with patch.object(self.resource, '_select', side_effect=revoked):
            with self.assertRaises(ContractError):
                await self.readiness(target)

    async def test_generation_change_after_original_load_refuses_disclosure(self):
        target = self.target()
        select = self.resource._select
        def changed(*args, **kwargs):
            result = select(*args, **kwargs)
            self.store.set_state(target, 'dead')
            self.target()
            return result
        with patch.object(self.resource, '_select', side_effect=changed):
            with self.assertRaises(ContractError):
                await self.readiness(target)

    async def test_generation_change_during_final_outer_admission_refuses(self):
        target = self.target()
        admit, calls = self.endpoint._admit, 0
        async def changed(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.store.set_state(target, 'dead')
                self.target()
            return await admit(*args, **kwargs)
        with patch.object(self.endpoint, '_admit', side_effect=changed):
            with self.assertRaises(ContractError):
                await self.readiness(target)
        self.assertEqual(calls, 2)

    def read_grant_until(self, seconds):
        current = strict_loads(self.js.messages[-1].data)
        next(x for x in current['state']['grants'] if
            x['ref'] == self.work_grants['human']['federation-work-read'])['expiresAt'] = (
                NOW + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(current)

    async def test_first_validity_is_not_extended_by_final_authority_snapshot(self):
        target = self.target()
        self.read_grant_until(1)
        admit, calls = self.endpoint._admit, 0
        async def extended(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.read_grant_until(4)
            return await admit(*args, **kwargs)
        raw = self.work_request('read', {'query': {'kind': 'readiness', 'session': target}})
        with patch.object(self.endpoint, '_admit', side_effect=extended):
            reply = await self.work_call(raw, include_valid_until=True)
        self.assertEqual(reply['validUntil'], (NOW + timedelta(seconds=1)).isoformat(
            timespec='microseconds').replace('+00:00', 'Z'))

    async def test_expiry_after_load_refuses_even_if_final_grant_is_extended(self):
        target = self.target()
        self.read_grant_until(1)
        select = self.resource._select
        class LaterClock:
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        def expired(*args, **kwargs):
            result = select(*args, **kwargs)
            self.read_grant_until(4)
            patch('capability_owner.work_legacy.datetime', LaterClock).start()
            return result
        with patch.object(self.resource, '_select', side_effect=expired):
            with self.assertRaises(ContractError):
                await self.readiness(target)

    async def test_reader_substitution_after_load_refuses(self):
        target = self.target()
        select, reader = self.resource._select, self.resource._legacy_authority
        def changed(*args, **kwargs):
            result = select(*args, **kwargs)
            self.resource._legacy_authority = object()
            return result
        try:
            with patch.object(self.resource, '_select', side_effect=changed):
                with self.assertRaises(ContractError):
                    await self.readiness(target)
        finally:
            self.resource._legacy_authority = reader

    async def test_actual_source_worker_substitution_after_load_refuses(self):
        target = self.target()
        select, worker = self.resource._select, self.hub.dbx
        def changed(*args, **kwargs):
            result = select(*args, **kwargs)
            self.hub.dbx = object()
            return result
        try:
            with patch.object(self.resource, '_select', side_effect=changed):
                with self.assertRaises(ContractError):
                    await self.readiness(target)
        finally:
            self.hub.dbx = worker

    async def test_cancelled_read_and_close_join_original_db_worker(self):
        target = self.target()
        entered, release = threading.Event(), threading.Event()
        original = self.store.claimable
        def held(*args, **kwargs):
            entered.set()
            if not release.wait(4):
                raise TimeoutError('controlled DB worker release')
            return original(*args, **kwargs)
        task = closing = None
        try:
            with patch.object(self.store, 'claimable', side_effect=held):
                task = asyncio.create_task(self.readiness(target))
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                closing = asyncio.create_task(self.endpoint.close(timeout=None))
                await asyncio.sleep(0.02)
                self.assertFalse(closing.done())
                self.assertTrue(self.local._pending)
                release.set()
                await closing
                self.assertFalse(self.local._pending)
                self.assertFalse(self.endpoint._workers)
        finally:
            release.set()
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)
            if closing is not None:
                await closing


class WorkReadinessClientTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    session_for = client_tests.LegacyWorkClientTests.session_for

    async def test_signed_client_keeps_readiness_validity_private_through_final_use(self):
        patch('capability_owner.legacy_work_client.datetime', _Clock).start()
        self.submitted, self.drop_after, self.drop_before = [], None, None
        session = self.session_for()
        client = LegacyWorkCommandClient(self.hub, (session,))
        self.addAsyncCleanup(client.close, timeout=None)
        target = reg(self.store, 'falcon', 'worker', 'client', snap={'max_active': 1})
        current = strict_loads(self.js.messages[-1].data)
        next(x for x in current['state']['grants'] if
            x['ref'] == self.work_grants['human']['federation-work-read'])['expiresAt'] = (
                NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(current)
        routes = client._select('operator', 'read', 'falcon')
        result = await client._read(routes, {'kind': 'readiness', 'session': target}, NOW + timedelta(seconds=4))
        self.assertNotIn('validUntil', canonical_bytes(result).decode())
        client.confirm_disclosure(result)
        with patch('capability_owner.legacy_work_client.datetime') as clock:
            clock.now.return_value = NOW + timedelta(seconds=2)
            with self.assertRaisesRegex(ContractError, 'expired'):
                client.finish_disclosure(result)
