"""Caller routing retains the original intent after an uncertain work reply."""
import unittest
import asyncio
import threading
from datetime import timedelta
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.test_authority import NOW
from identity.test_service import _Clock
from hub.store import HubError
from .legacy_work_client import LegacyWorkCommandClient
from . import test_legacy_work_client as client_support
from .test_work_bridge_owner import WorkBridgeFixture


class WorkPendingRouteTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    session_for = client_support.LegacyWorkClientTests.session_for
    route = client_support.LegacyWorkClientTests.route
    execute = client_support.LegacyWorkClientTests.execute
    mutations = client_support.LegacyWorkClientTests.mutations

    async def asyncSetUp(self):
        await super().asyncSetUp()
        patch('capability_owner.legacy_work_client.datetime', _Clock).start()
        self.submitted, self.drop_after, self.drop_before = [], None, None
        self.session = self.session_for()
        self.client = LegacyWorkCommandClient(self.hub, (self.session,))
        self.addAsyncCleanup(self.client.close, timeout=None)
        self.expires = NOW + timedelta(seconds=4)
        self.value = {'target': 'role:falcon/worker', 'title': 'Original', 'federate': True}
        self.intent = payload_digest({'verb': 'work_add', 'args': self.value})

    async def test_lost_reply_recovers_exact_original_input_before_new_route_selection(self):
        self.assertIsNone(await self.client.pending_route('operator', 'create', self.intent))
        self.drop_after = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.execute()
        row = self.store.q1('SELECT * FROM work_items')
        session, enrollment, value = await self.client.pending_route('operator', 'create', self.intent)
        self.assertIs(session, self.session)
        self.assertEqual(enrollment, self.session.work_enrollment())
        self.assertEqual(value, self.value)
        self.assertEqual(await self.execute(value=value), row)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_replaced_binding_cannot_turn_original_uncertainty_into_fresh_work(self):
        self.drop_before = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.execute()
        await self.client.close(timeout=None)
        enrollment = strict_loads(self.session._work_enrollment)
        enrollment['workCommands']['resourceRef']['revision'] += 1
        self.session._work_enrollment = canonical_bytes(enrollment)
        self.client = LegacyWorkCommandClient(self.hub, (self.session,))
        self.addAsyncCleanup(self.client.close, timeout=None)
        with self.assertRaises(ContractError):
            await self.client.pending_route('operator', 'create', self.intent)
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])
        self.assertEqual(len(self.mutations()), 1)

    async def test_different_intent_and_invalid_query_do_not_retarget_original(self):
        self.drop_before = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.execute()
        self.assertIsNone(await self.client.pending_route('operator', 'create', 'sha256:' + 'a' * 64))
        for command, digest in (('read', self.intent), ('create', 'invalid')):
            with self.assertRaises(ContractError):
                await self.client.pending_route('operator', command, digest)
        self.assertEqual((await self.client.pending_route('operator', 'create', self.intent))[2], self.value)

    async def test_cancelled_completion_joins_original_forget_before_client_close(self):
        entered, release = threading.Event(), threading.Event()
        original = self.client._forget
        def held(*args):
            entered.set()
            if not release.wait(3):
                raise TimeoutError('Original completion was not released')
            return original(*args)
        async def finish():
            result = await self.execute()
            session, enrollment = self.route()
            await self.client.confirm_completion(session, enrollment, 'create', self.intent, result)
        pending = closing = None
        try:
            with patch.object(self.client, '_forget', side_effect=held):
                pending = asyncio.create_task(finish())
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                pending.cancel()
                await asyncio.sleep(.02)
                self.assertFalse(pending.done())
                closing = asyncio.create_task(self.client.close(timeout=None))
                await asyncio.sleep(.02)
                self.assertFalse(closing.done())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await pending
                await closing
        finally:
            release.set()
            for owned in (pending, closing):
                if owned is not None:
                    await asyncio.gather(owned, return_exceptions=True)

    async def test_recovery_only_refuses_an_original_forgotten_after_route_lookup(self):
        result = await self.execute()
        session, enrollment, value = await self.client.pending_route('operator', 'create', self.intent)
        await self.client.confirm_completion(session, enrollment, 'create', self.intent, result)
        before = len(self.submitted)
        with self.assertRaisesRegex(HubError, 'no command was submitted'):
            await self.client._execute(session, enrollment, 'create', self.intent, value,
                'operator', self.expires, recover_only=True)
        self.assertEqual(len(self.submitted), before)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_recovery_only_returns_the_original_without_a_second_effect(self):
        self.drop_after = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.execute()
        original = self.store.q1('SELECT * FROM work_items')
        session, enrollment, value = await self.client.pending_route('operator', 'create', self.intent)
        result = await self.client._execute(session, enrollment, 'create', self.intent, value,
            'operator', self.expires, recover_only=True)
        self.assertEqual(result, original)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_completed_source_replay_queries_original_after_active_record_retired(self):
        result = await self.execute()
        row = self.store.q1("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")
        source = self.client._pending(row['k'])
        session, enrollment = self.route()
        await self.client.confirm_completion(session, enrollment, 'create', self.intent, result)
        self.client.finish_disclosure()
        self.assertIsNone(self.client._pending(row['k']))
        self.assertEqual(await self.client.verify_completed_source(source, self.expires), result)
        self.client.finish_disclosure()
        self.assertIsNone(self.client._pending(row['k']))
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_completed_source_substitution_never_reissues_a_mutation(self):
        result = await self.execute()
        row = self.store.q1("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")
        source = self.client._pending(row['k'])
        session, enrollment = self.route()
        await self.client.confirm_completion(session, enrollment, 'create', self.intent, result)
        self.client.finish_disclosure()
        source['operationId'] = 'another-original'
        with self.assertRaises(ContractError):
            await self.client.verify_completed_source(source, self.expires)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertIsNone(self.client._pending(row['k']))
