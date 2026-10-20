"""Explicit work RPC receipts retain original signed owner evidence."""
import asyncio
import copy
from datetime import timedelta
import json
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.test_authority import NOW
from identity.test_service import _Clock
from .legacy_work_client import LegacyWorkCommandClient
from .work_completion import WorkCompletionStore
from .test_work_bridge_owner import WorkBridgeFixture
from . import test_legacy_work_client as client_support


class WorkCompletionTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
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
        self.enrollment = self.session.work_enrollment()
        self.profile = {key: self.enrollment[key] for key in ('hubId', 'profileId', 'authorityId')}
        self.owner = WorkCompletionStore(self.hub, profile=self.profile)
        self.identity = {'operation_id': 'rpc-original', 'request_digest': 'a' * 64,
            'principal': {'authenticatedCaller': 'operator', 'caller': 'operator'},
            'verb': 'work_add', 'arguments': {'to': self.value['target'], 'title': self.value['title'], 'federate': True}}

    async def reserve(self, **changes):
        identity = {**self.identity, **changes}
        return await self.client._owned_db(self.owner.reserve, **identity, bindings=[self.enrollment])

    async def applied(self, **changes):
        pending = await self.reserve(**changes)
        self.intent = pending['intentDigest']
        result = await self.execute()
        self.completions = [(self.session, self.enrollment, 'create', self.intent, result)]
        return result

    def _complete(self, result, **changes):
        return self.owner.complete(**{**self.identity, 'bindings': [self.enrollment],
            'result': result, 'completions': self.completions, **changes})

    async def complete(self, result, **changes):
        def commit():
            with self.store.tx():
                return self._complete(result, **changes)
        return await self.client._owned_db(commit)

    async def lookup(self, **changes):
        return await self.client._owned_db(self.owner.lookup, **{**self.identity, **changes})

    async def test_discarded_drained_response_retains_original_after_client_restart_and_later_write(self):
        original = await self.applied()
        completed = await self.complete(original)
        await self.client._owned_db(self.owner.delivered, completed)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        await self.client.close(timeout=None)
        await self.replace()
        self.session = self.session_for()
        self.client = LegacyWorkCommandClient(self.hub, (self.session,))
        self.addAsyncCleanup(self.client.close, timeout=None)
        self.owner = WorkCompletionStore(self.hub, profile=self.profile)
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Later unrelated write')
        recovered = await self.lookup()
        self.assertEqual(recovered, completed)
        source = recovered['workSources'][0]
        verified = await self.client.verify_completed_source(source, self.expires)
        self.assertEqual(verified, source['confirmedReply']['result'])
        self.assertEqual(self.client.finish_disclosure(recovered['result']), original)
        self.assertEqual(recovered['result'], original)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 2)
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_different_explicit_ids_make_identical_intentional_calls_distinct(self):
        first = await self.applied()
        original_intent = self.intent
        await self.complete(first)
        second = await self.applied(operation_id='rpc-second')
        await self.complete(second, operation_id='rpc-second')
        self.assertNotEqual(first['id'], second['id'])
        self.assertNotEqual(original_intent, self.intent)
        self.assertEqual(len(self.mutations()), 2)
        self.assertEqual(len(self.store.outbox_pending()), 2)

    async def test_outer_result_must_match_the_confirmed_owner_result(self):
        original = await self.applied()
        with self.assertRaises(ContractError):
            await self.complete({**original, 'title': 'Substituted public result'})
        self.assertEqual((await self.lookup())['state'], 'pending')
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")), 1)

    async def test_completed_records_do_not_consume_active_capacity_or_get_evicted(self):
        first = None
        for index in range(34):
            identity = {'operation_id': 'completed-' + str(index)}
            result = await self.applied(**identity)
            completed = await self.complete(result, **identity)
            first = completed if first is None else first
        for index in range(32):
            await self.reserve(operation_id='pending-' + str(index))
        with self.assertRaisesRegex(ContractError, 'work_completion_capacity'):
            await self.reserve(operation_id='over-limit')
        self.assertEqual(await self.lookup(operation_id='completed-0'), first)
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")), 0)
        self.assertEqual(len(self.mutations()), 34)

    async def test_same_id_refuses_actor_arguments_verb_request_digest_and_source_changes(self):
        result = await self.applied()
        completed = await self.complete(result)
        for change in ({'request_digest': 'b' * 64}, {'arguments': {'title': 'Different'}},
                {'verb': 'work_cancel'}, {'principal': {'authenticatedCaller': 'other', 'caller': 'other'}},
                {'principal': {'authenticatedCaller': 'operator', 'caller': 'someone-else'}}):
            with self.subTest(change=tuple(change)), self.assertRaises(ContractError):
                await self.lookup(**change)
        changed = copy.deepcopy(self.enrollment)
        changed['workCommands']['resourceRef']['revision'] += 1
        with self.assertRaises(ContractError):
            await self.client._owned_db(self.owner.reserve, **self.identity, bindings=[changed])
        self.assertEqual(await self.lookup(), completed)

    async def test_completion_and_active_retirement_roll_back_with_notification_transaction(self):
        original = await self.applied()
        def failing():
            with self.store.tx():
                self._complete(original)
                self.store.db.execute("INSERT INTO fed_state(k,v) VALUES ('completion-companion','notification')")
                raise RuntimeError('controlled local follow-on failure')
        with self.assertRaisesRegex(RuntimeError, 'controlled local follow-on failure'):
            await self.client._owned_db(failing)
        self.assertEqual((await self.lookup())['state'], 'pending')
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")), 1)
        self.assertIsNone(self.store.q1("SELECT v FROM fed_state WHERE k='completion-companion'"))
        self.assertEqual((await self.complete(original))['state'], 'completed')

    async def test_complete_requires_transaction_and_exact_confirmed_owner_result(self):
        original = await self.applied()
        with self.assertRaisesRegex(ContractError, 'work_completion_transaction_required'):
            await self.client._owned_db(self._complete, original)
        changed = [(*self.completions[0][:4], {**original, 'title': 'Changed'})]
        with self.assertRaises(ContractError):
            await self.complete(original, completions=changed)
        with self.assertRaises(ContractError):
            await self.complete(original, completions=[])
        self.assertEqual((await self.lookup())['state'], 'pending')
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")), 1)

    async def test_uncertain_original_cannot_be_marked_completed_or_resent(self):
        pending = await self.reserve()
        self.intent = pending['intentDigest']
        self.drop_after = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.execute()
        row = self.store.q1('SELECT * FROM work_items')
        self.completions = [(self.session, self.enrollment, 'create', self.intent, row)]
        self.assertFalse(await self.client._owned_db(self.owner.abandon_unsubmitted, **self.identity))
        with self.assertRaises(ContractError):
            await self.complete(row)
        self.assertEqual((await self.lookup())['state'], 'pending')
        recovered = await self.execute()
        self.completions = [(self.session, self.enrollment, 'create', self.intent, recovered)]
        await self.complete(recovered)
        self.assertEqual(recovered, row)
        self.assertEqual(len(self.mutations()), 1)

    async def test_abandon_removes_only_exact_unsubmitted_reservation(self):
        pending = await self.reserve()
        with self.assertRaises(ContractError):
            await self.client._owned_db(self.owner.abandon_unsubmitted,
                **{**self.identity, 'arguments': {'title': 'Different'}})
        self.assertEqual(await self.lookup(), pending)
        self.assertTrue(await self.client._owned_db(self.owner.abandon_unsubmitted, **self.identity))
        self.assertIsNone(await self.lookup())
        row = await self.applied()
        self.assertFalse(await self.client._owned_db(self.owner.abandon_unsubmitted, **self.identity))
        completed = await self.complete(row)
        self.assertFalse(await self.client._owned_db(self.owner.abandon_unsubmitted, **self.identity))
        self.assertEqual(await self.lookup(), completed)

    async def test_current_original_permission_revocation_and_expiry_block_signed_replay(self):
        row = await self.applied()
        completed = await self.complete(row)
        source = completed['workSources'][0]
        state = strict_loads(self.js.messages[-1].data)
        grant = next(g for g in state['state']['grants']
            if g['ref'] == self.work_grants['human']['federation-work-create'])
        for modification in ({'status': 'revoked'}, {'expiresAt': (NOW - timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')}):
            changed = copy.deepcopy(state)
            target = next(g for g in changed['state']['grants'] if g['ref'] == grant['ref'])
            target.update(modification)
            self.js.messages[-1].data = canonical_bytes(changed)
            with self.assertRaises(ContractError):
                await self.client.verify_completed_source(source, self.expires)
        self.assertEqual(await self.lookup(), completed)
        self.assertEqual(len(self.mutations()), 1)

    async def test_cancelled_completion_joins_original_transaction_and_client_close(self):
        row = await self.applied()
        entered, release = threading.Event(), threading.Event()
        def held_commit():
            entered.set()
            if not release.wait(4):
                raise TimeoutError('Original completion was not released')
            with self.store.tx():
                return self._complete(row)
        task = closing = None
        try:
            task = asyncio.create_task(self.client._owned_db(held_commit))
            self.assertTrue(await asyncio.to_thread(entered.wait, 3))
            task.cancel()
            await asyncio.sleep(.02)
            self.assertFalse(task.done())
            closing = asyncio.create_task(self.client.close(timeout=None))
            await asyncio.sleep(.02)
            self.assertFalse(closing.done())
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await closing
            self.assertEqual(self.owner.lookup(**self.identity)['state'], 'completed')
            self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        finally:
            release.set()
            for owned in (task, closing):
                if owned is not None:
                    await asyncio.gather(owned, return_exceptions=True)

    async def test_malformed_and_oversized_records_refuse_without_losing_original(self):
        row = await self.applied()
        completed = await self.complete(row)
        stored = self.store.q1("SELECT k,v FROM fed_state WHERE k LIKE 'legacy-work-completion:completed:%'")
        for change in ({'workSources': []}, {'formatVersion': True}, {'result': 'x' * 1048576}):
            bad = {**completed, **change}
            self.store.db.execute('UPDATE fed_state SET v=? WHERE k=?', (json.dumps(bad), stored['k']))
            with self.assertRaises(ContractError):
                await self.lookup()
        self.store.db.execute('UPDATE fed_state SET v=? WHERE k=?', (stored['v'], stored['k']))
        self.assertEqual(await self.lookup(), completed)

    async def test_custody_change_refuses_existing_receipt(self):
        row = await self.applied()
        await self.complete(row)
        original = self.hub.dbx
        self.hub.dbx = object()
        try:
            with self.assertRaisesRegex(ContractError, 'work_completion_binding'):
                self.owner.lookup(**self.identity)
        finally:
            self.hub.dbx = original

    async def test_invalid_explicit_ids_and_unsupported_verbs_do_not_reserve(self):
        for operation in (None, '', 'with.dot', True, 'x' * 129):
            with self.assertRaises(ContractError):
                await self.reserve(operation_id=operation)
        with self.assertRaises(ContractError):
            await self.reserve(verb='arbitrary-effect')
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-completion:%'"), [])
