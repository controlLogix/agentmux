"""Real signed work owner recovery through retained application sessions."""
import asyncio
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.client_launch_session import ApplicationClientSession
from hub.store import HubError
from hub.tests.test_work_client_transport import material
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, ref
from identity.test_service import _Clock
from .legacy_work_client import LegacyWorkCommandClient
from .test_work_bridge_owner import WorkBridgeFixture


class LegacyWorkClientTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
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

    def session_for(self):
        loop = asyncio.get_running_loop()
        value = material()
        selected = value['workCommands']
        selected.update(transportRef=ref('transport'), grantRefs={contract: self.work_grants['human'][contract]
            for contract in ('federation-work-create', 'federation-work-read', 'federation-work-inspect', 'federation-work-outcome')})
        key = ApplicationClientKey(value)
        session = object.__new__(ApplicationClientSession)
        session._stopped = session._terminal_enrolled = session._terminal_active = False
        session._closing = session._final_closing = None
        session._work_enrollment = canonical_bytes({
            **{name: key.selection[name] for name in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
            'workCommands': key.selection['workCommands']})
        def command(*, contract_id, operation_id, payload, expires_at, deadline, include_valid_until=False):
            claims = {'purpose': 'agentmux-client-possession-v1',
                **{name: key.selection[name] for name in ('hubId', 'profileId', 'authorityId')},
                'transportRef': selected['transportRef'], 'grantRef': selected['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': payload['resourceRef']['revision'],
                'contractId': contract_id, 'payload': payload, 'approvalRefs': [],
                'issuedAt': NOW.isoformat().replace('+00:00', 'Z'), 'expiresAt': expires_at,
                'replySubject': '_INBOX.work_client_actual_01'}
            self.submitted.append(copy.deepcopy(claims))
            raw = key.sign_command(claims, subject=selected['subject'], now=NOW)
            if self.drop_before == contract_id:
                self.drop_before = None
                raise TimeoutError('controlled request loss')
            response = asyncio.run_coroutine_threadsafe(self.endpoint.handle(raw,
                received_reply_subject=claims['replySubject']), loop).result(timeout=6)
            if self.drop_after == contract_id:
                self.drop_after = None
                raise TimeoutError('controlled reply loss')
            return key.verify_command_response(response, raw, subject=selected['subject'], now=NOW,
                include_valid_until=include_valid_until)
        session.work_command = command
        return session

    def route(self):
        return self.client._select('operator', 'create', 'falcon')[0]

    async def execute(self, *, value=None, expires=None):
        session, enrollment = self.route()
        return await self.client._execute(session, enrollment, 'create', self.intent,
            self.value if value is None else value, 'operator', self.expires if expires is None else expires)

    def mutations(self):
        return [claim for claim in self.submitted if claim['contractId'] == 'federation-work-create']

    async def test_lost_reply_recovers_exact_result_after_client_and_owner_replacement(self):
        self.drop_after = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.execute()
        row = self.store.q1('SELECT * FROM work_items')
        original = self.mutations()[0]
        await self.client.close(timeout=None)
        await self.replace()
        self.session = self.session_for()
        self.client = LegacyWorkCommandClient(self.hub, (self.session,))
        self.addAsyncCleanup(self.client.close, timeout=None)
        result = await self.execute()
        self.assertEqual(result, row)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)
        recovered = next(c for c in self.submitted if c['contractId'] == 'federation-work-outcome')
        self.assertEqual(recovered['payload']['input'], {'contractId': original['contractId'],
            'operationId': original['operationId'], 'payloadDigest': payload_digest(original['payload'])})
        self.assertNotIn('validUntil', result)
        self.assertEqual(self.client.confirm_disclosure(result), row)

    async def test_uncertain_absent_does_not_resend_or_renew_original_effect(self):
        self.drop_before = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.execute(expires=NOW + timedelta(seconds=1))
        pending = self.store.q1("SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'")['v']
        with self.assertRaisesRegex(HubError, 'original recovery is retained'):
            await self.execute(expires=NOW + timedelta(seconds=4))
        self.assertEqual(self.store.q1("SELECT v FROM fed_state WHERE k LIKE 'legacy-work-client:%'")['v'], pending)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])
        self.assertEqual(strict_loads(pending)['originalDeadline'], (NOW + timedelta(seconds=1)).isoformat(timespec='microseconds').replace('+00:00', 'Z'))

    async def test_current_original_revocation_refuses_recovery_without_repeat(self):
        self.drop_after = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.execute()
        current = strict_loads(self.js.messages[-1].data)
        next(grant for grant in current['state']['grants']
            if grant['ref'] == self.work_grants['human']['federation-work-create'])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.execute()
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)

    async def test_final_aggregate_disclosure_preserves_earliest_private_owner_deadline(self):
        await self.execute()
        routes = self.client._select('operator', 'read', 'falcon')
        current = strict_loads(self.js.messages[-1].data)
        next(grant for grant in current['state']['grants']
            if grant['ref'] == self.work_grants['human']['federation-work-read'])['expiresAt'] = (
                NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(current)
        rows = await self.client._read(routes, {'kind': 'list', 'state': None}, self.expires)
        self.assertEqual(rows[0]['title'], 'Original')
        with patch('capability_owner.legacy_work_client.datetime') as timer:
            timer.now.return_value = NOW + timedelta(seconds=2)
            with self.assertRaisesRegex(ContractError, 'expired'):
                self.client.confirm_disclosure(rows)
        self.assertTrue(all('validUntil' not in row for row in rows))

    def _read_grant_expires(self, expires):
        current = strict_loads(self.js.messages[-1].data)
        next(grant for grant in current['state']['grants']
            if grant['ref'] == self.work_grants['human']['federation-work-read'])['expiresAt'] = (
                expires.isoformat().replace('+00:00', 'Z'))
        self.js.messages[-1].data = canonical_bytes(current)

    async def test_completed_independent_reads_on_same_task_have_separate_validity(self):
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Original')
        routes = self.client._select('operator', 'read', 'falcon')
        query = {'kind': 'list', 'state': None}
        self._read_grant_expires(NOW + timedelta(seconds=1))
        first = await self.client._read(routes, query, self.expires)
        self.assertEqual(self.client.confirm_disclosure(first), first)
        self.assertIn(asyncio.current_task(), self.client._disclosures)
        self.assertEqual(self.client.finish_disclosure(first), first)
        self.assertNotIn(asyncio.current_task(), self.client._disclosures)
        self._read_grant_expires(self.expires)
        class LaterClock(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        with patch('capability_owner.legacy_work_client.datetime', LaterClock):
            second = await self.client._read(routes, query, self.expires)
            self.assertEqual(self.client.confirm_disclosure(second), second)
            self.assertEqual(self.client.finish_disclosure(second), second)
        self.assertEqual(first, second)
        self.assertNotIn(asyncio.current_task(), self.client._disclosures)
        self.assertEqual(len(self.submitted), 2)
        self.assertTrue(all(claim['contractId'] == 'federation-work-read' for claim in self.submitted))
        self.assertTrue(all('validUntil' not in row for row in second))

    async def test_unfinished_aggregate_keeps_earliest_validity_across_later_reads(self):
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Original')
        routes = self.client._select('operator', 'read', 'falcon')
        query = {'kind': 'list', 'state': None}
        self._read_grant_expires(NOW + timedelta(seconds=1))
        first = await self.client._read(routes, query, self.expires)
        self.assertEqual(self.client.confirm_disclosure(first), first)
        await asyncio.sleep(0)
        self._read_grant_expires(self.expires)
        class LaterClock(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        with patch('capability_owner.legacy_work_client.datetime', LaterClock):
            second = await self.client._read(routes, query, self.expires)
            pending = self.client._disclosures[asyncio.current_task()]
            self.assertEqual(pending[1], NOW + timedelta(seconds=1))
            with self.assertRaisesRegex(ContractError, 'expired'):
                self.client.finish_disclosure([first, second])
            self.assertIs(self.client._disclosures[asyncio.current_task()], pending)
            with self.assertRaisesRegex(ContractError, 'expired'):
                self.client.confirm_disclosure(second)
        self.assertEqual(first, second)
        self.assertEqual(len(self.submitted), 2)

    async def test_close_clears_unfinished_disclosure_and_keeps_original_work(self):
        row = await self.execute()
        self.assertEqual(self.client.confirm_disclosure(row), row)
        self.assertIn(asyncio.current_task(), self.client._disclosures)
        await self.client.close(timeout=None)
        self.assertFalse(self.client._disclosures)
        with self.assertRaises(ContractError):
            self.client.finish_disclosure(row)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_mutation_row_validity_survives_await_and_blocks_final_use(self):
        result = await self.execute()
        await asyncio.sleep(0)
        with patch('capability_owner.legacy_work_client.datetime') as timer:
            timer.now.return_value = NOW + timedelta(seconds=5)
            with self.assertRaisesRegex(ContractError, 'expired'):
                self.client.confirm_disclosure(result)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.mutations()), 1)

    async def test_route_replacement_and_store_worker_replacement_refuse_disclosure(self):
        row = await self.execute()
        original = self.session._work_enrollment
        changed = strict_loads(original)
        changed['workCommands']['transportRef'] = ref('replacement')
        self.session._work_enrollment = canonical_bytes(changed)
        with self.assertRaises(ContractError):
            self.client.confirm_disclosure(row)
        self.session._work_enrollment = original
        self.hub.dbx = object()
        with self.assertRaises(ContractError):
            self.client.confirm_disclosure(row)
        self.hub.dbx = self.worker
        self.assertEqual(self.client.confirm_disclosure(row), row)

    async def test_changed_intent_under_original_digest_refuses_without_new_mutation(self):
        self.drop_after = 'federation-work-create'
        with self.assertRaises(TimeoutError):
            await self.execute()
        with self.assertRaisesRegex(ContractError, 'recovery_invalid'):
            await self.execute(value={**self.value, 'title': 'Substitution'})
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.store.q1('SELECT title FROM work_items')['title'], 'Original')

    async def test_verified_conflict_allows_only_a_later_explicit_fresh_attempt(self):
        loop = asyncio.get_running_loop()
        competing = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Competing'},
            operation='competing')
        original, interfere = self.session.work_command, True
        def command(**kwargs):
            nonlocal interfere
            if kwargs['contract_id'] == 'federation-work-create' and interfere:
                interfere = False
                asyncio.run_coroutine_threadsafe(self.work_call(competing), loop).result(timeout=6)
            return original(**kwargs)
        self.session.work_command = command
        from .legacy_messages_client import LegacyStorageConflict
        with self.assertRaises(LegacyStorageConflict):
            await self.execute()
        self.assertEqual(len(self.mutations()), 1)
        first = self.mutations()[0]
        result = await self.execute()
        self.assertEqual(result['title'], 'Original')
        self.assertEqual(len(self.mutations()), 2)
        self.assertNotEqual(first['operationId'], self.mutations()[1]['operationId'])
        self.assertEqual(first['payload']['input'], self.mutations()[1]['payload']['input'])
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 2)

    async def test_only_confirmed_exact_result_can_be_released_after_durable_completion(self):
        result = await self.execute()
        session, enrollment = self.route()
        with self.assertRaises(ContractError):
            await self.client.confirm_completion(session, enrollment, 'create', self.intent,
                {**result, 'title': 'Substituted'})
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")), 1)
        await self.client.confirm_completion(session, enrollment, 'create', self.intent, result)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_client_cancellation_and_close_join_original_work_transaction(self):
        from threading import Event
        entered, release = Event(), Event()
        create = self.store.work_create
        def blocked(*args, **kwargs):
            result = create(*args, **kwargs)
            entered.set()
            if not release.wait(5):
                raise AssertionError('original work transaction was not released')
            return result
        caller = None
        with patch.object(self.store, 'work_create', side_effect=blocked):
            try:
                caller = asyncio.create_task(self.execute())
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                caller.cancel()
                await asyncio.sleep(0)
                self.assertFalse(caller.done())
                with self.assertRaises(ContractError):
                    await self.client.close(timeout=.01)
                self.assertTrue(self.client._workers)
            finally:
                release.set()
                if caller is not None:
                    await asyncio.gather(caller, return_exceptions=True)
                await self.client.close(timeout=None)
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)
