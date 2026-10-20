"""Signed operator commands retain an explicit agent target and original outcome."""
import asyncio
import copy
from datetime import timedelta
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.client_launch_session import ApplicationClientSession
from hub.store import HubError
from hub.tests.test_hub_offline import reg
from hub.tests.test_work_client_transport import material
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, ref
from identity.test_service import _Clock
from .legacy_work_client import LegacyWorkCommandClient
from .test_work_bridge_owner import WorkBridgeFixture
from . import test_work_bridge_owner as owner_tests


class OperatorTargetFixture(WorkBridgeFixture):
    def target(self, *, repo='falcon', name='target', maximum=3):
        session = reg(self.store, repo, 'worker', name,
            snap={'capabilities': ['python'], 'max_active': maximum})
        return {'session': session, 'generation': self.store.agent(session)['generation']}

    def ready(self, *, repo='falcon', target='role:falcon/worker', title='Original', **kwargs):
        return self.store.work_create('virtual:operator', repo, target, title, **kwargs)

    def change_generation(self, target):
        self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (target['session'],))

    def revoke(self, action):
        current = strict_loads(self.js.messages[-1].data)
        next(g for g in current['state']['grants'] if
            g['ref'] == self.work_grants['human']['federation-work-' + action])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(current)


class OperatorWorkOwnerTests(OperatorTargetFixture, unittest.IsolatedAsyncioTestCase):
    async def test_create_on_behalf_keeps_agent_sender_and_parent_holder_rules(self):
        target = self.target()
        parent = self.ready()
        self.store.claim(target['session'], work_id=parent['id'], repository='falcon')
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Child',
            'parentId': parent['id'], 'onBehalfOf': target})
        receipt = await self.work_call(raw)
        row = receipt['result']
        self.assertEqual(row['created_by'], 'agent:' + target['session'])
        self.assertEqual(row['parent_id'], parent['id'])
        self.assertEqual(await self.work_call(raw), receipt)
        other = self.target(name='other')
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('create', {'target': 'role:falcon/worker',
                'title': 'Wrong holder', 'parentId': parent['id'], 'onBehalfOf': other},
                operation='wrong-holder', revision=2))
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 2)

    async def test_offer_on_behalf_keeps_exact_agent_sender_provenance(self):
        target = self.target()
        await self.replace(owner=self.owner)
        raw = self.work_request('offer', {'target': 'role:falcon/worker', 'title': 'Outbound',
            'onBehalfOf': target})
        receipt = await self.work_call(raw)
        self.assertEqual(receipt['result']['created_by'], 'agent:' + target['session'])
        self.assertEqual(await self.work_call(raw), receipt)
        outbox = self.store.q('SELECT * FROM fed_outbox')
        self.assertEqual(len(outbox), 1)
        item = strict_loads(outbox[0]['payload'])
        self.assertEqual(item['data']['sender'], {'rid': item['rid'], 'role': 'worker', 'agent': 'target'})

    async def test_operator_claim_heartbeat_path_release_keep_effective_agent_and_raw_result(self):
        target = self.target()
        row = self.ready()
        claim = self.work_request('claim', {'workId': row['id'], 'onBehalfOf': target})
        result = await self.work_call(claim)
        self.assertEqual(result['result']['claimed']['claimed_by'], target['session'])
        self.assertEqual(strict_loads(claim)['claims']['payload']['attribution'], 'operator')
        self.assertEqual(await self.work_call(claim), result)
        heartbeat = await self.work_call(self.work_request('heartbeat', {'onBehalfOf': target},
            operation='heartbeat', revision=2))
        self.assertEqual(heartbeat['result']['renewed'], 1)
        path = await self.work_call(self.work_request('claim-path',
            {'path': 'src/original.py', 'workId': row['id'], 'onBehalfOf': target},
            operation='path', revision=3))
        self.assertEqual(path['result']['holder'], target['session'])
        released = await self.work_call(self.work_request('release',
            {'workId': row['id'], 'outcome': 'done', 'result': 'Exact result', 'onBehalfOf': target},
            operation='release', revision=4))
        expected = self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],))
        self.assertEqual(released['result'], expected)
        self.assertEqual(expected['claimed_by'], target['session'])
        self.assertNotIn('children', released['result'])
        self.assertEqual(self.store.q('SELECT * FROM claims'), [])

    async def test_cross_home_group_and_global_capacity_keep_store_rules(self):
        self.store.repo_add('falcon', groups=['shared'])
        self.store.repo_add('other', groups=['shared'])
        target = self.target(repo='other', maximum=1)
        allowed = self.ready(target='role:group:shared/worker')
        hidden = self.ready(repo='other', target='role:other/worker', title='Foreign capacity')
        self.store.claim(target['session'], work_id=hidden['id'], repository='other')
        first = await self.work_call(self.work_request('claim', {'onBehalfOf': target}))
        self.assertIsNone(first['result']['claimed'])
        self.assertEqual(self.store.work(allowed['id'])['state'], 'ready')
        self.store.release(target['session'], hidden['id'], 'done')
        second = await self.work_call(self.work_request('claim',
            {'onBehalfOf': target}, operation='after-capacity', revision=2))
        self.assertEqual(second['result']['claimed']['id'], allowed['id'])
        self.assertEqual(second['result']['claimed']['repo'], 'falcon')

    async def test_foreign_work_and_foreign_scope_refuse_without_effect(self):
        target = self.target()
        foreign = self.ready(repo='other', target='role:other/worker')
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('claim', {'workId': foreign['id'], 'onBehalfOf': target}))
        own = self.ready()
        current = strict_loads(self.js.messages[-1].data)
        next(g for g in current['state']['grants'] if
            g['ref'] == self.work_grants['human']['federation-work-claim'])['scope']['projectId'] = 'foreign'
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('claim', {'workId': own['id'], 'onBehalfOf': target}))
        self.assertEqual(self.store.work(own['id'])['state'], 'ready')
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')

    async def test_agent_cannot_use_operator_target_even_for_itself(self):
        caller = await owner_tests.WorkBridgeOwnerTests._agent_owner(self)
        target = {'session': caller, 'generation': self.store.agent(caller)['generation']}
        row = self.ready()
        raw = owner_tests.WorkBridgeOwnerTests._agent_request(self, caller, 'claim',
            {'workId': row['id'], 'onBehalfOf': target})
        with self.assertRaises(ContractError):
            await self.work_call(raw)
        allowed = await self.work_call(owner_tests.WorkBridgeOwnerTests._agent_request(self, caller, 'claim',
            {'workId': row['id']}, operation='self-only'))
        self.assertEqual(allowed['result']['claimed']['claimed_by'], caller)

    async def test_missing_dead_and_replaced_target_refuse(self):
        target = self.target()
        row = self.ready()
        for selected in ({'session': 'missing', 'generation': 1}, {**target, 'generation': 2}):
            with self.subTest(selected=selected), self.assertRaises(ContractError):
                await self.work_call(self.work_request('claim', {'workId': row['id'], 'onBehalfOf': selected}))
        self.store.set_state(target['session'], 'dead')
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('claim', {'workId': row['id'], 'onBehalfOf': target}))
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')

    async def test_target_generation_rechecked_on_original_worker_before_effect(self):
        target = self.target()
        row = self.ready()
        commit = self.resource._journal.commit
        def changed(*args, **kwargs):
            self.change_generation(target)
            return commit(*args, **kwargs)
        with patch.object(self.resource._journal, 'commit', side_effect=changed):
            with self.assertRaises(ContractError):
                await self.work_call(self.work_request('claim', {'workId': row['id'], 'onBehalfOf': target}))
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')

    async def test_expiry_at_original_transaction_refuses_without_effect(self):
        target = self.target()
        row = self.ready()
        current = strict_loads(self.js.messages[-1].data)
        next(g for g in current['state']['grants'] if
            g['ref'] == self.work_grants['human']['federation-work-claim'])['expiresAt'] = (
                NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(current)
        commit = self.resource._journal.commit
        class LaterClock(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=2)
        def expired(*args, **kwargs):
            with patch('hub.fed.message_storage.datetime', LaterClock):
                return commit(*args, **kwargs)
        with patch.object(self.resource._journal, 'commit', side_effect=expired):
            with self.assertRaises(ContractError):
                await self.work_call(self.work_request('claim', {'workId': row['id'], 'onBehalfOf': target}))
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')

    async def test_final_target_change_refuses_rows_but_retains_original_effect(self):
        target = self.target()
        row = self.ready()
        raw = self.work_request('claim', {'workId': row['id'], 'onBehalfOf': target})
        admit, count = self.endpoint._admit, 0
        async def changed(*args):
            nonlocal count
            count += 1
            if count == 2:
                self.change_generation(target)
            return await admit(*args)
        with patch.object(self.endpoint, '_admit', side_effect=changed):
            with self.assertRaises(ContractError):
                await self.work_call(raw)
        self.assertEqual(self.store.work(row['id'])['claimed_by'], target['session'])
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('outcome', self.query(raw), operation='stale-outcome'))
        with self.assertRaises(ContractError):
            await self.work_call(raw)

    async def test_final_revocation_refuses_disclosure(self):
        target = self.target()
        row = self.ready()
        raw = self.work_request('claim', {'workId': row['id'], 'onBehalfOf': target})
        admit, count = self.endpoint._admit, 0
        async def revoked(*args):
            nonlocal count
            count += 1
            if count == 2:
                self.revoke('claim')
            return await admit(*args)
        with patch.object(self.endpoint, '_admit', side_effect=revoked):
            with self.assertRaises(ContractError):
                await self.work_call(raw)
        self.assertEqual(self.store.work(row['id'])['claimed_by'], target['session'])
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('outcome', self.query(raw), operation='revoked-outcome'))

    async def test_source_worker_substitution_after_effect_refuses_disclosure(self):
        target = self.target()
        row = self.ready()
        effect, worker = self.resource._effect, self.hub.dbx
        def changed(*args, **kwargs):
            result = effect(*args, **kwargs)
            self.hub.dbx = object()
            return result
        try:
            with patch.object(self.resource, '_effect', side_effect=changed):
                with self.assertRaises(ContractError):
                    await self.work_call(self.work_request('claim', {'workId': row['id'], 'onBehalfOf': target}))
        finally:
            self.hub.dbx = worker
        self.assertEqual(self.store.work(row['id'])['claimed_by'], target['session'])

    async def test_operator_label_on_service_principal_does_not_authorize_target(self):
        target = self.target()
        row = self.ready()
        current = strict_loads(self.js.messages[-1].data)
        next(identity for identity in current['state']['identities']
            if identity['ref'] == ref('human'))['kind'] = 'service'
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('claim', {'workId': row['id'], 'onBehalfOf': target}))
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')

    async def test_target_input_is_closed_and_native_generic_does_not_admit_it(self):
        target = self.target()
        for value in ({**target, 'callback': 'arbitrary'}, {**target, 'generation': True},
                {'session': target['session']}, {**target, 'session': '*'}):
            with self.subTest(value=value), self.assertRaises(ContractError):
                validate('federation-work-claim', {'resourceRef': ref('task-one'),
                    'attribution': 'operator', 'input': {'onBehalfOf': value}})
        with self.assertRaises(ContractError):
            self.resource._value({'payload': {'input': {'value': {'formatVersion': 1,
                'command': 'claim', 'onBehalfOf': target}}}})
        with self.assertRaises(ContractError):
            validate('federation-work-cancel', {'resourceRef': ref('task-one'),
                'attribution': 'operator', 'input': {'workId': 'one', 'reason': 'cancel', 'onBehalfOf': target}})

    async def test_cancelled_call_close_joins_original_target_effect(self):
        target = self.target()
        row = self.ready()
        entered, release = threading.Event(), threading.Event()
        original = self.store.claim
        def held(*args, **kwargs):
            entered.set()
            if not release.wait(4):
                raise TimeoutError('controlled original worker release')
            return original(*args, **kwargs)
        task = closing = None
        try:
            with patch.object(self.store, 'claim', side_effect=held):
                task = asyncio.create_task(self.work_call(self.work_request('claim',
                    {'workId': row['id'], 'onBehalfOf': target})))
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                closing = asyncio.create_task(self.endpoint.close(timeout=None))
                await asyncio.sleep(0.02)
                self.assertFalse(closing.done())
                release.set()
                await closing
                self.assertFalse(self.local._pending)
                self.assertFalse(self.endpoint._workers)
                self.assertEqual(self.store.work(row['id'])['claimed_by'], target['session'])
        finally:
            release.set()
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)
            if closing is not None:
                await closing


class OperatorWorkClientTests(OperatorTargetFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        patch('capability_owner.legacy_work_client.datetime', _Clock).start()
        self.submitted, self.drop_after, self.drop_before = [], None, None
        self.session = self.session_for()
        self.client = LegacyWorkCommandClient(self.hub, (self.session,))
        self.addAsyncCleanup(self.client.close, timeout=None)
        self.expires = NOW + timedelta(seconds=4)

    def session_for(self):
        loop = asyncio.get_running_loop()
        value = material()
        selected = value['workCommands']
        selected.update(transportRef=ref('transport'), grantRefs={contract: self.work_grants['human'][contract]
            for contract in ('federation-work-create', 'federation-work-claim', 'federation-work-heartbeat',
                'federation-work-release', 'federation-work-claim-path', 'federation-work-read',
                'federation-work-inspect', 'federation-work-outcome')})
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
                'replySubject': '_INBOX.work_operator_actual_01'}
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

    async def claim(self, target, row, *, expires=None):
        value = {'workId': row['id'], 'onBehalfOf': target}
        intent = payload_digest({'verb': 'claim', 'args': value})
        session, enrollment = self.client._select('operator', 'claim', 'falcon')[0]
        return await self.client._execute(session, enrollment, 'claim', intent, value, 'operator', expires or self.expires)

    async def test_signed_client_lost_reply_keeps_operator_original_and_raw_target_result(self):
        target, row = self.target(), self.ready()
        self.drop_after = 'federation-work-claim'
        with self.assertRaises(TimeoutError):
            await self.claim(target, row)
        original = next(x for x in self.submitted if x['contractId'] == 'federation-work-claim')
        expected = self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],))
        await self.replace()
        result = await self.claim(target, row)
        self.assertEqual(result['claimed'], expected)
        self.assertEqual(original['payload']['attribution'], 'operator')
        self.assertEqual(original['payload']['input']['onBehalfOf'], target)
        self.assertEqual(len([x for x in self.submitted if x['contractId'] == 'federation-work-claim']), 1)
        self.assertEqual(self.client.finish_disclosure(result), result)

    async def test_recovery_refuses_replaced_target_without_another_mutation(self):
        target, row = self.target(), self.ready()
        self.drop_after = 'federation-work-claim'
        with self.assertRaises(TimeoutError):
            await self.claim(target, row)
        self.change_generation(target)
        with self.assertRaises(ContractError):
            await self.claim(target, row)
        self.assertEqual(len([x for x in self.submitted if x['contractId'] == 'federation-work-claim']), 1)
        self.assertEqual(self.store.work(row['id'])['claimed_by'], target['session'])

    async def test_uncertain_absence_keeps_original_target_and_never_resubmits(self):
        target, row = self.target(), self.ready()
        self.drop_before = 'federation-work-claim'
        with self.assertRaises(TimeoutError):
            await self.claim(target, row, expires=NOW + timedelta(seconds=1))
        with self.assertRaisesRegex(HubError, 'original recovery is retained'):
            await self.claim(target, row)
        self.assertEqual(len([x for x in self.submitted if x['contractId'] == 'federation-work-claim']), 1)
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')

    async def test_target_mutation_keeps_original_private_expiry(self):
        target, row = self.target(), self.ready()
        current = strict_loads(self.js.messages[-1].data)
        next(g for g in current['state']['grants'] if
            g['ref'] == self.work_grants['human']['federation-work-claim'])['expiresAt'] = (
                NOW + timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        self.js.messages[-1].data = canonical_bytes(current)
        result = await self.claim(target, row)
        self.assertNotIn('validUntil', canonical_bytes(result).decode())
        with patch('capability_owner.legacy_work_client.datetime') as clock:
            clock.now.return_value = NOW + timedelta(seconds=2)
            with self.assertRaisesRegex(ContractError, 'expired'):
                self.client.finish_disclosure(result)
