"""Actual federation runtime paths backed by the signed retained work owner."""
import asyncio
from contextvars import ContextVar
import hashlib
import json
from types import MethodType, SimpleNamespace
import unittest
import weakref
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes
from hub.fed import envelope, ledger
from hub.fed.runtime import Federation
from hub.fed.work_services import reference
from hub.tests.test_fed_unit import REMOTE
from identity.test_service import _Clock
from . import test_federated_work_client as support
from .federated_work_client import FederatedWorkCommandClient, WorkBridgeIntents
from .legacy_work_client import LegacyWorkCommandClient
from .test_work_bridge_owner import WorkBridgeFixture


class WorkRuntimeTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    session_for = support.FederatedWorkTests.session_for
    caller = support.FederatedWorkTests.caller
    message = support.FederatedWorkTests.message
    claimed_envelope = support.FederatedWorkTests.claimed_envelope
    result_envelope = support.FederatedWorkTests.result_envelope

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.setup_runtime()

    async def setup_runtime(self):
        for module in ('capability_owner.legacy_work_client', 'capability_owner.federated_work_client',
                'hub.fed.message_bridge'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('work-runtime-proof', default=None)
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        self.hub._notify_work_owner = AsyncMock()
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.node = self.hub, 'mac'
        self.fed.cfg, self.fed.policy = self.owner.policy.cfg, self.owner.policy
        self.fed.cfg['federation']['plugins'] = ['work']
        self.fed.cfg['repos']['falcon']['remote'] = REMOTE
        self.fed.session, self.fed.presence = self.owner.session, {}
        self.addAsyncCleanup(self.fed.session.close)
        self.fed.log, self.fed.notify_operator = Mock(), AsyncMock()
        self.fed.loop = self.fed.wake = None
        self.fed.nc = SimpleNamespace(_subs={})
        self.fed._profile_context = None
        self.fed._qualified_work = True
        self.fed.connected, self.fed.last_error = False, ''
        self.fed.stats = {key: 0 for key in ('received', 'duplicates', 'errors', 'delivered', 'dropped', 'quarantined')}
        self.fed.plugins, self.fed.plugin_adapters, self.fed.routes = {}, {}, {}
        self.fed._load_plugins()
        self.fed.verbs = self.fed._core_verbs()
        self.fed.plugin_verbs = {}
        for adapter in self.fed.plugin_adapters.values():
            for name, verb in adapter.verbs().items():
                key = 'fed_' + adapter.name + '_' + name
                self.fed.verbs[key] = verb
                self.fed.plugin_verbs[key] = adapter, name
        self.hub.fed = self.fed
        await self.replace(owner=self.fed)
        self.submitted, self.drop_after = [], None
        self.storage = LegacyWorkCommandClient(self.hub,
            tuple(self.session_for(identity) for identity in ('human', 'service')))
        self.addAsyncCleanup(self.storage.close, timeout=None)
        self.client = FederatedWorkCommandClient(self.fed, self.storage)
        self.fed._work_commands = self.client
        self.fed._work_intents = WorkBridgeIntents(self.fed, self.client)

    async def deliver(self, item):
        message = self.message(item)
        return await self.fed.receive(message.subject, message.data, message)

    async def offer(self):
        args = {'to': 'role:falcon/worker', 'title': 'Runtime original offer'}
        async with self.caller('fed_work_add', args):
            row = await self.fed.dispatch('fed_work_add', args, 'operator')
        self.client.finish_disclosure()
        return row

    async def test_actual_receive_and_seen_duplicate_keep_one_claim_and_no_resubmit(self):
        item = self.item()
        self.assertEqual(await self.deliver(item), 'delivered')
        self.assertTrue(ledger.seen(self.store, item['id']))
        self.assertEqual(await self.deliver(item), 'duplicate')
        self.assertEqual(self.store.q1('SELECT count(*) n FROM work_items')['n'], 1)
        self.assertEqual(len(ledger.outbox_pending(self.store)), 1)
        self.assertEqual(sum(c['contractId'] == 'federation-work-ingest' for c in self.submitted), 1)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])

    async def test_seen_before_confirmation_recovers_exact_original_without_capture(self):
        offer = await self.offer()
        retained_offer = self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'")
        claim = self.claimed_envelope(offer)
        await self.deliver(claim)
        item = self.result_envelope(offer, claim)
        captured = []
        async def capture(kind, row, *, require_completion=False):
            self.assertTrue(require_completion)
            captured.append((kind, row))
        self.fed.local_event = capture
        with patch.object(self.client, 'confirm_receive', new=AsyncMock(side_effect=TimeoutError('controlled follow-on loss'))):
            with self.assertRaises(TimeoutError):
                await self.deliver(item)
        self.assertTrue(ledger.seen(self.store, item['id']))
        self.assertEqual(len(captured), 1)
        self.assertEqual(await self.deliver(item), 'duplicate')
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0][1], {**self.store.q1('SELECT * FROM work_items WHERE id=?', (offer['id'],)),
            'from_peer': 'alice'})
        self.assertEqual(sum(c['contractId'] == 'federation-work-result-envelope' for c in self.submitted), 1)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), retained_offer)

    async def test_actual_held_privileged_approval_commits_before_marking_approved(self):
        item = self.item(privileged=True)
        self.assertEqual(await self.deliver(item), 'quarantined')
        held = ledger.quarantine_list(self.store)[0]
        args = {'id': held['id'], 'privileged': True}
        async with self.caller('fed_approve', args):
            result = await self.fed.dispatch('fed_approve', args, 'operator')
        self.assertEqual(result, {'approved': held['id'], 'outcome': 'delivered'})
        self.assertEqual(ledger.quarantine_get(self.store, held['id'])['state'], 'approved')
        self.assertTrue(json.loads(self.store.q1('SELECT fed_flags FROM work_items')['fed_flags'])['privileged_ok'])
        self.client.finish_disclosure()

    async def test_still_quarantined_redelivery_acks_without_admitting_work(self):
        item = self.item(privileged=True)
        with patch('nats.aio.msg.Msg.ack', new_callable=AsyncMock) as ack:
            self.assertEqual(await self.deliver(item), 'quarantined')
            original = ledger.quarantine_list(self.store)
            submitted = list(self.submitted)
            self.assertTrue(ledger.seen(self.store, item['id']))
            self.assertEqual(await self.deliver(item), 'duplicate')
            self.assertEqual(ack.await_count, 2)
        self.assertEqual(ledger.quarantine_list(self.store), original)
        self.assertEqual(original[0]['state'], 'held')
        self.assertEqual(self.submitted, submitted)
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])
        self.assertEqual(ledger.outbox_pending(self.store), [])
        self.assertEqual(self.fed.notify_operator.await_count, 1)

    async def test_actual_panel_uses_authenticated_async_read(self):
        offer = await self.offer()
        async with self.caller('fed_panel', {}):
            proof = self.hub.current_authenticated_caller()
            self.hub._panel_dispatches = weakref.WeakKeyDictionary({proof:
                (weakref.ref(asyncio.current_task()), self.hub._authenticated_callers[proof].request_digest)})
            result = await self.fed.dispatch('fed_panel', {}, 'operator')
        panel = next(p for p in result['panels'] if p['plugin'] == 'work')
        self.assertNotIn('error', panel)
        self.assertEqual(panel['rows'][0][0], offer['id'])
        self.assertIn(asyncio.current_task(), self.storage._disclosures)
        self.client.finish_disclosure()

    async def test_approved_follow_on_loss_recovers_original_result_without_reapplying(self):
        item = self.item(privileged=True)
        await self.deliver(item)
        held = ledger.quarantine_list(self.store)[0]
        args = {'id': held['id'], 'privileged': True}
        async with self.caller('fed_approve', args):
            with patch.object(self.client, 'confirm_receive', new=AsyncMock(side_effect=TimeoutError('controlled loss'))):
                with self.assertRaises(TimeoutError):
                    await self.fed.dispatch('fed_approve', args, 'operator')
        self.assertEqual(ledger.quarantine_get(self.store, held['id'])['state'], 'approved')
        async with self.caller('fed_approve', args):
            result = await self.fed.dispatch('fed_approve', args, 'operator')
        self.assertEqual(result, {'approved': held['id'], 'outcome': 'delivered'})
        self.assertEqual(sum(c['contractId'] == 'federation-work-approve-privileged' for c in self.submitted), 1)
        self.assertEqual(len(ledger.outbox_pending(self.store)), 1)
        self.client.finish_disclosure()

    async def test_approved_recovery_cannot_change_original_privilege_permission(self):
        item = self.item(privileged=True)
        await self.deliver(item)
        held = ledger.quarantine_list(self.store)[0]
        args = {'id': held['id'], 'privileged': True}
        async with self.caller('fed_approve', args):
            with patch.object(self.client, 'confirm_receive', new=AsyncMock(side_effect=TimeoutError('controlled loss'))):
                with self.assertRaises(TimeoutError):
                    await self.fed.dispatch('fed_approve', args, 'operator')
        changed = {'id': held['id'], 'privileged': False}
        async with self.caller('fed_approve', changed):
            with self.assertRaisesRegex(Exception, 'no retained operation'):
                await self.fed.dispatch('fed_approve', changed, 'operator')
        self.assertEqual(sum(c['contractId'] == 'federation-work-approve-privileged' for c in self.submitted), 1)
        self.assertEqual(sum(c['contractId'] == 'federation-work-approve' for c in self.submitted), 0)
        self.assertTrue(json.loads(self.store.q1('SELECT fed_flags FROM work_items')['fed_flags'])['privileged_ok'])

    async def test_work_event_service_finishing_preserves_parent_disclosure(self):
        item = self.item()
        await self.deliver(item)
        raw = self.store.q1('SELECT * FROM work_items')
        flags = json.loads(raw['fed_flags'])
        grant = envelope.make('work_grant', 'alice', 'remote', item['rid'], 'nick', {
            **reference(flags), 'executor_peer': 'nick', 'executor_node': 'mac',
            'selected': True, 'grant_id': 'grant-original'})
        grant['id'] = 'grant-original'
        await self.deliver(grant)
        agent = self.store.register('falcon', 'worker', 'claude', 'claude', {'max_active': 1})
        self.store.db.execute("UPDATE agents SET state='ready' WHERE session=?", (agent,))
        self.store.claim(agent, work_id=raw['id'])
        self.store.release(agent, raw['id'], 'done', 'Original durable result', node='mac')
        released = self.store.q1('SELECT * FROM work_items WHERE id=?', (raw['id'],))
        rows = await self.client.service_read({'kind': 'list', 'state': None})
        parent = asyncio.current_task()
        before = self.storage._disclosures[parent]
        await self.fed.local_event('work_released', released)
        self.assertIs(self.storage._disclosures[parent], before)
        returned = [json.loads(row['payload']) for row in ledger.outbox_pending(self.store)
            if json.loads(row['payload'])['type'] == 'result']
        self.assertEqual(len(returned), 1)
        self.assertEqual(returned[0]['id'], json.loads(released['fed_flags'])['result_id'])
        self.assertEqual(returned[0]['data']['result'], 'Original durable result')
        self.client.finish_disclosure(rows)

    async def test_fabricated_peer_revoke_cannot_withdraw_work(self):
        from nats.aio.msg import Msg
        item = self.item()
        await self.deliver(item)
        control = envelope.make('revoke', 'alice', 'remote')
        message = Msg(_client=self.fed.nc, subject=envelope.subject('ctl', 'alice'),
            data=canonical_bytes(control), _sid=1)
        await self.fed._on_ctl(message)
        self.assertEqual(self.fed.policy.trust('alice'), 'auto')
        self.assertEqual(self.store.q1('SELECT state FROM work_items')['state'], 'blocked')
        self.assertFalse(any(command['contractId'] == 'federation-work-revoke' for command in self.submitted))
