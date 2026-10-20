"""Real signed work owner calls from the federation adapter."""
import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
import copy
from datetime import timedelta
import hashlib
import json
from types import SimpleNamespace
import unittest
import weakref
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.client_launch_session import ApplicationClientSession
from hub.fed import envelope, guard, ledger
from hub.fed.runtime import Federation
from hub.fed.work_services import _QualifiedWorkQueue, build_work_context, offer_digest, reference, result_digest
from hub.tests.test_work_client_transport import material
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, ref
from identity.test_service import _Clock
from .federated_work_client import FederatedWorkCommandClient, WorkBridgeIntents
from .legacy_work_client import LegacyWorkCommandClient
from .test_work_bridge_owner import WorkBridgeFixture


class FederatedWorkTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.legacy_work_client', 'capability_owner.federated_work_client',
                'hub.fed.message_bridge'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('work-test-proof', default=None)
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        self.hub._notify_work_owner = AsyncMock()
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.node = self.hub, 'mac'
        self.fed.cfg, self.fed.policy = self.owner.policy.cfg, self.owner.policy
        self.fed.session, self.fed.presence = self.owner.session, {}
        self.addAsyncCleanup(self.fed.session.close)
        self.fed.log, self.fed.local_event = Mock(), AsyncMock()
        self.fed.loop = self.fed.wake = None
        self.fed.nc = SimpleNamespace(_subs={})
        self.fed._qualified_work = True
        self.hub.fed = self.fed
        await self.replace(owner=self.fed)
        self.submitted, self.drop_after = [], None
        self.storage = LegacyWorkCommandClient(self.hub,
            tuple(self.session_for(identity) for identity in ('human', 'service')))
        self.addAsyncCleanup(self.storage.close, timeout=None)
        self.client = FederatedWorkCommandClient(self.fed, self.storage)
        self.fed._work_commands = self.client
        self.fed._work_intents = WorkBridgeIntents(self.fed, self.client)

    def session_for(self, identity):
        value = material()
        route = value['workCommands']
        value.update(scope=self.scope, callerRef=ref(identity))
        route.update(authenticatedCaller='operator' if identity == 'human' else 'federation',
            transportRef=ref('transport' if identity == 'human' else 'legacy-service-transport'),
            localPeer='nick', repository={'localName': 'falcon', 'repositoryId': self.resource.repository_id},
            grantRefs={k: v for k, v in self.work_grants[identity].items() if identity != 'human' or
                k.removeprefix('federation-work-') not in ('claim', 'heartbeat', 'release', 'claim-path')})
        key = ApplicationClientKey(value)
        session = object.__new__(ApplicationClientSession)
        session._stopped = session._terminal_enrolled = session._terminal_active = False
        session._closing = session._final_closing = None
        session._work_enrollment = canonical_bytes({
            **{k: key.selection[k] for k in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
            'workCommands': key.selection['workCommands']})
        loop = asyncio.get_running_loop()
        def submit(*, contract_id, operation_id, payload, expires_at, deadline, include_valid_until=False):
            claims = {'purpose': 'agentmux-client-possession-v1',
                **{name: key.selection[name] for name in ('hubId', 'profileId', 'authorityId')},
                'transportRef': route['transportRef'], 'grantRef': route['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': payload['resourceRef']['revision'],
                'contractId': contract_id, 'payload': payload, 'approvalRefs': [],
                'issuedAt': NOW.isoformat().replace('+00:00', 'Z'), 'expiresAt': expires_at,
                'replySubject': '_INBOX.work_federation_actual_01'}
            self.submitted.append(copy.deepcopy(claims))
            raw = key.sign_command(claims, subject=route['subject'], now=NOW)
            response = asyncio.run_coroutine_threadsafe(self.endpoint.handle(raw,
                received_reply_subject=claims['replySubject']), loop).result(timeout=6)
            if self.drop_after == contract_id:
                self.drop_after = None
                raise TimeoutError('controlled reply loss')
            return key.verify_command_response(response, raw, subject=route['subject'], now=NOW,
                include_valid_until=include_valid_until)
        session.work_command = submit
        return session

    @asynccontextmanager
    async def caller(self, verb, args):
        proof = await self.hub.authenticate_caller({'token': 'operator-secret', 'verb': verb, 'args': args},
            SimpleNamespace(), True)
        token = self.hub._authenticated_caller_context.set(proof)
        try:
            yield
        finally:
            self.hub._authenticated_caller_context.reset(token)
            self.hub._authenticated_callers.pop(proof, None)

    def message(self, item):
        from nats.aio.msg import Msg
        subject = (envelope.subject('work', item['from'], item['rid'], item['data']['role'])
            if item['type'] == 'work' else envelope.subject('msg', item['from'], item['to']))
        subscription = SimpleNamespace(_closed=False, unsubscribe=AsyncMock())
        self.fed.nc._subs[1] = subscription
        self.fed.session.own_subscription(subscription)
        return Msg(_client=self.fed.nc, subject=subject, data=canonical_bytes(item), _sid=1)

    async def receive(self, item, *, confirm=True):
        message = self.message(item)
        decision = guard.inbound(self.fed.policy, message.subject, item)
        with self.fed._work_intents.inbound(message.subject, item, decision, message):
            result = await build_work_context(self.fed).work.receive(item, decision)
        if confirm:
            await self.hub.db(ledger.mark_seen, self.store, item['id'])
            await self.client.confirm_receive(item)
            self.client.finish_disclosure()
        return result

    async def offer(self):
        args = {'to': 'role:falcon/worker', 'title': 'Original offer'}
        async with self.caller('fed_work_add', args):
            result = await build_work_context(self.fed).work.add('operator', args['to'], args['title'])
        self.client.finish_disclosure()
        return result

    async def test_offer_and_lost_reply_recover_same_placeholder_and_outbox(self):
        self.drop_after = 'federation-work-offer'
        with self.assertRaises(TimeoutError):
            await self.offer()
        original = self.store.q1('SELECT * FROM work_items')
        result = await self.offer()
        self.assertEqual(result['id'], original['id'])
        self.assertEqual(len(ledger.outbox_pending(self.store)), 1)
        self.assertEqual(sum(c['contractId'] == 'federation-work-offer' for c in self.submitted), 1)
        self.assertTrue(any(c['contractId'] == 'federation-work-outcome' for c in self.submitted))

    async def test_actual_owned_receive_preserves_offer_claim_and_private_result(self):
        item = self.item()
        self.assertEqual(await self.receive(item), 'delivered')
        row = self.store.q1('SELECT * FROM work_items')
        flags = json.loads(row['fed_flags'])
        self.assertEqual((row['origin_peer'], flags['origin_node'], flags['env']), ('alice', 'remote', item['id']))
        self.assertEqual(flags['offer_digest'], offer_digest(item))
        outbox = ledger.outbox_pending(self.store)
        self.assertEqual(len(outbox), 1)
        self.assertEqual(json.loads(outbox[0]['payload'])['type'], 'work_claim')
        self.assertNotIn('validUntil', row)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-work-client:%'"), [])

    async def test_fabricated_decision_without_receive_proof_has_no_effect(self):
        item = self.item()
        decision = guard.inbound(self.fed.policy, self.incoming(item)['subject'], item)
        with self.assertRaises(ContractError):
            await self.client.receive(item, decision)
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])

    async def test_held_first_privileged_approval_requires_explicit_current_operator(self):
        item = self.item(privileged=True)
        subject = self.incoming(item)['subject']
        qid = ledger.quarantine_add(self.store, item, subject, 'work', 'alice', 'privileged')
        held = ledger.quarantine_get(self.store, qid)
        decision = guard.Decision('deliver', 'approved by operator', 'auto', untrusted=True,
            local_repo='falcon', approved=True, privileged_ok=True)
        async with self.caller('fed_approve', {'id': qid, 'privileged': True}):
            with self.fed._work_intents.approved(held, 'operator'):
                result = await self.client.receive(item, decision)
        self.assertEqual(result, 'delivered')
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'held')
        flags = json.loads(self.store.q1('SELECT fed_flags FROM work_items')['fed_flags'])
        self.assertTrue(flags['privileged_ok'])
        self.assertTrue(any(c['contractId'] == 'federation-work-approve-privileged' for c in self.submitted))
        with self.assertRaises(ContractError):
            await self.client.confirm_receive(item, quarantine_id=qid, privileged=True)
        ledger.quarantine_decide(self.store, qid, 'approved', 'operator')
        await self.client.confirm_receive(item, quarantine_id=qid, privileged=True)
        self.client.finish_disclosure()

    async def test_final_read_refuses_replaced_session(self):
        await self.offer()
        async with self.caller('fed_work_list', {}):
            rows = await self.client.read('operator')
        self.assertEqual(len(rows), 1)
        self.fed.session = None
        with self.assertRaises(ContractError):
            self.client.finish_disclosure(rows)

    async def test_final_read_refuses_original_owner_expiry(self):
        await self.offer()
        async with self.caller('fed_work_list', {}):
            rows = await self.client.read('operator')
        with patch('capability_owner.legacy_work_client.datetime') as timer:
            timer.now.return_value = NOW + timedelta(seconds=6)
            with self.assertRaisesRegex(ContractError, 'expired'):
                self.client.finish_disclosure(rows)

    def claimed_envelope(self, offer):
        flags = json.loads(offer['fed_flags'])
        return envelope.make('work_claim', 'alice', 'remote', flags['rid'], 'nick', {
            'origin_id': offer['id'], 'origin_node': 'mac', 'offer_id': flags['env'],
            'offer_digest': flags['offer_digest'], 'execution_id': 'execution-original'})

    def result_envelope(self, offer, claim):
        grant = json.loads(ledger.outbox_pending(self.store)[-1]['payload'])
        data = {**claim['data'], 'grant_id': grant['data']['grant_id'], 'state': 'done',
            'result': 'Exact accepted evidence', 'by': 'remote-worker', 'by_sender': {'operator': True}}
        data['result_digest'] = result_digest(data)
        return envelope.make('result', 'alice', 'remote', json.loads(offer['fed_flags'])['rid'], 'nick', data)

    async def test_claim_result_lost_reply_keeps_exact_raw_capture_and_original_evidence(self):
        offer = await self.offer()
        claim = self.claimed_envelope(offer)
        self.assertEqual(await self.receive(claim), 'reserved')
        item = self.result_envelope(offer, claim)
        self.drop_after = 'federation-work-result-envelope'
        with self.assertRaises(TimeoutError):
            await self.receive(item)
        original = self.store.q1('SELECT * FROM work_items WHERE id=?', (offer['id'],))
        self.fed.local_event.assert_not_awaited()
        self.assertEqual(await self.receive(item), 'delivered')
        self.assertEqual(self.store.q1('SELECT * FROM work_items WHERE id=?', (offer['id'],)), original)
        event, captured = self.fed.local_event.await_args.args
        self.assertEqual(event, 'fed_result')
        self.assertEqual(captured, {**original, 'from_peer': 'alice'})
        accepted = json.loads(original['fed_flags'])['accepted_result']
        self.assertEqual((accepted['envelope_id'], accepted['digest']), (item['id'], item['data']['result_digest']))
        self.assertEqual(sum(c['contractId'] == 'federation-work-result-envelope' for c in self.submitted), 1)

    async def test_substituted_executor_cannot_complete_or_capture(self):
        offer = await self.offer()
        claim = self.claimed_envelope(offer)
        await self.receive(claim)
        item = self.result_envelope(offer, claim)
        item['data']['execution_id'] = 'execution-substitution'
        self.assertEqual(await self.receive(item), 'unbound_result')
        self.assertEqual(self.store.q1('SELECT state FROM work_items WHERE id=?', (offer['id'],))['state'], 'claimed')
        self.fed.local_event.assert_not_awaited()

    async def test_grant_and_terminal_recovery_stage_original_result_once(self):
        item = self.item()
        await self.receive(item)
        row = self.store.q1('SELECT * FROM work_items')
        flags = json.loads(row['fed_flags'])
        grant = envelope.make('work_grant', 'alice', 'remote', item['rid'], 'nick', {
            **reference(flags), 'executor_peer': 'nick', 'executor_node': 'mac',
            'selected': True, 'grant_id': 'grant-original'})
        grant['id'] = 'grant-original'
        self.assertEqual(await self.receive(grant), 'delivered')
        # Reproduce a completion already committed by the local work owner.
        agent = self.store.register('falcon', 'worker', 'claude', 'claude', {'max_active': 1})
        self.store.db.execute("UPDATE agents SET state='ready' WHERE session=?", (agent,))
        self.store.claim(agent, work_id=row['id'])
        self.store.release(agent, row['id'], 'done', 'Durable terminal evidence', node='mac')
        before = self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],))
        original_flags = json.loads(before['fed_flags'])
        self.assertTrue(original_flags['result_pending'])
        await self.client.recover_results()
        await self.client.recover_results()
        returned = [json.loads(r['payload']) for r in ledger.outbox_pending(self.store)
            if json.loads(r['payload'])['type'] == 'result']
        self.assertEqual(len(returned), 1)
        self.assertEqual(returned[0]['id'], original_flags['result_id'])
        self.assertEqual(returned[0]['data']['grant_id'], 'grant-original')
        self.assertEqual(returned[0]['data']['result'], 'Durable terminal evidence')
        self.assertFalse(json.loads(self.store.q1('SELECT fed_flags FROM work_items WHERE id=?', (row['id'],))['fed_flags'])['result_pending'])

    async def test_queue_respects_global_capacity_held_in_unselected_repository(self):
        agent = self.store.register('falcon', 'worker', 'claude', 'claude', {'max_active': 1})
        self.store.db.execute("UPDATE agents SET state='ready' WHERE session=?", (agent,))
        hidden = self.store.work_create('operator', 'other', 'agent:' + agent, 'Existing cross-repo work')
        self.assertEqual(self.store.claim(agent, work_id=hidden['id'])['claimed']['id'], hidden['id'])
        self.fed.peer_ids = set()
        subscription = SimpleNamespace(fetch=AsyncMock(return_value=[]), unsubscribe=AsyncMock())
        self.fed.js = SimpleNamespace(pull_subscribe=AsyncMock(return_value=subscription))
        await build_work_context(self.fed).consumer.poll()
        self.fed.js.pull_subscribe.assert_not_awaited()
        reads = [item for item in self.submitted if item['contractId'] == 'federation-work-read'
            and item['payload']['input']['query']['kind'] == 'readiness']
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0]['payload']['input']['query'], {'kind': 'readiness', 'session': agent})
        self.assertEqual(reads[0]['grantRef'], self.work_grants['service']['federation-work-read'])

    async def test_queue_receives_on_original_subject_with_separate_private_validity(self):
        agent = self.store.register('falcon', 'worker', 'claude', 'claude', {'max_active': 1})
        self.store.db.execute("UPDATE agents SET state='ready' WHERE session=?", (agent,))
        item = self.item()
        message = self.message(item)
        self.fed.peer_ids = {'alice'}
        subscription = SimpleNamespace(fetch=AsyncMock(return_value=[message]), unsubscribe=AsyncMock())
        self.fed.js = SimpleNamespace(pull_subscribe=AsyncMock(return_value=subscription))
        outer_task, receive_tasks = asyncio.current_task(), []
        async def receive(subject, content, incoming):
            receive_tasks.append(asyncio.current_task())
            self.assertIs(incoming, message)
            self.assertEqual((subject, content), (message.subject, message.data))
            result = await self.receive(strict_loads(content))
            self.assertIn(outer_task, self.storage._disclosures)
            return result
        self.fed.receive = receive
        await build_work_context(self.fed).consumer.poll()
        self.assertEqual(len(receive_tasks), 1)
        self.assertIsNot(receive_tasks[0], outer_task)
        self.assertNotIn(outer_task, self.storage._disclosures)
        self.assertNotIn(receive_tasks[0], self.storage._disclosures)
        self.assertEqual(self.fed.js.pull_subscribe.await_args.args, (message.subject,))
        self.assertEqual(self.fed.js.pull_subscribe.await_args.kwargs['durable'],
            'work3_alice_' + item['rid'] + '_worker')
        subscription.fetch.assert_awaited_once_with(1, timeout=0.2)
        self.assertTrue(ledger.seen(self.store, item['id']))
        self.assertEqual(self.store.q1('SELECT count(*) n FROM work_items')['n'], 1)

    async def test_queue_does_not_prefetch_when_scoped_work_is_already_waiting(self):
        agent = self.store.register('falcon', 'worker', 'claude', 'claude', {'max_active': 1})
        self.store.db.execute("UPDATE agents SET state='ready' WHERE session=?", (agent,))
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Already waiting')
        self.fed.peer_ids = set()
        self.fed.js = SimpleNamespace(pull_subscribe=AsyncMock())
        await build_work_context(self.fed).consumer.poll()
        self.fed.js.pull_subscribe.assert_not_awaited()

    async def test_queue_ignores_agents_without_a_selected_service_route(self):
        self.fed.policy.cfg['repos']['other'] = {'remote': 'github.com/example/other'}
        self.fed.policy._rid['other'] = 'r0123456789ab'
        self.fed.policy._local['r0123456789ab'] = 'other'
        for repo in ('other', 'falcon'):
            agent = self.store.register(repo, 'worker', 'claude', 'claude', {'max_active': 1})
            self.store.db.execute("UPDATE agents SET state='ready' WHERE session=?", (agent,))
        self.fed.peer_ids = set()
        subscription = SimpleNamespace(fetch=AsyncMock(return_value=[]), unsubscribe=AsyncMock())
        self.fed.js = SimpleNamespace(pull_subscribe=AsyncMock(return_value=subscription))
        await build_work_context(self.fed).consumer.poll()
        self.assertEqual(self.fed.js.pull_subscribe.await_count, 1)
        self.assertEqual(self.fed.js.pull_subscribe.await_args.args,
            (envelope.subject('work', 'nick', self.resource.repository_id, 'worker'),))


class QueueReceiveCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_poll_joins_original_receive_even_after_repeated_cancellation(self):
        started, release = asyncio.Event(), asyncio.Event()
        completed = []
        async def receive(subject, data, message):
            started.set()
            await release.wait()
            completed.append(message)
            return 'delivered'
        message = SimpleNamespace(subject='original', data=b'original')
        original = asyncio.create_task(_QualifiedWorkQueue._receive(SimpleNamespace(receive=receive), message))
        try:
            await started.wait()
            original.cancel()
            await asyncio.sleep(0)
            self.assertFalse(original.done())
            original.cancel()
            await asyncio.sleep(0)
            self.assertFalse(original.done())
        finally:
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await original
        self.assertEqual(completed, [message])
