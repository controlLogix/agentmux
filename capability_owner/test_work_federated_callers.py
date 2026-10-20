"""Actual federated callers keep original offers and accepted-result capture."""
import json
from unittest.mock import AsyncMock, patch

from agentmux_contracts import strict_loads
from hub.fed import ledger
from hub.fed.knowledge_bridge import KnowledgeBridgeIntents
from identity.test_service import _Clock
from .federated_work_client import FederatedWorkCommandClient, WorkBridgeIntents
from .legacy_knowledge_client import LegacyKnowledgeCommandClient
from .legacy_work_client import LegacyWorkCommandClient
from .local_work_client import LocalWorkClient
from .test_federated_work_client import FederatedWorkTests
from .test_work_capture_pipeline import WorkCapturePipelineTests


class FederatedCallerTests(WorkCapturePipelineTests):
    message = FederatedWorkTests.message
    claimed_envelope = FederatedWorkTests.claimed_envelope
    result_envelope = FederatedWorkTests.result_envelope

    async def prepare_capture_work(self):
        await super().prepare_capture_work()
        timer = patch('hub.fed.message_bridge.datetime', _Clock)
        timer.start()
        self.addCleanup(timer.stop)
        await self.hub._work_rpc.close(timeout=None)
        await self.commands.close(timeout=None)
        self.commands = LegacyWorkCommandClient(self.hub, tuple(
            FederatedWorkTests.session_for(self, identity) for identity in ('human', 'service')))
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.client = LocalWorkClient(self.hub, self.commands)
        self.install_client()
        fed = self.fed
        fed._work_commands = FederatedWorkCommandClient(fed, self.commands)
        fed.cfg['federation'].update(enabled=True, url='nats://127.0.0.1:4222')
        fed.stats = {key: 0 for key in ('received', 'duplicates', 'errors', 'delivered', 'dropped', 'quarantined')}
        fed.notify_operator = AsyncMock()
        fed._work_intents = WorkBridgeIntents(fed, fed._work_commands)
        adapter = fed.plugin_adapters['work']
        fed.routes = {kind: adapter for kind in adapter.handles}
        fed.verbs, fed.plugin_verbs = fed._core_verbs(), {}
        for name, verb in adapter.verbs().items():
            fed.verbs['fed_work_' + name] = verb
            fed.plugin_verbs['fed_work_' + name] = adapter, name

    async def deliver(self, item):
        message = self.message(item)
        with patch('nats.aio.msg.Msg.nak', new_callable=AsyncMock):
            return await self.fed.receive(message.subject, message.data, message)

    async def restart_callers(self):
        await self.hub._work_rpc.close(timeout=None)
        work_sessions = tuple(session for session, _ in self.commands._routes)
        knowledge = self.fed._knowledge_commands
        knowledge_sessions = tuple(session for session, _ in knowledge._routes)
        await knowledge.close(timeout=None)
        await self.commands.close(timeout=None)
        self.commands = LegacyWorkCommandClient(self.hub, work_sessions)
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.client = LocalWorkClient(self.hub, self.commands)
        self.install_client()
        self.fed._work_commands = FederatedWorkCommandClient(self.fed, self.commands)
        self.fed._work_intents = WorkBridgeIntents(self.fed, self.fed._work_commands)
        knowledge = LegacyKnowledgeCommandClient(self.hub, knowledge_sessions).bind(self.fed)
        self.addAsyncCleanup(knowledge.close, timeout=None)
        self.fed._knowledge_commands = knowledge
        self.fed._knowledge_intents = KnowledgeBridgeIntents(self.fed, knowledge)

    async def test_federated_offer_discarded_response_restart_and_later_write_recovers_original(self):
        args = {'to': 'role:falcon/worker', 'title': 'Original federated offer'}
        # Discard the fully drained response, then reconstruct caller clients.
        await self.packet('fed_work_add', args, operation_id='discarded-offer')
        row = self.store.q1('SELECT * FROM work_items')
        self.assertIsNotNone(row)
        completed = self.store.q("SELECT v FROM fed_state WHERE k LIKE 'legacy-work-completion:completed:%'")
        self.assertEqual(len(completed), 1)
        original = strict_loads(completed[0]['v'])['result']
        self.assertEqual(original['id'], row['id'])
        outbox = ledger.outbox_pending(self.store)
        self.assertEqual(len(outbox), 1)
        self.assertEqual(len(self.mutations('offer')), 1)
        await self.restart_callers()
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Later independent write')
        replay = await self.packet('fed_work_add', args, operation_id='discarded-offer')
        self.assertTrue(replay['ok'], replay)
        self.assertEqual(replay['result'], original)
        self.assertEqual(replay['operationId'], 'discarded-offer')
        self.assertEqual(len(self.mutations('offer')), 1)
        self.assertEqual(ledger.outbox_pending(self.store), outbox)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 2)

    async def test_actual_result_capture_reply_loss_and_restarted_receive_keep_one_original(self):
        args = {'to': 'role:falcon/worker', 'title': 'Original result source'}
        offered = await self.packet('fed_work_add', args, operation_id='capture-offer')
        self.assertTrue(offered['ok'], offered)
        row = offered['result']
        claim = self.claimed_envelope(row)
        self.assertEqual(await self.deliver(claim), 'reserved')
        item = self.result_envelope(row, claim)
        self.drop_capture_reply = True
        self.assertEqual(await self.deliver(item), 'error')
        self.assertFalse(self.drop_capture_reply)
        original = self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],))
        self.assertEqual(original['state'], 'done')
        self.assertFalse(ledger.seen(self.store, item['id']))
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)
        pending_captures = self.store.q("SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")
        self.assertEqual(len(pending_captures), 1)
        original_capture = strict_loads(pending_captures[0]['v'])
        self.assertEqual(original_capture['contractId'], 'federation-knowledge-capture')
        original_outbox = ledger.outbox_pending(self.store)
        self.assertEqual(len(self.mutations('result-envelope')), 1)
        self.assertEqual(sum(call['contractId'] == 'federation-knowledge-capture'
            for call in self.submitted), 1)
        await self.restart_callers()
        self.assertEqual(await self.deliver(item), 'delivered')
        self.assertEqual(await self.deliver(item), 'duplicate')
        self.assertEqual(self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],)), original)
        self.assertEqual(len(self.mutations('result-envelope')), 1)
        accepted = json.loads(original['fed_flags'])['accepted_result']
        self.assertEqual((accepted['envelope_id'], accepted['digest']), (item['id'], item['data']['result_digest']))
        findings = self.store.q('SELECT * FROM p_knowledge_items')
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0]['body'], findings[0]['ref'], findings[0]['source']),
            ('Exact accepted evidence', row['id'], 'auto:result'))
        captures = self.store.q("SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-capture:%'")
        self.assertEqual(len(captures), 1)
        completed_capture = strict_loads(captures[0]['v'])
        for field in ('binding', 'contractId', 'operationId', 'intentDigest', 'payload'):
            self.assertEqual(completed_capture[field], original_capture[field])
        self.assertEqual(ledger.outbox_pending(self.store), original_outbox)
        self.assertEqual(sum(call['contractId'] == 'federation-knowledge-capture'
            for call in self.submitted), 1)
        source = strict_loads(captures[0]['v'])['payload']['input']['source']
        self.assertEqual(source['kind'], 'fed-result')
        self.assertEqual(source['resourceRef']['id'], self.resource.binding.entity_id)
        self.assertTrue(ledger.seen(self.store, item['id']))
