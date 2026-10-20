"""Real Hub/legacy callbacks and enrolled owners with controlled session I/O."""
import asyncio
import copy
from contextvars import ContextVar
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
import weakref

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.client_launch_session import ApplicationClientSession
from hub.fed import envelope, ledger
from hub.fed.knowledge_bridge import KnowledgeBridgeIntents
from hub.fed.message_bridge import MessageBridgeIntents
from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
from hub.fed.plugins.knowledge import Knowledge
from hub.fed.plugins.messages import Messages
from hub.fed.runtime import Federation
from hub.server import Hub
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, ref
from identity.test_service import _Clock
from identity.test_knowledge_client import material
from .legacy_knowledge_client import LegacyKnowledgeCommandClient
from .legacy_messages_client import LegacyMessageCommandClient
from .message_bridge_service import MessageBridgeService
from . import test_knowledge_bridge_owner as support
from . import test_message_bridge_owner as message_support


class LegacyKnowledgeTests(support.KnowledgeBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.legacy_messages_client', 'capability_owner.legacy_knowledge_client',
                'capability_owner.message_bridge_service', 'hub.fed.message_bridge', 'hub.fed.knowledge_bridge'):
            patch(module + '.datetime', _Clock).start()
        self.hub = object.__new__(Hub)
        self.hub.store, self.hub.db = self.store, self.owner.db
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('knowledge-client-proof', default=None)
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.node = self.hub, 'mac'
        self.fed.cfg, self.fed.policy = self.owner.policy.cfg, self.owner.policy
        self.fed.presence, self.fed.session = {}, self.owner.session
        self.fed.connected, self.fed.last_error = False, None
        self.fed.refresh_policy = AsyncMock(side_effect=lambda: self.fed.policy)
        self.addAsyncCleanup(self.fed.session.close)
        self.fed.stats = dict.fromkeys(('received', 'duplicates', 'dropped', 'quarantined', 'delivered', 'errors'), 0)
        self.fed.log = Mock()
        self.fed.loop = self.fed.wake = None
        self.fed.nc = SimpleNamespace(_subs={}, publish=AsyncMock())
        self.fed._qualified_messages = self.fed._qualified_knowledge = True
        self.hub.fed = self.fed
        self.message_endpoint = MessageBridgeService(self.service.ingress, resources=(self.message_resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=support.SEED)
        self.addAsyncCleanup(self.message_endpoint.close, timeout=None)
        self.drop_share_reply = False
        self.drop_capture_reply = False
        self.drop_knowledge_inspect_reply = False
        self.submitted = []
        self.knowledge_sessions = tuple(self.session_for(self.knowledge_key(identity), 'knowledge', self.endpoint)
            for identity in ('human', 'service'))
        human = message_support.MessageBridgeServiceTests.application_key(self)
        service_material = strict_loads(human._material)
        service_material['callerRef'] = ref('service')
        service_material['messageCommands'].update(authenticatedCaller='federation',
            transportRef=ref('legacy-service-transport'), grantRefs=self.legacy_grants['service'])
        self.message_sessions = tuple(self.session_for(key, 'message', self.message_endpoint)
            for key in (human, ApplicationClientKey(service_material)))
        self.message_client = LegacyMessageCommandClient(self.hub, self.message_sessions).bind(self.fed)
        self.client = LegacyKnowledgeCommandClient(self.hub, self.knowledge_sessions).bind(self.fed)
        self.addAsyncCleanup(self.message_client.close, timeout=None)
        self.addAsyncCleanup(self.client.close, timeout=None)
        self.fed._message_commands, self.fed._knowledge_commands = self.message_client, self.client
        self.fed._message_intents = MessageBridgeIntents(self.fed, self.message_client)
        self.fed._knowledge_intents = KnowledgeBridgeIntents(self.fed, self.client)
        adapters = [TrustedPluginAdapter(plugin, builtin_context_factory(plugin.name)) for plugin in (Messages(), Knowledge())]
        self.fed.plugin_adapters = {adapter.name: adapter for adapter in adapters}
        self.fed.plugins = {adapter.name: adapter.original for adapter in adapters}
        self.fed.routes = {kind: adapter for adapter in adapters for kind in adapter.original.handles}
        self.fed.verbs, self.fed.plugin_verbs = self.fed._core_verbs(), {}
        for adapter in adapters:
            for name, verb in adapter.verbs().items():
                key = 'fed_' + adapter.name + '_' + name
                self.fed.verbs[key], self.fed.plugin_verbs[key] = verb, (adapter, name)

    def knowledge_key(self, identity):
        selected = material()
        selected['scope'] = self.scope
        selected['callerRef'] = ref(identity)
        selected['knowledgeCommands'].update(authenticatedCaller='operator' if identity == 'human' else 'federation',
            subject=self.reply_service.subject, resourceRef=ref('task-one'),
            transportRef=ref('transport' if identity == 'human' else 'legacy-service-transport'),
            repository={'localName': 'falcon', 'repositoryId': self.resource.repository_id},
            grantRefs=self.knowledge_grants[identity])
        return ApplicationClientKey(selected)

    def session_for(self, key, family, endpoint):
        loop = asyncio.get_running_loop()
        session = object.__new__(ApplicationClientSession)
        session._stopped = session._terminal_enrolled = session._terminal_active = False
        session._closing = session._final_closing = None
        selected = key.selection[family + 'Commands']
        setattr(session, '_' + family + '_enrollment', canonical_bytes({
            **{name: key.selection[name] for name in ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope')},
            family + 'Commands': selected}))
        def submit(*, contract_id, operation_id, payload, expires_at, deadline):
            claims = {'purpose': 'agentmux-client-possession-v1',
                **{name: key.selection[name] for name in ('hubId', 'profileId', 'authorityId')},
                'transportRef': selected['transportRef'], 'grantRef': selected['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': payload['resourceRef']['revision'],
                'contractId': contract_id, 'payload': payload, 'approvalRefs': [],
                'issuedAt': NOW.isoformat().replace('+00:00', 'Z'), 'expiresAt': expires_at,
                'replySubject': '_INBOX.knowledge_client_actual_01'}
            self.submitted.append(copy.deepcopy(claims))
            raw = key.sign_command(claims, subject=selected['subject'], now=NOW)
            response = asyncio.run_coroutine_threadsafe(endpoint.handle(raw,
                received_reply_subject=claims['replySubject']), loop).result(timeout=6)
            if self.drop_share_reply and contract_id == 'federation-knowledge-share':
                self.drop_share_reply = False
                raise TimeoutError()
            if self.drop_capture_reply and contract_id == 'federation-knowledge-capture':
                self.drop_capture_reply = False
                raise TimeoutError()
            if self.drop_knowledge_inspect_reply and contract_id == 'federation-knowledge-inspect':
                self.drop_knowledge_inspect_reply = False
                raise TimeoutError()
            return key.verify_command_response(response, raw, subject=selected['subject'], now=NOW)
        setattr(session, family + '_command', submit)
        return session

    async def request_hub(self, verb, args):
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps({
            'token': 'operator-secret', 'verb': verb, 'args': args}).encode()), at_eof=lambda: False)
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        await self.hub.handle_conn(reader, writer, tcp=True)
        return json.loads(writer.write.call_args.args[0])

    def broker_message(self, item):
        from nats.aio.msg import Msg
        sub = SimpleNamespace(_closed=False, unsubscribe=AsyncMock())
        self.fed.nc._subs[1] = sub
        self.fed.session.own_subscription(sub)
        return Msg(_client=self.fed.nc, subject='am.know.alice.' + item['rid'], data=canonical_bytes(item), _sid=1,
            reply='$JS.ACK.AM_SHARE.consumer.1.1.1.1.0')

    async def test_actual_hub_share_lost_reply_recovers_original_id_before_new_write(self):
        args = {'repo': 'falcon', 'title': 'Original title', 'body': 'Original body', 'tags': ['tag']}
        self.drop_share_reply = True
        self.assertFalse((await self.request_hub('fed_knowledge_share', args))['ok'])
        original = self.store.q1('SELECT id FROM p_knowledge_items')['id']
        self.assertEqual(len(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")), 1)
        result = await self.request_hub('fed_knowledge_share', args)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['result']['id'], original)
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertEqual(len([v for v in self.submitted if v['contractId'] == 'federation-knowledge-share']), 1)
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])

    async def test_original_inbound_index_notifications_and_seen_use_qualified_owners(self):
        self.store.repo_add('falcon')
        agent = self.store.register('falcon', 'worker', 'one', 'codex', {})
        self.store.set_state(agent, 'ready')
        item = self.item()
        item.update({'from': 'alice', 'node': 'remote'})
        msg = self.broker_message(item)
        result = await self.fed.receive(msg.subject, msg.data, msg)
        self.assertEqual(result, 'delivered')
        self.assertEqual(self.store.q1('SELECT id FROM p_knowledge_items')['id'], item['id'])
        note = self.store.q1('SELECT * FROM messages')
        self.assertEqual(note['idem_key'], f"know:{item['id']}:{agent}")
        self.assertTrue(ledger.seen(self.store, item['id']))
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-message-client:%'"), [])

    async def test_actual_handoff_capture_uses_committed_message_without_another_human_proof(self):
        result = await self.request_hub('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff',
            'body': 'Actual handoff body', 'ref': 'AMUX-45'})
        self.assertTrue(result['ok'], result)
        row = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertIsNotNone(row, self.fed.log.call_args_list)
        self.assertEqual((row['title'], row['body'], row['source']),
            ('handoff to peer:alice/falcon/worker', 'Actual handoff body', 'auto:handoff'))
        capture = next(v for v in self.submitted if v['contractId'] == 'federation-knowledge-capture')
        self.assertEqual(capture['transportRef'], ref('legacy-service-transport'))
        self.assertEqual(capture['payload']['attribution'], 'federation')
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)

    async def test_restart_tick_recovers_lost_capture_reply_without_reemitting_source_event(self):
        self.drop_capture_reply = True
        result = await self.request_hub('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff',
            'body': 'Retained capture body'})
        self.assertTrue(result['ok'], result)
        original = self.store.q1('SELECT id FROM p_knowledge_items')['id']
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")), 1)
        await self.client.close(timeout=None)
        self.client = LegacyKnowledgeCommandClient(self.hub, self.knowledge_sessions).bind(self.fed)
        self.addAsyncCleanup(self.client.close, timeout=None)
        self.fed._knowledge_commands = self.client
        self.fed._knowledge_intents = KnowledgeBridgeIntents(self.fed, self.client)
        await self.fed.plugin_adapters['knowledge'].start(self.fed)
        await self.fed.plugin_adapters['knowledge'].on_tick(self.fed)
        self.assertEqual(self.store.q('SELECT id FROM p_knowledge_items'), [{'id': original}])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])
        self.assertEqual(len([v for v in self.submitted if v['contractId'] == 'federation-knowledge-capture']), 1)
        outcome = next(v for v in self.submitted if v['contractId'] == 'federation-knowledge-outcome')
        capture = next(v for v in self.submitted if v['contractId'] == 'federation-knowledge-capture')
        self.assertEqual(outcome['payload']['input']['operationId'], capture['operationId'])

    async def test_actual_hub_search_recent_show_and_panel_preserve_public_values(self):
        created = await self.request_hub('fed_knowledge_share', {'repo': 'falcon',
            'title': 'Searchable finding', 'body': 'Specific searchable body', 'tags': ['sample']})
        self.assertTrue(created['ok'], created)
        finding = created['result']['id']
        for verb, args in (('fed_knowledge_search', {'query': 'searchable'}),
                ('fed_knowledge_recent', {'repo': 'falcon', 'limit': -1}),
                ('fed_knowledge_show', {'id': finding})):
            reply = await self.request_hub(verb, args)
            self.assertTrue(reply['ok'], reply)
            rows = reply['result'] if isinstance(reply['result'], list) else [reply['result']]
            self.assertEqual([row['id'] for row in rows], [finding])
            self.assertTrue(all('_rank' not in row for row in rows))
        panel = await self.request_hub('fed_panel', {})
        self.assertTrue(panel['ok'], panel)
        knowledge = next(value for value in panel['result']['panels'] if value['plugin'] == 'knowledge')
        self.assertEqual(knowledge['rows'][0][3], 'Searchable finding')
        self.assertNotIn('error', knowledge)

    async def test_actual_hub_held_approval_indexes_before_approval_and_keeps_untrusted_note(self):
        self.store.repo_add('falcon')
        agent = self.store.register('falcon', 'worker', 'one', 'codex', {})
        self.store.set_state(agent, 'ready')
        item = self.item()
        item.update({'from': 'alice', 'node': 'remote'})
        qid = ledger.quarantine_add(self.store, item, 'am.know.alice.' + item['rid'],
            'know', 'alice', 'original held approval')
        reply = await self.request_hub('fed_approve', {'id': qid})
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'approved')
        self.assertEqual(self.store.q1('SELECT untrusted FROM p_knowledge_items')['untrusted'], 1)
        note = self.store.q1('SELECT * FROM messages')
        self.assertEqual(note['idem_key'], f"know:{item['id']}:{agent}")
        self.assertIn('untrusted', note['body'].lower())
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])
        self.assertEqual(len([v for v in self.submitted if v['contractId'] == 'federation-knowledge-approve']), 1)

    async def test_inbound_commit_before_seen_failure_recovers_same_index_and_one_notification(self):
        self.store.repo_add('falcon')
        agent = self.store.register('falcon', 'worker', 'one', 'codex', {})
        self.store.set_state(agent, 'ready')
        item = self.item()
        item.update({'from': 'alice', 'node': 'remote'})
        msg = self.broker_message(item)
        with patch('hub.fed.runtime.ledger.mark_seen', side_effect=RuntimeError('seen transition failed')):
            with self.assertRaises(RuntimeError):
                await self.fed.receive(msg.subject, msg.data, msg)
        self.assertFalse(ledger.seen(self.store, item['id']))
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")), 1)
        self.assertEqual(await self.fed.receive(msg.subject, msg.data, msg), 'delivered')
        self.assertTrue(ledger.seen(self.store, item['id']))
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertEqual(len([v for v in self.submitted if v['contractId'] == 'federation-knowledge-index']), 1)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])

    async def test_actual_work_completion_capture_keeps_committed_author_and_content(self):
        self.store.repo_add('falcon')
        agent = self.store.register('falcon', 'worker', 'one', 'codex', {})
        self.store.set_state(agent, 'ready')
        work = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Original work')
        self.store.claim(agent, work_id=work['id'])
        released = self.store.release(agent, work['id'], 'done', 'Actual work result', 'mac')
        await self.fed.local_event('work_released', released)
        row = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertIsNotNone(row, self.fed.log.call_args_list)
        self.assertEqual((row['title'], row['body'], row['author'], row['ref']),
            ('done: Original work', 'Actual work result', 'worker/one', work['id']))
        forged = {**released, 'result': 'Forged source text'}
        await self.fed.local_event('work_released', forged)
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)

    async def test_confirmed_conflict_preserves_authorized_input_before_new_attempt(self):
        external = self.knowledge_request('share', {'envelope': self.item()}, operation='competing-share')
        original_handle, raced = self.endpoint.handle, False
        async def compete(raw, *, received_reply_subject):
            nonlocal raced
            if not raced and strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-share':
                raced = True
                await original_handle(external, received_reply_subject=strict_loads(external)['claims']['replySubject'])
            return await original_handle(raw, received_reply_subject=received_reply_subject)
        args = {'repo': 'falcon', 'title': 'Authorized original title', 'body': 'Authorized original body'}
        with patch.object(self.endpoint, 'handle', side_effect=compete):
            failed = await self.request_hub('fed_knowledge_share', args)
        self.assertFalse(failed['ok'], failed)
        first = next(value for value in self.submitted if value['contractId'] == 'federation-knowledge-share')
        pending = strict_loads(self.store.q1("SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")['v'])
        self.assertEqual(pending['conflictReceipt']['outcome'], 'conflict')
        retried = await self.request_hub('fed_knowledge_share', args)
        self.assertTrue(retried['ok'], retried)
        attempts = [value for value in self.submitted if value['contractId'] == 'federation-knowledge-share']
        self.assertEqual(len(attempts), 2)
        self.assertNotEqual(attempts[0]['operationId'], attempts[1]['operationId'])
        self.assertEqual(attempts[0]['payload']['input'], attempts[1]['payload']['input'])
        self.assertEqual(retried['result']['id'], first['payload']['input']['envelope']['id'])
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 2)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)

    async def test_cancelled_share_joins_original_exchange_then_recovers_its_outcome(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original_handle = self.endpoint.handle
        async def blocked(raw, *, received_reply_subject):
            if strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-share':
                entered.set()
                await release.wait()
            return await original_handle(raw, received_reply_subject=received_reply_subject)
        args = {'repo': 'falcon', 'title': 'Cancelled original', 'body': 'Preserve committed input'}
        with patch.object(self.endpoint, 'handle', side_effect=blocked):
            task = asyncio.create_task(self.request_hub('fed_knowledge_share', args))
            await asyncio.wait_for(entered.wait(), 4)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertTrue(self.client._workers)
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertFalse(self.client._workers)
        original = self.store.q1('SELECT id FROM p_knowledge_items')['id']
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")), 1)
        reply = await self.request_hub('fed_knowledge_share', args)
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(reply['result']['id'], original)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)

    async def test_automatic_capture_recovery_refuses_revoked_original_service_grant(self):
        self.drop_capture_reply = True
        reply = await self.request_hub('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff',
            'body': 'Committed capture before revocation'})
        self.assertTrue(reply['ok'], reply)
        pending = self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")
        self.assertEqual(len(pending), 1)
        self.claims.update(operationId='revoke-capture', contractId='identity-revoke',
            transportRef=ref('transport'), grantRef=ref('grant'), expectedVersion=2,
            payload={'authorityId': 'authority-one',
                'targetRef': self.knowledge_grants['service']['federation-knowledge-capture']})
        revoked = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(revoked['claims']['receipt']['decision'], 'allowed')
        await self.fed.plugin_adapters['knowledge'].on_tick(self.fed)
        self.assertEqual(self.store.q("SELECT * FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), pending)
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        self.assertEqual(len([v for v in self.submitted if v['contractId'] == 'federation-knowledge-capture']), 1)

    async def test_accepted_federated_result_capture_uses_original_work_protocol_digest(self):
        from hub.fed import guard
        from hub.fed.work_services import _WorkTransactions, PENDING, result_digest
        self.store.repo_add('falcon')
        work = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Original remote task')
        executor = {'peer': 'alice', 'node': 'remote', 'execution_id': 'original-execution', 'grant_id': 'original-grant'}
        flags = {'outgoing': True, 'protocol': 3, 'origin_node': 'mac', 'env': 'original-offer',
            'rid': self.resource.repository_id, 'offer_digest': 'original-offer-digest', 'executor': executor}
        self.store.db.execute('UPDATE work_items SET state=?, claimed_by=?, fed_flags=? WHERE id=?',
            ('claimed', PENDING, json.dumps(flags), work['id']))
        data = {'origin_id': work['id'], 'origin_node': 'mac', 'offer_id': flags['env'],
            'offer_digest': flags['offer_digest'], 'execution_id': executor['execution_id'],
            'grant_id': executor['grant_id'], 'state': 'done', 'result': 'Accepted original result',
            'by_sender': {'operator': True}}
        data['result_digest'] = result_digest(data)
        result = envelope.make('result', 'alice', 'remote', self.resource.repository_id, 'nick', data)
        decision = guard.inbound(self.fed.policy, 'am.msg.alice.nick', result)
        self.hub._notify_work_owner = AsyncMock()
        outcome = await _WorkTransactions()._on_result(self.fed, result, decision)
        self.assertEqual(outcome, 'delivered')
        stored = self.store.q1('SELECT * FROM work_items WHERE id=?', (work['id'],))
        accepted = json.loads(stored['fed_flags'])['accepted_result']
        self.assertEqual((accepted['envelope_id'], accepted['digest']), (result['id'], data['result_digest']))
        row = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertIsNotNone(row, self.fed.log.call_args_list)
        self.assertEqual((row['title'], row['body'], row['author'], row['source']),
            ('result from alice: Original remote task', 'Accepted original result', 'operator', 'auto:result'))
        await self.fed.local_event('fed_result', {**stored, 'from_peer': 'foreign'})
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)

    async def test_automatic_capture_retains_source_before_first_inspect_exchange(self):
        self.drop_knowledge_inspect_reply = True
        reply = await self.request_hub('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff',
            'body': 'Original source survives lost inspect'})
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])
        self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")), 1)
        pending = strict_loads(self.store.q1("SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")['v'])
        inspection = next(value for value in self.submitted if value['contractId'] == 'federation-knowledge-inspect')
        self.assertEqual(pending['originalDeadline'], inspection['expiresAt'])
        await self.fed.plugin_adapters['knowledge'].on_tick(self.fed)
        self.assertEqual(self.store.q1('SELECT body FROM p_knowledge_items')['body'],
            'Original source survives lost inspect')
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])

    async def test_later_automatic_capture_retries_only_its_confirmed_initial_version_conflict(self):
        for body in ('First completion', 'Second completion'):
            reply = await self.request_hub('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff', 'body': body})
            self.assertTrue(reply['ok'], reply)
        self.assertEqual({row['body'] for row in self.store.q('SELECT body FROM p_knowledge_items')},
            {'First completion', 'Second completion'})
        attempts = [value for value in self.submitted if value['contractId'] == 'federation-knowledge-capture']
        self.assertEqual(len(attempts), 3)
        self.assertNotEqual(attempts[1]['operationId'], attempts[2]['operationId'])
        self.assertEqual(attempts[1]['payload']['input'], attempts[2]['payload']['input'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 4)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])

    async def test_running_offline_hub_recovers_capture_without_a_restart_or_external_connection(self):
        self.hub.stop = asyncio.Event()
        self.fed.cfg = copy.deepcopy(self.fed.cfg)
        self.fed.cfg['federation']['enabled'] = False
        naps = 0
        async def next_iteration(_seconds):
            nonlocal naps
            naps += 1
            if naps == 1:
                self.drop_knowledge_inspect_reply = True
                reply = await self.request_hub('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff',
                    'body': 'Capture while already offline'})
                self.assertTrue(reply['ok'], reply)
                self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])
            else:
                self.hub.stop.set()
        with patch.object(self.fed, '_nap', side_effect=next_iteration), \
                patch.object(self.fed, '_connect_owned', new=AsyncMock()) as connect, \
                patch.object(self.fed, '_drain_outbox', new=AsyncMock()) as publish:
            await self.fed.run()
        connect.assert_not_awaited()
        publish.assert_not_awaited()
        rows = self.store.q('SELECT body FROM p_knowledge_items')
        self.assertEqual(rows, [{'body': 'Capture while already offline'}])
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])

    async def test_recovery_skips_a_busy_original_capture_without_waiting_for_its_lock(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original_handle = self.endpoint.handle
        async def blocked(raw, **kwargs):
            if strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-capture' and not entered.is_set():
                entered.set()
                await release.wait()
            return await original_handle(raw, **kwargs)
        with patch.object(self.endpoint, 'handle', side_effect=blocked):
            posting = asyncio.create_task(self.request_hub('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff',
                'body': 'Busy original capture'}))
            try:
                await asyncio.wait_for(entered.wait(), 6)
                await asyncio.wait_for(self.client.recover_captures(), 1)
                self.assertFalse(posting.done())
                self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])
                release.set()
                self.assertTrue((await posting)['ok'])
            finally:
                release.set()
                await asyncio.gather(posting, return_exceptions=True)
        self.assertEqual(self.store.q('SELECT body FROM p_knowledge_items'), [{'body': 'Busy original capture'}])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])

    async def test_recovery_snapshot_cannot_repeat_a_capture_completed_by_the_original_caller(self):
        entered, release = asyncio.Event(), asyncio.Event()
        snapshot, resume = asyncio.Event(), asyncio.Event()
        original_handle, original_db = self.endpoint.handle, self.hub.db
        async def blocked(raw, **kwargs):
            if strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-capture' and not entered.is_set():
                entered.set()
                await release.wait()
            return await original_handle(raw, **kwargs)
        async def delayed(function, *args, **kwargs):
            result = await original_db(function, *args, **kwargs)
            if function.__name__ == 'pending':
                snapshot.set()
                await resume.wait()
            return result
        with patch.object(self.endpoint, 'handle', side_effect=blocked), patch.object(self.hub, 'db', side_effect=delayed):
            posting = asyncio.create_task(self.request_hub('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff',
                'body': 'One original capture'}))
            recovery = None
            try:
                await asyncio.wait_for(entered.wait(), 6)
                recovery = asyncio.create_task(self.client.recover_captures())
                await asyncio.wait_for(snapshot.wait(), 3)
                release.set()
                self.assertTrue((await posting)['ok'])
                resume.set()
                await recovery
            finally:
                release.set()
                resume.set()
                await asyncio.gather(posting, *(() if recovery is None else (recovery,)), return_exceptions=True)
        self.assertEqual(self.store.q('SELECT body FROM p_knowledge_items'), [{'body': 'One original capture'}])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)

    async def test_offline_recovery_cancellation_joins_original_exchange_and_keeps_pending_source(self):
        self.hub.stop = asyncio.Event()
        self.fed.cfg = copy.deepcopy(self.fed.cfg)
        self.fed.cfg['federation']['enabled'] = False
        naps = 0
        async def next_iteration(_seconds):
            nonlocal naps
            naps += 1
            if naps == 1:
                self.drop_knowledge_inspect_reply = True
                reply = await self.request_hub('post', {'to': 'peer:alice/falcon/worker', 'kind': 'handoff',
                    'body': 'Original offline recovery source'})
                self.assertTrue(reply['ok'], reply)
            else:
                self.hub.stop.set()
        entered, release = asyncio.Event(), asyncio.Event()
        original_handle = self.endpoint.handle
        async def blocked(raw, **kwargs):
            if strict_loads(raw)['claims']['contractId'] == 'federation-knowledge-outcome':
                entered.set()
                await release.wait()
            return await original_handle(raw, **kwargs)
        with patch.object(self.fed, '_nap', side_effect=next_iteration):
            with patch.object(self.endpoint, 'handle', side_effect=blocked):
                running = asyncio.create_task(self.fed.run())
                try:
                    await asyncio.wait_for(entered.wait(), 6)
                    running.cancel()
                    await asyncio.sleep(0)
                    self.assertFalse(running.done())
                    self.assertTrue(self.client._workers)
                finally:
                    release.set()
                    if not running.done():
                        running.cancel()
                    await asyncio.gather(running, return_exceptions=True)
                self.assertTrue(running.cancelled())
            self.assertFalse(self.client._workers)
            self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])
            self.assertEqual(len(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")), 1)
            await self.fed.run()
        self.assertEqual(self.store.q('SELECT body FROM p_knowledge_items'), [{'body': 'Original offline recovery source'}])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        self.assertEqual(self.store.q("SELECT k FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'"), [])
