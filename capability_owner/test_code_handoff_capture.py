"""A retained code handoff keeps its original signed knowledge capture."""
import copy
import unittest
from unittest.mock import patch

from agentmux_contracts import canonical_bytes, strict_loads
from hub.fed.code_bridge import CodeBridgeIntents
from hub.fed.knowledge_bridge import KnowledgeBridgeIntents
from hub.fed.message_bridge import MessageBridgeIntents
from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
from hub.fed.plugins.knowledge import Knowledge
from identity.test_authority import ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .knowledge import KnowledgeStorageResource
from .knowledge_bridge_service import KnowledgeBridgeService
from .knowledge_legacy import LegacyKnowledgeActor
from .legacy_code_client import LegacyCodeCommandClient
from .legacy_knowledge_client import LegacyKnowledgeCommandClient
from .legacy_messages_client import LegacyMessageCommandClient
from .test_legacy_code_client import LegacyCodeTests
from .test_legacy_knowledge_client import LegacyKnowledgeTests


class CodeHandoffCaptureTests(LegacyCodeTests):
    def setUp(self):
        super().setUp()
        template = copy.deepcopy(next(grant for grant in self.record['state']['grants']
            if grant['ref'] == ref('messages-write')))
        grants = {}
        for action in ('capture', 'inspect', 'outcome'):
            contract = 'federation-knowledge-' + action
            grant = {**template, 'ref': ref('code-capture-' + action), 'callerRef': ref('service'),
                'actorRef': ref('service'), 'contractId': contract, 'resourceId': 'task-one'}
            self.record['state']['grants'].append(grant)
            grants[contract] = grant['ref']
        self.knowledge_grants = {'service': grants}
        self.js.messages[0].data = canonical_bytes(self.record)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.knowledge_legacy', 'capability_owner.knowledge_bridge_service',
                'capability_owner.legacy_knowledge_client', 'hub.fed.knowledge_bridge'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.owner.policy.cfg['federation']['capture'] = True
        self.fed._qualified_knowledge = True
        for statement in Knowledge.tables:
            self.store.db.execute(statement)
        actor = LegacyKnowledgeActor(canonical_bytes(ref('service')),
            canonical_bytes(ref('legacy-service-transport')), 'federation',
            canonical_bytes(self.knowledge_grants['service']))
        self.knowledge_resource = KnowledgeStorageResource(OwnerBinding('hub-one',
            'federation-knowledge', 'task-one', 'knowledge-channel', canonical_bytes(self.scope)),
            self.owner, repository='falcon', actors=self.message_resource.actors,
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one', legacy_actors=(actor,),
            message_sources=(self.message_resource,))
        self.knowledge_endpoint = KnowledgeBridgeService(self.service.ingress,
            resources=(self.knowledge_resource,), service_identity_ref=ref('service'),
            service_instance_id='ingress-one', signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(self.knowledge_endpoint.close, timeout=None)
        key = LegacyKnowledgeTests.knowledge_key(self, 'service')
        self.knowledge_sessions = (self.session_for(key, 'knowledge', self.knowledge_endpoint),)
        self.install_knowledge_client()
        adapter = TrustedPluginAdapter(Knowledge(), builtin_context_factory('knowledge'))
        self.fed.plugin_adapters['knowledge'] = adapter
        self.fed.plugins['knowledge'] = adapter.original
        self.fed.routes['knowledge'] = adapter
        self.arguments = {'repo': 'falcon', 'note': 'Original captured handoff',
            'to': 'peer:alice/falcon/worker'}

    def install_knowledge_client(self):
        self.knowledge_client = LegacyKnowledgeCommandClient(self.hub, self.knowledge_sessions).bind(self.fed)
        self.addAsyncCleanup(self.knowledge_client.close, timeout=None)
        self.fed._knowledge_commands = self.knowledge_client
        self.fed._knowledge_intents = KnowledgeBridgeIntents(self.fed, self.knowledge_client)

    def pending_captures(self):
        return [strict_loads(row['v']) for row in self.store.q(
            "SELECT v FROM fed_state WHERE k LIKE 'legacy-knowledge-client:%'")]

    def capture_commands(self):
        return [value for value in self.submitted
            if value['contractId'] == 'federation-knowledge-capture']

    def original_events(self):
        events = [strict_loads(row['payload']) for row in self.store.q('SELECT payload FROM fed_outbox')]
        self.assertEqual(sorted(item['type'] for item in events), ['code', 'handoff', 'knowledge'])
        rows = self.store.q('SELECT * FROM p_knowledge_items')
        self.assertEqual(len(rows), 1, self.fed.log.call_args_list)
        self.assertEqual(rows[0]['source'], 'auto:handoff')
        self.git['push'].assert_awaited_once()
        return events, rows[0]

    async def fail_final_completion(self):
        with patch.object(self.client, '_finish_effect', side_effect=RuntimeError('controlled final completion failure')):
            result = await self.request_hub('fed_code_share', self.arguments)
        self.assertFalse(result['ok'], result)
        return self.original_events()

    async def test_completed_capture_survives_group_failure_and_existing_recovery_retires_it(self):
        original = await self.fail_final_completion()
        pending = self.pending_captures()
        self.assertEqual(len(pending), 1)
        capture = self.capture_commands()[0]
        self.assertEqual(pending[0]['operationId'], capture['operationId'])
        result = await self.request_hub('fed_code_share', self.arguments)
        self.assertTrue(result['ok'], result)
        self.assertEqual(self.original_events(), original)
        self.assertEqual(self.capture_commands(), [capture])
        self.assertEqual(len(self.pending_captures()), 1)
        await self.knowledge_client.recover_captures()
        self.assertEqual(self.pending_captures(), [])
        self.assertEqual(self.original_events(), original)
        self.assertEqual(self.capture_commands(), [capture])

    async def test_lost_capture_reply_and_replacement_clients_recover_same_finding(self):
        self.drop_contract = 'federation-knowledge-capture'
        original = await self.fail_final_completion()
        capture = self.capture_commands()[0]
        self.assertEqual(len(self.pending_captures()), 1)
        for client in (self.client, self.message_client, self.knowledge_client):
            await client.close(timeout=None)
        self.client = LegacyCodeCommandClient(self.hub, self.sessions).bind(self.fed)
        self.message_client = LegacyMessageCommandClient(self.hub, self.message_sessions).bind(self.fed)
        self.addAsyncCleanup(self.client.close, timeout=None)
        self.addAsyncCleanup(self.message_client.close, timeout=None)
        self.fed._code_commands, self.fed._message_commands = self.client, self.message_client
        self.hub._code_commands = self.client
        self.fed._code_intents = CodeBridgeIntents(self.fed, self.client)
        self.fed._message_intents = MessageBridgeIntents(self.fed, self.message_client)
        self.install_knowledge_client()
        result = await self.request_hub('fed_code_share', self.arguments)
        self.assertTrue(result['ok'], result)
        self.assertEqual(self.original_events(), original)
        self.assertEqual(self.capture_commands(), [capture])
        queries = [value['payload']['input'] for value in self.submitted
            if value['contractId'] == 'federation-knowledge-outcome']
        self.assertTrue(any(query['operationId'] == capture['operationId'] for query in queries))
        await self.knowledge_client.recover_captures()
        self.assertEqual(self.pending_captures(), [])
        self.assertEqual(self.original_events(), original)

    async def test_revoked_original_capture_grant_keeps_pending_without_new_finding(self):
        original = await self.fail_final_completion()
        pending = self.pending_captures()
        self.assertEqual(len(pending), 1)
        self.claims.update(operationId='revoke-code-handoff-capture', contractId='identity-revoke',
            grantRef=ref('grant'), expectedVersion=2, payload={'authorityId': 'authority-one',
                'targetRef': self.knowledge_grants['service']['federation-knowledge-capture']})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        await self.knowledge_client.recover_captures()
        self.assertEqual(self.pending_captures(), pending)
        self.assertEqual(self.original_events(), original)
        self.assertEqual(len(self.capture_commands()), 1)

    async def test_ordinary_handoff_capture_is_retired_without_a_code_group(self):
        result = await self.request_hub('fed_messages_send', {'to': self.arguments['to'],
            'kind': 'handoff', 'body': 'Ordinary handoff'})
        self.assertTrue(result['ok'], result)
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1, self.fed.log.call_args_list)
        self.assertEqual(self.pending_captures(), [])
        self.assertEqual(len(self.capture_commands()), 1)
        self.git['push'].assert_not_awaited()

    async def test_only_exact_original_message_source_keeps_capture_pending(self):
        original = await self.fail_final_completion()
        pending = self.pending_captures()
        self.assertEqual(len(pending), 1)
        source = pending[0]['payload']['input']['source']
        self.assertTrue(self.client._retain_handoff_capture(source))
        for key, changed in (('id', 'other-handoff'), ('operationId', 'other-operation'),
                ('payloadDigest', 'sha256:' + '0' * 64),
                ('resourceRef', {**source['resourceRef'], 'revision': source['resourceRef']['revision'] + 1})):
            with self.subTest(key=key):
                self.assertFalse(self.client._retain_handoff_capture({**source, key: changed}))
        self.assertEqual(self.pending_captures(), pending)
        self.assertEqual(self.original_events(), original)


def load_tests(loader, standard_tests, pattern):
    # Reuse the actual Hub/owner setup without rediscovering its existing code
    # and knowledge test cases in this focused integration module.
    names = [name for name in CodeHandoffCaptureTests.__dict__ if name.startswith('test_')]
    return unittest.TestSuite(CodeHandoffCaptureTests(name) for name in sorted(names))
