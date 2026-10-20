"""Actual local work release and enrolled knowledge capture use the original row."""
import copy
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agentmux_contracts import canonical_bytes
from hub.fed.knowledge_bridge import KnowledgeBridgeIntents
from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
from hub.fed.plugins.knowledge import Knowledge
from hub.fed.runtime import Federation
from identity.test_authority import ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .knowledge import KnowledgeStorageResource
from .knowledge_bridge_service import KnowledgeBridgeService
from .knowledge_legacy import LegacyKnowledgeActor
from .legacy_knowledge_client import LegacyKnowledgeCommandClient
from .test_legacy_knowledge_client import LegacyKnowledgeTests
from .test_work_on_behalf_hub import OperatorWorkHubTests


class WorkCaptureHubTests(OperatorWorkHubTests):
    def setUp(self):
        super().setUp()
        self.knowledge_grants = {'service': {}}
        template = next(g for g in self.record['state']['grants'] if g['ref'] == ref('messages-write'))
        for action in ('capture', 'read', 'inspect', 'outcome'):
            contract = 'federation-knowledge-' + action
            grant = copy.deepcopy(template)
            grant.update(ref=ref('capture-' + action), callerRef=ref('service'),
                actorRef=ref('service'), contractId=contract)
            self.record['state']['grants'].append(grant)
            self.knowledge_grants['service'][contract] = grant['ref']
        self.js.messages[0].data = canonical_bytes(self.record)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.legacy_messages_client', 'capability_owner.knowledge_legacy',
                'capability_owner.knowledge_bridge_service', 'capability_owner.legacy_knowledge_client',
                'capability_owner.work_capture', 'hub.fed.knowledge_bridge'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        for statement in Knowledge.tables:
            self.store.db.execute(statement)
        fed = self.fed = object.__new__(Federation)
        fed.hub, fed.node, fed.cfg, fed.policy = self.hub, 'mac', self.owner.policy.cfg, self.owner.policy
        fed.session, fed.nc = self.owner.session, SimpleNamespace(_subs={})
        fed.log = Mock()
        fed._qualified_knowledge, fed._qualified_work = True, False
        fed._profile_context = None
        fed.cfg['federation'].update(capture=True, enabled=False)
        self.hub.fed = fed
        await self.prepare_capture_work()
        actor = LegacyKnowledgeActor(canonical_bytes(ref('service')),
            canonical_bytes(ref('legacy-service-transport')), 'federation',
            canonical_bytes(self.knowledge_grants['service']))
        resource = KnowledgeStorageResource(OwnerBinding('hub-one', 'federation-knowledge', 'task-one',
            'knowledge-channel', canonical_bytes(self.scope)), self.owner, repository='falcon',
            actors=self.resource.actors, plugin_identity_ref=ref('plugin'), instance_id='plugin-one',
            legacy_actors=(actor,), work_sources=(self.resource,))
        endpoint = KnowledgeBridgeService(self.service.ingress, resources=(resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(endpoint.close, timeout=None)
        work_resource = self.resource
        try:
            self.resource = resource
            key = LegacyKnowledgeTests.knowledge_key(self, 'service')
        finally:
            self.resource = work_resource
        self.drop_share_reply = self.drop_capture_reply = self.drop_knowledge_inspect_reply = False
        session = LegacyKnowledgeTests.session_for(self, key, 'knowledge', endpoint)
        client = LegacyKnowledgeCommandClient(self.hub, (session,)).bind(fed)
        self.addAsyncCleanup(client.close, timeout=None)
        fed._knowledge_commands = client
        fed._knowledge_intents = KnowledgeBridgeIntents(fed, client)
        adapter = TrustedPluginAdapter(Knowledge(), builtin_context_factory('knowledge'))
        fed.plugin_adapters = {**getattr(fed, 'plugin_adapters', {}), 'knowledge': adapter}
        self.hub.fed = fed

    async def prepare_capture_work(self):
        pass

    async def test_actual_release_capture_lost_reply_and_retry_keep_one_original(self):
        target = self.target()
        self.store.db.execute('ALTER TABLE work_items ADD COLUMN future_field TEXT')
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Original capture')
        self.store.claim(target, work_id=row['id'])
        self.store.db.execute('UPDATE work_items SET future_field=? WHERE id=?', ('retained', row['id']))
        arguments = {'work_id': row['id'], 'outcome': 'done', 'result': 'Original durable finding'}
        self.drop_capture_reply = True
        first = await self.packet('release', arguments, operation_id='capture-release', target=target)
        self.assertFalse(first['ok'], first)
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)
        recovered = await self.packet('release', arguments, operation_id='capture-release', target=target)
        self.assertTrue(recovered['ok'], recovered)
        self.assertEqual(recovered['result'], self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],)))
        self.assertNotIn('children', recovered['result'])
        self.assertEqual(recovered['result']['future_field'], 'retained')
        self.assertEqual(await self.packet('release', arguments, operation_id='capture-release', target=target), recovered)
        self.assertEqual(len(self.mutations('release')), 1)
        findings = self.store.q('SELECT * FROM p_knowledge_items')
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0]['body'], findings[0]['ref'], findings[0]['source']),
            ('Original durable finding', row['id'], 'auto:work'))
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
