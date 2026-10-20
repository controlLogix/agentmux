"""Actual typed native knowledge write/recovery on the existing TLS fixture."""
import unittest
from agentmux_contracts import canonical_bytes
from hub.fed import envelope
from hub.fed.plugins.knowledge import Knowledge
from identity.test_authority import ref
from state_owner.ledger import OwnerBinding
from .knowledge import KnowledgeStorageResource
from .messages import MessageActor
from .test_messages_live import MessageLiveFixture


class LiveKnowledgeTests(MessageLiveFixture, unittest.IsolatedAsyncioTestCase):
    def storage_resource(self):
        for statement in Knowledge.tables:
            self.store.db.execute(statement)
        binding = OwnerBinding('hub-one', 'federation-knowledge', 'task-one', 'knowledge-channel', canonical_bytes(self.scope))
        return KnowledgeStorageResource(binding, self.domain, repository='falcon',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')

    def storage_value(self, command):
        env = envelope.make('knowledge', 'nick', 'mac', self.resource.repository_id, '*',
            {'title': 'Native finding', 'body': 'Original native knowledge é', 'tags': ['kept'],
             'ref': 'AMUX-45', 'author': 'operator', 'source': 'explicit'})
        return {'formatVersion': 1, 'command': command, 'envelope': env}

    async def test_native_publish_keeps_original_knowledge_fts_outbox_and_recovery(self):
        await self.native_message('publish')
        self.success = False
        row = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertEqual(row['body'], 'Original native knowledge é')
        self.assertEqual(row['id'], self.store.q1('SELECT * FROM fed_outbox')['msg_id'])
        self.assertEqual(len(self.store.q("SELECT * FROM p_knowledge_fts WHERE p_knowledge_fts MATCH 'Original'")), 1)
        self.success = True
