"""Knowledge source custody uses the original file and joined executor."""
import os
import copy
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.plugins.knowledge import Knowledge
from hub.fed.session import FederationSession
from hub.store import Store
from identity.test_authority import ref
from identity.authority import AuthoritySnapshot
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .knowledge import KnowledgeStorageResource
from .knowledge_host import KnowledgeStoreHost, SelectedKnowledgeDomain
from .messages import MessageActor
from . import test_knowledge as knowledge_support
from .test_messages import MessageFixture
from .test_messages_host import selected_messages
from . import test_selected_storage as storage_support
from unittest.mock import AsyncMock


class SelectedKnowledgeTests(MessageFixture, unittest.IsolatedAsyncioTestCase):
    value = knowledge_support.KnowledgeStorageTests.value
    dispatch = knowledge_support.KnowledgeStorageTests.dispatch_owner

    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        patch('capability_owner.federated_storage.datetime', _Clock).start()
        self.pin = selected_messages(self.directory.name, scope=self.scope)
        store = Store(self.pin['source']['database']['path'])
        try:
            for statement in Knowledge.tables:
                store.db.execute(statement)
        finally:
            store.db.close()
        self.source = KnowledgeStoreHost(self.pin['source'], repository=self.pin['repository'],
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        self.owner = SelectedKnowledgeDomain(self.source, session, identity=self.service,
            scope=self.scope, local_node='mac')
        self.resource = KnowledgeStorageResource(OwnerBinding('hub-one', 'federation-knowledge', 'task-one',
            'knowledge-channel', canonical_bytes(self.scope)), self.owner, repository='falcon',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')

    async def test_actual_executor_preserves_original_file_record_fts_and_outbox(self):
        self.assertNotEqual(await self.source.db(threading.get_ident), threading.get_ident())
        receipt = await self.dispatch((await self.prepare())[0])
        row = await self.source.db(self.source._store.q1, 'SELECT * FROM p_knowledge_items')
        self.assertEqual(strict_loads(await self.resource.read(receipt['resourceRef']['revision'])), row)
        self.assertEqual(len(await self.source.db(self.source._store.q,
            "SELECT * FROM p_knowledge_fts WHERE p_knowledge_fts MATCH 'Original'")), 1)
        self.assertEqual((await self.source.db(self.source._store.q1, 'SELECT * FROM fed_outbox'))['msg_id'], row['id'])

    async def test_replaced_policy_fences_read_and_write_without_fallback(self):
        raw, _ = await self.prepare()
        path = Path(self.pin['source']['policy']['path'])
        path.write_text(path.read_text() + '\n# changed\n')
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        with self.assertRaises(ContractError):
            await self.resource.read(1)
        self.assertTrue(self.source._closed)

    async def test_missing_original_index_trigger_refuses_startup(self):
        await self.source.db(self.source._store.db.execute, 'DROP TRIGGER p_knowledge_ai')
        await self.source.close()
        replacement = KnowledgeStoreHost(self.pin['source'], repository=self.pin['repository'],
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(replacement.close)
        with self.assertRaises(ContractError):
            await replacement.start()

    async def test_ordinary_table_cannot_replace_original_fts_index(self):
        await self.source.db(self.source._store.db.execute, 'DROP TABLE p_knowledge_fts')
        await self.source.db(self.source._store.db.execute, 'CREATE TABLE p_knowledge_fts(title,body,tags)')
        await self.source.close()
        replacement = KnowledgeStoreHost(self.pin['source'], repository=self.pin['repository'],
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(replacement.close)
        with self.assertRaises(ContractError):
            await replacement.start()


def selected_knowledge(root, *, scope):
    selected = selected_messages(root, scope=scope)
    channel = selected['channels'][0]
    channel.pop('peer')
    channel['resourceRef'] = ref('knowledge-one')
    store = Store(selected['source']['database']['path'])
    try:
        for statement in Knowledge.tables:
            store.db.execute(statement)
    finally:
        store.db.close()
    return selected


class SelectedKnowledgeCompositionFixture:
    connection = storage_support.SelectedStorageCompositionTests.connection

    custody = storage_support.SelectedStorageCompositionTests.custody

    selected = storage_support.SelectedStorageCompositionTests.selected

    add_board = storage_support.SelectedStorageCompositionTests.add_board

    identity_inputs = storage_support.SelectedStorageCompositionTests.identity_inputs

    authority_record = storage_support.SelectedStorageCompositionTests.authority_record

    def setUp(self):
        storage_support.SelectedStorageCompositionTests.setUp(self)
        self.value['storage']['knowledge'] = selected_knowledge(self.root, scope=self.scope)
        self.selection = self.selected()
        current = strict_loads(self.snapshot.record)
        current['state']['identities'].append({'ref': ref('plugin-one'), 'kind': 'plugin', 'status': 'active',
            'principalId': 'plugin-one', 'externalIdentity': None})
        for transport in current['state']['transports']:
            if transport['ref'] == ref('transport'):
                transport.update(issuedAt=self.issuer_start, expiresAt=self.issuer_end)
        self.snapshot = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence)

    async def asyncSetUp(self):
        await storage_support.SelectedStorageCompositionTests.asyncSetUp(self)



class SelectedKnowledgeCompositionTests(SelectedKnowledgeCompositionFixture, unittest.IsolatedAsyncioTestCase):
    async def test_production_storage_host_builds_original_knowledge_source(self):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()
            self.host.check_health()
            knowledge = next(r for r in self.host._resources if isinstance(r, KnowledgeStorageResource))
            self.assertEqual(knowledge.binding.entity_id, 'knowledge-one')
            self.assertEqual(await knowledge.read(1), canonical_bytes({'formatVersion': 1, 'source': None}))
            source = self.host._message_stores[0]
            self.assertIs(knowledge._store, source._store)
            await self.host.close(timeout=None)
            self.assertTrue(source._closing.done())
            self.assertIsNone(source._store)
        self.assertFalse(self.identity._closed)

    async def test_identical_message_source_is_borrowed_without_another_database_owner(self):
        await self.host.close(timeout=None)
        message = copy.deepcopy(self.value['storage']['knowledge'])
        message['channels'][0].update(peer='alice', resourceRef=ref('messages-one'))
        self.value['storage']['messages'] = message
        self.selection = self.selected()
        from .selected_storage import SelectedStorageHost
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()
            self.assertEqual(len(self.host._message_stores), 1)
            resources = [r for r in self.host._resources if r.binding.entity_id in ('knowledge-one', 'messages-one')]
            self.assertEqual(len(resources), 2)
            self.assertIs(resources[0]._store, resources[1]._store)
            await self.host.close(timeout=None)

    async def test_missing_database_prevents_readiness_and_joins_partial_start(self):
        Path(self.value['storage']['knowledge']['source']['database']['path']).unlink()
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            with self.assertRaises(ContractError):
                await self.host.start()
            self.assertFalse(self.host._ready)
            await self.host.close(timeout=None)
        self.assertEqual(self.host._receivers, [])

    def test_foreign_actor_and_source_aliases_refuse_selection(self):
        for change in ('foreign-actor', 'database-policy-alias'):
            original = copy.deepcopy(self.value)
            if change == 'foreign-actor':
                from hub import names
                self.value['storage']['knowledge']['channels'][0]['actors'][0]['caller'] = names.session_name('other', 'worker', 'one')
            else:
                self.value['storage']['knowledge']['source']['policy']['path'] = (
                    self.value['storage']['knowledge']['source']['database']['path'])
            with self.assertRaises(ContractError):
                self.selected()
            self.value = original

