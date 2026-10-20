"""Checkpoint selected sources without changing their retained schema."""
import os
from pathlib import Path
import tempfile
import threading
import unittest

from agentmux_contracts import ContractError, strict_loads
from capability_owner.messages_host import MessageStoreHost
from capability_owner.test_messages_host import selected_messages
from capability_owner.test_work_host import WorkSourceTests
from capability_owner.work_host import SelectedWorkDomain, WorkStoreHost
from hub.fed.session import FederationSession
from hub.store import Store, HubError


class SelectedCheckpointTests(WorkSourceTests):
    async def checkpoint_retained(self, source, owner):
        store, connection = source._store, source._store.db
        custody, executor = store._selected_custody, source._executor
        thread = await source.db(threading.get_ident)
        def snapshot():
            return {
                'schema': store.q1('PRAGMA schema_version'),
                'objects': store.q('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'),
                'application': store.q1('PRAGMA application_id'),
                'version': store.q1('PRAGMA user_version'),
                'work': store.q('SELECT * FROM work_items'),
                'messages': store.q('SELECT * FROM messages'),
                'deliveries': store.q('SELECT * FROM deliveries'),
                'agents': store.q('SELECT * FROM agents'),
                'events': store.q('SELECT * FROM events'),
            }
        before = await source.db(snapshot)
        identity = source._database_identity
        statements = []
        wal = Path(source._pins['database']['path'] + '-wal')
        self.assertGreater(wal.stat().st_size, 0)
        await source.db(connection.set_trace_callback, statements.append)
        try:
            await source.db(store.agents, True)
            await source.db(store.checkpoint)
        finally:
            await source.db(connection.set_trace_callback, None)
        self.assertIn('PRAGMA wal_checkpoint(TRUNCATE)', statements)
        self.assertNotIn('PRAGMA optimize', statements)
        self.assertEqual(wal.stat().st_size, 0)
        self.assertEqual(await owner.db(snapshot), before)
        self.assertIs(source._store, store)
        self.assertIs(store.db, connection)
        self.assertIs(store._selected_custody, custody)
        self.assertIs(source._executor, executor)
        self.assertEqual(source._database_identity, identity)
        self.assertEqual(await source.db(threading.get_ident), thread)
        source.check_health()
        return before

    async def test_selected_work_checkpoint_keeps_signed_record_and_restart(self):
        reply, inner = await self.use(self.value('Retained checkpoint work'))
        before = await self.checkpoint_retained(self.source, self.local)
        row = strict_loads(await self.resource.read(reply['resourceRef']['revision']))
        self.assertEqual(row, before['work'][0])
        self.assertEqual((await self.contract_outcome(inner))['recordRef'], reply['receiptRef'])
        await self.local.close()
        await self.source.close()
        source = WorkStoreHost(self.pin, repository={'localName': 'falcon'}, owner_uid=os.getuid())
        self.addAsyncCleanup(source.close)
        await source.start()
        owner = SelectedWorkDomain(source, identity=self.service, scope=self.scope, local_node='mac')
        self.addAsyncCleanup(owner.close)
        self.assertEqual(await owner.db(source._store.q, 'SELECT * FROM work_items'), before['work'])

    async def test_combined_message_source_keeps_work_messages_and_custody(self):
        pin = selected_messages(self.directory.name, scope=self.scope)
        source = MessageStoreHost(pin['source'], repository=pin['repository'],
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(source.close)
        await source.start()
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        owner = SelectedWorkDomain(source, session, identity=self.service,
            scope=self.scope, local_node='mac')
        self.addAsyncCleanup(owner.close)
        store = source._store
        await owner.db(store.work_create, 'operator', 'falcon', 'role:falcon/worker', 'Combined work')
        await owner.db(store.post, 'virtual:operator', 'virtual:operator', 'note', 'Retained message')
        before = await self.checkpoint_retained(source, owner)
        self.assertEqual(len(before['work']), 1)
        self.assertEqual(len(before['messages']), 1)
        await source.db(store.db.execute, 'DROP TRIGGER work_audit')
        with self.assertRaises(ContractError):
            await owner.db(store.work, None)

    async def test_intentional_schema_change_still_refuses_after_checkpoint(self):
        await self.use(self.value('Original'))
        await self.checkpoint_retained(self.source, self.local)
        await self.source.db(self.source._store.db.execute, 'DROP TRIGGER fed_work_terminal')
        with self.assertRaises(ContractError):
            await self.resource.read(1)


class OrdinaryCheckpointTests(unittest.TestCase):
    def test_ordinary_optimization_and_migration_fence_remain_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(str(Path(directory)/'hub.db'))
            try:
                store.repo_add('falcon')
                store.agents(True)
                statements = []
                store.db.set_trace_callback(statements.append)
                store.checkpoint()
                self.assertIn('PRAGMA wal_checkpoint(TRUNCATE)', statements)
                self.assertIn('PRAGMA optimize', statements)
                fence = store.fence_legacy_writer()
                statements.clear()
                store.checkpoint()
                self.assertIn('PRAGMA wal_checkpoint(TRUNCATE)', statements)
                self.assertNotIn('PRAGMA optimize', statements)
                self.assertEqual(store.migration_fence_status(), fence)
                with self.assertRaises(HubError):
                    store.repo_add('blocked')
            finally:
                store.db.set_trace_callback(None)
                store.db.close()
