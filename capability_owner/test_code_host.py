"""Original code Store custody, policy fencing and joined shutdown."""
import asyncio
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.plugins.code import Code
from hub.fed.session import FederationSession
from hub.store import Store
from identity.test_authority import ref
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .code import CodeStorageResource
from .code_host import CodeStoreHost, SelectedCodeDomain
from .messages import MessageActor
from .test_messages import MessageFixture
from .test_messages_host import selected_messages
from . import test_code as code_support


class SelectedCodeTests(MessageFixture, unittest.IsolatedAsyncioTestCase):
    value = code_support.CodeFixture.value

    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        patch('capability_owner.federated_storage.datetime', _Clock).start()
        self.pin = selected_messages(self.directory.name, scope=self.scope)
        store = Store(self.pin['source']['database']['path'])
        try:
            for statement in Code.tables:
                store.db.execute(statement)
        finally:
            store.db.close()
        self.source = CodeStoreHost(self.pin['source'], repository=self.pin['repository'],
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        self.owner = SelectedCodeDomain(self.source, session, identity=self.service,
            scope=self.scope, local_node='mac')
        self.resource = CodeStorageResource(OwnerBinding('hub-one', 'federation-code', 'task-one',
            'code-channel', canonical_bytes(self.scope)), self.owner, repository='falcon',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')

    async def dispatch(self, raw):
        import base64
        inner = base64.b64decode(strict_loads(raw)['claims']['envelopeBytes'], validate=True)
        return await self.resource.write(self.service.reader, inner, raw)

    async def test_original_file_executor_row_outbox_and_empty_read(self):
        self.assertNotEqual(await self.source.db(threading.get_ident), threading.get_ident())
        self.assertEqual(strict_loads(await self.resource.read(1)), {'formatVersion': 1, 'source': None})
        receipt = await self.dispatch((await self.prepare())[0])
        row = await self.source.db(self.source._store.q1, 'SELECT * FROM p_code_shares')
        self.assertEqual(strict_loads(await self.resource.read(receipt['resourceRef']['revision'])), row)
        self.assertEqual((await self.source.db(self.source._store.q1, 'SELECT * FROM fed_outbox'))['msg_id'], row['id'])

    async def test_replaced_policy_fences_read_and_write(self):
        raw, _ = await self.prepare()
        path = Path(self.pin['source']['policy']['path'])
        path.write_text(path.read_text() + '\n# changed\n')
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        with self.assertRaises(ContractError):
            await self.resource.read(1)
        self.assertTrue(self.source._closed)

    async def test_missing_original_code_column_refuses_startup(self):
        await self.source.db(self.source._store.db.execute, 'ALTER TABLE p_code_shares DROP COLUMN fetched')
        await self.source.close()
        replacement = CodeStoreHost(self.pin['source'], repository=self.pin['repository'],
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(replacement.close)
        with self.assertRaises(ContractError):
            await replacement.start()

    async def test_read_refuses_oversized_original_row_without_truncation(self):
        value = self.value()
        await self.dispatch((await self.prepare(value))[0])
        await self.source.db(self.source._store.db.execute, 'UPDATE p_code_shares SET note=?', ('x' * 46000,))
        with self.assertRaises(ContractError):
            await self.resource.read(2)
        self.assertEqual((await self.source.db(self.source._store.q1,
            'SELECT length(note) n FROM p_code_shares'))['n'], 46000)

    async def test_shutdown_joins_original_executor_before_releasing_store(self):
        started, release = threading.Event(), threading.Event()
        def held():
            started.set()
            release.wait(3)
            return 7
        worker = asyncio.create_task(self.source.db(held))
        self.assertTrue(await asyncio.to_thread(started.wait, 1))
        closing = asyncio.create_task(self.source.close())
        await asyncio.sleep(.02)
        self.assertFalse(closing.done())
        self.assertIsNotNone(self.source._store)
        release.set()
        self.assertEqual(await worker, 7)
        await closing
        self.assertIsNone(self.source._store)
        self.assertTrue(self.source._closing.done())
