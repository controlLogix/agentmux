"""Actual selected work files, current authority and joined source custody."""
import asyncio
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.session import FederationSession
from hub.store import APP_ID, MIGRATIONS, Store
from identity.test_service import _Clock
from identity.test_authority import ref
from hub.tests.test_hub_offline import reg
from .messages import MessageActor
from .messages_host import MessageStoreHost
from .test_messages import MessageFixture
from .test_messages_host import selected_messages
from . import test_work as work_support
from .work_host import SelectedWorkDomain, WorkStoreHost


def selected_work(root):
    database = Path(root).resolve() / 'work.db'
    store = Store(str(database))
    try:
        store.repo_add('falcon')
        store.repo_add('other')
    finally:
        store.db.close()
    database.chmod(0o600)
    return {'database': {'path': str(database), 'applicationId': APP_ID, 'userVersion': len(MIGRATIONS)}}


class WorkSourceTests(MessageFixture, unittest.IsolatedAsyncioTestCase):
    endpoint = work_support.WorkStorageTests.endpoint
    open_work = work_support.WorkStorageTests.open_work
    value = work_support.WorkStorageTests.value
    use = work_support.WorkStorageTests.use
    replace_resource = work_support.WorkStorageTests.replace_resource
    prepare_read = work_support.WorkStorageTests.prepare_read

    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        patch('capability_owner.federated_storage.datetime', _Clock).start()
        self.pin = selected_work(self.directory.name)
        self.source = WorkStoreHost(self.pin, repository={'localName': 'falcon'}, owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        self.local = SelectedWorkDomain(self.source, identity=self.service, scope=self.scope, local_node='mac')
        self.addAsyncCleanup(self.local.close)
        self.resource = self.open_work()
        self.reply_service = self.endpoint()
        self.addAsyncCleanup(self.reply_service.close)

    async def test_local_unshared_signed_work_preserves_rows_events_and_contract(self):
        self.assertIsNone(self.resource.repository_id)
        self.assertIsNone(self.local.session)
        with self.assertRaises(ContractError):
            self.local.policy
        loop_thread = threading.get_ident()
        db_thread = await self.source.db(threading.get_ident)
        self.assertNotEqual(loop_thread, db_thread)
        reply, inner = await self.use(self.value('Unshared work'))
        row = await self.source.db(self.source._store.q1, 'SELECT * FROM work_items')
        self.assertEqual(row['title'], 'Unshared work')
        self.assertEqual(row['created_by'], 'virtual:operator')
        self.assertEqual(strict_loads(await self.resource.read(reply['resourceRef']['revision'])), row)
        events = await self.source.db(self.source._store.q, "SELECT * FROM events WHERE entity='work'")
        self.assertEqual([(e['entity_id'], e['event'], e['actor']) for e in events],
            [(row['id'], 'ready', 'virtual:operator')])
        self.assertEqual(await self.source.db(self.source._store.q, 'SELECT * FROM nats_outbox'), [])
        self.assertEqual(await self.source.db(self.source._store.q, 'SELECT * FROM fed_outbox'), [])
        self.assertEqual((await self.contract_outcome(inner))['recordRef'], reply['receiptRef'])
        self.assertEqual(await self.source.db(threading.get_ident), db_thread)

    async def test_admitted_source_supports_agent_claim_heartbeat_and_reregistration(self):
        from hub.tests.test_hub_offline import reg
        store = self.source._store
        caller = await self.source.db(reg, store, 'falcon', 'worker', 'one')
        row = await self.source.db(store.work_create, 'operator', 'falcon', 'role:falcon/worker', 'Agent work')
        self.assertEqual((await self.source.db(store.claim, caller, repository='falcon'))['claimed']['id'], row['id'])
        self.assertEqual(await self.source.db(store.heartbeat, caller, 240, repository='falcon'), 1)
        await self.source.db(store.set_state, caller, 'dead')
        self.assertEqual((await self.source.db(store.work, row['id']))['state'], 'ready')
        self.assertEqual(await self.source.db(reg, store, 'falcon', 'worker', 'one'), caller)
        self.assertEqual((await self.source.db(store.agent, caller))['generation'], 2)

    async def test_existing_bridge_offer_keeps_original_outbox_in_same_transaction(self):
        reply, _ = await self.use(self.value('Bridge work', federate=True))
        row = strict_loads(await self.resource.read(reply['resourceRef']['revision']))
        self.assertEqual(row['claimed_by'], 'nats:federated')
        pending = await self.source.db(self.source._store.outbox_pending)
        self.assertEqual(len(pending), 1)
        self.assertEqual(strict_loads(pending[0]['payload'])['origin_id'], row['id'])
        self.assertEqual(await self.source.db(self.source._store.q, 'SELECT * FROM fed_outbox'), [])

    async def test_restart_retains_original_work_and_outcome(self):
        raw, inner = await self.prepare(self.value('Original'))
        reply = await self.dispatch(raw)
        await self.local.close()
        await self.source.close()
        self.source = WorkStoreHost(self.pin, repository={'localName': 'falcon'}, owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        self.local = SelectedWorkDomain(self.source, identity=self.service, scope=self.scope, local_node='mac')
        self.addAsyncCleanup(self.local.close)
        await self.replace_resource(self.open_work())
        self.assertEqual(await self.dispatch(raw), reply)
        self.assertEqual(len(await self.source.db(self.source._store.q, 'SELECT * FROM work_items')), 1)
        self.assertEqual((await self.contract_outcome(inner))['recordRef'], reply['receiptRef'])

    async def test_database_replacement_refuses_before_work(self):
        path = Path(self.pin['database']['path'])
        path.rename(path.with_suffix('.retained'))
        path.write_bytes(b'replaced')
        path.chmod(0o600)
        with self.assertRaises(ContractError):
            await self.resource.read(1)
        self.assertTrue(self.source._closed)

    async def test_changed_schema_refuses_queued_transaction(self):
        raw, _ = await self.prepare()
        await self.source.db(self.source._store.db.execute, 'DROP TRIGGER fed_work_terminal')
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        # Inspect the retained connection directly after refusal; no host bypass
        # can turn this source into ready work service again.
        self.assertEqual(self.source._store.q('SELECT * FROM work_items'), [])

    async def test_changed_database_schema_metadata_refuses_work(self):
        for setting, restore in (('application_id=0', 'application_id=' + str(APP_ID)),
                ('user_version=0', 'user_version=' + str(len(MIGRATIONS)))):
            # The retained connection simulates a foreign metadata change while
            # leaving file identity and schema_version unchanged.
            self.source._store.db.execute('PRAGMA ' + setting)
            try:
                with self.assertRaises(ContractError):
                    await self.resource.read(1)
            finally:
                self.source._store.db.execute('PRAGMA ' + restore)

    async def test_revoked_current_caller_refuses_without_work(self):
        raw, _ = await self.prepare()
        current = strict_loads(self.js.messages[-1].data)
        grant = next(g for g in current['state']['grants'] if g['ref']['id'] == 'messages-write')
        grant['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(await self.source.db(self.source._store.q, 'SELECT * FROM work_items'), [])

    async def test_final_signed_read_refuses_registration_replacement_on_owned_worker(self):
        caller = await self.source.db(reg, self.source._store, 'falcon', 'worker', 'one')
        actors = (MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), caller),)
        await self.replace_resource(self.open_work(actors=actors))
        await self.use(self.value('Before registration change'))
        raw = await self.prepare_read(revision=2)
        original, calls = self.reply_service._admit, 0
        async def changed(*args, **kwargs):
            nonlocal calls
            result = await original(*args, **kwargs)
            calls += 1
            if calls == 2:
                await self.source.db(self.source._store.set_state, caller, 'dead')
                await self.source.db(reg, self.source._store, 'falcon', 'worker', 'one')
            return result
        with patch.object(self.reply_service, '_admit', side_effect=changed):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        self.assertEqual(calls, 2)
        rows = await self.source.db(self.source._store.q, 'SELECT * FROM work_items')
        self.assertEqual(len(rows), 1)

    async def test_scope_and_native_identity_replacements_refuse(self):
        for mutate, restore in (
            (lambda: setattr(self.local, 'node', 'other'), lambda: setattr(self.local, 'node', 'mac')),
            (lambda: setattr(self.local, '_scope', canonical_bytes({**self.scope, 'projectId': 'other'})),
                lambda: setattr(self.local, '_scope', canonical_bytes(self.scope))),
            (lambda: setattr(self.service.reader, '_profile', 'other'),
                lambda: setattr(self.service.reader, '_profile', 'profile-one')),
            (lambda: self.source._repository.update(localName='other'),
                lambda: self.source._repository.update(localName='falcon')),
        ):
            mutate()
            try:
                with self.assertRaises(ContractError):
                    await self.resource.read(1)
            finally:
                restore()
        foreign = {**self.scope, 'organizationId': 'foreign'}
        with self.assertRaises(ContractError):
            SelectedWorkDomain(self.source, identity=self.service, scope=foreign, local_node='mac')

    async def test_executor_and_reader_replacement_refuse(self):
        executor, reader = self.source._executor, self.service.reader
        self.source._executor = object()
        try:
            with self.assertRaises(ContractError):
                await self.resource.read(1)
        finally:
            self.source._executor = executor
        self.service.reader = object()
        try:
            with self.assertRaises(ContractError):
                await self.resource.read(1)
        finally:
            self.service.reader = reader

    async def test_borrowed_close_joins_original_cancelled_work_without_closing_source(self):
        entered, release = threading.Event(), threading.Event()
        def operation():
            entered.set()
            if not release.wait(3):
                raise TimeoutError()
            return self.source._store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Retained')
        original = asyncio.create_task(self.local.db(operation))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            original.cancel()
            closing = asyncio.create_task(self.local.close())
            await asyncio.sleep(0)
            self.assertFalse(original.done())
            self.assertFalse(closing.done())
        finally:
            release.set()
        with self.assertRaises(asyncio.CancelledError):
            await original
        await closing
        self.source.check_health()
        rows = await self.source.db(self.source._store.q, 'SELECT * FROM work_items')
        self.assertEqual([r['title'] for r in rows], ['Retained'])
        self.assertFalse(self.service._closed)

    async def test_source_close_keeps_connection_until_original_operation_finishes(self):
        entered, release = threading.Event(), threading.Event()
        def operation():
            entered.set()
            if not release.wait(3):
                raise TimeoutError()
            return self.source._store.q1('SELECT count(*) AS n FROM work_items')['n']
        original = asyncio.create_task(self.local.db(operation))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            closing = asyncio.create_task(self.source.close())
            await asyncio.sleep(0)
            self.assertIsNotNone(self.source._store)
            self.assertFalse(closing.done())
        finally:
            release.set()
        self.assertEqual(await original, 0)
        await closing
        self.assertIsNone(self.source._store)
        self.assertTrue(self.source._closing.done())
        self.assertFalse(self.service._closed)

    async def test_federated_source_requires_real_policy_and_session_and_reuses_custody(self):
        pin = selected_messages(self.directory.name, scope=self.scope)
        source = WorkStoreHost(pin['source'], repository=pin['repository'], local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(source.close)
        await source.start()
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        with self.assertRaises(ContractError):
            SelectedWorkDomain(source, identity=self.service, scope=self.scope, local_node='mac')
        owner = SelectedWorkDomain(source, session, identity=self.service, scope=self.scope, local_node='mac')
        self.addAsyncCleanup(owner.close)
        self.assertIs(owner.store, source._store)
        self.assertIs(owner.hub.dbx, source._executor)
        self.assertEqual(owner.hub.sender_of('operator'), 'virtual:operator')
        self.assertEqual(owner.sender_of('operator'), {'operator': True})
        self.assertEqual(owner.policy.rid_of('falcon'), pin['repository']['repositoryId'])
        await self.replace_resource(self.open_work(owner=owner))
        reply, _ = await self.use(self.value('Shared source local work'))
        self.assertEqual(strict_loads(await self.resource.read(reply['resourceRef']['revision']))['title'],
            'Shared source local work')
        await owner.close()
        source.check_health()
        policy = Path(pin['source']['policy']['path'])
        policy.write_text(policy.read_text() + '\n# changed\n')
        with self.assertRaises(ContractError):
            source.check_health()

    async def test_existing_message_source_is_borrowed_and_work_schema_is_checked(self):
        pin = selected_messages(self.directory.name, scope=self.scope)
        source = MessageStoreHost(pin['source'], repository=pin['repository'], local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(source.close)
        await source.start()
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        owner = SelectedWorkDomain(source, session, identity=self.service, scope=self.scope, local_node='mac')
        self.addAsyncCleanup(owner.close)
        self.assertIs(await owner.db(lambda: owner.store), source._store)
        await owner.close()
        source.check_health()
        await source.db(source._store.db.execute, 'DROP TRIGGER work_audit')
        with self.assertRaises(ContractError):
            SelectedWorkDomain(source, session, identity=self.service, scope=self.scope, local_node='mac')


class WorkSourceAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_required_agent_columns_refuse_before_readiness(self):
        for column in ('last_seen', 'cli', 'transport', 'handle', 'pane_pid', 'token_sha',
                'last_output', 'last_bell', 'created', 'term_name'):
            with self.subTest(column=column), tempfile.TemporaryDirectory() as directory:
                pins = selected_work(directory)
                store = Store(pins['database']['path'])
                try:
                    store.db.execute('ALTER TABLE agents DROP COLUMN ' + column)
                    before = store.q1('PRAGMA schema_version')
                finally:
                    store.db.close()
                source = WorkStoreHost(pins, repository={'localName': 'falcon'}, owner_uid=os.getuid())
                try:
                    with self.assertRaises(ContractError):
                        await source.start()
                    self.assertTrue(source._closed)
                    self.assertEqual(source._store.q1('PRAGMA schema_version'), before)
                finally:
                    await source.close()

    async def test_missing_tables_and_changed_triggers_refuse_without_migration(self):
        for statement in ('DROP TABLE claims', 'DROP TABLE fed_state', 'DROP TABLE events',
                'DROP TABLE nats_outbox', 'DROP TABLE agents', 'DROP TABLE deliveries', 'DROP TRIGGER work_audit',
                'DROP TRIGGER work_audit_ins', 'DROP TRIGGER agents_audit', 'DROP TRIGGER deliveries_audit',
                'DROP TRIGGER fed_work_terminal'):
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as directory:
                pins = selected_work(directory)
                connection = Store(pins['database']['path'])
                connection.db.execute(statement)
                before = connection.q1('PRAGMA schema_version')
                connection.db.close()
                source = WorkStoreHost(pins, repository={'localName': 'falcon'}, owner_uid=os.getuid())
                try:
                    with self.assertRaises(ContractError):
                        await source.start()
                    self.assertTrue(source._closed)
                    self.assertEqual(source._store.q1('PRAGMA schema_version'), before)
                finally:
                    await source.close()

    async def test_changed_trigger_event_literal_is_not_treated_as_same_sql(self):
        with tempfile.TemporaryDirectory() as directory:
            pins = selected_work(directory)
            store = Store(pins['database']['path'])
            try:
                trigger = store.q1("SELECT sql FROM sqlite_master WHERE name='work_audit_ins'")['sql']
                store.db.execute('DROP TRIGGER work_audit_ins')
                store.db.execute(trigger.replace("'work'", "'Work'"))
            finally:
                store.db.close()
            source = WorkStoreHost(pins, repository={'localName': 'falcon'}, owner_uid=os.getuid())
            try:
                with self.assertRaises(ContractError):
                    await source.start()
            finally:
                await source.close()

    async def test_missing_database_does_not_create_one(self):
        with tempfile.TemporaryDirectory() as directory:
            pins = selected_work(directory)
            path = Path(pins['database']['path'])
            path.unlink()
            source = WorkStoreHost(pins, repository={'localName': 'falcon'}, owner_uid=os.getuid())
            try:
                with self.assertRaises(ContractError):
                    await source.start()
                self.assertFalse(path.exists())
            finally:
                await source.close()

    async def test_local_source_rejects_fabricated_federation_and_absent_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            pins = selected_work(directory)
            for arguments in (
                    {'repository': {'localName': 'falcon', 'repositoryId': 'fake', 'normalizedRemote': 'fake'}},
                    {'repository': {'localName': 'falcon'}, 'local_peer': 'fake'}):
                with self.assertRaises(ContractError):
                    WorkStoreHost(pins, owner_uid=os.getuid(), **arguments)
            source = WorkStoreHost(pins, repository={'localName': 'absent'}, owner_uid=os.getuid())
            try:
                with self.assertRaises(ContractError):
                    await source.start()
            finally:
                await source.close()


class AggregateWorkSourceTests(MessageFixture, unittest.IsolatedAsyncioTestCase):
    message_repository = None
    message_scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
    endpoint = work_support.WorkStorageTests.endpoint
    open_work = work_support.WorkStorageTests.open_work
    value = work_support.WorkStorageTests.value
    use = work_support.WorkStorageTests.use

    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        patch('capability_owner.federated_storage.datetime', _Clock).start()
        self.pin = selected_work(self.directory.name)
        self.source = WorkStoreHost(self.pin, repository=None, owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        self.local = SelectedWorkDomain(self.source, identity=self.service, scope=self.scope, local_node='mac')
        self.addAsyncCleanup(self.local.close)
        self.resource = self.open_work(repository=None)
        self.reply_service = self.endpoint()
        self.addAsyncCleanup(self.reply_service.close)

    async def test_local_aggregate_reads_existing_repositories_without_create_permission(self):
        first = await self.source.db(self.source._store.work_create, 'virtual:operator', 'falcon',
            'role:falcon/worker', 'First')
        second = await self.source.db(self.source._store.work_create, 'virtual:operator', 'other',
            'role:other/worker', 'Second')
        rows = strict_loads(await self.resource.read(1))
        self.assertEqual({r['id'] for r in rows}, {first['id'], second['id']})
        with self.assertRaises(ContractError):
            await self.use(self.value('Forbidden aggregate creation'))
        self.assertEqual(len(await self.source.db(self.source._store.q, 'SELECT * FROM work_items')), 2)
