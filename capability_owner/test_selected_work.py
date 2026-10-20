"""Selected work composition keeps the admitted source and its original work."""
import asyncio
import copy
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.store import Store
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from .selected_storage import SelectedStorageHost, SelectedStorageFailure
from .test_code_selection import SelectedCodeFixture
from .work import WorkStorageResource
from .work_host import SelectedWorkDomain, WorkStoreHost


class SelectedWorkCompositionTests(SelectedCodeFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        SelectedCodeFixture.setUp(self)
        self.shared = self.value['storage'].pop('code')
        work = copy.deepcopy(self.shared)
        work['source'] = {'database': work['source']['database']}
        work.update(localPeer=None, repository={'localName': 'falcon'})
        channel = work['channels'][0]
        channel['resourceRef'] = ref('work-one')
        self.database = Path(work['source']['database']['path'])
        store = Store(str(self.database))
        try:
            store.db.execute('ALTER TABLE work_items ADD COLUMN future_field TEXT')
            store.db.execute('CREATE TABLE future_records (id TEXT PRIMARY KEY, value BLOB)')
            store.db.execute('INSERT INTO future_records VALUES (?, ?)', ('retained', b'future\x00data'))
            self.original = store.work_create('virtual:operator', 'falcon', 'role:falcon/worker',
                'Existing work', body='Preserve the original row', task_key='AMUX-662')
            channel['initialSource'] = {'kind': 'work', 'id': self.original['id']}
        finally:
            store.db.close()
        self.value['storage']['work'] = work
        self.selection = self.selected()
        current = strict_loads(self.snapshot.record)
        next(item for item in current['state']['transports'] if item['ref'] == ref('transport'))['issuerRef'] = (
            self.value['identity']['issuer']['issuerRef'])
        current['state']['memberships'].append({'ref': ref('work-member'), 'identityRef': ref('human'),
            'scope': copy.deepcopy(self.scope), 'status': 'active'})
        self.snapshot = AuthoritySnapshot(canonical_bytes(current), self.snapshot.sequence)

    async def start_host(self, current=None):
        snapshot = self.snapshot if current is None else AuthoritySnapshot(
            canonical_bytes(current), self.snapshot.sequence)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()

    async def replace_host(self):
        await self.host.close(timeout=None)
        self.selection = self.selected()
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)

    def work_resource(self):
        return next(resource for resource in self.host._resources if type(resource) is WorkStorageResource)

    def reopen(self):
        pin = self.value['storage']['work']['source']['database']
        return Store.open_existing(pin['path'], application_id=pin['applicationId'],
            user_version=pin['userVersion'], owner_uid=os.getuid())

    async def test_local_source_preserves_raw_row_and_uses_original_checked_executor(self):
        with patch.object(Store, '_migrate', side_effect=AssertionError('selected work must not migrate')):
            await self.start_host()
        resource = self.work_resource()
        domain = resource._owner
        source = self.host._message_stores[0]
        self.assertIs(type(source), WorkStoreHost)
        self.assertIs(type(domain), SelectedWorkDomain)
        self.assertIs(domain, self.host._work_domains[0])
        self.assertIs(resource._store, source._store)
        self.assertIs(domain._executor, source._executor)
        self.assertIsNone(source._policy)
        self.assertIsNone(domain.session)
        self.assertIsNone(resource.repository_id)
        self.assertEqual(self.host._message_sessions, [])
        thread = await source.db(threading.get_ident)
        self.assertNotEqual(thread, threading.get_ident())
        self.assertEqual(await domain.db(threading.get_ident), thread)
        self.assertEqual(source._store._identity_source_hub, 'hub-one')
        self.assertEqual(strict_loads(await resource.read(1)), self.original)
        self.assertNotIn('children', self.original)
        state = await domain.db(resource._journal.current)
        self.assertEqual(state['binding']['repository'], 'falcon')
        self.assertIsNone(state['binding']['repositoryId'])
        self.assertEqual(state['source'], {'kind': 'work', 'id': self.original['id']})
        self.assertTrue(all(service._receiver._resources['work-one'] is resource for service in self.host._receivers))
        await self.host.close(timeout=None)
        self.assertTrue(domain._closed)
        self.assertIsNone(source._store)
        self.assertTrue(source._closing.done())
        self.assertFalse(self.identity._closed)
        reopened = self.reopen()
        try:
            self.assertEqual(reopened.q1('SELECT * FROM work_items'), self.original)
            self.assertEqual(reopened.q('SELECT * FROM future_records'),
                [{'id': 'retained', 'value': b'future\x00data'}])
        finally:
            reopened.db.close()

    async def test_exact_shared_source_is_borrowed_with_message_and_code_owners(self):
        code = copy.deepcopy(self.shared)
        message = copy.deepcopy(code)
        message['channels'][0].update(peer='alice', resourceRef=ref('messages-one'))
        work = self.value['storage']['work']
        work.update(source=copy.deepcopy(code['source']), repository=copy.deepcopy(code['repository']), localPeer='nick')
        self.value['storage'].update(code=code, messages=message)
        await self.replace_host()
        await self.start_host()
        resource = self.work_resource()
        self.assertEqual(len(self.host._message_stores), 1)
        source = self.host._message_stores[0]
        resources = [item for item in self.host._resources if item.binding.entity_id in
            ('work-one', 'messages-one', 'code-one')]
        self.assertEqual(len(resources), 3)
        self.assertTrue(all(item._store is source._store for item in resources))
        self.assertIs(resource._owner._source, source)
        self.assertIsNotNone(resource._owner.session)
        self.assertEqual(resource.repository_id, code['repository']['repositoryId'])
        self.assertEqual(strict_loads(await resource.read(1)), self.original)
        await self.host.close(timeout=None)
        self.assertTrue(resource._owner._closed)
        self.assertIsNone(source._store)

    def test_incompatible_shared_source_cannot_alias_local_database(self):
        self.value['storage']['code'] = copy.deepcopy(self.shared)
        with self.assertRaises(ContractError):
            self.selected()

    async def test_missing_database_is_not_created_and_partial_start_joins(self):
        self.database.unlink()
        with self.assertRaises(ContractError):
            await self.start_host()
        self.assertFalse(self.host._ready)
        await self.host.close(timeout=None)
        self.assertFalse(self.database.exists())
        self.assertTrue(all(source._store is None for source in self.host._message_stores))

    async def test_missing_terminal_trigger_refuses_without_repair_or_data_loss(self):
        store = Store(str(self.database))
        try:
            store.db.execute('DROP TRIGGER fed_work_terminal')
        finally:
            store.db.close()
        with patch.object(Store, '_migrate', side_effect=AssertionError('must not repair the selected schema')):
            with self.assertRaises(ContractError):
                await self.start_host()
        self.assertFalse(self.host._ready)
        await self.host.close(timeout=None)
        store = self.reopen()
        try:
            self.assertIsNone(store.q1("SELECT name FROM sqlite_schema WHERE name='fed_work_terminal'"))
            self.assertEqual(store.q1('SELECT * FROM work_items'), self.original)
        finally:
            store.db.close()

    async def test_database_replacement_fences_selected_work_before_read(self):
        await self.start_host()
        resource = self.work_resource()
        replacement = self.database.with_suffix('.replacement')
        store = Store(str(replacement))
        store.db.close()
        replacement.chmod(0o600)
        retained = self.database.with_suffix('.retained')
        self.database.rename(retained)
        replacement.rename(self.database)
        with self.assertRaises(ContractError):
            await resource.read(1)
        self.assertIsNotNone(self.host._message_stores[0]._store)
        await self.host.close(timeout=None)
        self.assertTrue(retained.exists())

    async def test_current_identity_scope_and_source_substitution_refuse(self):
        await self.start_host()
        resource = self.work_resource()
        domain = resource._owner
        for target, attribute, changed in ((self.identity.reader, '_profile', 'other-profile'),
                (domain, '_scope', canonical_bytes({**self.scope, 'projectId': 'other-project'})),
                (domain._source, '_executor', object())):
            with self.subTest(attribute=attribute), patch.object(target, attribute, changed):
                with self.assertRaises(ContractError):
                    await resource.read(1)
        self.assertEqual(strict_loads(await resource.read(1)), self.original)

    async def test_revoked_work_transport_refuses_before_opening_selected_source(self):
        current = strict_loads(self.snapshot.record)
        next(item for item in current['state']['transports'] if item['ref'] == ref('transport'))['status'] = 'revoked'
        with self.assertRaises(ContractError):
            await self.start_host(current)
        self.assertFalse(self.host._ready)
        self.assertEqual(self.host._message_stores, [])
        self.assertEqual(self.host._receivers, [])
        await self.host.close(timeout=None)
        store = self.reopen()
        try:
            self.assertEqual(store.q1('SELECT * FROM work_items'), self.original)
        finally:
            store.db.close()

    async def test_cancelled_start_keeps_original_database_worker_until_close_joins(self):
        entered, release = threading.Event(), threading.Event()
        original = WorkStoreHost.check_work_tables
        def held(store):
            entered.set()
            if not release.wait(5):
                raise AssertionError('test did not release original work startup')
            return original(store)
        with patch.object(WorkStoreHost, 'check_work_tables', side_effect=held), \
                patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            starting = asyncio.create_task(self.host.start())
            closing = None
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                source = self.host._message_stores[0]
                starting.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await starting
                closing = asyncio.create_task(self.host.close(timeout=None))
                await asyncio.sleep(0.02)
                self.assertFalse(closing.done())
                self.assertTrue(source._pending)
            finally:
                release.set()
                await asyncio.gather(starting, return_exceptions=True)
                if closing is not None:
                    await closing
            self.assertIsNone(source._store)
            self.assertTrue(source._closing.done())

    async def test_cleanup_joins_original_work_domain_before_releasing_source(self):
        await self.start_host()
        resource = self.work_resource()
        domain, source = resource._owner, self.host._message_stores[0]
        entered, release = threading.Event(), threading.Event()
        def transaction():
            with source._store.tx():
                source._store.event('work', self.original['id'], 'begin', 'operator')
                entered.set()
                if not release.wait(5):
                    raise AssertionError('test did not release original work transaction')
                source._store.event('work', self.original['id'], 'end', 'operator')
        working = asyncio.create_task(domain.db(transaction))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            working.cancel()
            await asyncio.sleep(0)
            working.cancel()
            with self.assertRaises(SelectedStorageFailure):
                await self.host.close(timeout=0.01)
            closing = self.host._closing
            self.assertFalse(closing.done())
            self.assertTrue(domain._pending)
            self.assertIsNotNone(source._store)
            self.assertIsNone(source._closing)
        finally:
            release.set()
            await asyncio.gather(working, return_exceptions=True)
            await self.host.close(timeout=None)
        self.assertIs(self.host._closing, closing)
        self.assertTrue(domain._closed)
        self.assertFalse(domain._pending)
        self.assertIsNone(source._store)
        reopened = self.reopen()
        try:
            self.assertEqual([row['event'] for row in reopened.q(
                "SELECT event FROM events WHERE event IN ('begin', 'end') ORDER BY seq")], ['begin', 'end'])
            self.assertEqual(reopened.q1('SELECT * FROM work_items'), self.original)
        finally:
            reopened.db.close()


class SelectedWorkPolicyBootstrapTests(unittest.IsolatedAsyncioTestCase):
    from . import test_federation_policy_transition as _support
    asyncSetUp = _support.FederationPolicyTransitionTests.asyncSetUp
    make_owner = _support.FederationPolicyTransitionTests.make_owner
    request = _support.FederationPolicyTransitionTests.request
    selected_storage_host = _support.FederationPolicyTransitionTests.selected_storage_host
    final = _support.FederationPolicyTransitionTests.final
    project_request = _support.FederationPolicyTransitionTests.project_request

    def declare_work(self, selected, message):
        from identity.application_service_selection import ApplicationServiceSelection
        value = selected._selection.policy
        descriptor = copy.deepcopy(message)
        descriptor['source'] = copy.deepcopy(self.source._pins)
        descriptor['repository'] = {key: value for key, value in self.source._repository.items()
            if key != 'counterPrefix'}
        channel = descriptor['channels'][0]
        channel.pop('peer')
        channel['resourceRef'] = ref('work-one')
        value['storage']['work'] = descriptor
        selected._selection = ApplicationServiceSelection(canonical_bytes(value))
        selected._preconstructed_sources['work'] = self.source
        return descriptor

    async def run_work_startup(self, operation):
        selected, second, message = await self.selected_storage_host()
        descriptor = self.declare_work(selected, message)
        selected._preconstructed_sources.update(board=self.source, messages=second, work=self.source)
        raw, desired = await self.final({'verb': 'unshare', 'arguments': {'repo': 'falcon'}})
        await self.transition.apply(raw)
        project = await self.project_request(raw, desired)
        async def startup():
            await self.transition.project(project)
            await operation(selected, self.source, descriptor)
        task = asyncio.create_task(startup())
        selected._starting = task
        await task

    async def work_resource(self, selected, source, descriptor, *, selected_projection=False):
        from hub.fed.session import FederationSession
        from state_owner.ledger import OwnerBinding
        from .messages import MessageActor
        permit = await source._resource_bootstrap(self.transition, 'work')
        self.addAsyncCleanup(permit.close)
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        scope = selected._selection.policy['storage']['scope']
        channel = descriptor['channels'][0]
        projection = (dict(selection=selected._selection, channel_ref=channel['resourceRef'], _bootstrap=permit)
            if selected_projection else {})
        domain = SelectedWorkDomain(source, session, identity=selected._identity, scope=scope,
            local_node=descriptor['localNode'], **projection)
        self.addAsyncCleanup(domain.close)
        binding = OwnerBinding('hub-one', 'federation-work', channel['resourceRef']['id'],
            'work-channel', canonical_bytes(scope))
        args = dict(repository=descriptor['repository']['localName'],
            actors=tuple(MessageActor(canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']),
                actor['caller']) for actor in channel['actors']), plugin_identity_ref=channel['pluginIdentityRef'],
            instance_id=channel['instanceId'], initial_source=channel['initialSource'])
        await permit.submit(WorkStoreHost.check_work_tables, source._store)
        resource = WorkStorageResource(binding, domain, **args, _bootstrap=permit)
        return resource, permit, binding, domain, args

    async def test_unshare_structural_permission_cannot_authorize_live_work_or_substitution(self):
        async def check(selected, source, descriptor):
            resource, permit, binding, domain, args = await self.work_resource(selected, source, descriptor)
            await permit.validate(resource, 1)
            with self.assertRaises(ContractError):
                await resource.read(1)
            with self.assertRaises(ContractError):
                WorkStorageResource(binding, domain, **dict(args, instance_id='substituted'), _bootstrap=permit)
            with self.assertRaises(ContractError):
                await asyncio.create_task(permit.validate(resource, 1))
            permit.expire()
            with self.assertRaises(ContractError):
                permit.check(resource)
        await self.run_work_startup(check)

    async def test_selected_projection_requires_live_exact_structural_permission(self):
        async def check(selected, source, descriptor):
            resource, permit, _, domain, _ = await self.work_resource(selected, source, descriptor,
                selected_projection=True)
            await permit.validate(resource, 1)
            with self.assertRaises(ContractError):
                await resource.read(1)
            permit.expire()
            with self.assertRaises(ContractError):
                domain._current()
            with self.assertRaises(ContractError):
                await permit.validate(resource, 1)
        await self.run_work_startup(check)

    async def test_work_terminal_schema_is_checked_inside_original_startup_permission(self):
        async def check(selected, source, descriptor):
            resource, permit, *_ = await self.work_resource(selected, source, descriptor)
            await permit.validate(resource, 1)
            await permit.submit(source._store.db.execute, 'DROP TRIGGER fed_work_terminal')
            with self.assertRaisesRegex(ContractError, '^selected_work_store_invalid$'):
                await permit.submit(WorkStoreHost.check_work_tables, source._store)
        await self.run_work_startup(check)

    async def test_controlled_policy_resume_keeps_original_work_source_and_rejects_replacement(self):
        selected, _, message = await self.selected_storage_host()
        descriptor = self.declare_work(selected, message)
        await selected._work(descriptor)
        resource = next(item for item in selected._resources if type(item) is WorkStorageResource)
        domain = resource._owner
        original_store = self.source._store
        original_thread = await domain.db(threading.get_ident)
        raw, desired = await self.final()
        await self.transition.apply(raw)
        self.assertEqual(self.path.read_bytes(), desired)
        self.assertEqual(self.source._policy.trust('alice'), 'flag')
        self.assertIs(domain._policy, self.source._policy)
        self.assertEqual(domain._policy_generation, self.source._policy_generation)
        self.assertIs(resource._store, original_store)
        self.assertEqual(await domain.db(threading.get_ident), original_thread)
        self.assertEqual(await resource.read(1), canonical_bytes({'formatVersion': 1, 'source': None}))
        with patch.object(self.source, '_policy', copy.deepcopy(self.source._policy)):
            with self.assertRaises(ContractError):
                await resource.read(1)
        with self.assertRaises(ContractError):
            domain._resume_policy(object())
        with patch.object(self.source, '_policy_generation', domain._policy_generation - 1):
            with self.assertRaises(ContractError):
                domain._resume_policy(self.transition)

