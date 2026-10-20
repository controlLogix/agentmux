"""Selected code composition preserves the original source and startup custody."""
import asyncio
import copy
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from .code import CodeStorageResource
from .selected_storage import SelectedStorageHost
from .test_code_selection import SelectedCodeFixture


class SelectedCodeCompositionTests(SelectedCodeFixture, unittest.IsolatedAsyncioTestCase):
    async def start_host(self, current=None):
        current = current or strict_loads(self.snapshot.record)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(current), self.snapshot.sequence))), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()

    async def test_constructs_code_from_exact_original_file_and_joins_shutdown(self):
        await self.start_host()
        resource = next(r for r in self.host._resources if type(r) is CodeStorageResource)
        source = self.host._message_stores[0]
        self.assertIs(resource._store, source._store)
        self.assertEqual(await resource.read(1), canonical_bytes({'formatVersion': 1, 'source': None}))
        await self.host.close(timeout=None)
        self.assertTrue(source._closing.done())
        self.assertIsNone(source._store)
        self.assertFalse(self.identity._closed)

    async def test_shares_one_original_executor_with_message_and_knowledge_domains(self):
        code = self.value['storage']['code']
        message = copy.deepcopy(code)
        message['channels'][0].update(peer='alice', resourceRef=ref('messages-one'))
        knowledge = copy.deepcopy(code)
        knowledge['channels'][0]['resourceRef'] = ref('knowledge-one')
        self.value['storage'].update(messages=message, knowledge=knowledge)
        self.selection = self.selected()
        await self.host.close(timeout=None)
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)
        await self.start_host()
        self.assertEqual(len(self.host._message_stores), 1)
        resources = [r for r in self.host._resources if r.binding.entity_id in ('messages-one','knowledge-one','code-one')]
        self.assertEqual(len(resources), 3)
        self.assertTrue(all(r._store is resources[0]._store for r in resources))

    async def test_missing_source_or_code_table_refuses_readiness(self):
        path = Path(self.value['storage']['code']['source']['database']['path'])
        path.unlink()
        with self.assertRaises(ContractError):
            await self.start_host()
        self.assertFalse(self.host._ready)
        await self.host.close(timeout=None)
        self.assertEqual(self.host._receivers, [])

    async def test_selected_legacy_code_bridge_uses_pinned_owner_and_closes(self):
        current = self.configure_legacy()
        await self.host.close(timeout=None)
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)
        self.clients[1].max_payload = 1048576
        await self.start_host(current)
        bridge = self.host._receivers[0]._code_bridge
        self.assertIsNotNone(bridge)
        resource = bridge._resources['code-one']
        self.assertIs(resource._store, self.host._message_stores[0]._store)
        self.assertEqual(strict_loads(resource._legacy_actors[0].grants), self.actor()['grants'])
        await self.host.close(timeout=None)
        self.assertTrue(bridge._closed)
        self.assertEqual(bridge._workers, set())

    async def test_cancelled_start_retains_original_executor_until_close_joins(self):
        import threading
        from .code_host import CodeStoreHost
        entered, release = threading.Event(), threading.Event()
        original = CodeStoreHost.check_code_tables
        def held(store):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('test did not release original code startup')
            return original(store)
        with patch.object(CodeStoreHost,'check_code_tables',side_effect=held), \
                patch.object(self.identity.reader,'current',AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client',side_effect=self.clients):
            starting = asyncio.create_task(self.host.start())
            closing = None
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait,2))
                source = self.host._message_stores[0]
                starting.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await starting
                closing = asyncio.create_task(self.host.close(timeout=None))
                await asyncio.sleep(.02)
                self.assertFalse(closing.done())
                self.assertIsNotNone(source._store)
            finally:
                release.set()
                if not starting.done():
                    await asyncio.gather(starting,return_exceptions=True)
                if closing is not None:
                    await closing
            self.assertIsNone(source._store)
            self.assertTrue(source._closing.done())

    async def test_replaced_policy_fences_normal_code_access(self):
        await self.start_host()
        resource = next(r for r in self.host._resources if type(r) is CodeStorageResource)
        path = Path(self.value['storage']['code']['source']['policy']['path'])
        path.write_text(path.read_text()+'\n# replaced\n')
        with self.assertRaises(ContractError):
            await resource.read(1)
        self.assertTrue(self.host._message_stores[0]._closed)


class SelectedCodePolicyBootstrapTests(unittest.IsolatedAsyncioTestCase):
    from . import test_federation_policy_transition as _support
    asyncSetUp = _support.FederationPolicyTransitionTests.asyncSetUp
    make_owner = _support.FederationPolicyTransitionTests.make_owner
    request = _support.FederationPolicyTransitionTests.request
    selected_storage_host = _support.FederationPolicyTransitionTests.selected_storage_host
    final = _support.FederationPolicyTransitionTests.final
    project_request = _support.FederationPolicyTransitionTests.project_request

    async def run_code_startup(self, operation):
        from hub.fed.plugins.code import Code
        from identity.application_service_selection import ApplicationServiceSelection
        selected, second, message = await self.selected_storage_host()
        for statement in Code.tables:
            await self.source.db(self.source._store.db.execute, statement)
        value = selected._selection.policy
        descriptor = copy.deepcopy(message)
        descriptor['source'] = copy.deepcopy(self.source._pins)
        descriptor['repository'] = {k:v for k,v in self.source._repository.items() if k != 'counterPrefix'}
        channel = descriptor['channels'][0]
        channel.pop('peer')
        channel['resourceRef'] = ref('code-one')
        value['storage']['code'] = descriptor
        selected._selection = ApplicationServiceSelection(canonical_bytes(value))
        selected._preconstructed_sources.update(board=self.source, messages=second, code=self.source)
        raw, desired = await self.final({'verb': 'unshare', 'arguments': {'repo': 'falcon'}})
        await self.transition.apply(raw)
        project = await self.project_request(raw, desired)
        async def startup():
            await self.transition.project(project)
            await operation(selected, self.source, descriptor)
        task = asyncio.create_task(startup())
        selected._starting = task
        await task

    async def code_resource(self, selected, source, descriptor):
        from hub.fed.session import FederationSession
        from state_owner.ledger import OwnerBinding
        from .code_host import SelectedCodeDomain, CodeStoreHost
        from .messages import MessageActor
        permit = await source._resource_bootstrap(self.transition, 'code')
        self.addAsyncCleanup(permit.close)
        session = FederationSession()
        self.addAsyncCleanup(session.close)
        scope = selected._selection.policy['storage']['scope']
        domain = SelectedCodeDomain(source, session, identity=selected._identity, scope=scope,
            local_node=descriptor['localNode'])
        channel = descriptor['channels'][0]
        binding = OwnerBinding('hub-one','federation-code',channel['resourceRef']['id'],
            'code-channel',canonical_bytes(scope))
        args = dict(repository=descriptor['repository']['localName'],
            actors=tuple(MessageActor(canonical_bytes(a['identityRef']),canonical_bytes(a['transportRef']),
                a['caller']) for a in channel['actors']), plugin_identity_ref=channel['pluginIdentityRef'],
            instance_id=channel['instanceId'],initial_source=channel['initialSource'])
        await permit.submit(CodeStoreHost.check_code_tables, source._store)
        with self.assertRaises(ContractError):
            CodeStorageResource(binding, domain, **args)
        resource = CodeStorageResource(binding, domain, **args, _bootstrap=permit)
        return resource, permit, binding, domain, args

    async def test_unshared_code_structural_permission_expires_and_does_not_allow_live_reads(self):
        async def check(selected, source, descriptor):
            resource, permit, binding, domain, args = await self.code_resource(selected,source,descriptor)
            await permit.validate(resource,1)
            with self.assertRaises(ContractError):
                await resource.read(1)
            with self.assertRaises(ContractError):
                CodeStorageResource(binding, domain, **dict(args,instance_id='substituted'), _bootstrap=permit)
            with self.assertRaises(ContractError):
                await asyncio.create_task(permit.validate(resource,1))
            permit.expire()
            with self.assertRaises(ContractError):
                permit.check(resource)
        await self.run_code_startup(check)

    async def test_original_code_table_is_checked_inside_structural_permission(self):
        from .code_host import CodeStoreHost
        async def check(selected, source, descriptor):
            resource, permit, *_ = await self.code_resource(selected,source,descriptor)
            await permit.validate(resource,1)
            await permit.submit(source._store.db.execute,'ALTER TABLE p_code_shares DROP COLUMN fetched')
            with self.assertRaisesRegex(ContractError,'^selected_code_store_invalid$'):
                await permit.submit(CodeStoreHost.check_code_tables,source._store)
        await self.run_code_startup(check)
