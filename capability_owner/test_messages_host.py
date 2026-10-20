"""Selected message source custody and actual storage-host construction."""
import copy
import hashlib
import os
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.session import FederationSession
from hub.fed.message_services import LocalMessages, FederationPublisher
from hub.store import APP_ID, MIGRATIONS, Store
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref, SEED
from .messages import MessageStorageResource, MessageActor
from .messages_host import MessageStoreHost, SelectedMessageDomain
from .reply_service import CapabilityReplyService
from .selected_storage import SelectedStorageHost
from .test_messages import MessageFixture
from . import test_selected_storage as storage_support


def selected_messages(root, *, scope, repository=True):
    root = Path(root).resolve()
    database, policy = root / 'messages.db', root / 'messages.toml'
    store = Store(str(database))
    store.repo_add('falcon')
    store.db.close()
    database.chmod(0o600)
    raw = b'[federation]\npeer="nick"\n[repos.falcon]\nremote="example.invalid/falcon"\n[peers.alice]\ntrust="auto"\n'
    policy.write_bytes(raw)
    policy.chmod(0o600)
    from hub.fed.policy import rid_for_remote
    return {'source': {'database': {'path': str(database), 'applicationId': APP_ID, 'userVersion': len(MIGRATIONS)},
        'policy': {'path': str(policy), 'sha256': 'sha256:' + hashlib.sha256(raw).hexdigest()}},
        'repository': {'localName': 'falcon', 'repositoryId': rid_for_remote('example.invalid/falcon'),
            'normalizedRemote': 'example.invalid/falcon'} if repository else None,
        'localPeer': 'nick', 'localNode': 'mac',
        'channels': [{'resourceRef': ref('messages-one'), 'peer': 'alice',
            'actors': [{'identityRef': ref('human'), 'transportRef': ref('transport'), 'caller': 'operator'}],
            'pluginIdentityRef': ref('plugin-one'), 'instanceId': 'instance-one', 'initialSource': None}]}


class SelectedMessageSourceFixture(MessageFixture):
    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        self.pin = selected_messages(self.directory.name, scope=self.scope,
            repository=getattr(self, 'message_repository', 'falcon') is not None)
        self.source = MessageStoreHost(self.pin['source'], repository=self.pin['repository'],
            local_peer='nick', owner_uid=os.getuid())
        self.addAsyncCleanup(self.source.close)
        await self.source.start()
        self.session = FederationSession()
        self.addAsyncCleanup(self.session.close)
        self.owner = SelectedMessageDomain(self.source, self.session, identity=self.service, scope=self.scope, local_node='mac')
        await self.source.db(self.source._store.configure_identity_fencing, 'hub-one')
        self.resource = self.open_resource()
        self.reply_service = CapabilityReplyService(self.service.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection)
        self.addAsyncCleanup(self.reply_service.close)

    async def test_selected_store_uses_original_transaction_on_owned_executor(self):
        import threading
        loop_thread = threading.get_ident()
        db_thread = await self.source.db(threading.get_ident)
        self.assertNotEqual(loop_thread, db_thread)
        self.assertEqual(await self.resource.read(1), canonical_bytes({'formatVersion': 1, 'source': None}))
        receipt = await self.dispatch((await self.prepare())[0])
        row = await self.source.db(self.source._store.q1, 'SELECT * FROM messages')
        self.assertEqual(strict_loads(await self.resource.read(receipt['resourceRef']['revision'])), row)
        self.assertEqual(len(await self.source.db(self.source._store.q, 'SELECT * FROM deliveries')), 1)
        self.assertEqual(await self.source.db(threading.get_ident), db_thread)

    async def test_policy_replacement_fences_selected_source(self):
        path = Path(self.pin['source']['policy']['path'])
        path.write_text(path.read_text() + '\n# replaced\n')
        with self.assertRaises(ContractError):
            await self.resource.read(1)
        self.assertTrue(self.source._closed)

    async def test_selected_source_refuses_migration_fence(self):
        raw, _ = await self.prepare()
        await self.source.db(self.source._store.fence_legacy_writer)
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(await self.source.db(self.source._store.q, 'SELECT * FROM messages'), [])


class SelectedMessageSourceTests(SelectedMessageSourceFixture, unittest.IsolatedAsyncioTestCase):
    async def test_missing_role_preserves_operator_fallback_on_both_primary_settings(self):
        for primary in (True, False):
            self.source._policy.cfg['federation']['primary'] = primary
            value = self.value()
            value['envelope']['data']['target'] = {'rid': self.resource.repository_id, 'role': 'worker'}
            revision = (await self.source.db(self.resource._journal.current))['revision']
            reply = await self.dispatch((await self.prepare(value, operation='missing-' + str(primary).lower(),
                revision=revision))[0])
            self.assertEqual(reply['outcome'], 'applied')
            row = await self.source.db(self.source._store.q1, 'SELECT * FROM messages WHERE idem_key=?',
                ('fed:' + value['envelope']['id'],))
            self.assertEqual(row['target'], 'virtual:operator')
            self.assertIn('(for role:falcon/worker: no live agent satisfies role:falcon/worker)', row['body'])
            self.assertIn('[federated from peer alice]', row['body'])
            delivery = await self.source.db(self.source._store.q1, 'SELECT * FROM deliveries WHERE message_id=?',
                (row['id'],))
            self.assertEqual(delivery['recipient'], 'virtual:operator')

    async def test_live_role_without_enrolled_identity_cannot_fall_back(self):
        session = await self.source.db(self.source._store.register, 'falcon', 'worker', 'one', 'codex', {})
        await self.source.db(self.source._store.set_state, session, 'ready')
        value = self.value()
        value['envelope']['data']['target'] = {'rid': self.resource.repository_id, 'role': 'worker'}
        with self.assertRaises(ContractError):
            await self.dispatch((await self.prepare(value))[0])
        self.assertEqual(await self.source.db(self.source._store.q, 'SELECT * FROM messages'), [])
        self.assertEqual(await self.source.db(self.source._store.q, 'SELECT * FROM fed_state'), [])


class SelectedMessageCompositionTests(unittest.IsolatedAsyncioTestCase):
    connection = storage_support.SelectedStorageCompositionTests.connection
    custody = storage_support.SelectedStorageCompositionTests.custody
    selected = storage_support.SelectedStorageCompositionTests.selected
    add_board = storage_support.SelectedStorageCompositionTests.add_board
    identity_inputs = storage_support.SelectedStorageCompositionTests.identity_inputs
    authority_record = storage_support.SelectedStorageCompositionTests.authority_record

    def setUp(self):
        storage_support.SelectedStorageCompositionTests.setUp(self)
        self.value['storage']['messages'] = selected_messages(self.root, scope=self.scope)
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

    async def test_production_storage_host_builds_selected_message_channel(self):
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()
            self.host.check_health()
            messages = next(r for r in self.host._resources if isinstance(r, MessageStorageResource))
            self.assertEqual(messages.binding.entity_id, 'messages-one')
            self.assertEqual(await messages.read(1), canonical_bytes({'formatVersion': 1, 'source': None}))
            source = self.host._message_stores[0]
            self.assertIs(messages._store, source._store)
            await self.host.close(timeout=None)
            self.assertTrue(source._closing.done())
            self.assertIsNone(source._store)
        self.assertFalse(self.identity._closed)

    async def test_missing_selected_database_prevents_readiness(self):
        Path(self.value['storage']['messages']['source']['database']['path']).unlink()
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            with self.assertRaises(ContractError):
                await self.host.start()
            self.assertFalse(self.host._ready)
            await self.host.close(timeout=None)
        self.assertEqual(self.host._receivers, [])

    def legacy_actor(self):
        return {'identityRef': ref('human'), 'transportRef': ref('transport'), 'caller': 'operator',
            'grants': {'federation-message-' + c: ref('message-' + c)
                for c in ('send', 'approve', 'inspect', 'outcome')}}

    async def test_selected_legacy_bridge_requires_current_exact_grants(self):
        await self.host.close(timeout=None)
        actor = self.legacy_actor()
        self.value['storage']['messages']['channels'][0]['legacyActors'] = [actor]
        self.selection = self.selected()
        current = strict_loads(self.snapshot.record)
        state = current['state']
        next(t for t in state['transports'] if t['ref'] == ref('transport'))['issuerRef'] = (
            self.value['identity']['issuer']['issuerRef'])
        state['memberships'].append({'ref': ref('message-member'), 'identityRef': ref('human'),
            'scope': copy.deepcopy(self.scope), 'status': 'active'})
        for contract, reference in actor['grants'].items():
            state['grants'].append({'ref': reference, 'callerRef': ref('human'), 'actorRef': ref('human'),
                'scope': copy.deepcopy(self.scope), 'contractId': contract, 'resourceId': 'messages-one',
                'decision': 'allowed', 'delegationRef': None, 'definitionTarget': None,
                'status': 'active', 'issuedAt': self.issuer_start, 'expiresAt': self.issuer_end})
        async def check(record):
            with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                    canonical_bytes(record), self.snapshot.sequence))):
                await self.selection.check_storage_authority(self.identity)
        await check(current)
        for mutate in (lambda s:s['grants'][-1].update(status='revoked'),
                lambda s:s['grants'][-1].update(resourceId='other'),
                lambda s:s['grants'][-1].update(actorRef=ref('plugin-one')),
                lambda s:s['grants'].append(dict(s['grants'][-1], ref=ref('deny-message'), decision='denied')),
                lambda s:s['memberships'][-1].update(status='revoked')):
            changed = copy.deepcopy(current)
            mutate(changed['state'])
            with self.assertRaises(ContractError):
                await check(changed)
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)
        self.clients[1].max_payload = 1048576
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=AuthoritySnapshot(
                canonical_bytes(current), self.snapshot.sequence))), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients):
            await self.host.start()
            bridge = self.host._receivers[0]._message_bridge
            self.assertIsNotNone(bridge)
            self.assertIsNone(self.host._receivers[1]._message_bridge)
            self.assertEqual(len(bridge._resources), 1)
            await self.host.close(timeout=None)
            self.assertTrue(bridge._closed)

    async def test_legacy_selection_rejects_foreign_grants_or_wrong_caller_purpose(self):
        original = copy.deepcopy(self.value)
        for mutate in (lambda a:a['grants']['federation-message-send'].update(ownerHubId='foreign'),
                lambda a:a.update(caller='federation'),
                lambda a:a.update(caller='falcon-worker-one'),
                lambda a:a['grants'].update({'federation-message-deliver': ref('deliver')})):
            self.value = copy.deepcopy(original)
            actor = self.legacy_actor()
            mutate(actor)
            self.value['storage']['messages']['channels'][0]['legacyActors'] = [actor]
            with self.assertRaises(ContractError):
                self.selected()

    async def test_message_only_selection_starts_without_private_storage(self):
        await self.host.close(timeout=None)
        self.value['storage'].pop('privateStorage')
        self.selection = self.selected()
        self.host = SelectedStorageHost(self.selection, identity=self.identity)
        self.addAsyncCleanup(self.host.close, timeout=None)
        with patch.object(self.identity.reader, 'current', AsyncMock(return_value=self.snapshot)), \
                patch('capability_owner.selected_storage.new_client', side_effect=self.clients[1:]):
            await self.host.start()
            self.assertEqual(len(self.host._resources), 1)
            self.assertIsInstance(self.host._resources[0], MessageStorageResource)
            self.assertEqual(len(self.host._receivers), 2)
            self.assertEqual(self.host._custody, [])
            await self.host.close(timeout=None)
        self.assertFalse(self.identity._closed)

    async def shared_source(self, *, remove_messages=False):
        from .selected_storage import BoardAuditMirrorHost
        from hub.fed.plugins.board import Board
        pin = self.value['storage']['messages']
        store = Store(pin['source']['database']['path'])
        try:
            for statement in Board.tables:
                store.db.execute(statement)
            if remove_messages:
                store.db.execute('DROP TABLE messages')
        finally:
            store.db.close()
        policy = Path(pin['source']['policy']['path'])
        raw = policy.read_bytes().replace(b'remote="example.invalid/falcon"',
            b'remote="example.invalid/falcon"\nboard_prefix="SH"')
        policy.write_bytes(raw)
        pin['source']['policy']['sha256'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
        self.host._audit = BoardAuditMirrorHost(pin['source'],
            repository=dict(pin['repository'], counterPrefix='SH'), local_peer='nick', owner_uid=os.getuid())
        await self.host._audit.start()
        return pin

    async def test_messages_reuse_the_existing_board_store_and_executor(self):
        pin = await self.shared_source()
        await self.host._messages(pin)
        resource = next(r for r in self.host._resources if isinstance(r, MessageStorageResource))
        self.assertIs(resource._store, self.host._audit._store)
        self.assertEqual(self.host._message_stores, [])
        self.assertEqual(await resource.read(1), canonical_bytes({'formatVersion': 1, 'source': None}))
        await self.host.close(timeout=None)
        self.assertIsNone(self.host._audit._store)

    async def test_board_source_without_message_tables_cannot_become_message_owner(self):
        pin = await self.shared_source(remove_messages=True)
        with self.assertRaises(ContractError):
            await self.host._messages(pin)
        self.assertEqual(self.host._resources, [])

    async def test_message_selection_rejects_cross_scope_and_duplicate_resource(self):
        original = copy.deepcopy(self.value)
        for change in (lambda v:v['storage']['messages'].update(repository=None),
                lambda v:v['storage']['messages']['channels'][0]['resourceRef'].update(id='private-one'),
                lambda v:v['storage']['messages']['channels'][0]['actors'][0]['identityRef'].update(ownerHubId='other'),
                lambda v:v['storage']['messages']['channels'][0].update(extra=True)):
            value = copy.deepcopy(original)
            change(value)
            with self.assertRaises(ContractError):
                ApplicationServiceSelection(canonical_bytes(value))

    async def test_shared_database_requires_the_same_policy_repository_and_peer(self):
        self.add_board()
        messages, board = self.value['storage']['messages'], self.value['storage']['board']
        board['auditMirror'] = copy.deepcopy(messages['source'])
        board['repository'] = dict(messages['repository'], counterPrefix='SH')
        board['localPeer'] = messages['localPeer']
        self.selected()
        original = copy.deepcopy(self.value)
        for change in (lambda m:m['source']['policy'].update(sha256='sha256:'+'0'*64),
                lambda m:m.update(localPeer='other'),
                lambda m:m['repository'].update(localName='other'),
                lambda m:m['source']['database'].update(path=board['auditMirror']['policy']['path']),
                lambda m:m['source']['policy'].update(path=board['auditMirror']['database']['path'])):
            self.value = copy.deepcopy(original)
            change(self.value['storage']['messages'])
            with self.assertRaises(ContractError):
                self.selected()


class SelectedOperatorMessageSourceTests(SelectedMessageSourceFixture, unittest.IsolatedAsyncioTestCase):
    message_scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
    message_repository = None
