"""Original knowledge transactions under real retained native authorization."""
import unittest
import base64
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed import envelope
from hub.fed.knowledge_services import KnowledgeOwner
from hub.fed.plugins.knowledge import Knowledge
from identity.test_authority import ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .knowledge import KnowledgeStorageResource
from .messages import MessageActor
from .reply_service import CapabilityReplyService
from .test_messages import MessageFixture
from .test_storage_contract import StorageWriteContract


class KnowledgeStorageTests(MessageFixture, StorageWriteContract, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        patch('capability_owner.federated_storage.datetime', _Clock).start()
        self.owner.fcfg['capture'] = True
        for statement in Knowledge.tables:
            self.store.db.execute(statement)
        self.resource = self.open_knowledge()
        self.reply_service = CapabilityReplyService(self.service.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection)
        self.addAsyncCleanup(self.reply_service.close)

    def open_knowledge(self, **changes):
        binding = OwnerBinding('hub-one', 'federation-knowledge', 'task-one', 'knowledge-channel',
            canonical_bytes(self.scope))
        args = dict(repository='falcon',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')
        args.update(changes)
        return KnowledgeStorageResource(binding, self.owner, **args)

    def value(self, body='Original knowledge', command='publish'):
        env = envelope.make('knowledge', 'nick', 'mac', self.owner.policy.rid_of('falcon'), '*',
            {'title': 'Finding', 'body': body, 'tags': ['kept', 'searchable'], 'ref': 'AMUX-45',
             'author': 'operator', 'source': 'explicit'})
        return {'formatVersion': 1, 'command': command, 'envelope': env}

    dispatch = MessageFixture.dispatch

    async def dispatch_owner(self, raw):
        # Receiving-route composition is checked separately. This boundary uses
        # the real signed native wrapper and retained authority, without a broker.
        request = strict_loads(raw)
        import base64
        inner = base64.b64decode(request['claims']['envelopeBytes'], validate=True)
        return await self.resource.write(self.service.reader, inner, raw)

    async def test_publish_preserves_original_id_full_row_fts_and_outbox(self):
        value = self.value()
        result = await self.dispatch((await self.prepare(value))[0])
        row = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertEqual(row['id'], value['envelope']['id'])
        self.assertEqual(row['body'], value['envelope']['data']['body'])
        self.assertEqual(strict_loads(await self.resource.read(result['resourceRef']['revision'])), row)
        self.assertEqual(len(self.store.q("SELECT * FROM p_knowledge_fts WHERE p_knowledge_fts MATCH 'Original'")), 1)
        self.assertEqual(self.store.q1('SELECT * FROM fed_outbox')['msg_id'], row['id'])
        self.assertEqual(self.store.q1('SELECT * FROM fed_audit')['msg_id'], row['id'])

    async def test_receipt_failure_rolls_back_index_fts_outbox_and_audit(self):
        raw, _ = await self.prepare()
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('private failure')):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        for table in ('p_knowledge_items', 'p_knowledge_fts', 'fed_outbox', 'fed_audit', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])
        self.assertEqual((await self.dispatch(raw))['outcome'], 'applied')

    async def test_cas_replay_and_restart_keep_original_outcome(self):
        raw, inner = await self.prepare()
        first = await self.dispatch(raw)
        self.assertEqual(await self.dispatch(raw), first)
        later, _ = await self.prepare(self.value('later'), operation='later', revision=2)
        await self.dispatch(later)
        stale, _ = await self.prepare(self.value('stale'), operation='stale')
        conflict = await self.dispatch(stale)
        self.assertEqual(conflict['outcome'], 'conflict')
        self.assertEqual(await self.dispatch(stale), conflict)
        self.resource = self.open_knowledge()
        op = strict_loads(inner)['operation']
        _, query = await self.prepare(operation='query', query={'contractId': 'capability-storage-write',
            'operationId': op['operationId'], 'payloadDigest': op['payloadDigest']})
        recovered = await self.resource.reconcile(query)
        self.assertEqual(recovered['recordRef'], first['receiptRef'])
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 2)

    async def test_prior_unknown_fields_and_id_collision_preserve_original(self):
        prior = await KnowledgeOwner(self.owner).share('operator', 'falcon', 'Prior', 'Kept')
        self.store.db.execute('ALTER TABLE p_knowledge_items ADD COLUMN future_field TEXT')
        self.store.db.execute('UPDATE p_knowledge_items SET future_field=?', ('retained',))
        original = self.store.q1('SELECT * FROM p_knowledge_items')
        resource = self.open_knowledge(initial_source={'kind': 'knowledge', 'id': prior['id']})
        self.assertEqual(strict_loads(await resource.read(1)), original)
        value = self.value('different')
        value['envelope']['id'] = prior['id']
        with self.assertRaises(ContractError):
            await self.dispatch((await self.prepare(value))[0])
        self.assertEqual(self.store.q1('SELECT * FROM p_knowledge_items'), original)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])

    async def test_wrong_author_route_source_and_stopped_owner_refuse(self):
        for field, changed in (('author', 'other'), ('source', 'invented')):
            value = self.value()
            value['envelope']['data'][field] = changed
            with self.assertRaises(ContractError):
                await self.dispatch((await self.prepare(value, operation='wrong-' + field))[0])
        raw, _ = await self.prepare()
        await self.owner.session.close()
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])

    async def test_received_original_data_is_untrusted_and_withdrawal_is_repo_scoped(self):
        from hub.tests.test_fed_unit import policy
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        value = self.value(command='index')
        value['envelope'].update({'from': 'alice', 'node': 'remote'})
        value['envelope']['data']['author'] = 'remote/author'
        raw, _ = await self.prepare(value)
        result = await self.dispatch(raw)
        row = strict_loads(await self.resource.read(result['resourceRef']['revision']))
        self.assertEqual((row['from_peer'], row['author'], row['untrusted']), ('alice', 'remote/author', 1))
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])
        other = {**value['envelope'], 'id': 'other-repo-row', 'rid': 'other-repository'}
        KnowledgeOwner(self.owner)._index(other, 'other', 'approve', True)
        self.owner.policy = policy(peers={'alice': {'trust': 'deny'}})
        withdrawal = {'formatVersion': 1, 'command': 'withdraw', 'peer': 'alice'}
        await self.dispatch((await self.prepare(withdrawal, operation='withdraw', revision=2))[0])
        self.assertIsNotNone(self.store.q1('SELECT withdrawn FROM p_knowledge_items WHERE id=?',
            (value['envelope']['id'],))['withdrawn'])
        self.assertIsNone(self.store.q1('SELECT withdrawn FROM p_knowledge_items WHERE id=?',
            ('other-repo-row',))['withdrawn'])

    async def test_received_foreign_repo_and_same_id_changed_body_refuse_atomically(self):
        value = self.value(command='index')
        value['envelope'].update({'from': 'alice', 'node': 'remote'})
        raw, _ = await self.prepare(value)
        await self.dispatch(raw)
        original = self.store.q1('SELECT * FROM p_knowledge_items')
        value['envelope']['data']['body'] = 'forged replacement'
        with self.assertRaises(ContractError):
            await self.dispatch((await self.prepare(value, operation='collision', revision=2))[0])
        self.assertEqual(self.store.q1('SELECT * FROM p_knowledge_items'), original)
        self.assertEqual(self.resource._journal.current()['revision'], 2)
        value['envelope']['rid'] = 'r000000000000'
        with self.assertRaises(ContractError):
            await self.dispatch((await self.prepare(value, operation='foreign', revision=2))[0])

    async def test_current_transport_revocation_refuses_previously_signed_write(self):
        raw, _ = await self.prepare()
        self.claims.update(operationId='revoke-knowledge-transport', contractId='identity-revoke',
            grantRef=ref('grant'), expectedVersion=2,
            payload={'authorityId': 'authority-one', 'targetRef': ref('host-transport')})
        result = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(result['claims']['receipt']['decision'], 'allowed')
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        for table in ('p_knowledge_items', 'fed_outbox', 'fed_audit', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])

    async def test_capture_setting_rechecks_inside_original_transaction(self):
        value = self.value()
        value['envelope']['data']['source'] = 'auto:result'
        raw, _ = await self.prepare(value)
        self.owner.fcfg['capture'] = False
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])
        self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])
        self.owner.fcfg['capture'] = True
        self.assertEqual((await self.dispatch(raw))['outcome'], 'applied')

    async def test_signed_read_keeps_full_original_row_and_inner_alone_cannot_bypass_admission(self):
        receipt = await self.dispatch((await self.prepare())[0])
        reference = receipt['resourceRef']
        self.claims.update(operationId='knowledge-read', contractId='capability-storage-read',
            grantRef=ref('capability'), expectedVersion=reference['revision'],
            payload={'resourceRef': reference, 'input': {}})
        admitted = await self.service.ingress.admit(self.request(), cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        self.inner = admitted.envelope
        inner = strict_loads(self.inner)
        self.wrapper.update(serviceId='storage-owner', requestContractId='capability-storage-read',
            replyContractId='capability-content-reply', operationId='knowledge-read',
            requestId=inner['correlationId'], resourceRef=reference,
            envelopeBytes=base64.b64encode(self.inner).decode())
        response = await self.dispatch(self.signed())
        self.assertEqual(strict_loads(base64.b64decode(response['data'])),
            self.store.q1('SELECT * FROM p_knowledge_items'))
        with self.assertRaises(ContractError):
            await self.reply_service._receiver.handle(self.inner)
