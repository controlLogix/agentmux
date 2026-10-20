"""Signed message storage calls keep the original SQLite transaction and data."""
import base64
import copy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed import envelope, ledger
from hub.fed.message_services import LocalMessages, FederationPublisher
from hub.fed.runtime import Federation
from hub.fed.session import FederationSession
from hub.store import Store
from hub.tests.test_fed_unit import policy
from identity.test_authority import ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .messages import MessageActor, MessageStorageResource
from .reply_service import CapabilityReplyService
from . import test_reply_service as support
from .test_storage_contract import StorageWriteContract


class MessageFixture:
    request = support.ReplyServiceTests.request
    enroll = support.ReplyServiceTests.enroll
    signed = support.ReplyServiceTests.signed
    call = support.ReplyServiceTests.call
    verify = support.ReplyServiceTests.verify

    def setUp(self):
        support.ReplyServiceTests.setUp(self)
        patch('capability_owner.messages.datetime', _Clock).start()
        patch('hub.fed.message_storage.datetime', _Clock).start()
        self.scope = copy.deepcopy(getattr(self, 'message_scope',
            {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}))
        facts = self.row['facts']
        facts['grant'].update(scope=copy.deepcopy(self.scope), actions=['read', 'write', 'inspect'])
        facts['policy']['scope'] = copy.deepcopy(self.scope)
        for action, resource, contract in (('write', 'storage', 'capability-storage-write'),
                ('inspect', 'outcome', 'capability-outcome-query')):
            facts['policy']['decisions'].append({'access': {'action': action, 'resourceClass': resource,
                'resourceId': 'task-one'}, 'outcome': 'allow'})
            facts['domainBindings'].append({'id': 'messages-' + action, 'contractId': contract,
                'action': action, 'resourceClass': resource, 'resourceIds': ['task-one']})
            grant = copy.deepcopy(next(g for g in self.record['state']['grants'] if g['ref'] == ref('capability')))
            grant.update(ref=ref('messages-' + action), contractId=contract)
            self.record['state']['grants'].append(grant)
        for grant in self.record['state']['grants']:
            if grant['contractId'].startswith(('native-authority-', 'capability-')):
                grant['scope'] = copy.deepcopy(self.scope)
        for identity in ('human', 'host'):
            member = copy.deepcopy(self.record['state']['memberships'][0])
            member.update(ref=ref('messages-' + identity), identityRef=ref(identity), scope=copy.deepcopy(self.scope))
            self.record['state']['memberships'].append(member)
        self.js.messages[0].data = canonical_bytes(self.record)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = Store(str(Path(self.directory.name) / 'hub.db'))
        self.addCleanup(self.store.db.close)
        async def db(function, *args, **kwargs):
            return function(*args, **kwargs)
        self.owner = SimpleNamespace(me='nick', node='mac', policy=policy(), presence={},
            fcfg={'primary': True}, store=self.store, db=db, session=FederationSession(), kick=lambda: None)
        for name in ('sender_of', 'resolve_repo', 'address_of', 'stage', 'publish'):
            setattr(self.owner, name, getattr(Federation, name).__get__(self.owner))

    async def asyncSetUp(self):
        await support.ReplyServiceTests.asyncSetUp(self)
        await self.reply_service.close()
        self.binding = OwnerBinding('hub-one', 'federation-messages', 'task-one', 'message-channel', canonical_bytes(self.scope))
        self.resource = self.open_resource()
        self.reply_service = CapabilityReplyService(self.service.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection)
        self.addAsyncCleanup(self.reply_service.close)

    def open_resource(self, **changes):
        args = dict(repository=getattr(self, 'message_repository', 'falcon'), peer='alice',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')
        args.update(changes)
        return MessageStorageResource(self.binding, LocalMessages(self.owner), FederationPublisher(self.owner), **args)

    def value(self, body='Original é', command='post'):
        outgoing = command == 'publish'
        env = envelope.make('message', 'nick' if outgoing else 'alice', 'mac' if outgoing else 'other',
            self.resource.repository_id, 'alice' if outgoing else 'nick',
            {'kind': 'note', 'body': body, 'ref': 'AMUX-45', 'sender': {'operator': True}, 'target': None})
        return {'formatVersion': 1, 'command': command, 'envelope': env}

    async def prepare(self, value=None, *, operation='message-one', revision=1, query=None):
        contract = 'capability-outcome-query' if query is not None else 'capability-storage-write'
        self.claims.update(operationId=operation, contractId=contract,
            grantRef=ref('messages-inspect' if query is not None else 'messages-write'), expectedVersion=revision,
            payload={'resourceRef': {**ref('task-one'), 'revision': revision},
                     'input': query if query is not None else {'value': value or self.value()}})
        admitted = await self.service.ingress.admit(self.request(), cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        self.inner = admitted.envelope
        inner = strict_loads(self.inner)
        self.wrapper.update(serviceId='outcome-owner' if query is not None else 'storage-owner',
            requestContractId=contract,
            replyContractId='capability-outcome-query-reply' if query is not None else 'capability-storage-write-reply',
            operationId=operation, requestId=inner['correlationId'], resourceRef=inner['payload']['resourceRef'],
            nativeFactsDigest=payload_digest(self.row['facts']), envelopeBytes=base64.b64encode(self.inner).decode())
        return self.signed(), self.inner

    async def dispatch(self, raw):
        return strict_loads(self.verify(await self.call(raw), raw))

    async def contract_prepare(self, body, revision=1):
        return await self.prepare(self.value(body), operation=body, revision=revision)

    contract_dispatch = dispatch

    async def contract_outcome(self, inner):
        operation = strict_loads(inner)['operation']
        raw, _ = await self.prepare(operation='recover-' + operation['operationId'], query={
            'operationId': operation['operationId'], 'payloadDigest': operation['payloadDigest'],
            'contractId': 'capability-storage-write'})
        endpoint = CapabilityReplyService(self.service.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='outcome-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection)
        try:
            response = await endpoint.handle(raw, received_reply_subject=self.wrapper['replySubject'])
            return strict_loads(self.verify(response, raw))
        finally:
            await endpoint.close()


class MessageStorageTests(MessageFixture, StorageWriteContract, unittest.IsolatedAsyncioTestCase):
    async def test_existing_message_route_does_not_require_the_uninstalled_work_module(self):
        original_import = __import__
        def installed_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'work' and level == 1:
                raise ModuleNotFoundError('work owner is not in this installed package')
            return original_import(name, globals, locals, fromlist, level)
        raw, _ = await self.prepare()
        with patch('builtins.__import__', side_effect=installed_import):
            result = await self.dispatch(raw)
        self.assertEqual(result['outcome'], 'applied')

    async def test_prepared_undispatched_write_reconciles_as_typed_storage_absence(self):
        from agentmux_contracts import validate
        _, inner = await self.prepare()
        operation = strict_loads(inner)['operation']
        outcome = await self.contract_outcome(inner)
        self.assertEqual(outcome, {'operationId': operation['operationId'],
            'payloadDigest': operation['payloadDigest'], 'contractId': 'capability-storage-write',
            'recordRef': None, 'resourceRef': None, 'outcome': 'absent'})
        validate('capability-outcome-query-reply', outcome)
        self.assertEqual(self.store.q('SELECT * FROM messages'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])

    async def test_post_preserves_message_identity_fields_fts_and_delivery(self):
        value = self.value()
        first = await self.dispatch((await self.prepare(value))[0])
        row = self.store.q1('SELECT * FROM messages')
        self.assertEqual(row['idem_key'], 'fed:' + value['envelope']['id'])
        self.assertEqual(row['sender'], 'peer:alice')
        self.assertEqual(self.store.q1('SELECT * FROM deliveries')['message_id'], row['id'])
        self.assertEqual(self.store.q1('SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?', ('Original',))['rowid'], 1)
        self.assertEqual(strict_loads(await self.resource.read(first['resourceRef']['revision'])), row)
        duplicate = await self.dispatch((await self.prepare(value, operation='other-operation', revision=2))[0])
        self.assertEqual(duplicate['resourceRef']['revision'], 3)
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertEqual(self.store.q1('SELECT * FROM messages')['id'], row['id'])

    async def test_publication_keeps_original_id_redaction_audit_and_outbox(self):
        value = self.value('token ghp_' + 'a' * 36, 'publish')
        receipt = await self.dispatch((await self.prepare(value))[0])
        row = self.store.q1('SELECT * FROM fed_outbox')
        self.assertEqual(row['msg_id'], value['envelope']['id'])
        self.assertEqual(row['subject'], 'am.msg.nick.alice')
        clean = strict_loads(row['payload'])
        self.assertNotIn('ghp_' + 'a' * 36, clean['data']['body'])
        self.assertEqual(self.store.q1('SELECT * FROM fed_audit')['msg_id'], row['msg_id'])
        self.assertEqual(strict_loads(await self.resource.read(receipt['resourceRef']['revision'])), row)

    async def test_receipt_failure_rolls_back_message_delivery_and_search_together(self):
        raw, _ = await self.prepare()
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('private receipt write failure')):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        for table in ('messages', 'deliveries', 'messages_fts', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])
        self.assertEqual((await self.dispatch(raw))['outcome'], 'applied')

    async def test_cas_conflict_is_retained_without_another_message(self):
        first = await self.dispatch((await self.prepare())[0])
        raw, inner = await self.prepare(operation='conflict')
        receipt = await self.dispatch(raw)
        self.assertEqual(receipt['outcome'], 'conflict')
        self.assertEqual(receipt['resourceRef'], first['resourceRef'])
        self.assertEqual(await self.dispatch(raw), receipt)
        self.assertEqual((await self.contract_outcome(inner))['outcome'], 'rejected')
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)

    async def test_changed_intent_and_foreign_route_refuse(self):
        await self.dispatch((await self.prepare())[0])
        raw, _ = await self.prepare(self.value('changed'))
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        for command in ('post', 'publish'):
            value = self.value(command=command)
            value['envelope']['from'] = 'eve'
            raw, _ = await self.prepare(value, operation='foreign-' + command, revision=2)
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])

    async def test_reopened_owner_recovers_original_after_later_publication(self):
        first_raw, first_inner = await self.prepare(self.value('first', 'publish'))
        first = await self.dispatch(first_raw)
        await self.dispatch((await self.prepare(self.value('later', 'publish'), operation='later', revision=2))[0])
        self.resource = self.open_resource()
        recovered = await self.contract_outcome(first_inner)
        self.assertEqual((recovered['recordRef'], recovered['resourceRef']),
            (first['receiptRef'], first['resourceRef']))
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_audit')), 2)

    async def test_publication_receipt_failure_rolls_back_outbox_and_audit(self):
        raw, _ = await self.prepare(self.value('one', 'publish'))
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('private receipt failure')):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        for table in ('fed_outbox', 'fed_audit', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])
        await self.dispatch(raw)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)

    async def test_existing_record_and_unknown_column_remain_readable(self):
        prior = self.store.post('virtual:operator', 'virtual:operator', 'note', 'Stored before handles',
            ref='existing-ref', idem_key='existing-id', meta={'unknown': {'nested': [None, 4]}})
        self.store.db.execute('ALTER TABLE messages ADD COLUMN future_field TEXT')
        self.store.db.execute('UPDATE messages SET future_field=? WHERE id=?', ('preserved', prior['id']))
        original = self.store.q1('SELECT * FROM messages WHERE id=?', (prior['id'],))
        resource = self.open_resource(initial_source={'kind': 'message', 'id': prior['id']})
        self.assertEqual(strict_loads(await resource.read(1)), original)
        await self.reply_service.close()
        self.resource = resource
        self.reply_service = CapabilityReplyService(self.service.reader, resources=[resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection)
        self.addAsyncCleanup(self.reply_service.close)
        await self.dispatch((await self.prepare())[0])
        self.assertEqual(self.store.q1('SELECT * FROM messages WHERE id=?', (prior['id'],)), original)
        with self.assertRaises(ContractError):
            await resource.read(1)

    async def test_current_sharing_refuses_post_and_publish_without_receipts(self):
        for command in ('post', 'publish'):
            raw, _ = await self.prepare(self.value(command=command), operation='withdraw-' + command)
            with patch.object(self.owner.policy, 'may_receive' if command == 'post' else 'may_send', return_value=False):
                with self.assertRaises(ContractError):
                    await self.dispatch(raw)
        for table in ('messages', 'fed_outbox', 'fed_audit', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])

    async def test_same_publication_id_cannot_hide_changed_contents(self):
        value = self.value('first', 'publish')
        await self.dispatch((await self.prepare(value))[0])
        value['envelope']['data']['body'] = 'changed'
        raw, _ = await self.prepare(value, operation='changed-publication', revision=2)
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_audit')), 1)
        self.assertEqual(self.resource._journal.current()['revision'], 2)

    async def test_stale_recipient_binding_refuses_without_operator_fallback(self):
        from identity.legacy_identity import LegacyIdentityBinding
        self.store.repo_add('falcon')
        session = self.store.register('falcon', 'worker', 'one', 'codex', {})
        self.store.set_state(session, 'ready')
        self.store.configure_identity_fencing('hub-one')
        proof = LegacyIdentityBinding('agent:' + session, session, 'hub-one', 1,
            canonical_bytes(ref('plugin')), canonical_bytes(self.scope), canonical_bytes(self.row['owner']),
            canonical_bytes(ref('recipient-alias')), 2, True)
        async def resolve(target):
            with self.store.tx():
                self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (session,))
            return target, (proof,)
        self.owner.hub = SimpleNamespace(_legacy_identity=object(), _current_identity_target=resolve)
        value = self.value()
        value['envelope']['data']['target'] = {'rid': self.resource.repository_id, 'role': 'worker', 'agent': 'one'}
        raw, _ = await self.prepare(value)
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM messages'), [])
        self.assertEqual(self.store.q('SELECT * FROM deliveries'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])

    async def test_changed_enrolled_source_cannot_reset_committed_version(self):
        await self.dispatch((await self.prepare())[0])
        changed = self.open_resource(initial_source={'kind': 'message', 'id': 'different'})
        with self.assertRaises(ContractError):
            await changed.read(1)
        self.assertEqual(self.resource._journal.current()['revision'], 2)

    async def test_fenced_legacy_store_refuses_effect_and_receipt(self):
        raw, _ = await self.prepare()
        self.store.fence_legacy_writer()
        before = self.store.q('SELECT * FROM fed_state')
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM messages'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), before)

    async def test_cancelled_reply_keeps_original_sql_worker_until_close_joins(self):
        import asyncio
        raw, inner = await self.prepare()
        started, release = asyncio.Event(), asyncio.Event()
        original = self.owner.db
        async def delayed(function, *args, **kwargs):
            if function == self.resource._journal.commit:
                started.set()
                await release.wait()
            return await original(function, *args, **kwargs)
        self.owner.db = delayed
        request = asyncio.create_task(self.call(raw))
        await asyncio.wait_for(started.wait(), 1)
        request.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await request
        with self.assertRaises(ContractError):
            await self.reply_service.close(timeout=.01)
        self.assertTrue(self.reply_service._receiver._workers)
        release.set()
        await self.reply_service.close()
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        operation = strict_loads(inner)['operation']
        retained = self.resource._journal.outcome(operation['operationId'], operation['payloadDigest'])
        self.assertEqual(retained['reply']['outcome'], 'applied')

    async def test_secondary_role_fallback_and_wrapping_match_existing_plugin(self):
        from hub.fed import guard
        from hub.fed.message_services import build_message_context
        from hub.fed.plugins.messages import Messages
        legacy = copy.copy(self.owner)
        legacy.store = Store(str(Path(self.directory.name) / 'reference.db'))
        self.addCleanup(legacy.store.db.close)
        for primary, target in ((False, {'rid': self.resource.repository_id, 'role': 'worker'}),
                (True, {'rid': self.resource.repository_id, 'role': 'worker', 'agent': 'gone'}), (True, None)):
            self.owner.fcfg['primary'] = primary
            value = self.value()
            value['envelope']['data']['target'] = target
            incoming = value['envelope']
            decision = guard.inbound(legacy.policy, 'am.msg.alice.nick', incoming)
            await Messages().on_envelope(build_message_context(legacy), incoming, decision)
            revision = self.resource._journal.current()['revision']
            await self.dispatch((await self.prepare(value, operation='compat-' + incoming['id'].lower(), revision=revision))[0])
            expected = legacy.store.q1('SELECT * FROM messages WHERE idem_key=?', ('fed:' + incoming['id'],))
            actual = self.store.q1('SELECT * FROM messages WHERE idem_key=?', ('fed:' + incoming['id'],))
            for field in ('body', 'sender', 'target', 'kind', 'ref', 'meta', 'idem_key', 'body_sha'):
                self.assertEqual(actual[field], expected[field], field)

    async def test_approved_trust_requires_original_retained_operator_approval(self):
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        value = self.value()
        raw, _ = await self.prepare(value)
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        with self.store.tx():
            quarantine = ledger.quarantine_add(self.store, value['envelope'], 'am.msg.alice.nick', 'msg',
                'alice', 'trust approve for alice')
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        ledger.quarantine_decide(self.store, quarantine, 'approved', 'operator')
        await self.dispatch(raw)
        self.assertIn('REMOTE DATA', self.store.q1('SELECT body FROM messages')['body'])
        changed = copy.deepcopy(value)
        changed['envelope']['data']['body'] = 'not the approved payload'
        altered, _ = await self.prepare(changed, operation='changed-approved', revision=2)
        with self.assertRaises(ContractError):
            await self.dispatch(altered)
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.owner.policy = policy(peers={'alice': {'trust': 'deny'}})
        with self.assertRaises(ContractError):
            await self.dispatch(raw)


class MessageOperatorStorageTests(MessageFixture, StorageWriteContract, unittest.IsolatedAsyncioTestCase):
    message_repository = None
    message_scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}

    async def test_operator_message_without_repository_preserves_inbox_and_id(self):
        value = self.value()
        self.assertIsNone(value['envelope']['rid'])
        receipt = await self.dispatch((await self.prepare(value))[0])
        row = self.store.q1('SELECT * FROM messages')
        self.assertEqual(row['target'], 'virtual:operator')
        self.assertEqual(row['idem_key'], 'fed:' + value['envelope']['id'])
        self.assertEqual(strict_loads(await self.resource.read(receipt['resourceRef']['revision'])), row)

    async def test_operator_publication_without_repository_keeps_outbox_route(self):
        value = self.value(command='publish')
        await self.dispatch((await self.prepare(value))[0])
        row = self.store.q1('SELECT * FROM fed_outbox')
        self.assertEqual(row['subject'], 'am.msg.nick.alice')
        self.assertEqual(strict_loads(row['payload']), value['envelope'])
        self.assertEqual(self.store.q1('SELECT * FROM fed_audit')['msg_id'], value['envelope']['id'])
