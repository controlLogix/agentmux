"""Retained code storage uses the original row, authority and outbox."""
import asyncio
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed import envelope, guard
from hub.fed.plugins.code import Code
from hub.tests.test_fed_unit import policy
from identity.test_authority import ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .code import CodeStorageResource
from .messages import MessageActor
from .reply_service import CapabilityReplyService
from .test_messages import MessageFixture
from .test_storage_contract import StorageWriteContract


class CodeFixture(MessageFixture):
    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        patch('capability_owner.federated_storage.datetime', _Clock).start()
        for statement in Code.tables:
            self.store.db.execute(statement)
        self.resource = self.open_code()
        self.reply_service = CapabilityReplyService(self.service.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection)
        self.addAsyncCleanup(self.reply_service.close)

    def open_code(self, **changes):
        args = dict(repository='falcon',
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')
        args.update(changes)
        return CodeStorageResource(OwnerBinding('hub-one', 'federation-code', 'task-one', 'code-channel',
            canonical_bytes(self.scope)), self.owner, **args)

    def value(self, body='Original code', command='publish'):
        peer = 'alice' if command == 'index' else 'nick'
        env = envelope.make('code', peer, 'remote' if command == 'index' else 'mac',
            self.owner.policy.rid_of('falcon'), '*', {'ref': 'refs/agentmux/' + peer + '/feature',
                'sha': 'a' * 40, 'base': 'b' * 40, 'files': ['one.py', 'two.py'], 'stat': '2 files',
                'log': 'commit summary', 'note': body, 'slug': 'feature', 'author': 'operator',
                'remote': None})
        return {'formatVersion': 1, 'command': command, 'envelope': env}


class CodeStorageTests(CodeFixture, StorageWriteContract, unittest.IsolatedAsyncioTestCase):
    async def test_original_row_outbox_audit_and_unknown_fields_remain(self):
        self.store.db.execute('ALTER TABLE p_code_shares ADD COLUMN future_field TEXT')
        value = self.value()
        receipt = await self.dispatch((await self.prepare(value))[0])
        row = self.store.q1('SELECT * FROM p_code_shares')
        self.assertEqual(row['id'], value['envelope']['id'])
        self.assertEqual((row['sha'], row['files'], row['note']), ('a' * 40, 'one.py\ntwo.py', 'Original code'))
        self.assertEqual(strict_loads(await self.resource.read(receipt['resourceRef']['revision'])), row)
        self.assertEqual(self.store.q1('SELECT * FROM fed_outbox')['msg_id'], row['id'])
        self.assertEqual(self.store.q1('SELECT * FROM fed_audit')['msg_id'], row['id'])
        self.store.db.execute('UPDATE p_code_shares SET future_field=?', ('retained',))
        reopened = self.open_code()
        self.assertEqual(strict_loads(await reopened.read(2))['future_field'], 'retained')

    async def test_receipt_failure_rolls_back_original_row_outbox_and_audit(self):
        raw, _ = await self.prepare()
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('private failure')):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        for table in ('p_code_shares', 'fed_outbox', 'fed_audit', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])
        self.assertEqual((await self.dispatch(raw))['outcome'], 'applied')

    async def test_conflict_and_restart_keep_exact_original_result(self):
        raw, inner = await self.prepare()
        first = await self.dispatch(raw)
        later, _ = await self.prepare(self.value('later'), operation='later', revision=2)
        await self.dispatch(later)
        stale, _ = await self.prepare(self.value('stale'), operation='stale')
        conflict = await self.dispatch(stale)
        self.assertEqual(conflict['outcome'], 'conflict')
        self.resource = self.open_code()
        op = strict_loads(inner)['operation']
        self.assertEqual(self.resource._journal.outcome(op['operationId'], op['payloadDigest'])['reply'], first)
        self.assertEqual(await self.dispatch(raw), first)
        self.assertEqual(await self.dispatch(stale), conflict)
        self.assertEqual(len(self.store.q('SELECT * FROM p_code_shares')), 2)

    async def test_collision_preserves_original_row_and_outbox(self):
        value = self.value()
        await self.dispatch((await self.prepare(value))[0])
        original = self.store.q1('SELECT * FROM p_code_shares')
        value['envelope']['data']['note'] = 'changed'
        with self.assertRaises(ContractError):
            await self.dispatch((await self.prepare(value, operation='collision', revision=2))[0])
        self.assertEqual(self.store.q1('SELECT * FROM p_code_shares'), original)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertEqual(self.resource._journal.current()['revision'], 2)

    async def test_wrong_author_namespace_sha_scope_and_unsupported_command_refuse(self):
        changes = [('author', 'forged'), ('ref', 'refs/heads/main'), ('sha', 'a' * 39)]
        for field, changed in changes:
            value = self.value()
            value['envelope']['data'][field] = changed
            with self.assertRaises(ContractError):
                await self.dispatch((await self.prepare(value, operation='wrong-' + field))[0])
        for value in ({'formatVersion': 1, 'command': 'delete', 'id': 'some-id'},
                {**self.value(), 'formatVersion': True}):
            with self.assertRaises(ContractError):
                await self.dispatch((await self.prepare(value, operation='unsupported-' + str(value['command'])))[0])
        value = self.value()
        value['envelope']['rid'] = 'r000000000000'
        with self.assertRaises(ContractError):
            await self.dispatch((await self.prepare(value, operation='foreign'))[0])
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'), [])

    async def test_current_sharing_and_stopped_session_fence_read_and_write(self):
        raw, _ = await self.prepare()
        self.owner.policy = policy(repos={})
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        with self.assertRaises(ContractError):
            await self.resource.read(1)
        self.owner.policy = policy()
        await self.owner.session.close()
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])

    async def test_received_data_keeps_peer_author_untrusted_and_has_no_outbox(self):
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        value = self.value(command='index')
        value['envelope']['data'].update(author='remote/author', base='legacy-base-reference',
            remote='legacy-informational-remote')
        receipt = await self.dispatch((await self.prepare(value))[0])
        row = strict_loads(await self.resource.read(receipt['resourceRef']['revision']))
        self.assertEqual((row['from_peer'], row['author'], row['untrusted']), ('alice', 'remote/author', 1))
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])
        self.assertEqual(row['base'], 'legacy-base-reference')
        self.owner.policy = policy(peers={'alice': {'trust': 'deny'}})
        with self.assertRaises(ContractError):
            await self.dispatch((await self.prepare(self.value(command='index'), operation='revoked', revision=2))[0])

    async def test_quarantine_cannot_be_silently_indexed(self):
        value = self.value(command='index')
        raw, _ = await self.prepare(value)
        decision = guard.Decision('quarantine', 'held', 'approve', True, 'falcon')
        with patch('capability_owner.code.guard.inbound', return_value=decision):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'), [])

    async def test_fetched_timestamp_replay_and_reconcile_do_not_repeat_effect(self):
        value = self.value(command='index')
        await self.dispatch((await self.prepare(value))[0])
        raw, inner = await self.prepare({'formatVersion': 1, 'command': 'fetched', 'id': value['envelope']['id']},
            operation='fetch', revision=2)
        with patch('capability_owner.code.now', return_value='2026-10-17T12:00:00Z'):
            first = await self.dispatch(raw)
        original = self.store.q1('SELECT * FROM p_code_shares')
        with patch('capability_owner.code.now', side_effect=AssertionError('repeated mutation')):
            self.assertEqual(await self.dispatch(raw), first)
        self.resource = self.open_code()
        operation = strict_loads(inner)['operation']
        retained = self.resource._journal.outcome(operation['operationId'], operation['payloadDigest'])
        self.assertEqual(retained['result'], {'id': original['id'], 'fetched': original['fetched']})
        self.assertEqual(original['fetched'], '2026-10-17T12:00:00Z')
        self.assertEqual((await self.contract_outcome(inner))['recordRef'], first['receiptRef'])

    async def test_existing_foreign_row_cannot_be_read_or_marked_fetched(self):
        value = self.value(command='index')
        self.resource._code._store(value['envelope'], 'other-repo', False)
        with self.assertRaises(ContractError):
            self.resource._read_source({'kind': 'code', 'id': value['envelope']['id']})
        with self.assertRaises(ContractError):
            await self.dispatch((await self.prepare({'formatVersion': 1, 'command': 'fetched',
                'id': value['envelope']['id']}))[0])
        self.assertIsNone(self.store.q1('SELECT * FROM p_code_shares')['fetched'])


    async def test_changed_original_operation_digest_refuses_without_new_row(self):
        value = self.value()
        await self.dispatch((await self.prepare(value))[0])
        before = self.store.q1('SELECT * FROM p_code_shares')
        with self.assertRaises(ContractError):
            await self.dispatch((await self.prepare(self.value('changed'), revision=2))[0])
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'), [before])
        self.assertEqual(self.resource._journal.current()['revision'], 2)

    async def test_exact_quarantine_approval_retains_original_untrusted_data(self):
        from hub.fed import ledger
        value = self.value(command='index')
        env = value['envelope']
        decision = guard.Decision('quarantine', 'held', 'approve', True, 'falcon')
        subject = envelope.subject('code', 'alice', self.resource.repository_id)
        qid = ledger.quarantine_add(self.store, env, subject, 'code', 'alice', 'held')
        self.store.db.execute("UPDATE fed_quarantine SET state='approved' WHERE id=?", (qid,))
        with patch('capability_owner.code.guard.inbound', return_value=decision):
            receipt = await self.dispatch((await self.prepare(value))[0])
        row = strict_loads(await self.resource.read(receipt['resourceRef']['revision']))
        self.assertEqual((row['id'], row['untrusted']), (env['id'], 1))
        changed = self.value(command='index')
        changed['envelope']['id'] = env['id']
        changed['envelope']['data']['note'] = 'changed after approval'
        with patch('capability_owner.code.guard.inbound', return_value=decision):
            with self.assertRaises(ContractError):
                await self.dispatch((await self.prepare(changed, operation='changed-approval', revision=2))[0])
        self.assertEqual(self.store.q1('SELECT * FROM p_code_shares'), row)

    async def test_current_transport_revocation_refuses_prepared_write(self):
        raw, _ = await self.prepare()
        self.claims.update(operationId='revoke-code-transport', contractId='identity-revoke',
            grantRef=ref('grant'), expectedVersion=2,
            payload={'authorityId': 'authority-one', 'targetRef': ref('host-transport')})
        result = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(result['claims']['receipt']['decision'], 'allowed')
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM p_code_shares'), [])

    async def test_cancelled_reply_keeps_original_owner_until_close_joins(self):
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
        release.set()
        await self.reply_service.close()
        self.assertEqual(len(self.store.q('SELECT * FROM p_code_shares')), 1)
        op = strict_loads(inner)['operation']
        self.assertEqual(self.resource._journal.outcome(op['operationId'], op['payloadDigest'])['reply']['outcome'], 'applied')
