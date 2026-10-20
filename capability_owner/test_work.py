"""Real Store work parity, current authority and retained recovery."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed import envelope
from hub.fed.work_services import offer_digest, reference, result_digest
from hub.server import Hub
from hub.tests.test_hub_offline import reg
from identity.test_authority import ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .messages import MessageActor
from .reply_service import CapabilityReplyService
from .test_messages import MessageFixture
from .test_storage_contract import StorageWriteContract
from .work import LocalWorkDomain, WorkStorageResource


class WorkStorageTests(MessageFixture, StorageWriteContract, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        patch('capability_owner.federated_storage.datetime', _Clock).start()
        self.store.repo_add('falcon')
        self.store.repo_add('other')
        self.worker = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.worker.shutdown, wait=True)
        self.hub = Hub.__new__(Hub)
        self.hub.store, self.hub.dbx = self.store, self.worker
        self.hub.cfg, self.hub.stop = {'node': 'mac'}, asyncio.Event()
        self.local = LocalWorkDomain(self.hub)
        self.addAsyncCleanup(self.local.close)
        self.owner.hub = self.hub
        self.resource = self.open_work()
        self.reply_service = self.endpoint()
        self.addAsyncCleanup(self.reply_service.close)

    def endpoint(self):
        return CapabilityReplyService(self.service.reader, resources=[self.resource], hub_id='hub-one',
            profile_id='profile-one', authority_id='authority-one', service_id='storage-owner',
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection)

    def open_work(self, *, owner=None, **changes):
        binding = OwnerBinding('hub-one', 'federation-work', 'task-one', 'work-channel', canonical_bytes(self.scope))
        args = dict(repository='falcon', actors=(MessageActor(canonical_bytes(ref('human')),
            canonical_bytes(ref('transport')), 'operator'),), plugin_identity_ref=ref('plugin'), instance_id='plugin-one')
        args.update(changes)
        return WorkStorageResource(binding, owner or self.local, **args)

    def value(self, title='Original work', command='create', **fields):
        value = {'formatVersion': 1, 'command': command}
        if command in ('create', 'offer'):
            value.update(target='role:falcon/worker', title=title)
        value.update(fields)
        return value

    async def use(self, value, *, operation='work-one', revision=1):
        raw, inner = await self.prepare(value, operation=operation, revision=revision)
        return await self.dispatch(raw), inner

    async def replace_resource(self, resource):
        await self.reply_service.close()
        self.resource = resource
        self.reply_service = self.endpoint()
        self.addAsyncCleanup(self.reply_service.close)

    async def test_local_create_without_federation_keeps_raw_row_and_unknown_fields(self):
        self.assertIsNone(self.resource.repository_id)
        self.assertFalse(hasattr(self.local, 'policy'))
        self.store.db.execute('ALTER TABLE work_items ADD COLUMN future_field TEXT')
        reply, _ = await self.use(self.value('Local only', taskKey='AMUX-660', requirements={'capabilities': ['python']}))
        row = self.store.q1('SELECT * FROM work_items')
        self.assertEqual(row['created_by'], 'virtual:operator')
        self.assertEqual(row['title'], 'Local only')
        self.assertEqual(json.loads(row['requirements']), {'capabilities': ['python']})
        self.assertEqual(strict_loads(await self.resource.read(reply['resourceRef']['revision'])), row)
        self.assertNotIn('children', row)
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])
        self.assertEqual(self.store.q('SELECT * FROM nats_outbox'), [])

    async def test_receipt_failure_rolls_back_work_parent_and_bridge_outbox(self):
        parent = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Parent')
        self.store.db.execute("UPDATE work_items SET state='claimed', claimed_by='old' WHERE id=?", (parent['id'],))
        raw, _ = await self.prepare(self.value(parentId=parent['id'], federate=True))
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('private failure')):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        self.assertEqual(self.store.q1('SELECT state FROM work_items')['state'], 'claimed')
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(self.store.q('SELECT * FROM nats_outbox'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])
        await self.dispatch(raw)
        self.assertEqual(self.store.work(parent['id'])['state'], 'waiting_children')
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_replay_conflict_restart_and_changed_intent_keep_original_ids(self):
        raw, inner = await self.prepare(self.value(federate=True))
        reply = await self.dispatch(raw)
        row = self.store.q1('SELECT * FROM work_items')
        self.assertEqual(await self.dispatch(raw), reply)
        later, _ = await self.use(self.value('Later'), operation='later', revision=2)
        conflict_raw, _ = await self.prepare(self.value('Stale'), operation='stale')
        conflict = await self.dispatch(conflict_raw)
        self.assertEqual(conflict['outcome'], 'conflict')
        await self.replace_resource(self.open_work())
        self.assertEqual(await self.dispatch(raw), reply)
        self.assertEqual(await self.dispatch(conflict_raw), conflict)
        recovered = await self.contract_outcome(inner)
        self.assertEqual(recovered['recordRef'], reply['receiptRef'])
        self.assertEqual(self.store.q1('SELECT id FROM work_items ORDER BY created')['id'], row['id'])
        self.assertEqual(len(self.store.outbox_pending()), 1)
        changed, _ = await self.prepare(self.value('Changed'), revision=1)
        with self.assertRaises(ContractError):
            await self.dispatch(changed)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 2)

    async def test_closed_command_and_cross_repo_relationships_refuse(self):
        foreign = self.store.work_create('operator', 'other', 'role:other/worker', 'Foreign')
        for index, value in enumerate((self.value(target='role:other/worker'), self.value(parentId=foreign['id']),
                self.value(command='cancel', workId=foreign['id'], reason='No'),
                self.value(command='select', query={'kind': 'show', 'workId': foreign['id']}),
                self.value(command='execute', sql='DELETE FROM work_items'), self.value(repo='other'))):
            with self.subTest(index=index), self.assertRaises(ContractError):
                await self.use(value, operation='bad-' + str(index))
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])
        self.assertEqual(self.store.q1('SELECT * FROM work_items'), foreign)

    async def test_local_lifecycle_store_and_worker_replacement_refuse(self):
        raw, _ = await self.prepare()
        old = self.hub.dbx
        self.hub.dbx = object()
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.hub.dbx = old
        self.hub.stop.set()
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])

    async def test_current_transport_revocation_refuses_original_request(self):
        raw, _ = await self.prepare()
        self.claims.update(operationId='revoke-work-transport', contractId='identity-revoke',
            grantRef=ref('grant'), expectedVersion=2,
            payload={'authorityId': 'authority-one', 'targetRef': ref('host-transport')})
        result = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(result['claims']['receipt']['decision'], 'allowed')
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])

    async def test_agent_claim_path_heartbeat_release_and_cancel_controls(self):
        caller = reg(self.store, 'falcon', 'worker', 'one')
        actors = (MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), caller),)
        await self.replace_resource(self.open_work(actors=actors))
        created, _ = await self.use(self.value())
        work = self.store.q1('SELECT * FROM work_items')
        claimed, _ = await self.use(self.value(command='claim', workId=work['id']), operation='claim', revision=2)
        claimed_row = strict_loads(await self.resource.read(3))
        self.assertEqual((claimed_row['claimed_by'], claimed_row['attempts']), (caller, 1))
        await self.use(self.value(command='claim-path', path='a.py', workId=work['id']), operation='path', revision=3)
        await self.use(self.value(command='heartbeat', leaseSeconds=200), operation='heartbeat', revision=4)
        with self.assertRaises(ContractError):
            await self.use(self.value(command='cancel', workId=work['id'], reason='No'), operation='cancel', revision=5)
        await self.use(self.value(command='release', workId=work['id'], outcome='done', result='Complete'),
            operation='release', revision=5)
        self.assertEqual(self.store.q1('SELECT state FROM work_items')['state'], 'done')
        self.assertEqual(self.store.q('SELECT * FROM claims'), [])

    async def test_agent_reregistration_does_not_reuse_enrolled_caller(self):
        caller = reg(self.store, 'falcon', 'worker', 'one')
        actors = (MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), caller),)
        await self.replace_resource(self.open_work(actors=actors))
        raw, _ = await self.prepare()
        self.store.set_state(caller, 'dead')
        reg(self.store, 'falcon', 'worker', 'one')
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])

    async def test_federated_offer_keeps_redacted_protocol_hash_and_atomic_outbox(self):
        await self.replace_resource(self.open_work(owner=self.owner))
        value = self.value('Offer', command='offer', body='token ghp_' + 'a' * 36)
        raw, inner = await self.prepare(value)
        reply = await self.dispatch(raw)
        row = strict_loads(await self.resource.read(2))
        flags = json.loads(row['fed_flags'])
        out = strict_loads(self.store.q1('SELECT payload FROM fed_outbox')['payload'])
        self.assertEqual(flags['offer_digest'], offer_digest(out))
        self.assertNotEqual(flags['offer_digest'], strict_loads(inner)['operation']['payloadDigest'])
        self.assertEqual((row['state'], row['claimed_by']), ('claimed', 'fed:pending'))
        self.assertEqual(flags['env'], out['id'])
        self.assertNotIn('children', row)
        self.assertEqual(await self.dispatch(raw), reply)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)

    async def prepare_read(self, *, operation='work-read', revision=1):
        import base64
        from agentmux_contracts import payload_digest
        self.claims.update(operationId=operation, contractId='capability-storage-read',
            grantRef=ref('capability'), expectedVersion=revision,
            payload={'resourceRef': {**ref('task-one'), 'revision': revision}, 'input': {}})
        admitted = await self.service.ingress.admit(self.request(), cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        inner = strict_loads(admitted.envelope)
        self.wrapper.update(serviceId='storage-owner', requestContractId='capability-storage-read',
            replyContractId='capability-content-reply', operationId=operation,
            requestId=inner['correlationId'], resourceRef=inner['payload']['resourceRef'],
            nativeFactsDigest=payload_digest(self.row['facts']), envelopeBytes=base64.b64encode(admitted.envelope).decode())
        return self.signed()

    async def test_reregistered_actor_cannot_read_or_recover_old_outcome(self):
        caller = reg(self.store, 'falcon', 'worker', 'one')
        actors = (MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), caller),)
        await self.replace_resource(self.open_work(actors=actors))
        _, original = await self.use(self.value())
        read = await self.prepare_read(revision=2)
        self.store.set_state(caller, 'dead')
        reg(self.store, 'falcon', 'worker', 'one')
        with self.assertRaises(ContractError):
            await self.dispatch(read)
        with self.assertRaises(ContractError):
            await self.contract_outcome(original)

    async def test_named_repo_keeps_wildcard_group_claim_scope_and_capacity(self):
        self.store.repo_add('falcon', groups=['g1'])
        self.store.repo_add('other', groups=['g1'])
        caller = reg(self.store, 'falcon', 'worker', 'one')
        actors = (MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), caller),)
        await self.replace_resource(self.open_work(actors=actors))
        foreign = self.store.work_create('operator', 'other', 'role:group:g1/worker', 'Foreign', priority=1)
        for index, target in enumerate(('role:*/worker', 'role:group:g1/worker')):
            await self.use(self.value(target=target), operation='create-' + str(index), revision=1 + index)
        await self.use(self.value(command='claim'), operation='claim', revision=3)
        held = self.store.q1("SELECT * FROM work_items WHERE state='claimed'")
        self.assertEqual(held['repo'], 'falcon')
        await self.use(self.value(command='claim'), operation='at-capacity', revision=4)
        stored = self.resource._journal.outcome('at-capacity', strict_loads(self.inner)['operation']['payloadDigest'])
        self.assertIsNone(stored['result']['claimed'])
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')

    async def test_deadline_expiry_after_effect_rolls_back_business_state_and_receipt(self):
        from datetime import timedelta
        from identity.test_authority import NOW
        raw, _ = await self.prepare(self.value(federate=True))
        real_create = self.store.work_create
        class Expired(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(days=1)
        def expire_after_effect(*args, **kwargs):
            result = real_create(*args, **kwargs)
            patch('hub.fed.message_storage.datetime', Expired).start()
            return result
        with patch.object(self.store, 'work_create', side_effect=expire_after_effect):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        for table in ('work_items', 'nats_outbox', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])

    async def test_cancelled_local_call_and_close_join_original_worker(self):
        from threading import Event
        started, finish, completed = Event(), Event(), Event()
        def work():
            started.set()
            if not finish.wait(5):
                raise AssertionError('test did not release its worker')
            completed.set()
            return 7
        original = asyncio.create_task(self.local.db(work))
        try:
            self.assertTrue(await asyncio.to_thread(started.wait, 2))
            original.cancel()
            await asyncio.sleep(0)
            original.cancel()
            closing = asyncio.create_task(self.local.close())
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            self.assertFalse(completed.is_set())
        finally:
            finish.set()
        with self.assertRaises(asyncio.CancelledError):
            await original
        await closing
        self.assertTrue(completed.is_set())
        self.assertEqual(self.local._pending, set())
        self.assertEqual(self.store.q1('SELECT 7 AS value')['value'], 7)
        with self.assertRaises(ContractError):
            await self.local.db(lambda: None)

    async def test_federated_ingest_grant_release_and_result_keep_original_obligation(self):
        await self.replace_resource(self.open_work(owner=self.owner))
        rid = self.resource.repository_id
        offer = envelope.make('work', 'alice', 'origin', rid, '*',
            {'origin_id': 'W-original', 'title': 'Incoming', 'body': 'Read this', 'role': 'worker'})
        offer['data']['offer_digest'] = offer_digest(offer)
        ingest = self.value(command='ingest', envelope=offer)
        raw, _ = await self.prepare(ingest)
        first = await self.dispatch(raw)
        row = strict_loads(await self.resource.read(2))
        self.assertEqual((row['state'], row['blocked_reason']), ('blocked', 'awaiting origin grant'))
        self.assertEqual(row['origin_peer'], 'alice')
        self.assertEqual(await self.dispatch(raw), first)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        flags = json.loads(row['fed_flags'])
        grant = envelope.make('work_grant', 'alice', 'origin', rid, 'nick', {**reference(flags),
            'executor_peer': 'nick', 'executor_node': 'mac', 'selected': True, 'grant_id': 'grant-original'})
        grant['id'] = 'grant-original'
        await self.use(self.value(command='grant-envelope', envelope=grant), operation='grant', revision=2)
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')
        caller = reg(self.store, 'falcon', 'worker', 'one')
        self.store.claim(caller, work_id=row['id'])
        self.store.release(caller, row['id'], 'done', 'Result', 'mac')
        pending = json.loads(self.store.work(row['id'])['fed_flags'])
        self.assertTrue(pending['result_pending'])
        result_id = pending['result_id']
        raw, _ = await self.prepare(self.value(command='stage-result', workId=row['id']), operation='result', revision=3)
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('private failure')):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        self.assertTrue(json.loads(self.store.work(row['id'])['fed_flags'])['result_pending'])
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        reply = await self.dispatch(raw)
        out = [strict_loads(item['payload']) for item in self.store.q('SELECT payload FROM fed_outbox')]
        result = next(item for item in out if item['type'] == 'result')
        self.assertEqual(result['id'], result_id)
        self.assertEqual(result['data']['result_digest'], result_digest(result['data']))
        await self.replace_resource(self.open_work(owner=self.owner))
        self.assertEqual(await self.dispatch(raw), reply)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        self.assertFalse(json.loads(self.store.work(row['id'])['fed_flags'])['result_pending'])

    async def test_federated_claim_and_accepted_result_are_atomic_and_bound(self):
        await self.replace_resource(self.open_work(owner=self.owner))
        await self.use(self.value(command='offer'))
        row = self.store.q1('SELECT * FROM work_items')
        flags = json.loads(row['fed_flags'])
        data = {'origin_id': row['id'], 'origin_node': 'mac', 'offer_id': flags['env'],
            'offer_digest': flags['offer_digest'], 'execution_id': 'execution-original'}
        claim = envelope.make('work_claim', 'alice', 'receiver', self.resource.repository_id, 'nick', data)
        raw, _ = await self.prepare(self.value(command='claim-envelope', envelope=claim), operation='claim', revision=2)
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('private failure')):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        self.assertNotIn('executor', json.loads(self.store.work(row['id'])['fed_flags']))
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        reply = await self.dispatch(raw)
        selected = json.loads(self.store.work(row['id'])['fed_flags'])['executor']
        self.assertEqual(await self.dispatch(raw), reply)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 2)
        result = envelope.make('result', 'alice', 'receiver', self.resource.repository_id, 'nick',
            {**data, 'grant_id': selected['grant_id'], 'state': 'done', 'result': 'Verified', 'by_sender': {'operator': True}})
        result['data']['result_digest'] = result_digest(result['data'])
        raw, _ = await self.prepare(self.value(command='result-envelope', envelope=result), operation='result', revision=3)
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('private failure')):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        self.assertEqual(self.store.work(row['id'])['state'], 'claimed')
        reply = await self.dispatch(raw)
        committed = strict_loads(await self.resource.read(4))
        self.assertEqual(committed, self.store.q1('SELECT * FROM work_items'))
        self.assertEqual(json.loads(committed['fed_flags'])['accepted_result']['envelope_id'], result['id'])
        self.assertEqual(await self.dispatch(raw), reply)

    async def test_federated_peer_policy_is_rechecked_inside_transaction(self):
        from hub.tests.test_fed_unit import policy
        await self.replace_resource(self.open_work(owner=self.owner))
        rid = self.resource.repository_id
        offer = envelope.make('work', 'alice', 'origin', rid, '*',
            {'origin_id': 'W-original', 'title': 'Incoming', 'role': 'worker'})
        offer['data']['offer_digest'] = offer_digest(offer)
        raw, _ = await self.prepare(self.value(command='ingest', envelope=offer))
        previous = self.resource._journal.commit
        def changed(*args, **kwargs):
            self.owner.policy = policy(peers={'alice': {'trust': 'deny'}})
            return previous(*args, **kwargs)
        with patch.object(self.resource._journal, 'commit', side_effect=changed):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        for table in ('work_items', 'fed_outbox', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])

    async def test_service_lease_primitive_is_atomic_and_unavailable_to_native_commands(self):
        caller = reg(self.store, 'falcon', 'worker', 'one')
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Lease', max_attempts=1)
        self.store.claim(caller, work_id=row['id'])
        self.store.claim_path(caller, 'falcon', 'a.py', row['id'])
        with self.assertRaises(RuntimeError):
            with self.store.tx():
                self.resource._return_leases(caller, 'agent dead')
                raise RuntimeError('outer transition failed')
        self.assertEqual(self.store.work(row['id'])['state'], 'claimed')
        self.assertEqual(len(self.store.q('SELECT * FROM claims')), 1)
        with self.store.tx():
            self.resource._return_leases(caller, 'agent dead')
        self.assertEqual(self.store.work(row['id'])['state'], 'failed')
        self.assertEqual(self.store.q('SELECT * FROM claims'), [])
        for command in ('sweep-leases', 'return-leases', 'ingest-legacy', 'result-legacy'):
            with self.assertRaises(ContractError):
                await self.use(self.value(command=command), operation=command)

    async def test_explicit_other_repo_grant_keeps_group_caller_registration_and_scope(self):
        self.store.repo_add('falcon', groups=['g1'])
        self.store.repo_add('other', groups=['g1'])
        caller = reg(self.store, 'falcon', 'worker', 'one', snap={'capabilities': ['python'], 'max_active': 3})
        actors = (MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), caller),)
        own = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Own')
        foreign = self.store.work_create('operator', 'other', 'role:group:g1/worker', 'Granted other')
        self.store.claim(caller, work_id=own['id'])
        await self.replace_resource(self.open_work(repository='other', actors=actors))
        await self.use(self.value(command='claim'), operation='other-claim')
        row = strict_loads(await self.resource.read(2))
        self.assertEqual((row['id'], row['repo'], row['claimed_by']), (foreign['id'], 'other', caller))
        own_before = self.store.work(own['id'])['lease_until']
        await self.use(self.value(command='heartbeat', leaseSeconds=123), operation='other-heartbeat', revision=2)
        self.assertEqual(self.store.work(own['id'])['lease_until'], own_before)
        with self.assertRaises(ContractError):
            await self.use(self.value(command='release', workId=own['id'], outcome='done'), operation='wrong-release', revision=3)
        self.assertEqual(self.store.work(own['id'])['state'], 'claimed')
        with self.assertRaises(RuntimeError):
            with self.store.tx():
                self.resource._return_leases(caller, 'agent dead')
                raise RuntimeError('outer transition failed')
        self.assertEqual(self.store.work(foreign['id'])['state'], 'claimed')
        with self.store.tx():
            self.resource._return_leases(caller, 'agent dead')
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')
        self.assertEqual(self.store.work(own['id'])['state'], 'claimed')

    async def test_closed_connection_refuses_before_disclosure(self):
        raw, _ = await self.prepare()
        self.store.db.close()
        with self.assertRaisesRegex(ContractError, 'capability_resource_stale'):
            self.resource._current()
        with self.assertRaises(ContractError):
            await self.dispatch(raw)

    async def test_federated_source_and_worker_replacement_refuse(self):
        from types import SimpleNamespace
        resource = self.open_work(owner=self.owner)
        self.owner.hub = SimpleNamespace(store=self.store, dbx=self.worker)
        with self.assertRaises(ContractError):
            resource._current()
        self.owner.hub = self.hub
        self.hub.dbx = object()
        with self.assertRaises(ContractError):
            resource._current()
        self.hub.dbx = self.worker
        resource._current()

    async def test_revoke_is_repo_scoped_and_preserves_owned_work(self):
        from hub.tests.test_fed_unit import policy
        await self.replace_resource(self.open_work(owner=self.owner))
        local = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Incoming')
        foreign = self.store.work_create('operator', 'other', 'role:other/worker', 'Other')
        own = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Own')
        self.store.db.execute('UPDATE work_items SET origin_peer=? WHERE id IN (?,?)', ('alice', local['id'], foreign['id']))
        self.owner.policy = policy(peers={'alice': {'trust': 'deny'}})
        await self.use(self.value(command='revoke', peer='alice'))
        self.assertEqual(self.store.work(local['id'])['state'], 'cancelled')
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')
        self.assertEqual(self.store.work(own['id'])['state'], 'ready')

    async def test_lost_write_reply_and_close_keep_original_commit_for_recovery(self):
        from threading import Event
        started, finish = Event(), Event()
        create = self.store.work_create
        def paused_create(*args, **kwargs):
            result = create(*args, **kwargs)
            started.set()
            if not finish.wait(5):
                raise AssertionError('test did not release original work transaction')
            return result
        raw, inner = await self.prepare(self.value(federate=True))
        with patch.object(self.store, 'work_create', side_effect=paused_create):
            original = asyncio.create_task(self.resource.write(self.service.reader, inner, raw))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                original.cancel()
                await asyncio.sleep(0)
                original.cancel()
                closing = asyncio.create_task(self.local.close())
                await asyncio.sleep(0)
                self.assertFalse(original.done())
                self.assertFalse(closing.done())
            finally:
                finish.set()
            with self.assertRaises(asyncio.CancelledError):
                await original
            await closing
        row = self.store.q1('SELECT * FROM work_items')
        self.assertEqual(len(self.store.outbox_pending()), 1)
        replacement = LocalWorkDomain(self.hub)
        self.addAsyncCleanup(replacement.close)
        await self.replace_resource(self.open_work(owner=replacement))
        recovered = await self.contract_outcome(inner)
        self.assertEqual(recovered['outcome'], 'committed')
        self.assertEqual(await self.dispatch(raw), self.resource._journal.outcome(
            strict_loads(inner)['operation']['operationId'], strict_loads(inner)['operation']['payloadDigest'])['reply'])
        self.assertEqual(self.store.q1('SELECT * FROM work_items'), row)
        self.assertEqual(len(self.store.outbox_pending()), 1)


    async def _refuse_reregistration_after_final_admission(self, kind):
        caller = reg(self.store, 'falcon', 'worker', 'one')
        actors = (MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), caller),)
        await self.replace_resource(self.open_work(actors=actors))
        _, inner = await self.use(self.value())
        raw = await self.prepare_read(revision=2) if kind == 'read' else None
        if kind == 'write':
            raw, _ = await self.prepare(self.value('Second'), operation='second', revision=2)
        elif kind == 'outcome':
            operation = strict_loads(inner)['operation']
            raw, _ = await self.prepare(operation='final-outcome', query={
                'operationId': operation['operationId'], 'payloadDigest': operation['payloadDigest'],
                'contractId': 'capability-storage-write'})
            await self.reply_service.close()
            self.reply_service = CapabilityReplyService(self.service.reader, resources=[self.resource], hub_id='hub-one',
                profile_id='profile-one', authority_id='authority-one', service_id='outcome-owner',
                service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
                signing_seed=SEED, request_signing_key_ref=ref('issuer'), connection=self.connection)
            self.addAsyncCleanup(self.reply_service.close)
        original, calls = self.reply_service._admit, 0
        async def changed(*args, **kwargs):
            nonlocal calls
            result = await original(*args, **kwargs)
            calls += 1
            if calls == 2:
                await self.hub.db(self.store.set_state, caller, 'dead')
                await self.hub.db(reg, self.store, 'falcon', 'worker', 'one')
            return result
        with patch.object(self.reply_service, '_admit', side_effect=changed):
            with self.assertRaises(ContractError):
                await self.dispatch(raw)
        self.assertEqual(calls, 2)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 2 if kind == 'write' else 1)

    async def test_final_signing_refuses_reregistered_actor_read(self):
        await self._refuse_reregistration_after_final_admission('read')

    async def test_final_signing_refuses_reregistered_actor_write_receipt(self):
        await self._refuse_reregistration_after_final_admission('write')

    async def test_final_signing_refuses_reregistered_actor_outcome(self):
        await self._refuse_reregistration_after_final_admission('outcome')

    async def test_final_disclosure_worker_cannot_extend_service_validity(self):
        from datetime import timedelta
        await self.use(self.value())
        raw = await self.prepare_read(revision=2)
        original = self.resource.check_disclosure
        class Later:
            @staticmethod
            def now(tz=None):
                return _Clock.now(tz) + timedelta(seconds=10)
        clock = patch('capability_owner.reply_service.datetime', Later)
        async def expired(*args):
            await original(*args)
            clock.start()
        try:
            with patch.object(self.resource, 'check_disclosure', side_effect=expired):
                with self.assertRaises(ContractError):
                    await self.dispatch(raw)
        finally:
            clock.stop()

    async def test_final_disclosure_worker_survives_observer_cancellation_and_is_joined(self):
        from threading import Event
        started, finish = Event(), Event()
        await self.use(self.value())
        raw = await self.prepare_read(revision=2)
        original = self.resource.check_disclosure
        async def paused_disclosure(inner):
            def blocked_check():
                started.set()
                if not finish.wait(5):
                    raise AssertionError('test did not release original disclosure check')
                self.resource._check_caller('operator')
            await self.resource._owner.db(blocked_check)
            await original(inner)
        with patch.object(self.resource, 'check_disclosure', side_effect=paused_disclosure):
            task = asyncio.create_task(self.dispatch(raw))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                with self.assertRaisesRegex(ContractError, 'capability_cleanup_incomplete'):
                    await self.reply_service._receiver.close(timeout=0.01)
                self.assertTrue(self.reply_service._receiver._workers)
                self.assertIs(self.hub.store, self.store)
            finally:
                finish.set()
            await self.reply_service._receiver.close(timeout=2)
        self.assertFalse(self.reply_service._receiver._workers)
        self.assertFalse(self.local._pending)


class AggregateWorkStorageTests(MessageFixture, unittest.IsolatedAsyncioTestCase):
    message_scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
    message_repository = None

    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        patch('capability_owner.federated_storage.datetime', _Clock).start()
        self.store.repo_add('falcon')
        self.store.repo_add('other')
        self.worker = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.worker.shutdown, wait=True)
        self.hub = Hub.__new__(Hub)
        self.hub.store, self.hub.dbx = self.store, self.worker
        self.hub.cfg, self.hub.stop = {'node': 'mac'}, asyncio.Event()
        self.local = LocalWorkDomain(self.hub)
        self.addAsyncCleanup(self.local.close)
        binding = OwnerBinding('hub-one', 'federation-work', 'task-one', 'work-channel', canonical_bytes(self.scope))
        self.resource = WorkStorageResource(binding, self.local, repository=None,
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one')
        self.reply_service = WorkStorageTests.endpoint(self)
        self.addAsyncCleanup(self.reply_service.close)

    value = WorkStorageTests.value
    prepare_read = WorkStorageTests.prepare_read

    async def test_aggregate_native_read_needs_no_selection_write_or_global_create_permission(self):
        import base64
        first = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'First')
        second = self.store.work_create('operator', 'other', 'role:other/worker', 'Second')
        result = await self.dispatch(await self.prepare_read())
        self.assertEqual(strict_loads(base64.b64decode(result['data'])), [first, second])
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])
        raw, _ = await self.prepare(self.value())
        with self.assertRaises(ContractError):
            await self.dispatch(raw)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 2)
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])
