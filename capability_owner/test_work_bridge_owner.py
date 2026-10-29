"""Actual signed work admission, original transactions and final disclosure."""
import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from hub.fed import envelope, ledger
from hub.fed.work_services import offer_digest
from hub.server import Hub
from hub.tests.test_fed_unit import policy
from hub.tests.test_hub_offline import reg
from identity.test_authority import ref, SEED, NOW
from identity.test_service import _Clock
from identity.work_client import WORK_COMMANDS, WORK_MUTATIONS, WORK_SERVICE_COMMANDS
from state_owner.ledger import OwnerBinding
from .messages import MessageActor
from .work import LocalWorkDomain, WorkStorageResource
from .work_legacy import LegacyWorkActor, check_approval
from .work_bridge_service import WorkBridgeService, verify_work_bridge_reply
from . import test_message_bridge_owner as support
from .test_messages import MessageFixture


class WorkBridgeFixture(support.BridgeOwnerFixture):
    def setUp(self):
        super().setUp()
        self.work_grants, self.work_actors = {}, []
        template = next(g for g in self.record['state']['grants'] if g['ref'] == ref('messages-write'))
        for identity in ('human', 'service'):
            commands = (WORK_COMMANDS - WORK_SERVICE_COMMANDS if identity == 'human' else
                WORK_SERVICE_COMMANDS | {'federation-work-read', 'federation-work-inspect', 'federation-work-outcome'})
            grants = {}
            for contract in sorted(commands):
                grant = copy.deepcopy(template)
                action = contract.removeprefix('federation-work-')
                grant.update(ref=ref('work-' + identity + '-' + action), callerRef=ref(identity),
                    actorRef=ref(identity), contractId=contract)
                self.record['state']['grants'].append(grant)
                grants[contract] = grant['ref']
            self.work_grants[identity] = grants
            self.work_actors.append(LegacyWorkActor(canonical_bytes(ref(identity)),
                canonical_bytes(ref('transport' if identity == 'human' else 'legacy-service-transport')),
                'operator' if identity == 'human' else 'federation', canonical_bytes(grants)))
        self.work_actors = tuple(self.work_actors)
        self.js.messages[0].data = canonical_bytes(self.record)

    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        await self.reply_service.close()
        for module in ('capability_owner.work_legacy', 'capability_owner.work_bridge_service'):
            patch(module + '.datetime', _Clock).start()
        self.store.repo_add('falcon')
        self.store.repo_add('other')
        self.worker = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.worker.shutdown, wait=True)
        self.hub = Hub.__new__(Hub)
        self.hub.store, self.hub.dbx = self.store, self.worker
        self.hub.cfg, self.hub.stop = {'node': 'mac'}, asyncio.Event()
        self.hub._work_source_binding = None
        self.local = LocalWorkDomain(self.hub)
        self.addAsyncCleanup(self.local.close)
        self.owner.hub = self.hub
        self.resource = self.open_work()
        self.endpoint = self.open_endpoint()
        self.addAsyncCleanup(self.endpoint.close, timeout=None)

    def open_work(self, *, owner=None, actors=None, repository='falcon'):
        return WorkStorageResource(OwnerBinding('hub-one', 'federation-work', 'task-one', 'work-channel',
            canonical_bytes(self.scope)), owner or self.local, repository=repository,
            actors=(MessageActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')), 'operator'),),
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one',
            legacy_actors=actors or self.work_actors, legacy_authority=self.service.reader)

    def open_endpoint(self):
        return WorkBridgeService(self.service.ingress, resources=(self.resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)

    async def replace(self, **changes):
        await self.endpoint.close(timeout=None)
        self.resource = self.open_work(**changes)
        self.endpoint = self.open_endpoint()
        self.addAsyncCleanup(self.endpoint.close, timeout=None)

    def work_request(self, action, value=None, *, operation='work-one', revision=1, identity=None):
        contract = 'federation-work-' + action
        identity = identity or ('service' if contract in WORK_SERVICE_COMMANDS else 'human')
        payload = {'resourceRef': {**ref('task-one'), 'revision': revision}, 'input': value or {}}
        if contract in WORK_MUTATIONS:
            payload['attribution'] = 'operator' if identity == 'human' else 'federation'
        self.claims.update(operationId=operation, expectedVersion=revision, contractId=contract,
            transportRef=ref('transport' if identity == 'human' else 'legacy-service-transport'),
            grantRef=self.work_grants[identity][contract], payload=payload,
            replySubject='_INBOX.work_bridge_000000001')
        return self.request()

    def verify_reply(self, response, raw, *, now=NOW, include_valid_until=False):
        return verify_work_bridge_reply(response, raw,
            public_key=self.record['state']['issuers'][0]['publicKey'], service_identity_ref=ref('service'),
            service_instance_id='ingress-one', signing_key_ref=ref('issuer'), now=now,
            include_valid_until=include_valid_until)

    async def work_call(self, raw, *, include_valid_until=False):
        response = await self.endpoint.handle(raw,
            received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        return self.verify_reply(response, raw, include_valid_until=include_valid_until)

    def query(self, raw):
        claims = strict_loads(raw)['claims']
        return {'contractId': claims['contractId'], 'operationId': claims['operationId'],
            'payloadDigest': payload_digest(claims['payload'])}

    def item(self, *, privileged=False):
        item = envelope.make('work', 'alice', 'remote', self.owner.policy.rid_of('falcon'), '*',
            {'origin_id': 'remote-origin', 'title': 'Original remote work', 'body': 'Original body',
                'task_key': 'AMUX-661', 'requirements': {'capabilities': ['privileged']} if privileged else {},
                'priority': 100, 'role': 'worker', 'sender': {'operator': True}})
        item['data']['offer_digest'] = offer_digest(item)
        return item

    def incoming(self, item):
        return {'envelope': item, 'subject': envelope.subject('work', item['from'], item['rid'], item['data']['role']),
            'localNode': 'mac'}


class WorkBridgeOwnerTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def test_local_only_create_replay_raw_result_and_queries(self):
        self.store.db.execute('ALTER TABLE work_items ADD COLUMN future_field TEXT')
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Original local work',
            'requirements': {'capabilities': ['python']}, 'federate': True})
        first = await self.work_call(raw, include_valid_until=True)
        self.assertEqual(set(first), {'result', 'validUntil'})
        original = first['result']
        row = self.store.q1('SELECT * FROM work_items')
        self.assertEqual(original['result'], row)
        self.assertNotIn('children', original['result'])
        self.assertIn('future_field', row)
        self.assertIsNone(self.resource.repository_id)
        self.assertEqual((await self.work_call(raw)), original)
        for query in ({'kind': 'show', 'workId': row['id']}, {'kind': 'list', 'state': None}, {'kind': 'claims'}):
            result = await self.work_call(self.work_request('read', {'query': query}, operation='read-' + query['kind']))
            self.assertEqual(result['value'], self.resource._select(query, 'operator'))
        self.assertEqual(len(self.store.outbox_pending()), 1)
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])

    async def test_lost_reply_replacement_keeps_exact_original_row_and_outbox(self):
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Original', 'federate': True})
        first = await self.work_call(raw)
        await self.replace()
        recovered = await self.work_call(self.work_request('outcome', self.query(raw), operation='recover'))
        self.assertEqual({key: recovered[key] for key in first}, first)
        self.assertEqual(await self.work_call(raw), first)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)

    async def test_conflict_and_changed_original_digest_never_create_second_effect(self):
        value = {'target': 'role:falcon/worker', 'title': 'Original'}
        first = await self.work_call(self.work_request('create', value))
        stale = self.work_request('create', {**value, 'title': 'Stale'}, operation='stale')
        receipt = await self.work_call(stale)
        self.assertEqual((receipt['outcome'], receipt['result']), ('conflict', None))
        self.assertEqual(await self.work_call(stale), receipt)
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('create', {**value, 'title': 'Changed'}))
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(first['resourceRef']['revision'], 2)

    async def test_receipt_failure_rolls_back_original_row_and_outbox(self):
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Original', 'federate': True})
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('controlled receipt failure')):
            with self.assertRaises(ContractError):
                await self.work_call(raw)
        for table in ('work_items', 'nats_outbox', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])
        self.assertEqual((await self.work_call(raw))['outcome'], 'applied')

    async def test_operator_first_approval_keeps_held_row_and_privilege_separate(self):
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        await self.replace(owner=self.owner)
        item = self.item(privileged=True)
        value = self.incoming(item)
        qid = ledger.quarantine_add(self.store, item, value['subject'], 'work', 'alice', 'held for review')
        value['quarantineId'] = qid
        original = self.work_request('approve', value)
        result = await self.work_call(original)
        row = result['result']['work']
        self.assertEqual(json.loads(row['fed_flags'])['privileged_ok'], False)
        self.assertTrue(json.loads(row['fed_flags'])['approved'])
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'held')
        self.assertEqual(result['result']['outcome'], 'delivered')
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        # A second exact offer exercises the explicit privilege contract; no
        # approved-row inference supplies that permission.
        second = self.item(privileged=True)
        second['data']['origin_id'] = 'second-origin'
        second['data']['offer_digest'] = offer_digest(second)
        value2 = self.incoming(second)
        value2['quarantineId'] = ledger.quarantine_add(self.store, second, value2['subject'], 'work', 'alice', 'held')
        allowed = await self.work_call(self.work_request('approve-privileged', value2, operation='privileged', revision=2))
        self.assertTrue(json.loads(allowed['result']['work']['fed_flags'])['privileged_ok'])
        self.assertEqual(ledger.quarantine_get(self.store, value2['quarantineId'])['state'], 'held')

    async def test_privileged_approval_requires_its_own_current_permission(self):
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        await self.replace(owner=self.owner)
        item = self.item(privileged=True)
        value = self.incoming(item)
        value['quarantineId'] = ledger.quarantine_add(self.store, item, value['subject'], 'work', 'alice', 'held')
        current = strict_loads(self.js.messages[-1].data)
        next(grant for grant in current['state']['grants']
            if grant['ref'] == self.work_grants['human']['federation-work-approve-privileged'])['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('approve-privileged', value))
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('approve', {**value, 'privileged': True}))
        result = await self.work_call(self.work_request('approve', value))
        self.assertFalse(json.loads(result['result']['work']['fed_flags'])['privileged_ok'])
        self.assertEqual(ledger.quarantine_get(self.store, value['quarantineId'])['state'], 'held')

    async def test_approval_substitution_wrong_policy_and_arbitrary_decision_refuse(self):
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        await self.replace(owner=self.owner)
        item, value = self.item(), None
        value = self.incoming(item)
        value['quarantineId'] = ledger.quarantine_add(self.store, item, value['subject'], 'work', 'alice', 'held')
        changed = copy.deepcopy(value)
        changed['envelope']['data']['title'] = 'Changed'
        changed['envelope']['data']['offer_digest'] = offer_digest(changed['envelope'])
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('approve', changed))
        with self.assertRaises(ContractError):
            check_approval(self.resource, guard_decision())
        self.owner.policy = policy(peers={'alice': {'trust': 'deny'}})
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('approve', value))
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])

    async def test_service_peer_admission_rechecks_exact_subject_and_denies_quarantine(self):
        await self.replace(owner=self.owner)
        item, value = self.item(), None
        value = self.incoming(item)
        for key, replacement in (('subject', value['subject'].replace('alice', 'bob')), ('localNode', 'other')):
            with self.assertRaises(ContractError):
                await self.work_call(self.work_request('ingest', {**value, key: replacement}, operation='wrong-' + key))
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        qid = ledger.quarantine_add(self.store, item, value['subject'], 'work', 'alice', 'held')
        ledger.quarantine_decide(self.store, qid, 'approved', 'operator')
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('ingest', value))
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])

    async def test_peer_agent_sender_and_repository_evidence_survive_closed_contract(self):
        await self.replace(owner=self.owner)
        item = self.item()
        item['data']['sender'] = {'rid': item['rid'], 'role': 'worker', 'agent': 'original'}
        item['data']['offer_digest'] = offer_digest(item)
        result = await self.work_call(self.work_request('ingest', self.incoming(item)))
        row = result['result']['work']
        self.assertEqual(row['created_by'], 'peer:alice/falcon/worker/original')
        self.assertEqual(json.loads(row['fed_flags'])['offer_digest'], item['data']['offer_digest'])
        self.assertEqual(result['result']['outcome'], 'delivered')

    async def test_owner_refuses_substituted_authority_reader_even_with_same_reference_names(self):
        from identity.authority import LedgerAuthorityReader
        raw = self.work_request('inspect')
        _, _, inner, _ = await self.endpoint._admit(raw, self.claims['replySubject'])
        other = LedgerAuthorityReader(self.service.ledger, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        with self.assertRaises(ContractError):
            await self.resource.authorize_legacy(other, inner)
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])

    async def test_service_only_maintenance_and_current_original_permission(self):
        caller = reg(self.store, 'falcon', 'worker', 'one')
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Lease')
        self.store.claim(caller, work_id=row['id'])
        raw = self.work_request('return-leases', {'session': caller, 'reason': 'agent dead'})
        receipt = await self.work_call(raw)
        self.assertEqual(receipt['result']['returned'], [{'id': row['id'], 'state': 'ready'}])
        self.assertEqual(await self.work_call(raw), receipt)
        original = self.work_grants['service']['federation-work-return-leases']
        current = strict_loads(self.js.messages[-1].data)
        next(g for g in current['state']['grants'] if g['ref'] == original)['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('outcome', self.query(raw), operation='recover-service', identity='service'))
        self.assertEqual(self.store.work(row['id'])['state'], 'ready')

    async def test_legacy_service_key_without_publisher_proof_cannot_mutate_work(self):
        item = {'type': 'work', 'origin': 'remote:remote-one', 'origin_node': 'remote', 'origin_id': 'remote-one',
            'work': {'repo': 'falcon', 'target': 'role:falcon/worker', 'title': 'Unverified legacy',
                'created_by': 'agent:original', 'requirements': '{"capabilities":["python"]}'}}
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('ingest-legacy', {'envelope': item}))
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])
        outgoing = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Outgoing', federate=True, node='mac')
        before = self.store.work(outgoing['id'])
        completion = {'type': 'result', 'origin_id': outgoing['id'], 'state': 'done',
            'result': 'Unverified completion', 'node': 'remote', 'by': 'worker'}
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('result-legacy', {'envelope': completion},
                operation='legacy-result', revision=1))
        self.assertEqual(self.store.work(outgoing['id']), before)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)

    async def test_outcome_checks_exact_original_actor_transport_and_current_hard_denial(self):
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Original'})
        await self.work_call(raw)
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('outcome', self.query(raw), operation='other-actor', identity='service'))
        current = strict_loads(self.js.messages[-1].data)
        allowed = next(g for g in current['state']['grants'] if g['ref'] == self.work_grants['human']['federation-work-create'])
        current['state']['grants'].append({**allowed, 'ref': ref('work-create-denied'), 'decision': 'denied'})
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('outcome', self.query(raw), operation='hard-denied'))
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)

    async def test_wrong_resource_scope_attribution_and_unknown_command_refuse(self):
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Original'})
        original = copy.deepcopy(self.claims)
        for key, changed in (('grantRef', ref('messages-write')), ('transportRef', ref('legacy-service-transport'))):
            self.claims = copy.deepcopy(original)
            self.claims[key] = changed
            with self.assertRaises(ContractError):
                await self.work_call(self.request())
        self.claims = copy.deepcopy(original)
        self.claims['payload']['attribution'] = 'federation'
        with self.assertRaises(ContractError):
            await self.work_call(self.request())
        self.claims = copy.deepcopy(original)
        self.claims['payload']['resourceRef']['id'] = 'other'
        with self.assertRaises(ContractError):
            await self.work_call(self.request())
        with self.assertRaises(ContractError):
            validate('federation-work-create', {'resourceRef': ref('task-one'), 'attribution': 'operator',
                'input': {'target': 'role:falcon/worker', 'title': 'Original', 'callback': 'arbitrary'}})
        self.assertEqual(self.store.q('SELECT * FROM work_items'), [])

    async def test_signer_revocation_and_expired_reply_never_disclose_rows(self):
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Original'})
        response = await self.endpoint.handle(raw, received_reply_subject=self.claims['replySubject'])
        with self.assertRaises(ContractError):
            self.verify_reply(response, raw, now=NOW + timedelta(seconds=5))
        forged = strict_loads(response)
        forged['claims']['operationId'] = 'substituted'
        forged['signature'] = sign_claims(forged['claims'], SEED)
        with self.assertRaises(ContractError):
            self.verify_reply(canonical_bytes(forged), raw)
        current = strict_loads(self.js.messages[-1].data)
        current['state']['issuers'][0]['status'] = 'revoked'
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.work_call(self.work_request('read', {'query': {'kind': 'list', 'state': None}}, operation='revoked-signer'))

    async def _agent_owner(self):
        caller = reg(self.store, 'falcon', 'worker', 'signed', snap={'capabilities': ['python'], 'max_active': 3})
        self.work_actors = (LegacyWorkActor(canonical_bytes(ref('human')), canonical_bytes(ref('transport')),
            caller, canonical_bytes(self.work_grants['human'])), self.work_actors[1])
        await self.replace()
        return caller

    def _agent_request(self, caller, action, value=None, **fields):
        self.work_request(action, value, **fields)
        if 'attribution' in self.claims['payload']:
            self.claims['payload']['attribution'] = caller
        return self.request()

    async def test_legacy_agent_claim_release_cross_repo_and_generation_fence(self):
        caller = await self._agent_owner()
        own = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Own')
        foreign = self.store.work_create('operator', 'other', 'role:other/worker', 'Other')
        raw = self._agent_request(caller, 'claim', {'workId': own['id']})
        first = await self.work_call(raw)
        self.assertEqual(first['result']['claimed']['id'], own['id'])
        self.assertEqual(first['result']['claimed']['claimed_by'], caller)
        with self.assertRaises(ContractError):
            await self.work_call(self._agent_request(caller, 'release',
                {'workId': foreign['id'], 'outcome': 'done'}, operation='foreign', revision=2))
        released = await self.work_call(self._agent_request(caller, 'release',
            {'workId': own['id'], 'outcome': 'done', 'result': 'Exact completed result'},
            operation='release', revision=2))
        self.assertEqual(released['result'], self.store.q1('SELECT * FROM work_items WHERE id=?', (own['id'],)))
        self.assertNotIn('children', released['result'])
        self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (caller,))
        with self.assertRaises(ContractError):
            await self.work_call(self._agent_request(caller, 'read',
                {'query': {'kind': 'list', 'state': None}}, operation='stale-read'))
        with self.assertRaises(ContractError):
            await self.work_call(self._agent_request(caller, 'outcome', self.query(raw), operation='stale-outcome'))
        self.assertEqual(self.store.work(foreign['id'])['state'], 'ready')

    async def test_final_signed_read_refuses_registration_changed_after_last_authority(self):
        caller = await self._agent_owner()
        self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Private row')
        raw = self._agent_request(caller, 'read', {'query': {'kind': 'list', 'state': None}})
        original, count = self.resource.authorize_legacy, 0
        async def changed(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 2:
                self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (caller,))
            return await original(*args, **kwargs)
        with patch.object(self.resource, 'authorize_legacy', side_effect=changed):
            with self.assertRaises(ContractError):
                await self.work_call(raw)
        self.assertGreaterEqual(count, 2)

    async def test_final_signing_refuses_expiry_during_final_actor_worker_await(self):
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Original'})
        original, count = self.resource.authorize_legacy, 0
        clock = {'late': False}
        class FinalClock(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=5) if clock['late'] else NOW
        async def expired(*args, **kwargs):
            nonlocal count
            checked = await original(*args, **kwargs)
            count += 1
            if count == 2:
                clock['late'] = True
            return checked
        with patch('capability_owner.work_bridge_service.datetime', FinalClock):
            with patch.object(self.resource, 'authorize_legacy', side_effect=expired):
                with self.assertRaises(ContractError):
                    await self.work_call(raw)
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)

    async def test_cancelled_reply_retains_original_until_close_joins(self):
        from threading import Event
        entered, release = Event(), Event()
        create = self.store.work_create
        def blocked(*args, **kwargs):
            result = create(*args, **kwargs)
            entered.set()
            if not release.wait(5):
                raise AssertionError('original work transaction was not released')
            return result
        raw = self.work_request('create', {'target': 'role:falcon/worker', 'title': 'Original', 'federate': True})
        caller = None
        with patch.object(self.store, 'work_create', side_effect=blocked):
            try:
                caller = asyncio.create_task(self.endpoint.handle(raw, received_reply_subject=self.claims['replySubject']))
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                caller.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await caller
                with self.assertRaises(ContractError):
                    await self.endpoint.close(timeout=.01)
                self.assertTrue(self.endpoint._workers)
            finally:
                release.set()
                await self.endpoint.close(timeout=None)
                if caller is not None:
                    await asyncio.gather(caller, return_exceptions=True)
        await self.replace()
        recovered = await self.work_call(self.work_request('outcome', self.query(raw), operation='recover-cancel'))
        self.assertEqual(recovered['outcome'], 'applied')
        self.assertEqual(len(self.store.q('SELECT * FROM work_items')), 1)
        self.assertEqual(len(self.store.outbox_pending()), 1)


def guard_decision():
    from hub.fed.guard import Decision
    return Decision('deliver', 'caller flag', approved=True, privileged_ok=True)
