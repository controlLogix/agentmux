"""Retained work receipts qualify captures after staging and source changes."""
import asyncio
import copy
from datetime import timedelta
import json
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed.plugins.knowledge import Knowledge
from hub.tests.test_hub_offline import reg
from identity.test_authority import NOW, ref, SEED
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .knowledge import KnowledgeStorageResource
from .knowledge_bridge_service import KnowledgeBridgeService, verify_knowledge_bridge_reply
from .knowledge_legacy import LegacyKnowledgeActor
from .test_work_bridge_owner import WorkBridgeFixture
from .work_capture import bind_sources, capture_source


class WorkCaptureReceiptTests(WorkBridgeFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        self.capture_grants = {}
        template = next(g for g in self.record['state']['grants'] if g['ref'] == ref('messages-write'))
        for action in ('capture', 'inspect', 'outcome'):
            contract = 'federation-knowledge-' + action
            grant = copy.deepcopy(template)
            grant.update(ref=ref('capture-' + action), callerRef=ref('service'), actorRef=ref('service'),
                contractId=contract, resourceId='knowledge-one')
            self.record['state']['grants'].append(grant)
            self.capture_grants[contract] = grant['ref']
        self.js.messages[0].data = canonical_bytes(self.record)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        for module in ('capability_owner.work_capture', 'capability_owner.knowledge_legacy',
                'capability_owner.knowledge_bridge_service'):
            timer = patch(module + '.datetime', _Clock)
            timer.start()
            self.addCleanup(timer.stop)
        self.owner.fcfg['capture'] = True
        self.owner.db = self.hub.db
        for statement in Knowledge.tables:
            self.store.db.execute(statement)
        actor = LegacyKnowledgeActor(canonical_bytes(ref('service')),
            canonical_bytes(ref('legacy-service-transport')), 'federation', canonical_bytes(self.capture_grants))
        self.knowledge_args = dict(repository='falcon', actors=self.resource.actors,
            plugin_identity_ref=ref('plugin'), instance_id='plugin-one', legacy_actors=(actor,),
            work_sources=(self.resource,))
        self.knowledge_binding = OwnerBinding('hub-one', 'federation-knowledge', 'knowledge-one',
            'knowledge-channel', canonical_bytes(self.scope))
        self.knowledge = KnowledgeStorageResource(self.knowledge_binding, self.owner, **self.knowledge_args)
        self.knowledge_endpoint = self.open_knowledge_endpoint()
        self.addAsyncCleanup(self.knowledge_endpoint.close, timeout=None)

    def open_knowledge_endpoint(self):
        return KnowledgeBridgeService(self.service.ingress, resources=(self.knowledge,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)

    async def release(self):
        session = reg(self.store, 'falcon', 'worker', 'target')
        self.target = {'session': session, 'generation': self.store.agent(session)['generation']}
        self.store.db.execute('ALTER TABLE work_items ADD COLUMN future_field TEXT')
        row = self.store.work_create('operator', 'falcon', 'role:falcon/worker', 'Original title')
        self.store.claim(session, work_id=row['id'])
        self.store.db.execute('UPDATE work_items SET future_field=? WHERE id=?', ('preserved', row['id']))
        raw = self.work_request('release', {'workId': row['id'], 'outcome': 'done',
            'result': 'Original body', 'onBehalfOf': self.target}, operation='release-original')
        applied = await self.work_call(raw)
        self.source = {'kind': 'work-released', 'id': row['id'], 'digest': payload_digest(applied['result']),
            'resourceRef': applied['resourceRef'], 'receiptRef': applied['receiptRef'],
            'operationId': 'release-original', 'payloadDigest': payload_digest(strict_loads(raw)['claims']['payload'])}
        return applied

    def capture_request(self, *, source=None, operation='capture-original', revision=1, action='capture', value=None):
        contract = 'federation-knowledge-' + action
        payload = {'resourceRef': {**ref('knowledge-one'), 'revision': revision},
            'input': value or {'source': copy.deepcopy(self.source if source is None else source)}}
        if action == 'capture':
            payload['attribution'] = 'federation'
        self.claims.update(operationId=operation, expectedVersion=revision, contractId=contract,
            transportRef=ref('legacy-service-transport'), grantRef=self.capture_grants[contract],
            payload=payload, replySubject='_INBOX.capture_receipt_000001')
        return self.request()

    async def capture(self, raw):
        reply = await self.knowledge_endpoint.handle(raw,
            received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        return verify_knowledge_bridge_reply(reply, raw,
            public_key=self.record['state']['issuers'][0]['publicKey'], service_identity_ref=ref('service'),
            service_instance_id='ingress-one', signing_key_ref=ref('issuer'), now=NOW)

    async def test_original_row_survives_later_changes_restart_and_exact_retry(self):
        original = await self.release()
        self.store.db.execute('UPDATE work_items SET title=?,result=?,future_field=? WHERE id=?',
            ('Later title', 'Later body', 'changed', self.source['id']))
        row, _ = capture_source(self.knowledge, self.source, await self.service.reader.current())
        self.assertEqual(row, original['result'])
        self.assertEqual(row['future_field'], 'preserved')
        request = self.capture_request()
        first = await self.capture(request)
        await self.knowledge_endpoint.close(timeout=None)
        self.knowledge = KnowledgeStorageResource(self.knowledge_binding, self.owner, **self.knowledge_args)
        self.knowledge_endpoint = self.open_knowledge_endpoint()
        self.addAsyncCleanup(self.knowledge_endpoint.close, timeout=None)
        self.assertEqual(await self.capture(request), first)
        findings = self.store.q('SELECT * FROM p_knowledge_items')
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0]['title'], findings[0]['body'], findings[0]['ref'], findings[0]['author']),
            ('done: Original title', 'Original body', self.source['id'], 'worker/target'))
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)
        self.assertEqual(self.store.q1('SELECT result FROM work_items WHERE id=?', (self.source['id'],))['result'], 'Later body')

    async def test_substitutions_absent_outcome_and_raw_bypass_never_capture(self):
        await self.release()
        variants = []
        for field, value in (('operationId', 'missing'), ('payloadDigest', 'sha256:' + 'a' * 64),
                ('digest', 'sha256:' + 'b' * 64), ('id', 'foreign')):
            changed = copy.deepcopy(self.source)
            changed[field] = value
            variants.append(changed)
        for field in ('receiptRef', 'resourceRef'):
            changed = copy.deepcopy(self.source)
            changed[field]['revision'] += 1
            variants.append(changed)
        variants.append({key: self.source[key] for key in ('kind', 'id', 'digest')})
        for index, source in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ContractError):
                await self.capture(self.capture_request(source=source, operation='forged-' + str(index)))
        self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])

    async def test_current_original_work_and_capture_grants_remain_required(self):
        await self.release()
        baseline = self.js.messages[-1].data
        for reference in (self.work_grants['human']['federation-work-release'],
                self.capture_grants['federation-knowledge-capture']):
            current = strict_loads(baseline)
            next(g for g in current['state']['grants'] if g['ref'] == reference)['status'] = 'revoked'
            self.js.messages[-1].data = canonical_bytes(current)
            with self.assertRaises(ContractError):
                await self.capture(self.capture_request())
            self.js.messages[-1].data = baseline
        self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])
        self.store.db.execute('UPDATE agents SET generation=generation+1 WHERE session=?', (self.target['session'],))
        with self.assertRaises(ContractError):
            await self.capture(self.capture_request())

    async def test_source_replacement_and_undeclared_source_refuse(self):
        await self.release()
        snapshot = await self.service.reader.current()
        pins = self.knowledge._work_capture_sources
        self.knowledge._work_capture_sources = ()
        with self.assertRaises(ContractError):
            capture_source(self.knowledge, self.source, snapshot)
        self.knowledge._work_capture_sources = pins
        original = self.owner.db
        async def replacement(function, *args, **kwargs):
            return await original(function, *args, **kwargs)
        self.owner.db = replacement
        with self.assertRaises(ContractError):
            capture_source(self.knowledge, self.source, snapshot)
        self.owner.db = original
        foreign = copy.copy(self.resource)
        foreign.binding = OwnerBinding('hub-one', 'federation-work', 'foreign', 'work-channel',
            canonical_bytes({**self.scope, 'projectId': 'different'}))
        with self.assertRaises(ContractError):
            bind_sources(self.knowledge, (foreign,))

    async def test_completed_request_expiry_does_not_renew_or_resubmit_work(self):
        original = await self.release()
        class Later(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=10)
        with patch('capability_owner.work_capture.datetime', Later):
            row, deadline = capture_source(self.knowledge, self.source, await self.service.reader.current())
        self.assertEqual(row, original['result'])
        self.assertGreater(deadline, NOW + timedelta(seconds=10))
        self.assertEqual(self.resource._journal.current()['revision'], 2)

    async def test_original_transport_issuer_membership_and_hard_denial_refuse(self):
        await self.release()
        baseline = self.js.messages[-1].data
        selectors = [('transports', ref('transport')), ('issuers', ref('issuer')),
            ('memberships', ref('messages-human'))]
        for collection, reference in selectors:
            current = strict_loads(baseline)
            next(item for item in current['state'][collection] if item['ref'] == reference)['status'] = 'revoked'
            self.js.messages[-1].data = canonical_bytes(current)
            with self.subTest(collection=collection), self.assertRaises(ContractError):
                await self.capture(self.capture_request())
            self.js.messages[-1].data = baseline
        current = strict_loads(baseline)
        denied = copy.deepcopy(next(g for g in current['state']['grants']
            if g['ref'] == self.work_grants['human']['federation-work-release']))
        denied.update(ref=ref('hard-denial'), decision='denied')
        current['state']['grants'].append(denied)
        self.js.messages[-1].data = canonical_bytes(current)
        with self.assertRaises(ContractError):
            await self.capture(self.capture_request())
        self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])

    async def test_cancelled_response_joins_original_capture_before_cleanup(self):
        await self.release()
        from . import knowledge_legacy
        entered, release = threading.Event(), threading.Event()
        original = knowledge_legacy._capture
        def blocked(*args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('test capture was not released')
            return original(*args)
        with patch.object(knowledge_legacy, '_capture', side_effect=blocked):
            request = self.capture_request()
            pending = asyncio.create_task(self.capture(request))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                pending.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await pending
                closing = asyncio.create_task(self.knowledge_endpoint.close(timeout=None))
                await asyncio.sleep(.02)
                self.assertFalse(closing.done())
            finally:
                release.set()
                await asyncio.gather(pending, return_exceptions=True)
            await closing
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)

    async def test_accepted_result_capture_keeps_original_protocol_evidence(self):
        from .test_federated_work_client import FederatedWorkTests
        await self.replace(owner=self.owner)
        self.knowledge_args['work_sources'] = (self.resource,)
        self.knowledge = KnowledgeStorageResource(self.knowledge_binding, self.owner, **self.knowledge_args)
        await self.knowledge_endpoint.close(timeout=None)
        self.knowledge_endpoint = self.open_knowledge_endpoint()
        self.addAsyncCleanup(self.knowledge_endpoint.close, timeout=None)
        offered = await self.work_call(self.work_request('offer', {'target': 'role:falcon/worker',
            'title': 'Accepted title'}, operation='offer-original'))
        row = offered['result']
        claim = FederatedWorkTests.claimed_envelope(self, row)
        incoming = lambda item: {'envelope': item, 'subject': 'am.msg.alice.nick', 'localNode': 'mac'}
        claimed = await self.work_call(self.work_request('claim-envelope', incoming(claim),
            operation='claim-remote', revision=offered['resourceRef']['revision']))
        result = FederatedWorkTests.result_envelope(self, row, claim)
        request = self.work_request('result-envelope', incoming(result), operation='accepted-original',
            revision=claimed['resourceRef']['revision'])
        accepted = await self.work_call(request)
        self.assertEqual(accepted['result']['outcome'], 'delivered')
        original = accepted['result']['work']
        self.source = {'kind': 'fed-result', 'id': original['id'], 'digest': payload_digest(original),
            'resourceRef': accepted['resourceRef'], 'receiptRef': accepted['receiptRef'],
            'operationId': 'accepted-original', 'payloadDigest': payload_digest(strict_loads(request)['claims']['payload'])}
        self.store.db.execute('UPDATE work_items SET result=? WHERE id=?', ('Later result', original['id']))
        captured = await self.capture(self.capture_request())
        self.assertTrue(captured['result']['captured'])
        finding = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertEqual((finding['title'], finding['body'], finding['author'], finding['source']),
            ('result from alice: Accepted title', 'Exact accepted evidence', 'operator', 'auto:result'))
        retained, _ = capture_source(self.knowledge, self.source, await self.service.reader.current())
        self.assertEqual(json.loads(retained['fed_flags'])['accepted_result']['envelope_id'], result['id'])
        self.assertEqual(retained, original)
