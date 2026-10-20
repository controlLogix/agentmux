"""Actual enrolled knowledge bridge against original SQLite and source owners."""
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.fed.plugins.knowledge import Knowledge
from hub.tests.test_fed_unit import policy
from identity.test_authority import ref, SEED, NOW
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding
from .knowledge import KnowledgeStorageResource
from .knowledge_legacy import LegacyKnowledgeActor
from .knowledge_bridge_service import KnowledgeBridgeService, verify_knowledge_bridge_reply
from . import test_message_bridge_owner as message_support
from .test_messages import MessageFixture


class KnowledgeBridgeFixture(message_support.BridgeOwnerFixture):
    def setUp(self):
        super().setUp()
        from .messages import LegacyMessageActor
        finding = copy.deepcopy(next(g for g in self.record['state']['grants'] if g['ref'] == ref('messages-write')))
        finding.update(ref=ref('knowledge-finding-grant'), callerRef=ref('service'), actorRef=ref('service'),
            contractId='federation-message-finding')
        self.record['state']['grants'].append(finding)
        self.legacy_grants['service']['federation-message-finding'] = finding['ref']
        self.legacy_actors = (self.legacy_actors[0], LegacyMessageActor(canonical_bytes(ref('service')),
            canonical_bytes(ref('legacy-service-transport')), 'federation', canonical_bytes(self.legacy_grants['service'])))
        self.knowledge_grants = {}
        state = self.record['state']
        template = next(g for g in state['grants'] if g['ref'] == ref('messages-write'))
        actors = []
        for identity, actions in (('human', ('share', 'approve', 'read', 'inspect', 'outcome')),
                ('service', ('index', 'capture', 'withdraw', 'read', 'inspect', 'outcome'))):
            grants = {}
            for action in actions:
                contract = 'federation-knowledge-' + action
                grant = copy.deepcopy(template)
                grant.update(ref=ref('knowledge-' + identity + '-' + action), callerRef=ref(identity),
                    actorRef=ref(identity), contractId=contract)
                state['grants'].append(grant)
                grants[contract] = grant['ref']
            self.knowledge_grants[identity] = grants
            actors.append(LegacyKnowledgeActor(canonical_bytes(ref(identity)),
                canonical_bytes(ref('transport' if identity == 'human' else 'legacy-service-transport')),
                'operator' if identity == 'human' else 'federation', canonical_bytes(grants)))
        self.knowledge_actors = tuple(actors)
        self.js.messages[0].data = canonical_bytes(self.record)

    async def asyncSetUp(self):
        await MessageFixture.asyncSetUp(self)
        self.message_resource = self.resource
        await self.reply_service.close()
        patch('capability_owner.knowledge_legacy.datetime', _Clock).start()
        patch('capability_owner.knowledge_bridge_service.datetime', _Clock).start()
        for statement in Knowledge.tables:
            self.store.db.execute(statement)
        self.resource = KnowledgeStorageResource(OwnerBinding('hub-one', 'federation-knowledge', 'task-one',
            'knowledge-channel', canonical_bytes(self.scope)), self.owner, repository='falcon',
            actors=self.message_resource.actors, plugin_identity_ref=ref('plugin'), instance_id='plugin-one',
            legacy_actors=self.knowledge_actors, message_sources=(self.message_resource,))
        self.endpoint = KnowledgeBridgeService(self.service.ingress, resources=(self.resource,),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            signing_key_ref=ref('issuer'), signing_seed=SEED)
        self.addAsyncCleanup(self.endpoint.close, timeout=None)

    def knowledge_request(self, action, value=None, *, operation='knowledge-one', revision=1, identity=None):
        identity = identity or ('service' if action in ('index', 'capture', 'withdraw') else 'human')
        contract = 'federation-knowledge-' + action
        payload = {'resourceRef': {**ref('task-one'), 'revision': revision}, 'input': value or {}}
        if action not in ('read', 'inspect', 'outcome'):
            payload['attribution'] = 'operator' if identity == 'human' else 'federation'
        self.claims.update(operationId=operation, expectedVersion=revision, contractId=contract,
            transportRef=ref('transport' if identity == 'human' else 'legacy-service-transport'),
            grantRef=self.knowledge_grants[identity][contract], payload=payload,
            replySubject='_INBOX.knowledge_bridge_00001')
        return self.request()

    async def knowledge_call(self, raw):
        response = await self.endpoint.handle(raw,
            received_reply_subject=strict_loads(raw)['claims']['replySubject'])
        return verify_knowledge_bridge_reply(response, raw,
            public_key=self.record['state']['issuers'][0]['publicKey'], service_identity_ref=ref('service'),
            service_instance_id='ingress-one', signing_key_ref=ref('issuer'), now=NOW)

    def item(self):
        from hub.fed import envelope
        return envelope.make('knowledge', 'nick', 'mac', self.resource.repository_id, '*',
            {'title': 'Finding', 'body': 'Original knowledge body', 'tags': ['kept'],
             'ref': 'AMUX-45', 'author': 'operator', 'source': 'explicit'})


class KnowledgeBridgeTests(KnowledgeBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def test_share_signed_replay_original_outcome_and_reads(self):
        item = self.item()
        raw = self.knowledge_request('share', {'envelope': item})
        first = await self.knowledge_call(raw)
        self.assertEqual(first['result']['id'], item['id'])
        self.assertEqual(await self.knowledge_call(raw), first)
        query = {'contractId': 'federation-knowledge-share', 'operationId': 'knowledge-one',
            'payloadDigest': payload_digest(strict_loads(raw)['claims']['payload'])}
        outcome = await self.knowledge_call(self.knowledge_request('outcome', query, operation='recover'))
        self.assertEqual(outcome['receiptRef'], first['receiptRef'])
        for value, field in (({'command': 'show', 'id': item['id']}, 'row'),
                ({'command': 'search', 'query': 'Original', 'limit': 10}, 'rows'),
                ({'command': 'recent', 'limit': 10}, 'rows'), ({'command': 'panel'}, 'panel')):
            result = await self.knowledge_call(self.knowledge_request('read', value, operation='read-' + value['command']))
            self.assertTrue(result[field])
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM fed_outbox')), 1)

    async def test_index_and_withdraw_keep_remote_identity_and_repo_boundaries(self):
        self.owner.policy = policy(peers={'alice': {'trust': 'approve'}})
        item = self.item()
        item.update({'from': 'alice', 'node': 'remote'})
        item['data']['author'] = 'remote/author'
        value = {'envelope': item, 'subject': 'am.know.alice.' + item['rid'], 'localNode': 'mac'}
        await self.knowledge_call(self.knowledge_request('index', value))
        row = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertEqual((row['author'], row['untrusted']), ('remote/author', 1))
        self.owner.policy = policy(peers={'alice': {'trust': 'deny'}})
        await self.knowledge_call(self.knowledge_request('withdraw', {'peer': 'alice'}, operation='withdraw', revision=2))
        self.assertIsNotNone(self.store.q1('SELECT withdrawn FROM p_knowledge_items')['withdrawn'])

    async def test_capture_handoff_requires_the_actual_committed_message_operation(self):
        value = MessageFixture.value(self, 'original handoff text', 'publish')
        value['envelope']['type'] = value['envelope']['data']['kind'] = 'handoff'
        await self.bridge_prepare('send', value=value)
        self.claims['payload']['input']['requestedTo'] = 'peer:alice/falcon/worker'
        admitted = await self.service.ingress.admit(self.request(), cancellation_ref=ref('cancel'))
        sent = await self.message_resource.legacy(self.service.reader, admitted.envelope)
        original = strict_loads(admitted.envelope)['operation']
        source = {'kind': 'handoff', 'id': value['envelope']['id'], 'resourceRef': sent['resourceRef'],
            'operationId': original['operationId'], 'payloadDigest': original['payloadDigest']}
        result = await self.knowledge_call(self.knowledge_request('capture', {'source': source}))
        self.assertTrue(result['result']['captured'])
        row = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertEqual((row['title'], row['body'], row['source']),
            ('handoff to peer:alice/falcon/worker', 'original handoff text', 'auto:handoff'))
        source['operationId'] = 'missing-source'
        with self.assertRaises(ContractError):
            await self.knowledge_call(self.knowledge_request('capture', {'source': source}, operation='forged', revision=2))
        self.assertEqual(len(self.store.q('SELECT * FROM p_knowledge_items')), 1)

    async def test_missing_source_and_receipt_failure_leave_no_partial_finding(self):
        source = {'kind': 'work-released', 'id': 'missing', 'digest': 'sha256:' + 'a' * 64}
        with self.assertRaises(ContractError):
            await self.knowledge_call(self.knowledge_request('capture', {'source': source}))
        raw = self.knowledge_request('share', {'envelope': self.item()})
        with patch.object(self.resource._journal, '_set', side_effect=RuntimeError('private failure')):
            with self.assertRaises(ContractError):
                await self.knowledge_call(raw)
        for table in ('p_knowledge_items', 'p_knowledge_fts', 'fed_outbox', 'fed_audit', 'fed_state'):
            self.assertEqual(self.store.q('SELECT * FROM ' + table), [])

    async def test_capture_uses_the_actual_released_work_record_and_refuses_changed_digest(self):
        self.store.repo_add('falcon')
        agent = self.store.register('falcon', 'worker', 'one', 'codex', {})
        self.store.set_state(agent, 'ready')
        work = self.store.work_create('virtual:operator', 'falcon', 'role:falcon/worker', 'Original task')
        self.assertEqual(self.store.claim(agent, work_id=work['id'])['claimed']['id'], work['id'])
        released = self.store.release(agent, work['id'], 'done', 'Actual completion', 'mac')
        source = {'kind': 'work-released', 'id': work['id'], 'digest': payload_digest(released)}
        result = await self.knowledge_call(self.knowledge_request('capture', {'source': source}))
        self.assertTrue(result['result']['captured'])
        row = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertEqual((row['body'], row['author'], row['ref']), ('Actual completion', 'worker/one', work['id']))
        source['digest'] = 'sha256:' + 'a' * 64
        with self.assertRaises(ContractError):
            await self.knowledge_call(self.knowledge_request('capture', {'source': source},
                operation='changed-work', revision=2))

    async def test_incoming_optional_fields_keep_original_defaults_and_custom_source(self):
        item = self.item()
        item.update({'from': 'alice', 'node': 'remote'})
        item['data'] = {'title': 'Old peer finding', 'source': 'custom-existing-source'}
        value = {'envelope': item, 'subject': 'am.know.alice.' + item['rid'], 'localNode': 'mac'}
        result = await self.knowledge_call(self.knowledge_request('index', value))
        self.assertEqual(result['result']['outcome'], 'delivered')
        row = self.store.q1('SELECT * FROM p_knowledge_items')
        self.assertEqual((row['title'], row['author'], row['tags'], row['ref'], row['source']),
            ('Old peer finding', None, '', None, 'custom-existing-source'))

    async def test_held_knowledge_approval_keeps_original_data_and_untrusted_framing(self):
        from hub.fed import ledger
        item = self.item()
        item.update({'from': 'alice', 'node': 'remote'})
        subject = 'am.know.alice.' + item['rid']
        qid = ledger.quarantine_add(self.store, item, subject, 'know', 'alice', 'old approval policy')
        value = {'envelope': item, 'subject': subject, 'localNode': 'mac', 'quarantineId': qid, 'privileged': False}
        first = await self.knowledge_call(self.knowledge_request('approve', value))
        self.assertEqual(first['result']['id'], item['id'])
        self.assertEqual(self.store.q1('SELECT untrusted FROM p_knowledge_items')['untrusted'], 1)
        self.assertEqual(ledger.quarantine_get(self.store, qid)['state'], 'held')
        ledger.quarantine_decide(self.store, qid, 'approved', 'operator')
        self.assertEqual(await self.knowledge_call(self.knowledge_request('approve', value)), first)

    async def test_denied_held_knowledge_never_indexes_or_records_a_receipt(self):
        from hub.fed import ledger
        item = self.item()
        item.update({'from': 'alice', 'node': 'remote'})
        subject = 'am.know.alice.' + item['rid']
        qid = ledger.quarantine_add(self.store, item, subject, 'know', 'alice', 'old approval policy')
        value = {'envelope': item, 'subject': subject, 'localNode': 'mac', 'quarantineId': qid, 'privileged': False}
        raw = self.knowledge_request('approve', value)
        self.owner.policy = policy(peers={'alice': {'trust': 'deny'}})
        with self.assertRaises(ContractError):
            await self.knowledge_call(raw)
        self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])
