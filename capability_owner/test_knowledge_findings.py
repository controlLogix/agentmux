"""Finding notifications reuse the original message owner and indexed source."""
import copy
import unittest

from agentmux_contracts import ContractError, canonical_bytes
from hub.fed.knowledge_services import KnowledgeOwner
from hub.fed.plugins.knowledge import Knowledge
from identity.test_authority import ref
from .messages import LegacyMessageActor
from . import test_message_bridge_owner as support


class FindingMessageTests(support.BridgeOwnerFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        super().setUp()
        grant = copy.deepcopy(next(g for g in self.record['state']['grants'] if g['ref'] == ref('messages-write')))
        grant.update(ref=ref('finding-grant'), callerRef=ref('service'), actorRef=ref('service'),
            contractId='federation-message-finding')
        self.record['state']['grants'].append(grant)
        self.legacy_grants['service']['federation-message-finding'] = grant['ref']
        self.legacy_actors = (self.legacy_actors[0], LegacyMessageActor(canonical_bytes(ref('service')),
            canonical_bytes(ref('legacy-service-transport')), 'federation',
            canonical_bytes(self.legacy_grants['service'])))
        self.js.messages[0].data = canonical_bytes(self.record)

    async def asyncSetUp(self):
        await support.MessageBridgeServiceTests.asyncSetUp(self)
        for statement in Knowledge.tables:
            self.store.db.execute(statement)
        self.store.repo_add('falcon')
        self.recipient = self.store.register('falcon', 'worker', 'one', 'codex', {})
        self.store.set_state(self.recipient, 'ready')
        from hub.fed import envelope
        self.finding = envelope.make('knowledge', 'alice', 'other', self.resource.repository_id, '*',
            {'title': 'Original finding', 'body': 'Full private finding body', 'author': 'peer/author',
             'tags': ['tag'], 'ref': 'AMUX-45', 'source': 'explicit'})
        KnowledgeOwner(self.owner)._index(self.finding, 'falcon', 'approve', True)

    async def finding_request(self, *, operation='finding-one', revision=1, finding=None, recipient=None):
        self.claims.update(operationId=operation, expectedVersion=revision,
            contractId='federation-message-finding', transportRef=ref('legacy-service-transport'),
            grantRef=ref('finding-grant'), payload={'resourceRef': {**ref('task-one'), 'revision': revision},
                'attribution': 'federation', 'input': {'envelope': finding or self.finding,
                    'recipient': recipient or self.recipient, 'localNode': 'mac'}})
        admitted = await self.service.ingress.admit(self.request(), cancellation_ref=ref('cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return admitted.envelope

    async def test_original_indexed_source_produces_one_finding_with_same_deduplication(self):
        first = await self.resource.legacy(self.service.reader, await self.finding_request())
        row = self.store.q1('SELECT * FROM messages')
        self.assertEqual(row['idem_key'], f"know:{self.finding['id']}:{self.recipient}")
        self.assertIn('(untrusted data)', row['body'])
        self.assertNotIn('Full private finding body', row['body'])
        again = await self.resource.legacy(self.service.reader,
            await self.finding_request(operation='another', revision=2))
        self.assertEqual(first['result']['id'], again['result']['id'])
        self.assertEqual(len(self.store.q('SELECT * FROM messages')), 1)
        self.assertEqual(len(self.store.q('SELECT * FROM deliveries')), 1)

    async def test_missing_or_changed_source_and_foreign_target_never_post(self):
        changed = copy.deepcopy(self.finding)
        changed['data']['title'] = 'forged title'
        with self.assertRaises(ContractError):
            await self.resource.legacy(self.service.reader, await self.finding_request(finding=changed))
        from hub import names
        with self.assertRaises(ContractError):
            await self.resource.legacy(self.service.reader,
                await self.finding_request(recipient=names.session_name('other', 'worker', 'one')))
        self.assertEqual(self.store.q('SELECT * FROM messages'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])

    async def test_current_notification_setting_preserves_original_noop(self):
        self.owner.fcfg['notify_findings'] = False
        result = await self.resource.legacy(self.service.reader, await self.finding_request())
        self.assertEqual(result['result']['deliveryOutcome'], 'not_hosted')
        self.assertEqual(self.store.q('SELECT * FROM messages'), [])
