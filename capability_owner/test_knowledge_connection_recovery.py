"""Signed knowledge recovery through the real client, with controlled broker I/O.

Connection admission is controlled as in the existing message bridge tests.
Owner authorization, signatures, receipts and original SQLite effects are real;
this does not qualify the Hub facade, selected startup or a live broker.
"""
import asyncio
import copy
from datetime import timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import canonical_bytes, payload_digest, strict_loads
from hub.client_launch_binding import ClientBindingState
from hub.client_launch_connection import ClientConnectionOwner, ConnectionFailure, MessageOutcomeUnconfirmed
from identity.application_client import ApplicationClientKey
from identity.test_authority import NOW, ref
from identity.test_knowledge_client import material
from identity.test_service import _Clock
from .test_knowledge_bridge_owner import KnowledgeBridgeFixture


class KnowledgeConnectionRecoveryTests(KnowledgeBridgeFixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.expiry = (NOW + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')
        for target in ('hub.client_launch_connection.datetime', 'identity.application_client.datetime'):
            clock = patch(target, _Clock)
            clock.start()
            self.addCleanup(clock.stop)

    def open_client(self, *, lose_reply=False):
        selected = material()
        selected['scope'] = copy.deepcopy(self.scope)
        route = selected['knowledgeCommands']
        route.update(subject=self.reply_service.subject, transportRef=ref('transport'),
                     grantRefs=copy.deepcopy(self.knowledge_grants['human']))
        route['repository']['repositoryId'] = self.resource.repository_id
        key = ApplicationClientKey(selected)
        client = SimpleNamespace(is_connected=True, max_payload=1048576,
                                 flush=AsyncMock(), close=AsyncMock())
        binding = ClientBindingState(client, public_key=key.selection['replyIssuerPublicKey'],
            signing_key_ref=ref('issuer'), caller_ref=ref('human'), scope=self.scope)
        owner = ClientConnectionOwner(client, binding,
            command_subject='amx.v1.h.hub-one.o.org-one.identity.authority-one.command',
            reply_prefix='_INBOX.knowledge_client_000001', signer=key)
        owner._connected = True
        owner._current_command_binding = AsyncMock(return_value={'validUntil': self.expiry})
        owner._require_query_binding = Mock(return_value={'validUntil': self.expiry})
        self.addAsyncCleanup(owner.close, deadline=asyncio.get_running_loop().time() + 10)
        wire = SimpleNamespace(subscriptions=[], requests=[], responses=[], limits=[])

        async def subscribe(subject, **options):
            wire.limits.append(options['pending_bytes_limit'])
            async def next_message(**_options):
                if lose_reply:
                    raise TimeoutError()
                return SimpleNamespace(subject=subject, data=wire.responses[-1])
            subscription = SimpleNamespace(unsubscribe=AsyncMock(), next_msg=next_message)
            wire.subscriptions.append(subscription)
            return subscription

        async def publish(subject, raw, *, reply):
            self.assertEqual(subject, route['subject'])
            wire.requests.append(raw)
            wire.responses.append(await self.endpoint.handle(raw, received_reply_subject=reply))

        client.subscribe, client.publish = subscribe, publish
        return owner, client, wire

    async def command(self, owner, action, value, *, operation, revision=1):
        payload = {'resourceRef': {**ref('task-one'), 'revision': revision}, 'input': value}
        if action == 'share':
            payload['attribution'] = 'operator'
        return await owner.knowledge_command(contract_id='federation-knowledge-' + action,
            operation_id=operation, payload=payload, expires_at=self.expiry,
            deadline=asyncio.get_running_loop().time() + 3,
            cleanup_deadline=asyncio.get_running_loop().time() + 4)

    def assert_single_finding(self, item):
        rows = self.store.q('SELECT * FROM p_knowledge_items')
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['id'], rows[0]['body']), (item['id'], item['data']['body']))
        outbox = self.store.q('SELECT * FROM fed_outbox')
        self.assertEqual(len(outbox), 1)
        self.assertEqual(strict_loads(outbox[0]['payload']), item)
        self.assertEqual(len(self.store.q('SELECT rowid FROM p_knowledge_fts')), 1)
        self.assertEqual(len(self.store.q(
            'SELECT rowid FROM p_knowledge_fts WHERE p_knowledge_fts MATCH ?', ('Original',))), 1)

    async def test_replacement_client_recovers_committed_share_and_reads_large_original(self):
        original, client, wire = self.open_client(lose_reply=True)
        item = self.item()
        item['data']['body'] = 'Original ' + 'z' * 80000
        with self.assertRaises(MessageOutcomeUnconfirmed):
            await self.command(original, 'share', {'envelope': item}, operation='lost-knowledge')
        retained = original.command_request
        self.assertEqual(retained, wire.requests[0])
        self.assertFalse(original._subscriptions)
        self.assertIsNone(original._exchange_task)
        wire.subscriptions[0].unsubscribe.assert_awaited_once()
        client.close.assert_not_awaited()
        self.assert_single_finding(item)
        await original.close(deadline=asyncio.get_running_loop().time() + 2)
        client.close.assert_awaited_once()

        replacement, _, fresh = self.open_client()
        claims = strict_loads(retained)['claims']
        query = {'contractId': claims['contractId'], 'operationId': claims['operationId'],
                 'payloadDigest': payload_digest(claims['payload'])}
        recovered = await self.command(replacement, 'outcome', query,
                                      operation='recover-knowledge', revision=2)
        committed = strict_loads(wire.responses[0])['claims']['result']
        self.assertEqual({name: recovered[name] for name in committed}, committed)
        for name, value in query.items():
            self.assertEqual(recovered[name], value)
        self.assertEqual(recovered['result']['id'], item['id'])
        self.assertNotEqual(fresh.requests[0], retained)
        self.assertNotEqual(strict_loads(fresh.requests[0])['claims']['replySubject'], claims['replySubject'])
        shown = await self.command(replacement, 'read', {'command': 'show', 'id': item['id']},
                                   operation='show-large', revision=2)
        self.assertEqual(shown['row']['body'], item['data']['body'])
        self.assertGreater(len(fresh.responses[-1]), 65536)
        self.assertEqual(fresh.limits, [1048576, 1048576])
        self.assertFalse(replacement._subscriptions)
        for subscription in fresh.subscriptions:
            subscription.unsubscribe.assert_awaited_once()
        self.assert_single_finding(item)

    async def test_replacement_recovery_refuses_revoked_original_grant(self):
        owner, _, wire = self.open_client(lose_reply=True)
        item = self.item()
        with self.assertRaises(MessageOutcomeUnconfirmed):
            await self.command(owner, 'share', {'envelope': item}, operation='lost-revoked')
        claims = strict_loads(owner.command_request)['claims']
        self.claims.update(operationId='revoke-knowledge-share', contractId='identity-revoke',
            grantRef=ref('grant'), expectedVersion=2,
            payload={'authorityId': 'authority-one',
                     'targetRef': self.knowledge_grants['human']['federation-knowledge-share']})
        receipt = strict_loads(await self.service.handle(self.request()))
        self.assertEqual(receipt['claims']['receipt']['decision'], 'allowed')
        replacement, client, fresh = self.open_client()
        query = {'contractId': claims['contractId'], 'operationId': claims['operationId'],
                 'payloadDigest': payload_digest(claims['payload'])}
        with self.assertRaises(ConnectionFailure):
            await self.command(replacement, 'outcome', query, operation='revoked-recovery', revision=2)
        self.assertEqual(fresh.responses, [])
        client.close.assert_awaited_once()
        self.assertFalse(replacement._subscriptions)
        self.assert_single_finding(item)

    async def test_changed_signed_request_refuses_before_owner_effect(self):
        owner, client, wire = self.open_client()
        raw = self.knowledge_request('share', {'envelope': self.item()})
        owner._signer.verify_command_request(raw, subject=self.reply_service.subject)
        packet = strict_loads(raw)
        packet['claims']['payload']['input']['envelope']['data']['body'] = 'substituted'
        from agentmux_contracts import ContractError
        with self.assertRaises(ContractError):
            await owner._exchange_message(canonical_bytes(packet), subject=self.reply_service.subject,
                binding_epoch=None, deadline=asyncio.get_running_loop().time() + 3,
                cleanup_deadline=asyncio.get_running_loop().time() + 4)
        self.assertEqual(wire.requests, [])
        self.assertEqual(wire.subscriptions, [])
        self.assertEqual(self.store.q('SELECT * FROM p_knowledge_items'), [])
        self.assertEqual(self.store.q('SELECT * FROM fed_outbox'), [])
        client.close.assert_not_awaited()
