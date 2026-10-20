"""Receive the legacy owners' bounded replies on an enrolled connection."""
from datetime import datetime, timedelta, timezone
import unittest

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.client_launch_connection import ConnectionFailure, selected_publish_subjects
from hub.tests import test_client_launch_connection as connection_support
from identity.application_client import ApplicationClientKey
from identity import test_knowledge_client as knowledge_support


class StorageReplyLimits(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = connection_support.ClientLaunchConnection()
        await self.fixture.asyncSetUp()
        self.owner, self.client = self.fixture.owner, self.fixture.client
        await self.fixture.connect()
        self.fixture.exchange_fixture()
        self.key = ApplicationClientKey(knowledge_support.material())
        self.owner._signer = self.key
        self.owner._publish_subjects = selected_publish_subjects(self.key)
        self.client.max_payload = 1048576
        self.addAsyncCleanup(self.close)

    async def close(self):
        await self.owner.close(deadline=self.fixture.deadline())

    def request(self):
        route = self.key.selection['knowledgeCommands']
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1',
            **{k: self.key.selection[k] for k in ('hubId', 'profileId', 'authorityId')},
            'transportRef': route['transportRef'],
            'grantRef': route['grantRefs']['federation-knowledge-read'],
            'operationId': 'large-knowledge-read', 'expectedVersion': 1,
            'contractId': 'federation-knowledge-read',
            'payload': {'resourceRef': route['resourceRef'],
                'input': {'command': 'show', 'id': 'finding-one'}},
            'approvalRefs': [], 'replySubject': '_INBOX.abcdefghijklmnop.request_one',
            'issuedAt': now.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (now + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')}
        return self.key.sign_command(claims, subject=route['subject'], now=now)

    async def exchange(self, request):
        return await self.owner._exchange_message(request,
            subject=self.key.selection['knowledgeCommands']['subject'], binding_epoch=None,
            deadline=self.fixture.deadline(), cleanup_deadline=self.fixture.deadline())

    async def test_enrolled_knowledge_accepts_owner_frame_through_one_mib(self):
        for size in (65537, 1048576):
            with self.subTest(size=size):
                self.fixture.subscription.next_msg.return_value.data = b'x' * size
                self.assertEqual(await self.exchange(self.request()), b'x' * size)
                self.assertEqual(self.client.subscribe.call_args.kwargs,
                    {'pending_msgs_limit': 1, 'pending_bytes_limit': 1048576})
                self.assertFalse(self.owner._subscriptions)
                self.assertIsNone(self.owner._exchange_task)
        self.assertEqual(self.fixture.subscription.unsubscribe.await_count, 2)
        self.client.close.assert_not_awaited()

    async def test_over_limit_reply_is_refused_and_original_resources_join(self):
        self.fixture.subscription.next_msg.return_value.data = b'x' * 1048577
        with self.assertRaisesRegex(ConnectionFailure, '^application_reply_refused$'):
            await self.exchange(self.request())
        original = self.owner._exchange_task
        self.assertTrue(original.done())
        await self.close()
        self.assertIs(self.owner._exchange_task, original)
        self.fixture.subscription.unsubscribe.assert_awaited_once()
        self.client.close.assert_awaited_once()
        self.assertFalse(self.owner._subscriptions)

    async def test_large_reply_on_another_inbox_still_refuses(self):
        self.fixture.subscription.next_msg.return_value.data = b'x' * 65537
        self.fixture.subscription.next_msg.return_value.subject = '_INBOX.otherprincipalxx.request_one'
        with self.assertRaisesRegex(ConnectionFailure, '^application_reply_refused$'):
            await self.exchange(self.request())
        await self.close()
        self.fixture.subscription.unsubscribe.assert_awaited_once()
        self.client.close.assert_awaited_once()

    async def test_changed_signed_request_cannot_select_larger_inbox(self):
        packet = strict_loads(self.request())
        packet['claims']['payload']['input']['id'] = 'substituted'
        with self.assertRaises(ContractError):
            await self.exchange(canonical_bytes(packet))
        self.client.subscribe.assert_not_awaited()
        self.client.publish.assert_not_awaited()
        self.assertIsNone(self.owner._exchange_task)
