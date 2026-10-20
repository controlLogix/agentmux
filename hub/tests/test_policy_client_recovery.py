"""Policy timeouts retain the original exchange and permit only joined recovery."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import time
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import canonical_bytes, payload_digest, sign_claims, strict_loads
from hub.client_launch_connection import PolicyOutcomeUnconfirmed, selected_publish_subjects
from hub.client_launch_session import ApplicationClientSession, ApplicationSessionFailure
from hub.tests import test_client_launch_connection as connection_support
from hub.tests.test_client_launch_binding import SEED
from identity.application_client import ApplicationClientKey
from identity.test_authority import ref
from identity.test_federation_policy_commands import material


class PolicySessionRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.mode = 'timeout'
        self.release = threading.Event()
        self.policy_requests, self.subscriptions = [], []
        self.session = ApplicationClientSession(SimpleNamespace(
            application_client='/private/client.key', application_connection='/private/connection'))
        async def opening(*_args, **_kwargs):
            fixture = self.fixture = connection_support.ClientLaunchConnection()
            await fixture.asyncSetUp()
            fixture.fixture.scope['projectId'] = 'project-one'
            fixture.fixture.state._scope = copy.deepcopy(fixture.fixture.scope)
            base = fixture.authentication_fixture()
            value = material(strict_loads(base._material))
            key = self.key = ApplicationClientKey(value)
            owner, client = fixture.owner, fixture.client
            owner._signer = key
            owner._publish_subjects = selected_publish_subjects(key)
            client.max_payload = 1048576
            await fixture.connect()
            await owner.authenticate(key, deadline=fixture.deadline(4), cleanup_deadline=fixture.deadline(5))
            original_subscribe = client.subscribe.side_effect
            original_publish = client.publish.side_effect
            async def publish(subject, raw, **options):
                if subject == value['federationPolicyCommands']['subject']:
                    self.policy_requests.append(raw)
                else:
                    await original_publish(subject, raw, **options)
            async def subscribe(subject, **options):
                if owner._authenticating:
                    return await original_subscribe(subject, **options)
                async def receive(*, timeout):
                    if self.mode == 'nats-timeout':
                        from nats.errors import TimeoutError as NatsTimeoutError
                        raise NatsTimeoutError()
                    if self.mode in ('timeout', 'slow-close'):
                        await asyncio.sleep(timeout)
                        raise TimeoutError()
                    if self.mode == 'blocked':
                        try:
                            await asyncio.sleep(timeout)
                        except asyncio.CancelledError:
                            while not self.release.is_set():
                                await asyncio.sleep(.001)
                            raise
                    if self.mode == 'late-invalid':
                        try:
                            await asyncio.sleep(timeout)
                        except asyncio.CancelledError:
                            await asyncio.sleep(.02)
                            return SimpleNamespace(subject=subject, data=b'x' * 65537)
                    if self.mode == 'loss':
                        await owner.disconnected()
                        raise TimeoutError()
                    if self.mode == 'invalid':
                        return SimpleNamespace(subject=subject, data=b'{}')
                    if self.mode == 'oversize':
                        return SimpleNamespace(subject=subject, data=b'x' * 65537)
                    return SimpleNamespace(subject=subject, data=self.response(self.policy_requests[-1]))
                async def unsubscribe():
                    if self.mode == 'slow-close':
                        while not self.release.is_set():
                            await asyncio.sleep(.001)
                subscription = SimpleNamespace(next_msg=AsyncMock(side_effect=receive),
                    unsubscribe=AsyncMock(side_effect=unsubscribe))
                self.subscriptions.append((subscription, options))
                owner.own_subscription(subscription)
                return subscription
            client.publish.side_effect, client.subscribe.side_effect = publish, subscribe
            return owner
        with patch('hub.client_launch_session.open_application_client', side_effect=opening):
            self.session.start(deadline=time.monotonic() + 5)
        self.addCleanup(self.session.join_final)
        self.addCleanup(self.release.set)

    def response(self, raw):
        packet = strict_loads(raw)
        request = packet['claims']
        route = self.key.selection['federationPolicyCommands']
        current = {'format': 'amx-federation-policy-current-v1',
            'configurationRef': route['configurationRef'], 'owner': route['owner'], 'target': route['target'],
            'projected': False, 'state': None, 'operation': None,
            'originalOperationId': None, 'originalPayloadDigest': None}
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-federation-policy-client-response-v1',
            'requestDigest': payload_digest(packet), 'replySubject': request['replySubject'], 'kind': 'current',
            'requestBinding': {**{k: request[k] for k in ('hubId', 'profileId', 'authorityId',
                'transportRef', 'grantRef', 'contractId', 'operationId', 'expectedVersion')},
                'callerRef': self.key.selection['callerRef'], 'scope': self.key.selection['scope'],
                'payloadDigest': payload_digest(request['payload'])},
            'configurationRef': request['payload']['configurationRef'], 'owner': route['owner'],
            'target': route['target'], 'resultBytes': base64.b64encode(canonical_bytes(current)).decode(),
            'authorityRef': ref('authority-one'), 'signingKeyRef': route['replyIssuerRef'],
            'issuedAt': now.isoformat().replace('+00:00', 'Z'), 'validUntil': request['expiresAt']}
        return canonical_bytes({'claims': claims, 'signature': sign_claims(claims, SEED)})

    def call(self, operation, *, seconds=.15):
        route = self.key.selection['federationPolicyCommands']
        return self.session.federation_policy_command(contract_id='configuration-read',
            operation_id=operation, expected_version=0,
            payload={'configurationRef': route['configurationRef'], 'owner': route['owner']},
            expires_at=(datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat(),
            deadline=time.monotonic() + seconds)

    def wait_original(self):
        future = self.session._command_future
        if future is not None:
            try:
                future.result(timeout=3)
            except PolicyOutcomeUnconfirmed:
                pass

    def test_lost_reply_joins_original_then_accepts_fresh_signed_read(self):
        with self.assertRaises(ApplicationSessionFailure):
            self.call('original-read')
        self.wait_original()
        original = self.fixture.owner.command_request
        self.assertTrue(self.fixture.owner._exchange_task is None)
        self.assertFalse(self.fixture.owner._subscriptions)
        self.subscriptions[0][0].unsubscribe.assert_awaited_once()
        self.fixture.client.close.assert_not_awaited()
        self.mode = 'reply'
        result = self.call('recovery-read', seconds=2)
        self.assertEqual(result.kind, 'current')
        self.assertEqual(strict_loads(result.data)['configurationRef']['revision'], 0)
        self.assertEqual(strict_loads(original)['claims']['operationId'], 'original-read')
        self.assertEqual([strict_loads(r)['claims']['operationId'] for r in self.policy_requests],
            ['original-read', 'recovery-read'])
        self.assertTrue(all(options['pending_bytes_limit'] == 65536 for _, options in self.subscriptions))
        self.assertIsNone(self.session._command_future)
        self.assertTrue(self.session.close(deadline=time.monotonic() + 3))
        self.assertFalse(self.session._thread.is_alive())

    def test_invalid_signed_reply_cannot_release_failed_future_for_another_command(self):
        self.mode = 'invalid'
        with self.assertRaises(ApplicationSessionFailure):
            self.call('invalid-reply', seconds=1)
        original = self.session._command_future
        self.assertIsNotNone(original)
        self.assertTrue(original.done())
        self.mode = 'reply'
        with self.assertRaises(ApplicationSessionFailure):
            self.call('must-not-start', seconds=1)
        self.assertIs(self.session._command_future, original)
        self.assertEqual(len(self.policy_requests), 1)
        self.fixture.client.close.assert_awaited_once()

    def test_actual_nats_timeout_type_allows_a_fresh_signed_read_after_join(self):
        self.mode = 'nats-timeout'
        with self.assertRaises(ApplicationSessionFailure):
            self.call('nats-original-read', seconds=1)
        self.wait_original()
        self.assertIsNone(self.fixture.owner._exchange_task)
        self.assertFalse(self.fixture.owner._subscriptions)
        self.fixture.client.close.assert_not_awaited()
        self.mode = 'reply'
        self.assertEqual(self.call('after-nats-timeout', seconds=2).kind, 'current')
        self.assertEqual([strict_loads(r)['claims']['operationId'] for r in self.policy_requests],
            ['nats-original-read', 'after-nats-timeout'])

    def test_connection_loss_is_not_a_recoverable_policy_timeout(self):
        self.mode = 'loss'
        with self.assertRaises(ApplicationSessionFailure):
            self.call('lost-connection', seconds=1)
        original = self.session._command_future
        self.assertTrue(original.done())
        self.assertNotIsInstance(original.exception(), PolicyOutcomeUnconfirmed)
        with self.assertRaises(ApplicationSessionFailure):
            self.call('must-not-reconnect', seconds=1)
        self.assertEqual(len(self.policy_requests), 1)
        self.fixture.client.connect.assert_awaited_once()

    def test_oversize_policy_reply_does_not_use_legacy_storage_limit(self):
        self.mode = 'oversize'
        with self.assertRaises(ApplicationSessionFailure):
            self.call('oversize-policy', seconds=1)
        self.assertNotIsInstance(self.session._command_future.exception(), PolicyOutcomeUnconfirmed)
        self.assertEqual(self.subscriptions[0][1]['pending_bytes_limit'], 65536)
        self.fixture.client.close.assert_awaited_once()

    def test_invalid_reply_after_waiter_timeout_is_still_a_terminal_refusal(self):
        self.mode = 'late-invalid'
        with self.assertRaises(ApplicationSessionFailure):
            self.call('late-invalid-policy')
        original = self.session._command_future
        try:
            original.result(timeout=2)
        except Exception:
            pass
        self.assertTrue(original.done())
        self.assertNotIsInstance(original.exception(), PolicyOutcomeUnconfirmed)
        with self.assertRaises(ApplicationSessionFailure):
            self.call('must-not-replace-late-invalid')
        self.assertEqual(len(self.policy_requests), 1)
        self.fixture.client.close.assert_awaited_once()

    def test_running_original_future_cannot_be_replaced(self):
        self.mode = 'blocked'
        try:
            with self.assertRaises(ApplicationSessionFailure):
                self.call('running-original')
            original = self.session._command_future
            self.assertFalse(original.done())
            with self.assertRaises(ApplicationSessionFailure):
                self.call('must-not-replace')
            self.assertIs(self.session._command_future, original)
            self.assertEqual(len(self.policy_requests), 1)
        finally:
            self.release.set()
        self.wait_original()
        self.mode = 'reply'
        self.assertEqual(self.call('after-original-joined', seconds=2).kind, 'current')

    def test_incomplete_inbox_cleanup_cannot_release_original_future(self):
        self.mode = 'slow-close'
        try:
            with self.assertRaises(ApplicationSessionFailure):
                self.call('incomplete-cleanup')
            original = self.session._command_future
            try:
                original.result(timeout=2)
            except Exception:
                pass
            self.assertTrue(original.done())
            self.assertNotIsInstance(original.exception(), PolicyOutcomeUnconfirmed)
            with self.assertRaises(ApplicationSessionFailure):
                self.call('must-not-replace')
            self.assertIs(self.session._command_future, original)
            self.assertEqual(len(self.policy_requests), 1)
            self.assertTrue(self.fixture.owner._subscriptions)
        finally:
            self.release.set()
        self.assertTrue(self.session.close(deadline=time.monotonic() + 3))
        self.assertFalse(self.fixture.owner._subscriptions)
        self.subscriptions[0][0].unsubscribe.assert_awaited_once()
