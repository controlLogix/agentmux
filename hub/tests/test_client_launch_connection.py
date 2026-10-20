"""Offline connection ownership checks; no transport or enrollment is admitted."""
import asyncio
from datetime import datetime, timedelta, timezone
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from hub.client_launch_connection import ClientConnectionOwner, ConnectionFailure
from hub.tests import test_client_launch_binding as binding_tests


class ClientLaunchConnection(unittest.IsolatedAsyncioTestCase):
    def retain_signer(self, signer):
        # Configure the owned offline fixture before starting authentication.
        self.owner._signer = signer

    def install_short_binding(self):
        from agentmux_contracts import payload_digest, strict_loads
        now = datetime.now(timezone.utc)
        current = self.owner.binding.current(self.client, now=now)
        request = {**strict_loads(self.requests[-1])['claims'], 'issuedAt': now.isoformat().replace('+00:00', 'Z'),
            'requestId': 'short-binding-request', 'nonce': 'c' * 64,
            'expiresAt': (now + timedelta(milliseconds=100)).isoformat().replace('+00:00', 'Z')}
        response = {**current, 'issuedAt': request['issuedAt'], 'requestId': request['requestId'], 'nonce': request['nonce'],
            'validUntil': request['expiresAt'], 'requestDigest': payload_digest(request)}
        attempt = self.owner.binding.begin(self.client, binding_tests.signed(request))
        self.owner.binding.accept(self.client, attempt, binding_tests.signed(response), now=now)
        return now

    async def test_short_current_binding_gets_one_fresh_admission_on_same_connection(self):
        signer = self.authentication_fixture()
        self.retain_signer(signer)
        await self.connect()
        await self.owner.authenticate(signer, deadline=self.deadline(3), cleanup_deadline=self.deadline(3))
        now = self.install_short_binding()
        old_epoch = self.owner.binding._epoch
        old_attempt = self.owner.binding._latest_attempt
        observed = await self.owner._current_command_binding(deadline=self.deadline(3),
            cleanup_deadline=self.deadline(3), required_until=now + timedelta(seconds=2))
        self.assertEqual(len(self.requests), 4)
        self.assertIsNot(old_epoch, self.owner.binding._epoch)
        self.assertIsNot(old_attempt, self.owner.binding._latest_attempt)
        self.assertGreater(datetime.fromisoformat(observed['validUntil']), now + timedelta(seconds=2))
        self.assertIs(self.owner.require_connection(), self.client)
        self.client.close.assert_not_awaited()
        await self.owner.close(deadline=self.deadline())

    async def test_adequate_current_binding_does_not_repeat_admission(self):
        signer = self.authentication_fixture()
        self.retain_signer(signer)
        await self.connect()
        await self.owner.authenticate(signer, deadline=self.deadline(3), cleanup_deadline=self.deadline(3))
        epoch = self.owner.binding._epoch
        await self.owner._current_command_binding(deadline=self.deadline(3), cleanup_deadline=self.deadline(3),
            required_until=datetime.now(timezone.utc) + timedelta(seconds=1))
        self.assertEqual(len(self.requests), 2)
        self.assertIs(self.owner.binding._epoch, epoch)
        await self.owner.close(deadline=self.deadline())

    async def test_short_binding_cannot_survive_refused_current_admission(self):
        signer = self.authentication_fixture()
        self.retain_signer(signer)
        await self.connect()
        await self.owner.authenticate(signer, deadline=self.deadline(3), cleanup_deadline=self.deadline(3))
        now = self.install_short_binding()
        self.authentication_fixture(wrong_scope=True)
        with self.assertRaises(ConnectionFailure):
            await self.owner._current_command_binding(deadline=self.deadline(3), cleanup_deadline=self.deadline(3),
                required_until=now + timedelta(seconds=2))
        self.assertEqual(len(self.requests), 1)
        self.client.close.assert_awaited_once()
        with self.assertRaises(ConnectionFailure):
            self.owner.require_connection()

    async def asyncSetUp(self):
        fixture = binding_tests.ClientLaunchBinding()
        fixture.setUp()
        self.client = fixture.connection = type('Client', (), {})()
        fixture.state._connection = self.client
        self.client.is_connected = True
        self.client.connect, self.client.close = AsyncMock(), AsyncMock()
        self.owner = ClientConnectionOwner(self.client, fixture.state,
            command_subject='amx.v1.h.hub-one.o.org-one.identity.authority-one.command',
            reply_prefix='_INBOX.abcdefghijklmnop')
        self.fixture = fixture

    def deadline(self, seconds=1):
        return asyncio.get_running_loop().time() + seconds

    async def connect(self):
        return await self.owner._connect({}, deadline=self.deadline(), cleanup_deadline=self.deadline())

    async def test_controls_are_fixed_and_same_client_is_retained(self):
        await self.owner._connect({'allow_reconnect': True, 'max_reconnect_attempts': -1},
                                  deadline=self.deadline(), cleanup_deadline=self.deadline())
        selected = self.client.connect.call_args.kwargs
        self.assertFalse(selected['allow_reconnect'])
        self.assertEqual(selected['max_reconnect_attempts'], 1)
        self.assertEqual(selected['disconnected_cb'], self.owner.disconnected)
        self.assertIs(self.owner.require_connection(), self.client)
        with self.assertRaises(ConnectionFailure):
            await self.connect()
        await self.owner.close(deadline=self.deadline())
        self.client.connect.assert_awaited_once()
        self.client.close.assert_awaited_once()

    async def test_disconnect_and_reconnect_cannot_restore_binding(self):
        await self.connect()
        self.fixture.accept()
        await self.owner.disconnected()
        with self.assertRaises(ConnectionFailure):
            self.owner.require_connection()
        await self.owner.reconnected()
        with self.assertRaises(ConnectionFailure):
            self.owner.require_connection()
        await self.owner.close(deadline=self.deadline())

    async def test_pending_close_rejoins_original_task(self):
        release = asyncio.Event()
        self.client.close.side_effect = release.wait
        await self.connect()
        with self.assertRaises(ConnectionFailure) as pending:
            await self.owner.close(deadline=self.deadline(0))
        self.assertIs(pending.exception.owner, self.owner)
        original = self.owner._close_task
        release.set()
        await self.owner.close(deadline=self.deadline())
        self.assertIs(self.owner._close_task, original)
        self.client.close.assert_awaited_once()

    async def test_failed_consumed_close_is_never_replaced(self):
        self.client.close.side_effect = OSError('PRIVATE_SENTINEL')
        await self.connect()
        for _ in range(2):
            with self.assertRaises(ConnectionFailure) as failure:
                await self.owner.close(deadline=self.deadline())
            self.assertNotIn('PRIVATE_SENTINEL', str(failure.exception))
            self.assertNotIn('PRIVATE_SENTINEL', repr(failure.exception))
        self.client.close.assert_awaited_once()

    async def test_cancelled_connect_joins_setup_before_original_close(self):
        entered, release = asyncio.Event(), asyncio.Event()
        events = []
        async def connect(**_options):
            entered.set()
            try:
                await release.wait()
            finally:
                events.append('connect-joined')
        async def close():
            events.append('close')
        self.client.connect.side_effect, self.client.close.side_effect = connect, close
        caller = asyncio.create_task(self.connect())
        await entered.wait()
        caller.cancel()
        with self.assertRaises(ConnectionFailure):
            await caller
        self.assertEqual(events, ['connect-joined', 'close'])
        self.assertTrue(self.owner._connect_task.done())
        self.client.close.assert_awaited_once()

    async def test_loss_during_setup_refuses_connected_flag(self):
        async def connect(**_):
            await self.owner.disconnected()
        self.client.connect.side_effect = connect
        with self.assertRaises(ConnectionFailure):
            await self.connect()
        self.client.close.assert_awaited_once()

    def exchange_fixture(self):
        self.fixture.request['replySubject'] = '_INBOX.abcdefghijklmnop.request_one'
        self.subscription = SimpleNamespace(unsubscribe=AsyncMock(), next_msg=AsyncMock(
            return_value=SimpleNamespace(subject=self.fixture.request['replySubject'], data=b'signed-response')))
        async def subscribe(*_args, **_kwargs):
            self.owner.own_subscription(self.subscription)
            self.owner.check_open()
            return self.subscription
        self.client.subscribe = AsyncMock(side_effect=subscribe)
        self.client.publish, self.client.flush = AsyncMock(), AsyncMock()
        return binding_tests.signed(self.fixture.request)

    async def exchange(self, raw):
        return await self.owner.exchange(raw, deadline=self.deadline(), cleanup_deadline=self.deadline())

    async def test_exchange_uses_pinned_command_and_private_inbox(self):
        await self.connect()
        raw = self.exchange_fixture()
        self.assertEqual(await self.exchange(raw), b'signed-response')
        self.client.publish.assert_awaited_once_with(self.owner._command_subject, raw,
                                    reply='_INBOX.abcdefghijklmnop.request_one')
        self.subscription.unsubscribe.assert_awaited_once()
        self.assertFalse(self.owner._subscriptions)
        self.client.close.assert_not_awaited()
        await self.owner.close(deadline=self.deadline())

    async def test_other_inbox_and_malformed_request_never_publish(self):
        await self.connect()
        self.exchange_fixture()
        self.fixture.request['replySubject'] = '_INBOX.otherprincipalxx.request_one'
        for raw in (binding_tests.signed(self.fixture.request), b'{}', b'PRIVATE_SENTINEL'):
            with self.assertRaisesRegex(ConnectionFailure, '^application_request_refused$'):
                await self.exchange(raw)
        self.client.subscribe.assert_not_awaited()
        self.client.publish.assert_not_awaited()
        await self.owner.close(deadline=self.deadline())

    async def test_partial_subscribe_failure_retains_and_retires_original(self):
        await self.connect()
        raw = self.exchange_fixture()
        async def partial(*_args, **_kwargs):
            self.owner.own_subscription(self.subscription)
            raise OSError('PRIVATE_SENTINEL')
        self.client.subscribe.side_effect = partial
        with self.assertRaisesRegex(ConnectionFailure, '^application_request_unconfirmed$'):
            await self.exchange(raw)
        self.subscription.unsubscribe.assert_awaited_once()
        self.client.close.assert_awaited_once()
        self.assertFalse(self.owner._subscriptions)

    async def test_cancelled_exchange_joins_response_before_close(self):
        await self.connect()
        raw = self.exchange_fixture()
        entered, release = asyncio.Event(), asyncio.Event()
        events = []
        async def next_msg(**_):
            entered.set()
            try:
                await release.wait()
            finally:
                events.append('response-joined')
        async def close():
            events.append('close')
        self.subscription.next_msg.side_effect = next_msg
        self.client.close.side_effect = close
        caller = asyncio.create_task(self.exchange(raw))
        await entered.wait()
        caller.cancel()
        with self.assertRaises(ConnectionFailure):
            await caller
        self.assertEqual(events, ['response-joined', 'close'])
        self.subscription.unsubscribe.assert_awaited_once()

    async def test_failed_unsubscribe_is_not_replaced_or_hidden_by_client_close(self):
        await self.connect()
        raw = self.exchange_fixture()
        self.subscription.unsubscribe.side_effect = OSError('PRIVATE_SENTINEL')
        with self.assertRaisesRegex(ConnectionFailure, '^application_connection_cleanup_pending$'):
            await self.exchange(raw)
        with self.assertRaises(ConnectionFailure):
            await self.owner.close(deadline=self.deadline())
        self.assertEqual(len(self.owner._subscriptions), 1)
        self.subscription.unsubscribe.assert_awaited_once()
        self.client.close.assert_awaited_once()

    async def test_disconnect_before_publish_is_refused(self):
        await self.connect()
        raw = self.exchange_fixture()
        async def disconnect(**_):
            await self.owner.disconnected()
        self.client.flush.side_effect = disconnect
        with self.assertRaises(ConnectionFailure):
            await self.exchange(raw)
        self.client.publish.assert_not_awaited()

    async def test_concurrent_exchange_cannot_replace_original(self):
        await self.connect()
        raw = self.exchange_fixture()
        entered, release = asyncio.Event(), asyncio.Event()
        async def next_msg(**_):
            entered.set()
            await release.wait()
            return SimpleNamespace(subject=self.fixture.request['replySubject'], data=b'response')
        self.subscription.next_msg.side_effect = next_msg
        original = asyncio.create_task(self.exchange(raw))
        await entered.wait()
        with self.assertRaisesRegex(ConnectionFailure, '^application_request_in_progress$'):
            await self.exchange(raw)
        release.set()
        self.assertEqual(await original, b'response')
        self.client.publish.assert_awaited_once()
        await self.owner.close(deadline=self.deadline())

    def authentication_fixture(self, *, wrong_scope=False, wrong_binding_lifetime=False):
        import base64
        from agentmux_contracts import strict_loads, payload_digest
        from identity.application_client import ApplicationClientKey
        selection = {key: self.fixture.request[key] for key in (
            'hubId', 'profileId', 'authorityId', 'instanceId', 'releaseDigest',
            'policyRef', 'workspaceRef', 'transportRef', 'grantRef')}
        selection.update(callerRef=binding_tests.ref('caller'), scope=self.fixture.scope,
            replyIssuerRef=binding_tests.ref('issuer'), replyIssuerPublicKey=self.fixture.state._public_key)
        signer = ApplicationClientKey({**selection, 'purpose': 'agentmux-application-client-key-v1',
                                      'seed': base64.b64encode(binding_tests.SEED).decode()})
        self.requests, self.inboxes = [], []
        async def subscribe(subject, **_options):
            async def next_msg(**_):
                request = strict_loads(self.requests[-1])['claims']
                discovery = request['purpose'] == 'agentmux-application-discovery-request-v1'
                claims = {key: value for key, value in request.items()
                          if key not in ('purpose', 'replySubject', 'expiresAt')}
                claims.update(purpose='agentmux-application-' + ('discovery' if discovery else 'binding') + '-response-v1',
                    generation=2, lifetimeId='f' * 64, requestDigest=payload_digest(request),
                    callerRef=selection['callerRef'], scope=selection['scope'],
                    signingKeyRef=selection['replyIssuerRef'], authorityRef=binding_tests.ref('authority-one'),
                    authoritySequence=1, validUntil=request['expiresAt'])
                if wrong_scope:
                    claims['scope'] = {**selection['scope'], 'projectId': 'substituted'}
                if not discovery and wrong_binding_lifetime:
                    claims['lifetimeId'] = 'e' * 64
                return SimpleNamespace(subject=subject, data=binding_tests.signed(claims))
            sub = SimpleNamespace(unsubscribe=AsyncMock(), next_msg=AsyncMock(side_effect=next_msg))
            self.owner.own_subscription(sub)
            self.inboxes.append(sub)
            return sub
        async def publish(_subject, raw, **_options):
            self.requests.append(raw)
        self.client.subscribe = AsyncMock(side_effect=subscribe)
        self.client.publish = AsyncMock(side_effect=publish)
        self.client.flush = AsyncMock()
        return signer

    async def test_real_signer_discovers_then_binds_current_lifetime(self):
        from agentmux_contracts import strict_loads
        signer = self.authentication_fixture()
        await self.connect()
        claims = await self.owner.authenticate(signer, deadline=self.deadline(), cleanup_deadline=self.deadline())
        self.assertEqual(claims['generation'], 2)
        self.assertEqual(claims['lifetimeId'], 'f' * 64)
        self.assertEqual(len(self.requests), 2)
        discovery, binding = [strict_loads(raw)['claims'] for raw in self.requests]
        self.assertNotIn('generation', discovery)
        self.assertNotIn('lifetimeId', discovery)
        self.assertEqual(binding['generation'], claims['generation'])
        self.assertEqual(binding['lifetimeId'], claims['lifetimeId'])
        for field in ('requestId', 'nonce', 'replySubject'):
            self.assertNotEqual(discovery[field], binding[field])
        for sub in self.inboxes:
            sub.unsubscribe.assert_awaited_once()
        self.assertIs(self.owner.require_connection(), self.client)
        await self.owner.close(deadline=self.deadline())

    async def test_signed_wrong_discovery_scope_stops_before_binding(self):
        signer = self.authentication_fixture(wrong_scope=True)
        await self.connect()
        with self.assertRaisesRegex(ConnectionFailure, '^application_binding_unavailable$'):
            await self.owner.authenticate(signer, deadline=self.deadline(), cleanup_deadline=self.deadline())
        self.assertEqual(len(self.requests), 1)
        self.client.close.assert_awaited_once()

    async def test_signed_wrong_binding_lifetime_never_installs_binding(self):
        signer = self.authentication_fixture(wrong_binding_lifetime=True)
        await self.connect()
        with self.assertRaisesRegex(ConnectionFailure, '^application_binding_unavailable$'):
            await self.owner.authenticate(signer, deadline=self.deadline(), cleanup_deadline=self.deadline())
        self.assertEqual(len(self.requests), 2)
        self.client.close.assert_awaited_once()
        with self.assertRaises(ValueError):
            self.owner.binding.current(self.client, now=binding_tests.NOW)

    async def test_oversized_reply_closes_original_resources(self):
        await self.connect()
        raw = self.exchange_fixture()
        self.subscription.next_msg.return_value.data = b'x' * 65537
        with self.assertRaisesRegex(ConnectionFailure, '^application_request_unconfirmed$'):
            await self.exchange(raw)
        self.subscription.unsubscribe.assert_awaited_once()
        self.client.close.assert_awaited_once()

    async def test_reply_on_another_subject_is_refused(self):
        await self.connect()
        raw = self.exchange_fixture()
        self.subscription.next_msg.return_value.subject = '_INBOX.otherprincipalxx.request_one'
        with self.assertRaisesRegex(ConnectionFailure, '^application_request_unconfirmed$'):
            await self.exchange(raw)
        self.subscription.unsubscribe.assert_awaited_once()
        self.client.close.assert_awaited_once()

    async def test_fixed_allocator_uses_shared_tls_factory_and_enrolled_pins(self):
        from hub.client_launch_connection import _new_connection_owner
        signer = self.authentication_fixture()
        client = SimpleNamespace(is_connected=False, close=AsyncMock())
        with patch('hub.nats_transport.new_client', return_value=client) as allocate:
            owner = _new_connection_owner(signer, reply_prefix='_INBOX.abcdefghijklmnop')
        allocate.assert_called_once_with(require_tls=True)
        self.assertIs(client._agentmux_session, owner)
        self.assertEqual(owner.binding._caller_ref, signer.selection['callerRef'])
        with self.assertRaises(ConnectionFailure):
            owner.require_connection()
        await owner.close(deadline=self.deadline())
