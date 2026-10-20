"""Remote controls use actual retained authority and original owned resources."""
import asyncio
import base64
import copy
from types import SimpleNamespace
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from capability_owner.test_reply_service import Connection
from identity.ingress import verify_possession
from identity.test_authority import ref, NOW
from identity.test_native_bridge import HOST_SEED
from identity.test_service import _Clock
from state_owner.configuration_events import ConfigurationEventRoute, ConfigurationEventSource
from state_owner.configuration_subscriptions import ConfigurationSubscriptions
from state_owner import test_configuration_activation as support


class ConfigurationSubscriptionTests(unittest.IsolatedAsyncioTestCase):
    request = support.ConfigurationActivationTests.request
    bridge_request = support.ConfigurationActivationTests.bridge_request
    activation = support.ConfigurationActivationTests.activation
    configuration_request = support.ConfigurationActivationTests.configuration_request
    call = support.ConfigurationActivationTests.call
    revoke = support.ConfigurationActivationTests.revoke

    def setUp(self):
        support.ConfigurationActivationTests.setUp(self)
        patch('state_owner.configuration_subscriptions.datetime', _Clock).start()
        state, facts = self.record['state'], self.row['facts']
        for name, contract, resource in [('subscription-method', 'native-authority-prepare-subscription-call', 'plugin-one'),
                ('subscription-grant', 'configuration-change-subscribe', 'configuration-one')]:
            grant = copy.deepcopy(state['grants'][0])
            grant.update(ref=ref(name), callerRef=ref('host'), actorRef=ref('host'),
                contractId=contract, resourceId=resource)
            state['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)
        facts['grant']['actions'].append('subscribe')
        facts['grant']['resourceIds'].append('configuration-one')
        facts['policy']['decisions'].append({'access': {'action': 'subscribe', 'resourceClass': 'configuration',
            'resourceId': 'configuration-one'}, 'outcome': 'allow'})
        facts['domainBindings'].append({'id': 'subscription', 'contractId': 'configuration-change-subscribe',
            'action': 'subscribe', 'resourceClass': 'configuration', 'resourceIds': ['configuration-one']})
        self.connection = Connection()
        self.source._connection = self.connection
        self.events = ConfigurationEventSource(self.source, ConfigurationEventRoute.from_ledger(self.source._ledger,
            account_public_key='A' * 56, jetstream_domain='SELECTED'))
        self.subscriptions = ConfigurationSubscriptions(self.source, self.events)
        self.source._subscription_service = self.subscriptions
        self.addAsyncCleanup(self.subscriptions.close, timeout=None)
        self.open_id = 'request_' + 'a' * 64
        self.control_number = 0

    async def prepare_open(self, *, subscription_seconds=4):
        self.row['configurationEventSources'] = [await self.events.enrollment_pin()]
        await self.service.handle(self.activation())
        await self.call(self.configuration_request('set'))
        payload = {'resourceRef': dict(ref('configuration-one'), revision=0), 'eventContractId': 'configuration-change',
            'filter': {'owner': copy.deepcopy(self.owner), 'schemaRef': 'config.json'}, 'cursor': self.events.route.cursor(0)}
        payload['filterDigest'] = payload_digest({k: payload[k] for k in ('resourceRef', 'eventContractId', 'filter')})
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('host-transport'), 'grantRef': ref('subscription-grant'),
            'operationId': 'original-subscription', 'expectedVersion': 0, 'contractId': 'configuration-change-subscribe',
            'payload': payload, 'approvalRefs': [], 'issuedAt': NOW.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (NOW + timedelta(seconds=subscription_seconds)).isoformat().replace('+00:00', 'Z')}
        signed = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims, 'signature': sign_claims(claims, HOST_SEED)})
        admitted = await self.service.ingress.admit(signed, cancellation_ref=ref('subscription-cancel'))
        envelope = strict_loads(admitted.envelope)
        self.open_claims = {'purpose': 'agentmux-configuration-subscription-control-v1', 'action': 'open',
            'requestId': self.open_id, 'openRequestId': self.open_id, 'leaseId': None,
            'owner': copy.deepcopy(self.owner), 'operationId': envelope['operation']['operationId'],
            'approvedEnvelopeDigest': payload_digest(envelope), 'filterDigest': payload['filterDigest'],
            'cursor': payload['cursor'], 'signingKeyRef': ref('host-transport'),
            'issuedAt': claims['issuedAt'], 'expiresAt': (NOW + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z'),
            'subscriptionEnvelopeBytes': base64.b64encode(admitted.envelope).decode(),
            'profileId': 'profile-one', 'hubId': 'hub-one', 'authorityId': 'authority-one',
            'replySubject': '_INBOX.abcdefghijklmnop.' + 'a' * 64}
        return self.encoded(self.open_claims)

    def encoded(self, claims):
        return canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims, 'signature': sign_claims(claims, HOST_SEED)})

    def control(self, action, *, cursor=None, lease_id=None, now=NOW, seconds=4):
        self.control_number += 1
        nonce = format(self.control_number, '064x')
        claims = copy.deepcopy(self.open_claims)
        claims.pop('subscriptionEnvelopeBytes')
        claims.update(action=action, requestId='request_' + nonce, leaseId=lease_id,
            cursor=cursor or self.open_claims['cursor'], issuedAt=now.isoformat().replace('+00:00', 'Z'),
            expiresAt=(now + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z'),
            replySubject='_INBOX.abcdefghijklmnop.' + nonce)
        return self.encoded(claims)

    async def invoke(self, raw):
        reply = strict_loads(raw)['claims']['replySubject']
        response = strict_loads(await self.subscriptions.handle(raw, reply_subject=reply))
        verify_possession(response['claims'], response['signature'], self.record['state']['issuers'][0]['publicKey'])
        self.assertEqual(response['claims']['requestDigest'], payload_digest(strict_loads(raw)))
        self.assertEqual(response['claims']['previousCursor'], strict_loads(raw)['claims']['cursor'])
        return response['claims']

    async def test_actual_open_next_close_and_original_open_replay(self):
        raw = await self.prepare_open()
        with patch.object(self.connection, 'subscribe', wraps=self.connection.subscribe) as subscribe:
            opened = await self.invoke(raw)
            self.assertEqual((await self.invoke(raw))['leaseId'], opened['leaseId'])
            self.assertEqual(subscribe.call_count, 1)
        event = await self.invoke(self.control('next', lease_id=opened['leaseId']))
        self.assertEqual(event['outcome'], 'event')
        original = canonical_bytes(strict_loads(self.configuration_js.messages[0].data)['effects'][0]['payload'])
        self.assertEqual(base64.b64decode(event['eventEnvelopeBytes']), original)
        # A close carrying the previous position must not inherit the offered
        # event's cursor, even though the server prepared that event response.
        closed = await self.invoke(self.control('close', lease_id=opened['leaseId']))
        self.assertTrue(closed['joined'])
        self.assertEqual(closed['cursor']['sequence'], 0)
        self.assertFalse(self.source._watches)
        self.assertEqual(self.connection.subscription.drains, 1)

    async def test_lost_open_cancellation_keeps_original_allocation_until_close_joins(self):
        raw = await self.prepare_open()
        self.connection.release.clear()
        opening = asyncio.create_task(self.invoke(raw))
        try:
            await self.connection.subscribed.wait()
            entry = self.subscriptions._entries[self.open_id]
            allocation = entry.opening
            opening.cancel()
            await asyncio.gather(opening, return_exceptions=True)
            closed = await self.invoke(self.control('close', seconds=0.15))
            self.assertFalse(closed['joined'])
            self.assertIs(entry.opening, allocation)
            self.assertFalse(allocation.cancelled())
            self.assertFalse(entry.joined)
            self.connection.release.set()
            closed = await self.invoke(self.control('close'))
            self.assertTrue(closed['joined'])
            self.assertTrue(allocation.done())
            self.assertEqual(self.connection.subscription.drains, 1)
        finally:
            self.connection.release.set()
            await asyncio.gather(opening, return_exceptions=True)

    async def test_close_after_revocation_and_expiry_is_cleanup_only_and_uses_current_signer_view(self):
        raw = await self.prepare_open()
        opened = await self.invoke(raw)
        await self.revoke(ref('host-transport'))
        entry = self.subscriptions._entries[self.open_id]
        await self.subscriptions._begin_close(entry)
        class LateClock(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=20)
        with patch('state_owner.configuration_subscriptions.datetime', LateClock), patch.object(
                self.events, 'next', side_effect=AssertionError('cleanup cannot read events')):
            closed = await self.invoke(self.control('close', now=NOW + timedelta(seconds=20), lease_id=opened['leaseId']))
        self.assertTrue(closed['joined'])
        self.assertEqual(closed['authorityRef']['revision'], 3)
        self.assertEqual(closed['cursor'], self.open_claims['cursor'])

    async def test_close_cancels_and_joins_original_pending_next(self):
        opened = await self.invoke(await self.prepare_open())
        event = await self.invoke(self.control('next', lease_id=opened['leaseId']))
        pending = asyncio.create_task(self.invoke(self.control('next', cursor=event['cursor'], lease_id=opened['leaseId'])))
        entry = self.subscriptions._entries[self.open_id]
        try:
            while entry.next_work is None or entry.next_work.done():
                await asyncio.sleep(0)
            original = entry.next_work
            closed = await self.invoke(self.control('close', cursor=event['cursor'], lease_id=opened['leaseId']))
            self.assertTrue(closed['joined'])
            self.assertTrue(original.done())
            self.assertEqual(closed['cursor'], event['cursor'])
        finally:
            await asyncio.gather(pending, return_exceptions=True)

    async def test_revocation_after_source_read_blocks_event_response(self):
        opened = await self.invoke(await self.prepare_open())
        original = self.events.next
        async def revoke_after_read(cursor):
            delivery = await original(cursor)
            await self.revoke(ref('subscription-grant'))
            return delivery
        with patch.object(self.events, 'next', side_effect=revoke_after_read):
            with self.assertRaisesRegex(ContractError, '^subscription_control_not_authorized$'):
                await self.invoke(self.control('next', lease_id=opened['leaseId']))
        entry = self.subscriptions._entries[self.open_id]
        self.assertEqual(entry.offered['sequence'], 0)
        self.assertTrue((await self.invoke(self.control('close', lease_id=opened['leaseId'])))['joined'])

    async def test_unknown_close_and_unoffered_cursor_never_establish_join(self):
        await self.prepare_open()
        with self.assertRaisesRegex(ContractError, '^subscription_control_allocation_required$'):
            await self.invoke(self.control('close'))
        self.assertFalse(self.subscriptions._entries)
        opened = await self.invoke(self.encoded(self.open_claims))
        with self.assertRaisesRegex(ContractError, '^configuration_subscription_cursor_binding$'):
            await self.invoke(self.control('close', cursor=self.events.route.cursor(1), lease_id=opened['leaseId']))
        self.assertFalse(self.subscriptions._entries[self.open_id].joined)

    async def test_close_waits_original_handed_open_reply_worker(self):
        raw = await self.prepare_open()
        reply = self.open_claims['replySubject']
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.connection.publish
        async def publish(subject, data):
            if subject == reply:
                entered.set()
                await release.wait()
            await original(subject, data)
        self.connection.publish = publish
        opening = asyncio.create_task(self.source._deliver(raw, reply))
        try:
            await entered.wait()
            closed = await self.invoke(self.control('close', seconds=0.15))
            self.assertFalse(closed['joined'])
            self.assertFalse(opening.done())
            release.set()
            self.assertTrue((await self.invoke(self.control('close')))['joined'])
            self.assertTrue(opening.done())
        finally:
            release.set()
            await asyncio.gather(opening, return_exceptions=True)

    async def test_cleanup_control_has_capacity_when_original_request_pool_is_full(self):
        raw = await self.prepare_open()
        opened = await self.invoke(raw)
        await self.source.start(reply_prefix='_INBOX.abcdefghijklmnop.')
        for _ in range(32):
            await self.source._receive(SimpleNamespace(data=raw, reply=self.open_claims['replySubject']))
        self.assertEqual(len(self.source._requests), 32)
        closing = self.control('close', lease_id=opened['leaseId'])
        reply = strict_loads(closing)['claims']['replySubject']
        await self.source._receive(SimpleNamespace(data=closing, reply=reply))
        self.assertEqual(len(self.source._cleanup_requests), 1)
        await asyncio.gather(*tuple(self.source._requests), return_exceptions=True)
        responses = [strict_loads(data)['claims'] for subject, data in self.connection.sent if subject == reply]
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]['outcome'], 'closed')
        if not responses[0]['joined']:
            self.assertTrue((await self.invoke(self.control('close', lease_id=opened['leaseId'])))['joined'])
        self.assertTrue(self.subscriptions._entries[self.open_id].joined)

    async def test_expired_original_event_returns_explicit_resync_without_advancing(self):
        original = self.producer.prepare_change_event
        async def short_event(payload, *, operation):
            operation = copy.deepcopy(operation)
            operation['deadline'] = (NOW + timedelta(seconds=0.1)).isoformat().replace('+00:00', 'Z')
            return await original(payload, operation=operation)
        with patch.object(self.producer, 'prepare_change_event', side_effect=short_event):
            opened = await self.invoke(await self.prepare_open())
        later = NOW + timedelta(seconds=0.2)
        class LateClock(_Clock):
            @classmethod
            def now(cls, tz=None):
                return later
        with patch('state_owner.configuration.datetime', LateClock), patch('state_owner.configuration_subscriptions.datetime', LateClock):
            response = await self.invoke(self.control('next', lease_id=opened['leaseId'], now=later))
        self.assertEqual(response['outcome'], 'resync-required')
        self.assertEqual(response['cursor'], self.open_claims['cursor'])
        self.assertNotIn('eventEnvelopeBytes', response)
        self.assertEqual(self.subscriptions._entries[self.open_id].cursor['sequence'], 0)

    async def test_failed_drain_retains_original_watch_for_explicit_close_retry(self):
        opened = await self.invoke(await self.prepare_open())
        entry = self.subscriptions._entries[self.open_id]
        watch, subscription = entry.watch, entry.watch.subscription
        original = subscription.drain
        attempts = 0
        async def drain():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError('private drain detail')
            await original()
        subscription.drain = drain
        with self.assertRaisesRegex(ContractError, '^configuration_subscription_cleanup_incomplete$'):
            await self.invoke(self.control('close', lease_id=opened['leaseId']))
        self.assertFalse(entry.joined)
        self.assertIs(entry.watch, watch)
        self.assertIs(entry.watch.subscription, subscription)
        self.assertEqual(attempts, 1)
        with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
            await self.call(self.configuration_request('read', revision=1))
        closed = await self.invoke(self.control('close', lease_id=opened['leaseId']))
        self.assertTrue(closed['joined'])
        self.assertTrue(watch.done.is_set())
        self.assertEqual(attempts, 2)

    async def test_actual_host_fence_blocks_event_but_keeps_cleanup_available(self):
        import tempfile
        from pathlib import Path
        from state_owner.backup_host import BackupHost
        from state_owner.checkpoint_host import CheckpointHost
        from state_owner.configuration_host import ConfigurationHost
        from state_owner.history import OwnerHistory
        raw = await self.prepare_open()
        await self.source.close()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        identity = self.source._ledger._identity
        history = OwnerHistory(root / 'history.sqlite', self.binding, stream_identity=identity)
        self.addCleanup(history.close)
        checkpoint_root = root / 'checkpoints'
        checkpoint_root.mkdir(mode=0o700)
        checkpoint = CheckpointHost(checkpoint_root / 'checkpoint', stream='OWNER',
            binding=self.binding, stream_identity=identity, commit_ref=ref('configuration-checkpoint'))
        directories = [root / name for name in ('backup', 'inventory', 'keys')]
        for directory in directories:
            directory.mkdir(mode=0o700)
        backup = BackupHost(*directories, destination_id='configuration-backup', binding=self.binding, stream_identity=identity)
        backup.enroll_key('backup-key')
        self.connection.jetstream = lambda **kwargs: self.configuration_js
        from identity.test_authority import SEED
        host = ConfigurationHost.from_enrolled_host(self.connection, authority=self.service.reader,
            stream='OWNER', binding=self.binding, stream_identity=identity, retention=self.source._ledger._retention,
            history=history, jetstream_domain='SELECTED', reply_prefix='_INBOX.abcdefghijklmnop',
            owner=self.owner, schema_ref='config.json', schema_resources={'config.json': b'{"type":"object"}'},
            issuer_ref=ref('issuer'), signing_seed=SEED, checkpoint_host=checkpoint,
            backup_host=backup, backup_key_id='backup-key', event_producer=self.producer,
            event_account_public_key='A' * 56, event_jetstream_domain='SELECTED')
        self.addAsyncCleanup(host.close, timeout=None)
        await host.start()
        self.source, self.events, self.subscriptions = host.owner, host.events, host.subscriptions
        opened = await self.invoke(raw)
        original = self.events.next
        async def fence_after_read(cursor):
            delivery = await original(cursor)
            host._closed = True
            return delivery
        with patch.object(self.events, 'next', side_effect=fence_after_read):
            with self.assertRaisesRegex(ContractError, '^configuration_host_unavailable$'):
                await self.invoke(self.control('next', lease_id=opened['leaseId']))
        closing = self.control('close', lease_id=opened['leaseId'])
        response = strict_loads(await host.handle_subscription(closing,
            reply_subject=strict_loads(closing)['claims']['replySubject']))
        self.assertTrue(response['claims']['joined'])
        self.assertEqual(response['claims']['cursor']['sequence'], 0)

    async def test_failed_watch_flush_automatically_joins_original_admitted_allocation(self):
        raw = await self.prepare_open()
        with patch.object(self.connection, 'flush', side_effect=OSError('private flush detail')):
            with self.assertRaisesRegex(ContractError, '^configuration_subscription_unavailable$'):
                await self.invoke(raw)
        entry = self.subscriptions._entries[self.open_id]
        self.assertIsNotNone(entry.timer)
        self.assertIsNotNone(entry.closing)
        opening, watch = entry.opening, entry.watch
        await asyncio.wait_for(asyncio.shield(entry.closing), 2)
        self.assertIs(entry.opening, opening)
        self.assertIs(entry.watch, watch)
        self.assertTrue(entry.joined)
        self.assertTrue(entry.timer.done())
        self.assertTrue(watch.done.is_set())
        self.assertEqual(self.connection.subscription.drains, 1)
        self.assertFalse(self.source._watches)

    async def test_expiry_during_pending_subscribe_retains_then_joins_original_allocation(self):
        raw = await self.prepare_open(subscription_seconds=2)
        self.connection.release.clear()
        opening = asyncio.create_task(self.invoke(raw))
        try:
            await asyncio.wait_for(self.connection.subscribed.wait(), 2)
            entry = self.subscriptions._entries[self.open_id]
            original, watch = entry.opening, entry.watch
            subscription_work = watch._allocation
            await asyncio.wait_for(entry.stop.wait(), 3)
            self.assertIsNotNone(entry.closing)
            self.assertFalse(entry.joined)
            self.assertFalse(original.cancelled())
            self.assertFalse(subscription_work.cancelled())
            self.assertIn(watch, self.source._watches)
            opening.cancel()
            await asyncio.gather(opening, return_exceptions=True)
            self.assertFalse(original.cancelled())
            self.connection.release.set()
            await asyncio.wait_for(asyncio.shield(entry.closing), 2)
            self.assertIs(entry.opening, original)
            self.assertIs(watch._allocation, subscription_work)
            self.assertTrue(entry.joined)
            self.assertTrue(original.done())
            self.assertTrue(watch.done.is_set())
            self.assertEqual(self.connection.subscription.drains, 1)
        finally:
            self.connection.release.set()
            await asyncio.gather(opening, return_exceptions=True)

    async def test_older_authorized_next_cannot_roll_back_newer_acknowledgment(self):
        opened = await self.invoke(await self.prepare_open())
        event = await self.invoke(self.control('next', lease_id=opened['leaseId']))
        older_raw = self.control('next', lease_id=opened['leaseId'])
        newer_raw = self.control('next', cursor=event['cursor'], lease_id=opened['leaseId'])
        admitted, release, duplicate_admitted = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original = self.subscriptions._admit
        newer_admissions = 0
        async def admit(raw, *args, **kwargs):
            nonlocal newer_admissions
            result = await original(raw, *args, **kwargs)
            if raw == older_raw:
                admitted.set()
                await release.wait()
            elif raw == newer_raw:
                newer_admissions += 1
                if newer_admissions == 2:
                    duplicate_admitted.set()
            return result
        older = newer = duplicate = None
        try:
            with patch.object(self.subscriptions, '_admit', side_effect=admit):
                older = asyncio.create_task(self.invoke(older_raw))
                await asyncio.wait_for(admitted.wait(), 2)
                newer = asyncio.create_task(self.invoke(newer_raw))
                entry = self.subscriptions._entries[self.open_id]
                async with asyncio.timeout(2):
                    while entry.cursor['sequence'] != 1:
                        await asyncio.sleep(0)
                work = entry.next_work
                duplicate = asyncio.create_task(self.invoke(newer_raw))
                await asyncio.wait_for(duplicate_admitted.wait(), 2)
                self.assertIs(entry.next_work, work)
                release.set()
                with self.assertRaisesRegex(ContractError, '^configuration_subscription_busy$'):
                    await older
                self.assertEqual(entry.cursor, event['cursor'])
                self.assertIs(entry.next_work, work)
                self.assertFalse(work.done())
                closed = await self.invoke(self.control('close', cursor=event['cursor'], lease_id=opened['leaseId']))
                self.assertTrue(closed['joined'])
                self.assertEqual(closed['cursor'], event['cursor'])
        finally:
            release.set()
            await self.subscriptions.close(timeout=None)
            await asyncio.gather(*(task for task in (older, newer, duplicate) if task is not None), return_exceptions=True)
