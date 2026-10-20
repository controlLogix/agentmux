"""Atomic configuration event retention, publication and retained replay."""
import asyncio
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from capability_owner.test_reply_service import Connection
from identity.test_authority import ref, NOW
from identity.test_service import _Clock
from state_owner.configuration_events import ConfigurationEventRoute, ConfigurationEventSource
from state_owner import test_configuration_activation as support


class ConfigurationEventTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.ConfigurationActivationTests.setUp
    request = support.ConfigurationActivationTests.request
    bridge_request = support.ConfigurationActivationTests.bridge_request
    activation = support.ConfigurationActivationTests.activation
    configuration_request = support.ConfigurationActivationTests.configuration_request
    call = support.ConfigurationActivationTests.call
    revoke = support.ConfigurationActivationTests.revoke

    def event_source(self, **changes):
        options = {'account_public_key': 'A' * 56, 'jetstream_domain': 'SELECTED'}
        options.update(changes)
        route = ConfigurationEventRoute.from_ledger(self.source._ledger, **options)
        return ConfigurationEventSource(self.source, route)

    async def test_atomic_intent_confirmed_before_publish_and_exact_retry_never_resigns(self):
        replay = self.event_source()
        pin = await replay.enrollment_pin()
        self.assertEqual(pin, {'configurationRef': dict(ref('configuration-one'), revision=0),
            'schemaRef': 'config.json', 'sourceDigest': replay.route.source_digest,
            'streamCreated': replay.route.stream_created})
        await self.service.handle(self.activation())
        connection = Connection()
        self.source._connection = connection
        original = connection.publish
        async def publish(subject, raw):
            record = strict_loads(self.configuration_js.messages[-1].data)
            self.assertEqual(canonical_bytes(record['effects'][0]['payload']), raw)
            self.assertEqual(record['state']['revision'], 1)
            await original(subject, raw)
        connection.publish = publish
        raw = self.configuration_request('set')
        self.configuration_js.lose_ack = True
        with patch.object(self.producer, 'prepare_change_event', wraps=self.producer.prepare_change_event) as prepare:
            await self.call(raw)
            await self.call(raw)
            self.assertEqual(prepare.call_count, 1)
        self.assertEqual(len(self.configuration_js.messages), 1)
        self.assertEqual(len(connection.sent), 2)
        self.assertEqual(connection.sent[0], connection.sent[1])
        from native_security.nats_credentials import service_policy
        policy = service_policy(role='configuration', hub_id='hub-one', entity_id='configuration-one',
            scope=strict_loads(self.binding.scope), stream='OWNER', reply_prefix='_INBOX.event_fixture_0001')
        self.assertIn(connection.sent[0][0], policy.publish_subjects)
        event = strict_loads(connection.sent[0][1])
        self.assertEqual(set(event['payload']), {'configurationRef', 'owner', 'schemaRef', 'configurationChecksum'})
        self.assertEqual((await replay.enrollment_pin())['configurationRef']['revision'], 1)
        cursor = replay.route.cursor(0)
        delivery = await replay.next(cursor)
        self.assertEqual(delivery.envelope, connection.sent[0][1])
        self.assertEqual(cursor['sequence'], 0)
        self.assertEqual(delivery.cursor['sequence'], 1)
        self.assertIsNone(await replay.next(delivery.cursor))

    async def test_cancelled_committed_publish_retry_retains_original_event(self):
        await self.service.handle(self.activation())
        raw = self.configuration_request('set')
        original = self.configuration_js.publish
        async def cancelled(*args, **kwargs):
            await original(*args, **kwargs)
            raise asyncio.CancelledError()
        with patch.object(self.producer, 'prepare_change_event', wraps=self.producer.prepare_change_event) as prepare:
            with patch.object(self.configuration_js, 'publish', side_effect=cancelled):
                with self.assertRaises(asyncio.CancelledError):
                    await self.call(raw)
            retained = self.configuration_js.messages[0].data
            await self.call(raw)
            self.assertEqual(prepare.call_count, 1)
        self.assertEqual(self.configuration_js.messages[0].data, retained)

    async def test_producer_revoked_after_signing_cannot_append(self):
        await self.service.handle(self.activation())
        original = self.producer.prepare_change_event
        async def prepare(*args, **kwargs):
            prepared = await original(*args, **kwargs)
            await self.revoke(ref('configuration-event-grant'))
            return prepared
        with patch.object(self.producer, 'prepare_change_event', side_effect=prepare):
            with self.assertRaises(ContractError):
                await self.call(self.configuration_request('set'))
        self.assertEqual(self.configuration_js.messages, [])

    async def test_retained_source_rechecks_publication_permission(self):
        await self.service.handle(self.activation())
        await self.call(self.configuration_request('set'))
        replay = self.event_source()
        cursor = replay.route.cursor(0)
        await self.revoke(ref('configuration-event-grant'))
        with self.assertRaisesRegex(ContractError, '^configuration_event_publication_not_authorized$'):
            await replay.next(cursor)
        self.assertEqual(cursor['sequence'], 0)

    async def test_expired_event_requires_explicit_resync_without_advancing_or_resigning(self):
        await self.service.handle(self.activation())
        raw = self.configuration_request('set')
        await self.call(raw)
        retained = self.configuration_js.messages[0].data
        replay = self.event_source()
        cursor = replay.route.cursor(0)
        class LateClock(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(minutes=10)
        with patch('state_owner.configuration.datetime', LateClock):
            with self.assertRaisesRegex(ContractError, '^configuration_event_resync_required$'):
                await replay.next(cursor)
        self.assertEqual(cursor['sequence'], 0)
        self.assertEqual(self.configuration_js.messages[0].data, retained)

    async def test_cursor_binds_account_domain_aggregate_coverage_and_creation(self):
        await self.service.handle(self.activation())
        await self.call(self.configuration_request('set'))
        replay = self.event_source()
        cursor = replay.route.cursor(0)
        for changes in ({'account_public_key': 'A' + 'B' * 55}, {'jetstream_domain': 'OTHER'}):
            other = self.event_source(**changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ContractError, '^configuration_event_resync_required$'):
                await other.next(cursor)
        with self.assertRaisesRegex(ContractError, '^configuration_event_source_invalid$'):
            self.event_source(start_revision=2)
        from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject
        ledger = self.source._ledger
        other_binding = OwnerBinding('hub-one', 'configuration', 'other-configuration', 'configuration', self.binding.scope)
        other_ledger = OwnerLedger(self.configuration_js, stream='OTHER', subject=owner_subject(other_binding), binding=other_binding,
            retention=ledger._retention, stream_identity=ledger._identity, require_completion_budget=True)
        other_route = ConfigurationEventRoute.from_ledger(other_ledger,
            account_public_key='A' * 56, jetstream_domain='SELECTED')
        with self.assertRaisesRegex(ContractError, '^configuration_event_source_invalid$'):
            ConfigurationEventSource(self.source, other_route)
        changed = dict(cursor, streamCreated='2026-10-01T00:00:00.000000Z')
        with self.assertRaises(ContractError):
            await replay.next(changed)
        with self.assertRaises(ContractError):
            await replay.next(replay.route.cursor(2))
        self.assertEqual(cursor['sequence'], 0)

    async def test_changed_intent_cannot_be_exposed(self):
        await self.service.handle(self.activation())
        await self.call(self.configuration_request('set'))
        record = strict_loads(self.configuration_js.messages[0].data)
        record['effects'][0]['payload']['payload']['configurationChecksum'] = 'sha256:' + 'f' * 64
        record['effects'][0]['payloadDigest'] = payload_digest(record['effects'][0]['payload'])
        from state_owner.ledger import StoredRecord
        with self.assertRaises(ContractError):
            self.source._retained(StoredRecord(canonical_bytes(record), 1))

    async def test_missing_retained_record_cannot_reset_cursor(self):
        await self.service.handle(self.activation())
        await self.call(self.configuration_request('set'))
        replay = self.event_source()
        cursor = replay.route.cursor(0)
        self.configuration_js.messages.clear()
        with self.assertRaises(ContractError):
            await replay.next(cursor)
        self.assertEqual(cursor['sequence'], 0)

    async def test_close_keeps_original_handed_publication_until_join(self):
        await self.service.handle(self.activation())
        connection = Connection()
        self.source._connection = connection
        entered, release = asyncio.Event(), asyncio.Event()
        original = connection.publish
        async def publish(*args):
            entered.set()
            await release.wait()
            await original(*args)
        connection.publish = publish
        request = asyncio.create_task(self.call(self.configuration_request('set')))
        try:
            await entered.wait()
            publication, = self.source._publications
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await self.source.close(timeout=0.01)
            self.assertFalse(self.source.done.is_set())
            self.assertFalse(publication.cancelled())
            self.assertIn(publication, self.source._publications)
        finally:
            release.set()
            await asyncio.gather(request, return_exceptions=True)
            await self.source.close(timeout=None)
        self.assertTrue(publication.done())
        self.assertTrue(self.source.done.is_set())

    async def test_close_reports_failed_publication_after_draining_original_command_subscription(self):
        await self.service.handle(self.activation())
        connection = Connection()
        self.source._connection = connection
        await self.source.start(reply_prefix='_INBOX.event_fixture_0001.')
        entered, release = asyncio.Event(), asyncio.Event()
        async def publish(*args):
            entered.set()
            await release.wait()
            raise OSError('private transport detail')
        connection.publish = publish
        request = asyncio.create_task(self.call(self.configuration_request('set')))
        await entered.wait()
        closing = asyncio.create_task(self.source.close(timeout=None))
        try:
            await asyncio.sleep(0)
            release.set()
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await closing
            self.assertEqual(connection.subscription.drains, 1)
            self.assertFalse(self.source.done.is_set())
            self.assertFalse(self.source._publications)
            await self.source.close(timeout=None)
            self.assertEqual(connection.subscription.drains, 1)
            self.assertTrue(self.source.done.is_set())
        finally:
            release.set()
            await asyncio.gather(request, closing, return_exceptions=True)
