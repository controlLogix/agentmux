"""Actual retained records and signed authority with offline broker controls."""
import asyncio
import base64
import copy
from types import SimpleNamespace
from datetime import timedelta
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.authority import AuthorityReader
from identity.test_authority import fixture, ref, SEED, NOW
from identity.test_native_bridge import native_row
from identity.test_service import _Clock
from capability_owner.test_reply_service import Connection, Subscription
from state_owner.configuration import ConfigurationOwner, ConfigurationWatch, verify_configuration_response
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner.test_ledger import FakeJetStream, CREATED


class ConfigurationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.record, self.envelope = fixture()
        patch('state_owner.configuration.datetime', _Clock).start()
        patch('state_owner.ledger.datetime', _Clock).start()
        self.addCleanup(patch.stopall)
        self.owner = native_row()['owner']
        scope = self.envelope['operation']['scope']
        self.binding = OwnerBinding('hub-one', 'configuration', 'configuration-one', 'configuration', canonical_bytes(scope))
        self.policy = Retention(16 * 131072, 131072)
        self.js = FakeJetStream(self.policy)
        self.js.config.subjects = [owner_subject(self.binding)]
        self.ledger = OwnerLedger(self.js, stream='OWNER', subject=owner_subject(self.binding), binding=self.binding,
            retention=self.policy, stream_identity=StreamIdentity(CREATED, 0), require_completion_budget=True)
        for name in ('read', 'set', 'watch'):
            grant = copy.deepcopy(self.record['state']['grants'][0])
            grant.update(ref=ref('configuration-' + name), contractId='configuration-' + name,
                         resourceId='configuration-one')
            self.record['state']['grants'].append(grant)
        async def authority(*args, **kwargs):
            return SimpleNamespace(subject='identity.owner', seq=1, data=canonical_bytes(self.record))
        self.authority = AuthorityReader(SimpleNamespace(get_msg=authority), stream='IDENTITY', subject='identity.owner',
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')
        self.connection = Connection()
        self.source = self.new_source()
        self.addAsyncCleanup(self.source.close)
        self.number = 0

    def new_source(self):
        return ConfigurationOwner(self.authority, self.ledger, owner=self.owner, schema_ref='config.json',
            schema_resources={'config.json': b'{"type":"object","properties":{"private":{"type":"integer"}},"required":["private"],"additionalProperties":false}'},
            issuer_ref=ref('issuer'), signing_seed=SEED, connection=self.connection,
            require_native_activation=False)

    def request(self, method='read', *, revision=0, value=b' {"private":1} ', after=None):
        self.number += 1
        envelope = copy.deepcopy(self.envelope)
        contract = 'configuration-' + method
        payload = {'configurationRef': {'id': self.binding.entity_id, 'ownerHubId': 'hub-one', 'revision': revision},
                   'owner': copy.deepcopy(self.owner)}
        if method == 'set':
            payload.update(schemaRef='config.json', configurationBytes=base64.b64encode(value).decode(), secretReferences=[ref('secret-reference')])
        if method == 'watch':
            payload['afterRevision'] = revision if after is None else after
        envelope.update(contractId=contract, destinationServiceId='configuration-owner', payload=payload)
        envelope['operation'].update(operationId='configuration-command-' + str(self.number), expectedVersion=revision,
            payloadDigest=payload_digest(payload), grantRef=ref(contract))
        claims = envelope['ingressAttestation']['claims']
        claims.update(contractId=contract, operation=copy.deepcopy(envelope['operation']),
                      audience={'hubId': 'hub-one', 'serviceId': 'configuration-owner'})
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(envelope)

    async def call(self, raw):
        response = await self.source.handle(raw)
        return verify_configuration_response(response, raw,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'), now=NOW)

    async def test_signed_write_read_exact_bytes_replay_and_restart(self):
        request = self.request('set')
        first = await self.call(request)
        self.assertEqual(first['configurationRef']['revision'], 1)
        self.assertEqual(base64.b64decode(first['state']['configurationBytes']), b' {"private":1} ')
        self.assertEqual(first['state']['secretReferences'], [ref('secret-reference')])
        self.assertEqual((await self.call(request))['state'], first['state'])
        await self.source.close()
        self.source = self.new_source()
        self.addAsyncCleanup(self.source.close)
        self.assertEqual((await self.call(self.request(revision=1)))['state'], first['state'])
        self.assertEqual(len(self.js.messages), 1)
        record = strict_loads(self.js.messages[0].data)
        self.assertEqual((record['effects'], record['artifacts']), ([], []))

    async def test_invalid_schema_value_owner_scope_and_revoked_grant_cannot_write(self):
        for value in (b'{"private":"wrong"}', b'{"private":1,"extra":true}', b'not json'):
            with self.assertRaises(ContractError):
                await self.source.handle(self.request('set', value=value))
        with self.assertRaisesRegex(ContractError, '^configuration_binding_mismatch$'):
            self.owner['generation'] += 1
            await self.source.handle(self.request('set'))
        self.owner['generation'] -= 1
        next(g for g in self.record['state']['grants'] if g['ref'] == ref('configuration-set'))['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
            await self.source.handle(self.request('set'))
        self.assertEqual(self.js.messages, [])

    async def test_lost_ack_reconciles_original_and_changed_payload_conflicts(self):
        raw = self.request('set')
        self.js.lose_ack = True
        await self.call(raw)
        await self.call(raw)
        changed = strict_loads(raw)
        changed['payload']['configurationBytes'] = base64.b64encode(b'{"private":2}').decode()
        changed['operation']['payloadDigest'] = payload_digest(changed['payload'])
        changed['ingressAttestation']['claims']['operation'] = copy.deepcopy(changed['operation'])
        changed['ingressAttestation']['signature'] = sign_claims(changed['ingressAttestation']['claims'], SEED)
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.source.handle(canonical_bytes(changed))
        self.assertEqual(len(self.js.messages), 1)

    async def test_conditional_competitors_do_not_both_commit_from_one_revision(self):
        first, second = self.request('set'), self.request('set', value=b'{"private":2}')
        results = await asyncio.gather(self.source.handle(first), self.source.handle(second), return_exceptions=True)
        self.assertEqual(sum(isinstance(result, bytes) for result in results), 1)
        self.assertEqual(len(self.js.messages), 1)

    async def test_rollback_gap_and_unavailable_source_never_return_a_cached_value(self):
        await self.call(self.request('set'))
        await self.call(self.request('set', revision=1))
        second = self.js.messages.pop()
        with self.assertRaises(ContractError):
            await self.source.handle(self.request(revision=1))
        self.js.messages.append(second)
        self.js.deleted = 1
        with self.assertRaises(ContractError):
            await self.source.handle(self.request())
        self.js.deleted = 0
        with patch.object(self.ledger, 'current', side_effect=OSError('private broker data')):
            with self.assertRaisesRegex(ContractError, '^configuration_unavailable$'):
                await self.source.handle(self.request())

    async def test_revocation_during_read_blocks_disclosure(self):
        await self.call(self.request('set'))
        original = self.ledger.current
        async def revoke():
            result = await original()
            next(g for g in self.record['state']['grants'] if g['ref'] == ref('configuration-read'))['status'] = 'revoked'
            return result
        with patch.object(self.ledger, 'current', side_effect=revoke):
            with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
                await self.source.handle(self.request())

    async def test_watch_ignores_uncommitted_notification_and_drains_original_subscription(self):
        await self.call(self.request('set'))
        request = self.request('watch', revision=1)
        task = asyncio.create_task(self.call(request))
        await self.connection.subscribed.wait()
        await self.connection.options['cb'](SimpleNamespace(data=b'uncommitted candidate'))
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        await self.call(self.request('set', revision=1, value=b'{"private":2}'))
        await self.connection.options['cb'](SimpleNamespace())
        result = await task
        self.assertEqual(result['state']['revision'], 2)
        self.assertEqual(self.connection.subscription.drains, 1)
        self.assertEqual(self.source._watches, set())

    async def test_cancelled_watch_retains_pending_allocation_until_original_close(self):
        await self.call(self.request('set'))
        self.connection.release.clear()
        task = asyncio.create_task(self.source.handle(self.request('watch', revision=1)))
        await self.connection.subscribed.wait()
        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.assertEqual(len(self.source._watches), 1)
        self.connection.release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.connection.subscription.drains, 1)
        self.assertEqual(self.source._watches, set())

    async def test_failed_drain_retains_same_subscription_for_another_close_attempt(self):
        await self.call(self.request('set'))
        original = self.connection.subscription.drain
        async def failed():
            raise OSError('private close failure')
        self.connection.subscription.drain = failed
        task = asyncio.create_task(self.source.handle(self.request('watch', revision=1)))
        await self.connection.subscribed.wait()
        task.cancel()
        with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
            await task
        watch, = self.source._watches
        self.assertFalse(watch.done.is_set())
        allocation = watch._allocation
        for request in (self.request(revision=1), self.request('watch', revision=1)):
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await self.source.handle(request)
        self.assertEqual(self.source._watches, {watch})
        self.assertIs(watch._allocation, allocation)
        self.connection.subscription.drain = original
        await watch.close()
        self.assertEqual((await self.call(self.request(revision=1)))['state']['revision'], 1)
        # Only after the original subscription joined may another watch open.
        self.assertEqual((await self.call(self.request('watch', revision=1, after=0)))['state']['revision'], 1)
        await self.source.close()
        self.assertTrue(watch.done.is_set())
        self.assertEqual(self.connection.subscription.drains, 2)

    def pinned_connection(self):
        from nats.aio.client import Client
        connection = Client()
        connection._status = connection.CONNECTED
        connection._send_command = AsyncMock()
        connection._flush_pending = AsyncMock()
        connection._error_cb = AsyncMock()
        connection.flush = AsyncMock()
        subscriptions = []
        original = connection._send_subscribe
        async def send(subscription):
            subscriptions.append(subscription)
            return await original(subscription)
        connection._send_subscribe = send
        async def cleanup():
            await connection.close()
            workers = [sub._wait_for_msgs_task for sub in subscriptions]
            await asyncio.gather(*workers, return_exceptions=True)
        self.addAsyncCleanup(cleanup)
        self.source._connection = connection
        return connection, subscriptions

    async def pinned_cleanup_owner(self, *, command):
        if command:
            await self.source.start(reply_prefix='_INBOX.configuration.')
            return self.source, self.source._subscription, self.source._subscribe_task
        watch = ConfigurationWatch(self.source)
        self.source._watches.add(watch)
        await watch.start()
        return watch, watch.subscription, watch._allocation

    async def assert_pinned_drain_retry(self, *, command):
        from nats.aio.subscription import Subscription as NatsSubscription
        from nats.errors import FlushTimeoutError
        attempts = []
        class Subscription(NatsSubscription):
            async def _drain(self):
                attempts.append((self, self._closed))
                return await super()._drain()
        connection, subscriptions = self.pinned_connection()
        with patch('nats.aio.client.Subscription', Subscription):
            owned, subscription, allocation = await self.pinned_cleanup_owner(command=command)
        worker, identifier = subscription._wait_for_msgs_task, subscription._id
        for failure in (FlushTimeoutError(), OSError('controlled original drain failure')):
            connection.flush.side_effect = failure
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await owned.close()
            self.assertIs(owned._closing.exception(), failure)
            self.assertTrue(subscription._closed)
            self.assertFalse(worker.done())
            self.assertFalse(owned.done.is_set())
            self.assertIs(connection._subs[identifier], subscription)
            self.assertIs(subscription._wait_for_msgs_task, worker)
        connection.flush.side_effect = None
        await owned.close()
        self.assertEqual(attempts, [(subscription, False), (subscription, True), (subscription, True)])
        self.assertEqual(subscriptions, [subscription])
        self.assertIs(allocation.result(), subscription)
        self.assertTrue(worker.done())
        self.assertNotIn(identifier, connection._subs)
        self.assertTrue(owned.done.is_set())
        self.assertFalse(connection.is_closed)

    async def test_pinned_watch_retries_failed_drain_without_replacing_subclass_or_worker(self):
        await self.assert_pinned_drain_retry(command=False)

    async def test_pinned_command_retries_failed_drain_without_replacing_subclass_or_worker(self):
        await self.assert_pinned_drain_retry(command=True)

    async def assert_closed_connection_joins_original(self, *, command):
        from nats.aio.subscription import Subscription as NatsSubscription
        from nats.errors import FlushTimeoutError
        started, stopping, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        class Subscription(NatsSubscription):
            async def _wait_for_msgs(self, error_cb):
                started.set()
                try:
                    return await super()._wait_for_msgs(error_cb)
                finally:
                    stopping.set()
                    await release.wait()
        connection, subscriptions = self.pinned_connection()
        with patch('nats.aio.client.Subscription', Subscription):
            owned, subscription, allocation = await self.pinned_cleanup_owner(command=command)
        worker = subscription._wait_for_msgs_task
        waiter = None
        try:
            await asyncio.wait_for(started.wait(), 1)
            connection.flush.side_effect = FlushTimeoutError()
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await owned.close()
            self.assertTrue(subscription._closed)
            self.assertIs(connection._subs[subscription._id], subscription)
            self.assertFalse(worker.done())
            flushes = connection.flush.await_count
            await connection.close()
            await asyncio.wait_for(stopping.wait(), 1)
            self.assertNotIn(subscription._id, connection._subs)
            self.assertFalse(worker.done())
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await owned.close(timeout=.01)
            closing = owned._closing
            waiter = asyncio.create_task(owned.close(timeout=None))
            await asyncio.sleep(0)
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            self.assertIs(owned._closing, closing)
            self.assertFalse(closing.done())
            self.assertFalse(owned.done.is_set())
            self.assertEqual(worker.cancelling(), 1)
        finally:
            release.set()
            await owned.close(timeout=None)
            if waiter is not None:
                await asyncio.gather(waiter, return_exceptions=True)
        self.assertTrue(worker.done())
        self.assertTrue(owned.done.is_set())
        self.assertEqual(subscriptions, [subscription])
        self.assertIs(allocation.result(), subscription)
        self.assertEqual(connection.flush.await_count, flushes)

    async def test_pinned_watch_closed_connection_joins_original_callback_after_waiter_cancel(self):
        await self.assert_closed_connection_joins_original(command=False)

    async def test_pinned_command_closed_connection_joins_original_callback_after_waiter_cancel(self):
        await self.assert_closed_connection_joins_original(command=True)

    async def assert_pinned_ownership_refusals(self, *, command):
        from nats.errors import FlushTimeoutError
        connection, subscriptions = self.pinned_connection()
        owned, subscription, allocation = await self.pinned_cleanup_owner(command=command)
        worker, identifier = subscription._wait_for_msgs_task, subscription._id
        connection.flush.side_effect = FlushTimeoutError()
        with self.assertRaises(ContractError):
            await owned.close()
        connection.flush.side_effect = None
        other = object()
        replacement = asyncio.create_task(asyncio.Event().wait())
        changes = (
            (lambda: setattr(subscription, '_id', identifier + 1),
             lambda: setattr(subscription, '_id', identifier)),
            (lambda: setattr(subscription, '_conn', other),
             lambda: setattr(subscription, '_conn', connection)),
            (lambda: setattr(self.source, '_connection', other),
             lambda: setattr(self.source, '_connection', connection)),
            (lambda: setattr(subscription, '_wait_for_msgs_task', replacement),
             lambda: setattr(subscription, '_wait_for_msgs_task', worker)),
            (lambda: connection._subs.__setitem__(identifier, other),
             lambda: connection._subs.__setitem__(identifier, subscription)),
            (lambda: connection._subs.__setitem__(identifier + 1, subscription),
             lambda: connection._subs.pop(identifier + 1)),
        )
        try:
            for alter, restore in changes:
                calls = connection.flush.await_count
                alter()
                try:
                    with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                        await owned.close()
                    self.assertFalse(owned.done.is_set())
                    self.assertFalse(worker.done())
                    self.assertEqual(connection.flush.await_count, calls)
                    self.assertFalse(replacement.done())
                finally:
                    restore()
        finally:
            replacement.cancel()
            await asyncio.gather(replacement, return_exceptions=True)
            await owned.close()
        self.assertIs(allocation.result(), subscription)
        self.assertEqual(subscriptions, [subscription])

    async def test_pinned_watch_retry_refuses_changed_original_ownership(self):
        await self.assert_pinned_ownership_refusals(command=False)

    async def test_pinned_command_retry_refuses_changed_original_ownership(self):
        await self.assert_pinned_ownership_refusals(command=True)

    async def test_pinned_closed_flag_without_detachment_cannot_complete_cleanup(self):
        connection, _ = self.pinned_connection()
        owned, subscription, _ = await self.pinned_cleanup_owner(command=False)
        worker = subscription._wait_for_msgs_task
        connection._status = connection.CLOSED
        try:
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await owned.close()
            self.assertFalse(owned.done.is_set())
            self.assertFalse(worker.done())
            self.assertIs(connection._subs[subscription._id], subscription)
        finally:
            connection._status = connection.CONNECTED
            await connection.close()
            await asyncio.gather(worker, return_exceptions=True)
            await owned.close()

    async def test_command_subscription_uses_scoped_reply_and_joins_on_close(self):
        await self.source.start(reply_prefix='_INBOX.configuration.')
        self.assertEqual(self.connection.subject, self.source.subject)
        raw = self.request('set')
        await self.source._receive(SimpleNamespace(reply='_INBOX.another.client', data=raw))
        self.assertEqual(self.connection.sent, [])
        await self.source._receive(SimpleNamespace(reply='_INBOX.configuration.client', data=raw))
        await asyncio.gather(*tuple(self.source._requests))
        self.assertEqual(len(self.connection.sent), 1)
        claims = verify_configuration_response(self.connection.sent[0][1], raw,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'), now=NOW)
        self.assertEqual(claims['state']['revision'], 1)
        await self.source.close()
        self.assertTrue(self.source.done.is_set())
        self.assertEqual(self.connection.subscription.drains, 1)

    async def test_start_cancellation_and_close_timeout_keep_original_command_subscription(self):
        self.connection.release.clear()
        start = asyncio.create_task(self.source.start(reply_prefix='_INBOX.configuration.'))
        await self.connection.subscribed.wait()
        start.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await start
        original = self.source._subscribe_task
        with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
            await self.source.close(timeout=0.01)
        self.assertFalse(original.done())
        self.assertFalse(self.source.done.is_set())
        self.connection.release.set()
        await self.source.close()
        self.assertIs(self.source._subscribe_task, original)
        self.assertTrue(original.done())
        self.assertTrue(self.source.done.is_set())
        self.assertEqual(self.connection.subscription.drains, 1)

    async def test_watch_close_joins_real_nats_callback_worker_and_pending_queue(self):
        from nats.aio.subscription import Subscription
        await self.call(self.request('set'))
        removed, errors = [], []
        async def unsubscribe(sid):
            pass
        async def on_error(error):
            errors.append(error)
        async def subscribe(subject, **options):
            subscription = Subscription(self.connection, id=7, subject=subject, **options)
            subscription._start(on_error)
            self.connection.subscription = subscription
            self.connection.subscribed.set()
            return subscription
        self.connection.is_closed = self.connection.is_draining = False
        self.connection._send_unsubscribe = unsubscribe
        self.connection._remove_sub = removed.append
        self.connection.subscribe = subscribe
        task = asyncio.create_task(self.source.handle(self.request('watch', revision=1)))
        await self.connection.subscribed.wait()
        subscription = self.connection.subscription
        worker = subscription._wait_for_msgs_task
        message = SimpleNamespace(data=b'hint')
        subscription._pending_size += len(message.data)
        subscription._pending_queue.put_nowait(message)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(worker.done())
        await asyncio.wait_for(subscription._pending_queue.join(), 1)
        await asyncio.wait_for(worker, 1)
        self.assertEqual(errors, [])
        self.assertEqual(removed, [7])
        self.assertEqual(self.source._watches, set())

    async def test_revocation_during_original_watch_drain_blocks_signed_disclosure(self):
        await self.call(self.request('set'))
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.connection.subscription.drain
        async def drain():
            entered.set()
            await release.wait()
            await original()
        self.connection.subscription.drain = drain
        task = asyncio.create_task(self.source.handle(self.request('watch', revision=1)))
        try:
            await self.connection.subscribed.wait()
            await self.call(self.request('set', revision=1, value=b'{"private":2}'))
            await self.connection.options['cb'](SimpleNamespace())
            await asyncio.wait_for(entered.wait(), 1)
            self.assertIn(task, self.source._active)
            next(g for g in self.record['state']['grants'] if g['ref'] == ref('configuration-watch'))['status'] = 'revoked'
        finally:
            release.set()
        with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
            await task
        self.assertEqual(self.connection.subscription.drains, 1)
        self.assertEqual(self.source._watches, set())

    async def test_serial_nats_callback_does_not_block_a_write_behind_a_watch(self):
        from nats.aio.subscription import Subscription
        await self.call(self.request('set'))
        subscriptions, removed, errors = [], [], []
        async def unsubscribe(sid):
            pass
        async def on_error(error):
            errors.append(error)
        async def subscribe(subject, **options):
            subscription = Subscription(self.connection, id=len(subscriptions) + 1, subject=subject, **options)
            subscription._start(on_error)
            subscriptions.append(subscription)
            return subscription
        self.connection.is_closed = self.connection.is_draining = False
        self.connection._send_unsubscribe = unsubscribe
        self.connection._remove_sub = removed.append
        self.connection.subscribe = subscribe
        replied = asyncio.Event()
        original_send = self.connection.publish
        async def send(*args):
            await original_send(*args)
            if len(self.connection.sent) == 2:
                replied.set()
        self.connection.publish = send
        original_append = self.js.publish
        def enqueue(subscription, message):
            subscription._pending_size += len(message.data)
            subscription._pending_queue.put_nowait(message)
        async def append(subject, data, **options):
            result = await original_append(subject, data, **options)
            for subscription in subscriptions:
                if subscription.subject == self.ledger._subject:
                    enqueue(subscription, SimpleNamespace(data=data))
            return result
        self.js.publish = append
        await self.source.start(reply_prefix='_INBOX.configuration.')
        commands = subscriptions[0]
        watch, write = self.request('watch', revision=1), self.request('set', revision=1, value=b'{"private":2}')
        for name, raw in (('watch', watch), ('write', write)):
            enqueue(commands, SimpleNamespace(data=raw, reply='_INBOX.configuration.' + name))
        try:
            await asyncio.wait_for(replied.wait(), 2)
            self.assertEqual(len(self.js.messages), 2)
            for name, raw in (('watch', watch), ('write', write)):
                response = dict(self.connection.sent)['_INBOX.configuration.' + name]
                result = verify_configuration_response(response, raw,
                    public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'), now=NOW)
                self.assertEqual(result['state']['revision'], 2)
        finally:
            await self.source.close()
        for subscription in subscriptions:
            self.assertTrue(subscription._wait_for_msgs_task.done())
            await asyncio.wait_for(subscription._pending_queue.join(), 1)
            await asyncio.wait_for(subscription._wait_for_msgs_task, 1)
        self.assertEqual(errors, [])
        self.assertEqual(len(removed), len(subscriptions))
        self.assertEqual(self.source._requests, set())

    async def test_close_keeps_original_reply_until_publish_and_drain_join(self):
        await self.source.start(reply_prefix='_INBOX.configuration.')
        entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original = self.connection.publish
        async def send(*args):
            entered.set()
            try:
                await release.wait()
                await original(*args)
            finally:
                finished.set()
        self.connection.publish = send
        await self.source._receive(SimpleNamespace(reply='_INBOX.configuration.client', data=self.request('set')))
        await asyncio.wait_for(entered.wait(), 1)
        original_request, = self.source._requests
        try:
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await self.source.close(timeout=0.01)
            self.assertFalse(self.source.done.is_set())
            self.assertFalse(original_request.done())
            self.assertEqual(self.connection.subscription.drains, 0)
        finally:
            release.set()
        await self.source.close()
        self.assertTrue(finished.is_set())
        self.assertTrue(original_request.done())
        self.assertTrue(self.source.done.is_set())
        self.assertEqual(self.connection.subscription.drains, 1)

    async def test_idle_watch_timeout_joins_cleanup_before_fresh_authorized_read(self):
        await self.call(self.request('set'))
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.connection.subscription.drain
        async def drain():
            entered.set()
            await release.wait()
            await original()
        self.connection.subscription.drain = drain
        task = asyncio.create_task(self.source.handle(self.request('watch', revision=1)))
        try:
            # Exercise the real five-second request bound. A quiet watch has no
            # newer retained revision and cannot return an unchanged snapshot.
            await asyncio.wait_for(entered.wait(), 6.5)
            self.assertFalse(task.done())
            self.assertIn(task, self.source._active)
            watch, = self.source._watches
            allocation = watch._allocation
            self.assertTrue(allocation.done())
            self.assertFalse(watch.done.is_set())
            for request in (self.request(revision=1), self.request('watch', revision=1)):
                with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                    await self.source.handle(request)
            self.assertEqual(self.source._watches, {watch})
        finally:
            release.set()
        with self.assertRaisesRegex(ContractError, '^configuration_unavailable$'):
            await task
        self.assertTrue(watch.done.is_set())
        self.assertIs(watch._allocation, allocation)
        self.assertEqual(self.connection.subscription.drains, 1)
        self.assertEqual(self.source._watches, set())
        read = await self.call(self.request(revision=1))
        self.assertEqual(read['state']['revision'], 1)
        next(g for g in self.record['state']['grants'] if g['ref'] == ref('configuration-read'))['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
            await self.source.handle(self.request(revision=1))

    async def test_healthy_concurrent_watches_allow_authorized_reads_and_another_watch(self):
        await self.call(self.request('set'))
        subscriptions, ready = [], asyncio.Event()
        async def subscribe(subject, **options):
            subscription = Subscription()
            subscriptions.append(subscription)
            if len(subscriptions) == 2:
                ready.set()
            return subscription
        self.connection.subscribe = subscribe
        tasks = [asyncio.create_task(self.source.handle(self.request('watch', revision=1))) for _ in range(2)]
        try:
            await asyncio.wait_for(ready.wait(), 1)
            self.assertEqual(len(self.source._watches), 2)
            self.assertTrue(all(watch._closing is None for watch in self.source._watches))
            self.assertEqual((await self.call(self.request(revision=1)))['state']['revision'], 1)
            self.assertEqual((await self.call(self.request('watch', revision=1, after=0)))['state']['revision'], 1)
            self.assertEqual([subscription.drains for subscription in subscriptions], [0, 0, 1])
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        self.assertEqual([subscription.drains for subscription in subscriptions], [1, 1, 1])
        self.assertEqual(self.source._watches, set())

    async def test_cleanup_started_during_read_blocks_final_signed_disclosure(self):
        await self.call(self.request('set'))
        original_watch = asyncio.create_task(self.source.handle(self.request('watch', revision=1)))
        await self.connection.subscribed.wait()
        watch, = self.source._watches
        entered, release = asyncio.Event(), asyncio.Event()
        original_drain, original_current = self.connection.subscription.drain, self.source._current
        cleanup = None
        async def drain():
            entered.set()
            await release.wait()
            await original_drain()
        self.connection.subscription.drain = drain
        async def current(minimum):
            nonlocal cleanup
            result = await original_current(minimum)
            cleanup = asyncio.create_task(watch.close())
            await entered.wait()
            return result
        try:
            with patch.object(self.source, '_current', side_effect=current):
                with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                    await self.source.handle(self.request(revision=1))
        finally:
            release.set()
            if cleanup is not None:
                await cleanup
            original_watch.cancel()
            await asyncio.gather(original_watch, return_exceptions=True)
        self.assertTrue(watch.done.is_set())
        self.assertEqual(self.connection.subscription.drains, 1)
        self.assertEqual((await self.call(self.request(revision=1)))['state']['revision'], 1)

    async def test_no_signed_read_until_original_pinned_sdk_callback_worker_joins(self):
        from nats.aio.subscription import Subscription as NatsSubscription
        await self.call(self.request('set'))
        stopping, release = asyncio.Event(), asyncio.Event()
        removed, errors = [], []
        async def unsubscribe(sid):
            pass
        async def on_error(error):
            errors.append(error)
        async def subscribe(subject, **options):
            subscription = NatsSubscription(self.connection, id=7, subject=subject, **options)
            original_wait = subscription._wait_for_msgs
            async def wait(error_cb):
                try:
                    await original_wait(error_cb)
                finally:
                    stopping.set()
                    await release.wait()
            subscription._wait_for_msgs = wait
            subscription._start(on_error)
            self.connection.subscription = subscription
            self.connection.subscribed.set()
            return subscription
        self.connection.is_closed = self.connection.is_draining = False
        self.connection._send_unsubscribe = unsubscribe
        self.connection._remove_sub = removed.append
        self.connection.subscribe = subscribe
        raw = self.request('watch', revision=1)
        task = asyncio.create_task(self.source.handle(raw))
        await self.connection.subscribed.wait()
        subscription = self.connection.subscription
        worker = subscription._wait_for_msgs_task
        watch, = self.source._watches
        allocation = watch._allocation
        try:
            await self.call(self.request('set', revision=1, value=b'{"private":2}'))
            message = SimpleNamespace(data=b'hint')
            subscription._pending_size += len(message.data)
            subscription._pending_queue.put_nowait(message)
            await asyncio.wait_for(stopping.wait(), 1)
            self.assertTrue(subscription._closed)
            self.assertFalse(worker.done())
            self.assertFalse(watch.done.is_set())
            self.assertFalse(task.done())
            self.assertIn(watch, self.source._watches)
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await watch.close(timeout=0.01)
            waiter = asyncio.create_task(watch.close())
            await asyncio.sleep(0)
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            self.assertFalse(watch._closing.cancelled())
            self.assertIs(watch._worker, worker)
            self.assertIs(watch._allocation, allocation)
            for request in (self.request(revision=2), self.request('watch', revision=2)):
                with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                    await self.source.handle(request)
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
            await asyncio.gather(worker, return_exceptions=True)
        result = verify_configuration_response(task.result(), raw,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'), now=NOW)
        self.assertEqual(result['state']['revision'], 2)
        self.assertTrue(worker.done())
        self.assertTrue(watch.done.is_set())
        self.assertEqual(removed, [7])
        self.assertEqual(errors, [])
        self.assertEqual((await self.call(self.request(revision=2)))['state']['revision'], 2)

    async def test_late_watch_arrival_uses_original_deadline_before_client_rearm(self):
        await self.call(self.request('set'))
        request = strict_loads(self.request('watch', revision=1))
        expiry = (NOW + timedelta(seconds=5)).isoformat().replace('+00:00', 'Z')
        request['operation']['deadline'] = expiry
        claims = request['ingressAttestation']['claims']
        claims.update(operation=copy.deepcopy(request['operation']), expiresAt=expiry)
        request['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        class LateClock(_Clock):
            @classmethod
            def now(cls, tz=None):
                return NOW + timedelta(seconds=4.85)
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.connection.subscription.drain
        async def drain():
            entered.set()
            await release.wait()
            await original()
        self.connection.subscription.drain = drain
        with patch('state_owner.configuration.datetime', LateClock):
            task = asyncio.create_task(self.source.handle(canonical_bytes(request)))
            try:
                # Only 150 ms of the original caller budget remains. The local
                # five-second maximum must not extend this received request.
                await asyncio.wait_for(entered.wait(), 1)
                watch, = self.source._watches
                allocation = watch._allocation
                self.assertFalse(task.done())
                for raw in (self.request(revision=1), self.request('watch', revision=1)):
                    with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                        await self.source.handle(raw)
                self.assertEqual(self.source._watches, {watch})
                self.assertIs(watch._allocation, allocation)
            finally:
                release.set()
                results = await asyncio.gather(task, return_exceptions=True)
        self.assertIsInstance(results[0], ContractError)
        self.assertEqual(results[0].code, 'configuration_unavailable')
        self.assertTrue(watch.done.is_set())
        self.assertEqual((await self.call(self.request(revision=1)))['state']['revision'], 1)
        await self.call(self.request('watch', revision=1, after=0))
        self.assertEqual(self.connection.subscription.drains, 2)

    async def test_confirmed_local_write_wakes_watch_without_core_echo(self):
        await self.call(self.request('set'))
        task = asyncio.create_task(self.call(self.request('watch', revision=1)))
        try:
            await self.connection.subscribed.wait()
            # The controlled publish emits no core notification, like the
            # enrolled service connection with no_echo=True.
            await self.call(self.request('set', revision=1, value=b'{"private":2}'))
            result = await asyncio.wait_for(task, 1)
            self.assertEqual(result['state']['revision'], 2)
            self.assertEqual(self.connection.subscription.drains, 1)
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_exact_retry_after_committed_publish_cancellation_wakes_watch(self):
        await self.call(self.request('set'))
        task = asyncio.create_task(self.call(self.request('watch', revision=1)))
        try:
            await self.connection.subscribed.wait()
            await asyncio.sleep(0)
            raw = self.request('set', revision=1, value=b'{"private":2}')
            original = self.js.publish
            async def cancelled_after_append(*args, **kwargs):
                await original(*args, **kwargs)
                raise asyncio.CancelledError()
            with patch.object(self.js, 'publish', side_effect=cancelled_after_append):
                with self.assertRaises(asyncio.CancelledError):
                    await self.call(raw)
            self.assertEqual(len(self.js.messages), 2)
            self.assertFalse(task.done())
            self.assertEqual((await self.call(raw))['state']['revision'], 2)
            result = await asyncio.wait_for(task, 1)
            self.assertEqual(result['state']['revision'], 2)
            self.assertEqual(len(self.js.messages), 2)
            self.assertEqual(self.connection.subscription.drains, 1)
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
