"""Watch cleanup retains actual admitted authority and original async owners."""
import asyncio
import base64
import copy
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from capability_owner.test_reply_service import Connection
from identity.ingress import verify_possession
from identity.test_authority import ref, SEED, NOW
from identity.test_native_bridge import HOST_SEED
from state_owner import test_configuration_activation as support
from state_owner.configuration_watch_control import _sizing_frames


class _Clock(datetime):
    value = NOW

    @classmethod
    def now(cls, tz=None):
        return cls.value


def _stamp(value):
    return value.isoformat(timespec='microseconds').replace('+00:00', 'Z')


class ConfigurationWatchControlTests(unittest.IsolatedAsyncioTestCase):
    request = support.ConfigurationActivationTests.request
    bridge_request = support.ConfigurationActivationTests.bridge_request
    activation = support.ConfigurationActivationTests.activation
    configuration_request = support.ConfigurationActivationTests.configuration_request
    call = support.ConfigurationActivationTests.call
    revoke = support.ConfigurationActivationTests.revoke

    def setUp(self):
        support.ConfigurationActivationTests.setUp(self)
        other = copy.deepcopy(self.record['state']['issuers'][0])
        other.update(ref=ref('other-issuer'), publicKey=base64.urlsafe_b64encode(
            bytes(SigningKey(bytes([42]) * 32).verify_key)).decode().rstrip('='))
        self.record['state']['issuers'].append(other)
        self.js.messages[0].data = canonical_bytes(self.record)
        _Clock.value = NOW
        patch('state_owner.configuration.datetime', _Clock).start()
        patch('state_owner.configuration_watch_control.datetime', _Clock).start()
        self.connection = Connection()
        self.source._connection = self.connection
        self.controls = self.source._watch_controls
        self.control_number = 0
        self.tasks = []

    async def asyncSetUp(self):
        await self.service.handle(self.activation())
        await self.call(self.configuration_request('set'))

    async def asyncTearDown(self):
        self.connection.release.set()
        await self.source.close(timeout=None)
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)

    def watch(self, *, after=1, seconds=4):
        envelope = strict_loads(self.configuration_request('watch', revision=1, after=after))
        now = _Clock.value
        envelope['sentAt'] = _stamp(now)
        envelope['operation'].update(deadline=_stamp(now + timedelta(seconds=seconds)),
            cancellationRef=ref('watch-cancel-' + str(self.number)))
        claims = envelope['ingressAttestation']['claims']
        claims.update(operation=copy.deepcopy(envelope['operation']), sentAt=envelope['sentAt'],
            issuedAt=_stamp(now), expiresAt=envelope['operation']['deadline'])
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(envelope)

    def signed(self, claims, *, seed=HOST_SEED):
        return canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
            'signature': sign_claims(claims, seed)})

    def control(self, watch, *, proof=None, seconds=4, change=None):
        self.control_number += 1
        nonce = format(self.control_number, '064x')
        claims = {'purpose': 'agentmux-configuration-watch-close-v1',
            **self.controls._binding(strict_loads(watch)), 'requestId': 'request_' + nonce,
            'replySubject': '_INBOX.abcdefghijklmnop.' + nonce,
            'issuedAt': _stamp(_Clock.value), 'expiresAt': _stamp(_Clock.value + timedelta(seconds=seconds))}
        if proof is not None:
            claims['joinedResponseBytes'] = base64.b64encode(proof).decode()
        if change is not None:
            change(claims)
        return self.signed(claims)

    async def invoke(self, raw):
        wanted = strict_loads(raw)['claims']
        result = await self.controls.handle(raw, reply_subject=wanted['replySubject'])
        response = strict_loads(result)
        validate('configuration-watch-close-response', response)
        verify_possession(response['claims'], response['signature'], self.record['state']['issuers'][0]['publicKey'])
        self.assertEqual(response['claims']['requestDigest'], payload_digest(strict_loads(raw)))
        self.assertEqual(response['claims']['replySubject'], wanted['replySubject'])
        self.assertNotIn('state', response['claims'])
        return result

    def start(self, raw):
        task = asyncio.create_task(self.source.handle(raw))
        self.tasks.append(task)
        return task

    async def opened(self, raw):
        self.connection.subscribed.clear()
        task = self.start(raw)
        await asyncio.wait_for(self.connection.subscribed.wait(), 2)
        return task, self.controls._entries[payload_digest(strict_loads(raw))]

    async def test_close_joins_original_watch_and_confirms_without_configuration_data(self):
        raw = self.watch()
        original, entry = await self.opened(raw)
        handler, allocation = entry.handler, entry.watch._allocation
        response = await self.invoke(self.control(raw))
        claims = strict_loads(response)['claims']
        self.assertTrue(claims['joined'])
        self.assertFalse(claims['receiptConfirmed'])
        await asyncio.gather(original, return_exceptions=True)
        self.assertTrue(handler.done())
        self.assertTrue(allocation.done())
        self.assertEqual(self.connection.subscription.drains, 1)
        self.assertFalse(self.source._watches)
        confirmed = strict_loads(await self.invoke(self.control(raw, proof=response)))['claims']
        self.assertTrue(confirmed['receiptConfirmed'])
        self.assertIn(entry.digest, self.controls._entries)
        _Clock.value += timedelta(seconds=5)
        self.controls._reclaim()
        self.assertFalse(self.controls._entries)

    async def test_close_before_original_arrival_cannot_report_joined(self):
        raw = self.watch()
        with self.assertRaisesRegex(ContractError, '^configuration_watch_allocation_required$'):
            await self.invoke(self.control(raw))
        self.assertFalse(self.source._watches)
        await self.opened(raw)
        self.assertTrue(strict_loads(await self.invoke(self.control(raw)))['claims']['joined'])

    async def test_reservation_precedes_authorization_and_duplicate_never_allocates(self):
        raw = self.watch()
        entered, release = asyncio.Event(), asyncio.Event()
        authorize = self.source._authorize
        async def delayed(*args):
            entered.set()
            await release.wait()
            return await authorize(*args)
        try:
            with patch.object(self.source, '_authorize', side_effect=delayed):
                original = self.start(raw)
                await asyncio.wait_for(entered.wait(), 2)
                entry = self.controls._entries[payload_digest(strict_loads(raw))]
                handler = entry.handler
                close = asyncio.create_task(self.invoke(self.control(raw)))
                self.tasks.append(close)
                with self.assertRaisesRegex(ContractError, '^configuration_watch_duplicate$'):
                    await self.source.handle(raw)
                await asyncio.sleep(0)
                self.assertFalse(close.done())
                self.assertFalse(entry.admission.done())
                self.assertFalse(self.source._watches)
                release.set()
                result = strict_loads(await close)['claims']
                self.assertTrue(result['joined'])
                self.assertTrue(handler.done())
                self.assertIsNone(entry.handler)
                await asyncio.gather(original, return_exceptions=True)
                with self.assertRaisesRegex(ContractError, '^configuration_watch_duplicate$'):
                    await self.source.handle(raw)
        finally:
            release.set()

    async def test_failed_original_admission_cannot_be_confirmed(self):
        raw = self.watch()
        await self.revoke(ref('configuration-watch'))
        original = self.start(raw)
        result, = await asyncio.gather(original, return_exceptions=True)
        self.assertIsInstance(result, ContractError)
        with self.assertRaisesRegex(ContractError, '^configuration_watch_allocation_required$'):
            await self.invoke(self.control(raw))
        self.assertFalse(self.source._watches)
        self.assertFalse(self.controls._entries)

    async def test_pending_subscribe_and_canceled_close_keep_original_owners(self):
        raw = self.watch()
        self.connection.release.clear()
        original, entry = await self.opened(raw)
        allocation, handler = entry.watch._allocation, entry.handler
        closing = asyncio.create_task(self.invoke(self.control(raw)))
        self.tasks.append(closing)
        try:
            async with asyncio.timeout(2):
                while entry.closing is None:
                    await asyncio.sleep(0)
            owner = entry.closing
            closing.cancel()
            await asyncio.gather(closing, return_exceptions=True)
            original.cancel()
            await asyncio.gather(original, return_exceptions=True)
            response = strict_loads(await self.invoke(self.control(raw, seconds=0.05)))['claims']
            self.assertFalse(response['joined'])
            self.assertFalse(owner.done())
            self.assertFalse(allocation.cancelled())
            self.assertIs(entry.handler, handler)
            self.assertIs(entry.closing, owner)
        finally:
            self.connection.release.set()
        self.assertTrue(strict_loads(await self.invoke(self.control(raw)))['claims']['joined'])
        self.assertTrue(allocation.done())
        self.assertEqual(self.connection.subscription.drains, 1)

    async def test_failed_drain_retains_allocation_for_explicit_retry(self):
        raw = self.watch()
        _, entry = await self.opened(raw)
        watch = entry.watch
        original_drain = self.connection.subscription.drain
        async def failed():
            raise OSError('private transport error')
        self.connection.subscription.drain = failed
        with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
            await self.invoke(self.control(raw))
        self.assertFalse(entry.joined)
        self.assertIs(entry.watch, watch)
        self.assertIn(watch, self.source._watches)
        self.connection.subscription.drain = original_drain
        self.assertTrue(strict_loads(await self.invoke(self.control(raw)))['claims']['joined'])
        self.assertTrue(watch.done.is_set())

    async def test_join_waits_for_original_sdk_callback_worker(self):
        from nats.aio.subscription import Subscription
        stopping, release = asyncio.Event(), asyncio.Event()
        async def subscribe(subject, **options):
            subscription = Subscription(self.connection, id=7, subject=subject, **options)
            original_wait = subscription._wait_for_msgs
            async def wait(error_cb):
                try:
                    await original_wait(error_cb)
                finally:
                    stopping.set()
                    await release.wait()
            async def on_error(error):
                raise error
            subscription._wait_for_msgs = wait
            subscription._start(on_error)
            self.connection.subscription = subscription
            self.connection.subscribed.set()
            return subscription
        async def unsubscribe(sid):
            pass
        self.connection.subscribe = subscribe
        self.connection.is_closed = self.connection.is_draining = False
        self.connection._send_unsubscribe = unsubscribe
        self.connection._remove_sub = lambda sid: None
        raw = self.watch()
        _, entry = await self.opened(raw)
        watch = entry.watch
        try:
            response = strict_loads(await self.invoke(self.control(raw, seconds=0.05)))['claims']
            await asyncio.wait_for(stopping.wait(), 2)
            worker = self.connection.subscription._wait_for_msgs_task
            self.assertFalse(response['joined'])
            self.assertFalse(worker.done())
            self.assertFalse(watch.done.is_set())
            with self.assertRaisesRegex(ContractError, '^configuration_cleanup_incomplete$'):
                await self.source.handle(self.configuration_request(revision=1))
        finally:
            release.set()
        self.assertTrue(strict_loads(await self.invoke(self.control(raw)))['claims']['joined'])
        self.assertTrue(worker.done())

    async def test_close_waits_for_original_reply_delivery_without_self_join(self):
        await self.source.start(reply_prefix='_INBOX.abcdefghijklmnop.')
        raw = self.watch(after=0)
        original_reply = '_INBOX.abcdefghijklmnop.' + 'e' * 64
        entered, release = asyncio.Event(), asyncio.Event()
        publish = self.connection.publish
        async def blocked(subject, data):
            if subject == original_reply:
                entered.set()
                await release.wait()
            await publish(subject, data)
        self.connection.publish = blocked
        try:
            await self.source._receive(SimpleNamespace(reply=original_reply, data=raw))
            await asyncio.wait_for(entered.wait(), 2)
            entry = self.controls._entries[payload_digest(strict_loads(raw))]
            delivery, = entry.deliveries
            response = strict_loads(await self.invoke(self.control(raw, seconds=0.05)))['claims']
            self.assertFalse(response['joined'])
            self.assertFalse(delivery.done())
        finally:
            release.set()
        result = strict_loads(await self.invoke(self.control(raw)))['claims']
        self.assertTrue(result['joined'])
        self.assertTrue(delivery.done())
        self.assertEqual(len([item for item in self.connection.sent if item[0] == original_reply]), 1)

    async def test_lost_first_reply_retries_retained_owner_after_expiry_and_revocation(self):
        raw = self.watch()
        await self.opened(raw)
        await self.revoke(ref('host-transport'))
        _Clock.value += timedelta(seconds=5)
        first = await self.invoke(self.control(raw))
        entry = self.controls._entries[payload_digest(strict_loads(raw))]
        self.assertTrue(entry.joined)
        self.assertFalse(entry.confirmed)
        _Clock.value += timedelta(seconds=5)
        retried = await self.invoke(self.control(raw))
        self.assertTrue(strict_loads(retried)['claims']['joined'])
        self.assertFalse(entry.confirmed)
        confirmed = strict_loads(await self.invoke(self.control(raw, proof=retried)))['claims']
        self.assertTrue(confirmed['receiptConfirmed'])
        self.assertFalse(self.controls._entries)
        self.assertEqual(self.connection.subscription.drains, 1)
        self.assertNotEqual(first, retried)
        with self.assertRaises(ContractError):
            await self.source.handle(self.watch(after=0))

    async def test_lost_confirmation_reply_recovers_from_expired_historical_proof(self):
        raw = self.watch()
        await self.opened(raw)
        proof = await self.invoke(self.control(raw))
        await self.revoke(ref('configuration-watch'))
        _Clock.value += timedelta(seconds=5)
        confirmed = strict_loads(await self.invoke(self.control(raw, proof=proof)))['claims']
        self.assertTrue(confirmed['receiptConfirmed'])
        self.assertFalse(self.controls._entries)
        _Clock.value += timedelta(seconds=5)
        recovered = strict_loads(await self.invoke(self.control(raw, proof=proof)))['claims']
        self.assertTrue(recovered['joined'] and recovered['receiptConfirmed'])
        self.assertFalse(self.controls._entries)
        self.assertFalse(self.source._watches)
        with self.assertRaisesRegex(ContractError, '^configuration_watch_expired$'):
            await self.source.handle(raw)

    async def test_forged_and_cross_bound_receipts_cannot_confirm(self):
        raw = self.watch()
        await self.opened(raw)
        proof = await self.invoke(self.control(raw))
        alterations = [lambda c: c['owner'].update(epoch='e' * 64),
            lambda c: c.update(watchRequestDigest='sha256:' + 'f' * 64),
            lambda c: c.update(authorityId='other-authority'),
            lambda c: c.update(profileId='other-profile'),
            lambda c: c.update(configurationRef=ref('other-configuration')),
            lambda c: c.update(requestPublicKey='a' * 43),
            lambda c: c.update(signingKeyRef=ref('other-issuer')),
            lambda c: c['authorityRef'].update(ownerHubId='other-hub'),
            lambda c: c.update(joined=False)]
        for alter in alterations:
            claims = strict_loads(proof)['claims']
            alter(claims)
            # A correctly signed receipt from a different allocation still
            # cannot satisfy this original request's exact bindings.
            wrong = self.signed(claims, seed=SEED)
            with self.subTest(change=alter), self.assertRaises(ContractError):
                await self.invoke(self.control(raw, proof=wrong))
        forged = strict_loads(proof)
        forged['signature'] = 'a' * 86
        with self.assertRaises(ContractError):
            await self.invoke(self.control(raw, proof=canonical_bytes(forged)))
        self.assertFalse(self.controls._entries[payload_digest(strict_loads(raw))].confirmed)
        _Clock.value += timedelta(seconds=5)
        await self.invoke(self.control(raw, proof=proof))
        self.assertFalse(self.controls._entries)
        with self.assertRaises(ContractError):
            await self.invoke(self.control(raw, proof=canonical_bytes(forged)))
        wrong_host = strict_loads(self.control(raw, proof=proof))
        wrong_host['signature'] = sign_claims(wrong_host['claims'], bytes([99]) * 32)
        with self.assertRaises(ContractError):
            await self.invoke(canonical_bytes(wrong_host))
        self.assertFalse(self.source._watches)

    async def test_unavailable_historical_key_retains_entry_for_retry(self):
        raw = self.watch()
        await self.opened(raw)
        proof = await self.invoke(self.control(raw))
        await self.revoke(ref('configuration-watch'))
        entry = self.controls._entries[payload_digest(strict_loads(raw))]
        current = self.source._authority._ledger.current
        reads = 0
        async def unavailable_history():
            nonlocal reads
            reads += 1
            if reads == 2:
                raise ContractError('owner_history_gap')
            return await current()
        with patch.object(self.source._authority._ledger, 'current', side_effect=unavailable_history):
            with self.assertRaisesRegex(ContractError, '^owner_history_gap$'):
                await self.invoke(self.control(raw, proof=proof))
        self.assertIn(entry.digest, self.controls._entries)
        self.assertFalse(entry.confirmed)
        self.assertTrue(strict_loads(await self.invoke(self.control(raw, proof=proof)))['claims']['receiptConfirmed'])

    async def test_same_service_identity_cannot_substitute_a_different_issuer(self):
        raw = self.watch()
        await self.opened(raw)
        proof = await self.invoke(self.control(raw))
        claims = strict_loads(proof)['claims']
        claims['signingKeyRef'] = ref('other-issuer')
        other_proof = self.signed(claims, seed=bytes([42]) * 32)
        with self.assertRaisesRegex(ContractError, '^configuration_watch_receipt_authority$'):
            await self.invoke(self.control(raw, proof=other_proof))
        self.assertFalse(self.controls._entries[payload_digest(strict_loads(raw))].confirmed)

    async def test_signer_revocation_during_receipt_lookup_refuses_fresh_acknowledgement(self):
        raw = self.watch()
        await self.opened(raw)
        proof = await self.invoke(self.control(raw))
        receipt = self.controls._receipt
        async def revoke_after_lookup(*args):
            admission = await receipt(*args)
            await self.revoke(ref('issuer'))
            return admission
        with patch.object(self.controls, '_receipt', side_effect=revoke_after_lookup):
            with self.assertRaisesRegex(ContractError, '^configuration_signer_unavailable$'):
                await self.invoke(self.control(raw, proof=proof))
        self.assertIn(payload_digest(strict_loads(raw)), self.controls._entries)
        # Inactivity does not erase the historical key or authorize a fresh
        # acknowledgement. Only the original fact can still be verified.
        historical = await self.controls._historical_signer(strict_loads(proof)['claims'],
            strict_loads((await self.source._authority.current()).record))
        self.assertEqual(historical, self.record['state']['issuers'][0]['publicKey'])
        with self.assertRaisesRegex(ContractError, '^configuration_signer_unavailable$'):
            await self.invoke(self.control(raw))

    async def test_expired_outer_control_and_unknown_receipt_before_deadline_refuse(self):
        raw = self.watch()
        await self.opened(raw)
        proof = await self.invoke(self.control(raw))
        expired = self.control(raw)
        entry = self.controls._entries.pop(payload_digest(strict_loads(raw)))
        try:
            with self.assertRaisesRegex(ContractError, '^configuration_watch_receipt_early$'):
                await self.invoke(self.control(raw, proof=proof))
        finally:
            self.controls._entries[entry.digest] = entry
        _Clock.value += timedelta(seconds=5)
        with self.assertRaisesRegex(ContractError, '^configuration_watch_close_expired$'):
            await self.invoke(expired)

    async def test_acknowledged_reclamation_sustains_more_than_table_capacity(self):
        self.controls._capacity = 3
        for _ in range(12):
            raw = self.watch(after=0, seconds=0.5)
            await self.source.handle(raw)
            proof = await self.invoke(self.control(raw))
            await self.invoke(self.control(raw, proof=proof))
            _Clock.value += timedelta(seconds=1)
        self.controls._reclaim()
        self.assertFalse(self.controls._entries)
        self.assertEqual(self.connection.subscription.drains, 12)

    async def test_unconfirmed_entries_are_never_evicted_by_expiry_or_capacity(self):
        self.controls._capacity = 2
        saved = []
        for _ in range(2):
            raw = self.watch(after=0)
            await self.source.handle(raw)
            saved.append((raw, await self.invoke(self.control(raw))))
            _Clock.value += timedelta(seconds=5)
        with self.assertRaisesRegex(ContractError, '^configuration_watch_capacity$'):
            await self.source.handle(self.watch(after=0))
        self.assertEqual(len(self.controls._entries), 2)
        await self.invoke(self.control(saved[0][0], proof=saved[0][1]))
        self.assertEqual(len(self.controls._entries), 1)
        await self.source.handle(self.watch(after=0))

    async def test_oversized_valid_owner_refuses_before_authorization_or_allocation(self):
        raw = strict_loads(self.watch())
        raw['payload']['owner']['pin']['version'] = '1' * 13000 + '.0.0'
        self.source._owner = canonical_bytes(raw['payload']['owner'])
        raw['operation']['payloadDigest'] = payload_digest(raw['payload'])
        raw['ingressAttestation']['claims']['operation'] = copy.deepcopy(raw['operation'])
        raw['ingressAttestation']['signature'] = sign_claims(raw['ingressAttestation']['claims'], SEED)
        validate('message-envelope', raw)
        validate('configuration-watch', raw['payload'])
        with patch.object(self.source, '_authorize', wraps=self.source._authorize) as authorize:
            with self.assertRaisesRegex(ContractError, '^configuration_watch_receipt_capacity$'):
                await self.source.handle(canonical_bytes(raw))
            authorize.assert_not_called()
        self.assertFalse(self.controls._entries)
        self.assertFalse(self.source._watches)

    async def test_schema_lengths_and_exact_receipt_size_boundary(self):
        binding = self.controls._binding(strict_loads(self.watch()))
        base, _ = _sizing_frames(binding)
        original_length = len(binding['owner']['pin']['version'])
        digits = 12288 - len(base) + original_length - len('.0.0')
        binding['owner']['pin']['version'] = '1' * digits + '.0.0'
        proof, confirmation = _sizing_frames(binding)
        self.assertEqual(len(proof), 12288)
        self.assertEqual(len(base64.b64encode(proof)), 16384)
        self.assertLessEqual(len(confirmation), 65536)
        validate('configuration-watch-close-response', strict_loads(proof))
        validate('configuration-watch-close', strict_loads(confirmation))
        binding['owner']['pin']['version'] += '1'
        self.assertEqual(len(_sizing_frames(binding)[0]), 12289)
        for schema, body, field in (
                ('configuration-watch-close-response', proof, 'requestId'),
                ('configuration-watch-close-response', proof, 'requestPublicKey'),
                ('configuration-watch-close', confirmation, 'joinedResponseBytes')):
            value = strict_loads(body)
            value['claims'][field] += '\n'
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate(schema, value)
        value = strict_loads(proof)
        value['signature'] += '\n'
        with self.assertRaises(ContractError):
            validate('configuration-watch-close-response', value)

    async def test_shared_native_sizing_vector_has_the_same_exact_boundary(self):
        path = Path(__file__).resolve().parents[1] / 'tests/contracts/vectors/configuration-watch-close-sizing.json'
        vector = strict_loads(path.read_bytes())
        binding = vector['binding']
        for digits in (vector['maximumVersionDigits'] - 1, vector['maximumVersionDigits'],
                       vector['maximumVersionDigits'] + 1):
            binding['owner']['pin']['version'] = '1' * digits + '.0.0'
            proof, confirmation = _sizing_frames(binding)
            fits = len(proof) <= vector['proofLimit'] and len(confirmation) <= vector['confirmationLimit']
            self.assertEqual(fits, digits <= vector['maximumVersionDigits'])
            if digits == vector['maximumVersionDigits']:
                self.assertEqual(len(proof), vector['proofLimit'])
