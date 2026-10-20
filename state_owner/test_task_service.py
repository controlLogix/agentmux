"""Real task/identity/signature checks at a controlled offline transport boundary."""
import asyncio
import copy
from datetime import timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from capability_owner.test_reply_service import Connection
from identity.test_authority import ref, SEED, NOW
from identity.test_service import _Clock
from state_owner.task_service import TaskService, verify_task_reply, RESPONSE_LIMIT, ENCODED_RECORD_LIMIT, REPLY_METADATA_LIMIT
from state_owner import test_task as support


class TaskServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        support.TaskReservationTests.setUp(self)
        patch('state_owner.task_service.datetime', _Clock).start()
        self.connection = Connection()
        self.reply = '_INBOX.task_caller_00000001.'+'a'*64
        self.transport = TaskService(self.owner, self.service.ingress, connection=self.connection,
            service_identity_ref=ref('service'), service_instance_id='ingress-one', signing_key_ref=ref('issuer'),
            signing_seed=SEED, requester_reply_prefix='_INBOX.task_caller_00000001', account_public_key='A'*56)
        self.addAsyncCleanup(self.transport.close, timeout=None)

    new_ledger = support.TaskReservationTests.new_ledger
    reset_task = support.TaskReservationTests.reset_task
    possession = support.TaskReservationTests.possession

    def request(self, contract='task-reserve', *, operation='reserve-one'):
        request = strict_loads(self.possession(operation=operation))
        request['claims'].update(contractId=contract, replySubject=self.reply)
        if contract=='task-inspect':
            request['claims'].update(grantRef=ref('grant'), payload={'taskId': 'task-one'})
        request['signature'] = sign_claims(request['claims'], bytes(reversed(SEED)))
        return canonical_bytes(request)

    def verified(self, response, request):
        return verify_task_reply(response, request, binding=self.binding, source_pin=self.transport.source_pin,
            public_key=self.record['state']['issuers'][0]['publicKey'], signing_key_ref=ref('issuer'),
            service_identity_ref=ref('service'), service_instance_id='ingress-one',
            minimum_source_revision=1, now=NOW)

    async def test_actual_possession_preparation_commit_signed_reply_and_original_replay(self):
        request = self.request()
        response = await self.transport.handle(request, received_reply_subject=self.reply)
        stored = self.verified(response, request)
        self.assertEqual(stored.sequence, 2)
        self.assertEqual(strict_loads(stored.record)['state']['executionGrant']['ref'],
            self.owner.reservation_references('reserve-one')['executionGrantRef'])
        replay = self.verified(await self.transport.handle(request, received_reply_subject=self.reply), request)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record, stored.record)
        self.assertEqual(len(self.task_js.messages), 2)

    async def test_bad_possession_and_wrong_reply_never_read_task_source(self):
        request = strict_loads(self.request())
        request['signature'] = sign_claims(request['claims'], bytes([31])*32)
        with patch.object(self.ledger, 'current', wraps=self.ledger.current) as current:
            with self.assertRaises(ContractError):
                await self.transport.handle(canonical_bytes(request), received_reply_subject=self.reply)
            with self.assertRaisesRegex(ContractError, '^task_service_request_invalid$'):
                await self.transport.handle(self.request(), received_reply_subject=self.reply+'x')
            current.assert_not_called()
        self.assertEqual(len(self.task_js.messages), 1)

    async def test_reply_refuses_changed_request_source_key_and_record_revision(self):
        request = self.request('task-inspect')
        response = await self.transport.handle(request, received_reply_subject=self.reply)
        self.assertEqual(self.verified(response, request).record, self.task_js.messages[0].data)
        changed_request = self.request('task-inspect', operation='other-read')
        with self.assertRaisesRegex(ContractError, '^task_reply_unconfirmed$'):
            self.verified(response, changed_request)
        pristine = strict_loads(response)
        for mutate in (lambda c: c['source'].update(streamCreated='2026-10-17T00:00:00Z'),
                lambda c: c.update(signingKeyRef=ref('other-signer')),
                lambda c: c.update(sourceRevision=2), lambda c: c.update(replySubject=self.reply+'x')):
            value = copy.deepcopy(pristine)
            mutate(value['claims'])
            value['signature'] = sign_claims(value['claims'], SEED)
            with self.assertRaisesRegex(ContractError, '^task_reply_unconfirmed$'):
                self.verified(canonical_bytes(value), request)

    async def test_current_signer_revocation_after_commit_produces_no_reply(self):
        handle = self.owner.handle
        async def commit_then_revoke(*args, **kwargs):
            stored = await handle(*args, **kwargs)
            self.record['state']['issuers'][0]['status'] = 'revoked'
            self.js.messages[0].data = canonical_bytes(self.record)
            return stored
        with patch.object(self.owner, 'handle', side_effect=commit_then_revoke):
            with self.assertRaises(ContractError):
                await self.transport.handle(self.request(), received_reply_subject=self.reply)
        self.assertEqual(len(self.task_js.messages), 2)
        self.assertEqual(strict_loads(self.task_js.messages[1].data)['state']['status'], 'reserved')

    async def test_maximum_record_fits_calculated_frame_without_reducing_owner_limit(self):
        value = copy.deepcopy(self.original)
        value['state']['body'] = ''
        value['state']['body'] = 'x'*(65536-len(canonical_bytes(value)))
        raw = canonical_bytes(value)
        self.assertEqual(len(raw), 65536)
        self.task_js.messages[0].data = raw
        request = self.request('task-inspect')
        response = await self.transport.handle(request, received_reply_subject=self.reply)
        self.assertEqual(self.verified(response, request).record, raw)
        self.assertEqual(len(strict_loads(response)['claims']['recordBytes']), ENCODED_RECORD_LIMIT)
        self.assertLessEqual(len(response), ENCODED_RECORD_LIMIT+REPLY_METADATA_LIMIT)
        self.assertEqual(RESPONSE_LIMIT, 95576)

    async def test_transport_callback_publishes_only_bound_reply_and_joins(self):
        await self.transport.start()
        request = self.request()
        await self.transport._receive(SimpleNamespace(data=request, reply=self.reply))
        jobs = tuple(self.transport._requests)
        await asyncio.gather(*jobs)
        self.assertEqual(len(self.connection.sent), 1)
        subject, response = self.connection.sent[0]
        self.assertEqual(subject, self.reply)
        self.assertEqual(self.verified(response, request).sequence, 2)
        await self.transport.close(timeout=None)
        self.assertTrue(self.transport.done.is_set())
        self.assertFalse(self.transport._requests or self.transport._active)
        self.assertEqual(self.connection.subscription.drains, 1)

    async def test_cancelled_start_and_close_keep_original_pending_subscription(self):
        self.connection.release.clear()
        starting = asyncio.create_task(self.transport.start())
        await self.connection.subscribed.wait()
        allocation = self.transport._subscribe_task
        starting.cancel()
        await asyncio.gather(starting, return_exceptions=True)
        with self.assertRaisesRegex(ContractError, '^task_service_cleanup_incomplete$'):
            await self.transport.close(timeout=.01)
        self.assertIs(self.transport._subscribe_task, allocation)
        self.assertFalse(allocation.cancelled())
        self.assertFalse(self.transport.done.is_set())
        self.connection.release.set()
        await self.transport.close(timeout=None)
        self.assertTrue(allocation.done())
        self.assertEqual(self.connection.subscription.drains, 1)

    async def test_frame_limit_refuses_before_command_allocation(self):
        self.connection.max_payload = RESPONSE_LIMIT-1
        with self.assertRaisesRegex(ContractError, '^task_service_frame_limit$'):
            await self.transport.start()
        self.assertIsNone(self.transport._subscribe_task)

    async def test_close_keeps_reply_already_handed_to_transport_until_joined(self):
        await self.transport.start()
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.connection.publish
        async def publish(subject, response):
            entered.set()
            await release.wait()
            await original(subject, response)
        with patch.object(self.connection, 'publish', side_effect=publish):
            await self.transport._receive(SimpleNamespace(data=self.request(), reply=self.reply))
            await entered.wait()
            delivery = next(iter(self.transport._requests))
            try:
                with self.assertRaisesRegex(ContractError, '^task_service_cleanup_incomplete$'):
                    await self.transport.close(timeout=.01)
                self.assertFalse(delivery.done() or self.transport.done.is_set())
                self.assertEqual(self.connection.subscription.drains, 0)
            finally:
                release.set()
                await self.transport.close(timeout=None)
        self.assertTrue(delivery.done())
        self.assertEqual(self.connection.subscription.drains, 1)
        self.assertEqual(len(self.connection.sent), 1)

    async def test_expired_callback_deadline_never_reads_source_or_renews_budget(self):
        with patch.object(self.owner, 'handle', wraps=self.owner.handle) as handle:
            await self.transport._deliver(self.request(), self.reply,
                deadline=asyncio.get_running_loop().time()-1)
            handle.assert_not_called()
        self.assertFalse(self.connection.sent)
