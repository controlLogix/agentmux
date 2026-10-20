"""Enrolled receiving service with real signatures, history, ledger and files."""
import asyncio
import copy
import threading
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from definition_command_service import DefinitionCommandService, verify_receipt
from definition_commands import (DefinitionCommandOwner, DefinitionReceipt,
                                 LocalDefinitionOutcomeUnconfirmed)
from identity.authority import LedgerAuthorityReader
from identity.ingress import EnrolledIngress
from identity.test_authority import SEED, ref
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import FakeJetStream
import test_definition_commands as support
import ccboard


class DefinitionServiceTests(unittest.IsolatedAsyncioTestCase):
    # Reuse the existing real-owner fixture and controlled broker boundary.
    setUp = support.DefinitionCommandTests.setUp
    new_ledger = support.DefinitionCommandTests.new_ledger
    new_owner = support.DefinitionCommandTests.new_owner
    authority_message = support.DefinitionCommandTests.authority_message
    resign = support.DefinitionCommandTests.resign
    effect_request = support.DefinitionCommandTests.effect_request

    async def asyncSetUp(self):
        self.history = OwnerHistory(Path(self.tmp.name).resolve() / 'history.sqlite', self.binding,
                                    stream_identity=self.ledger._identity)
        self.ledger = OwnerLedger(self.js, stream='OWNER', subject=self.ledger._subject, binding=self.binding,
            retention=self.policy, stream_identity=self.ledger._identity, history=self.history,
            require_completion_budget=True)
        self.owner = DefinitionCommandOwner(self.service, self.authority, self.ledger, self.binding, self.artifacts)
        self.subscription = SimpleNamespace(drain=AsyncMock())
        self.connection = SimpleNamespace(subscribe=AsyncMock(return_value=self.subscription),
                                          flush=AsyncMock(), publish=AsyncMock())
        self.ingress = EnrolledIngress(self.authority, issuer_ref=ref('issuer'), signing_seed=SEED)
        self.checkpoints = []
        async def committed(receipt):
            self.checkpoints.append(receipt)
        self.receiver = DefinitionCommandService(self.connection, self.owner, self.ingress,
            checkpoint_path=Path(self.tmp.name).resolve() / 'checkpoint.json', checkpoint_committed=committed)
        self.addAsyncCleanup(self.receiver.close)

    def request(self, *, reply=None):
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': ref('grant'),
            'operationId': self.env['operation']['operationId'],
            'expectedVersion': self.env['operation']['expectedVersion'],
            'contractId': self.env['contractId'], 'payload': copy.deepcopy(self.env['payload']),
            'approvalRefs': [], 'issuedAt': (self.now - timedelta(seconds=1)).isoformat().replace('+00:00', 'Z'),
            'expiresAt': (self.now + timedelta(seconds=50)).isoformat().replace('+00:00', 'Z')}
        if reply is not None:
            claims['replySubject'] = reply
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})

    def receipt(self, response, request):
        return verify_receipt(response, request, public_key=self.authority_record['state']['issuers'][0]['publicKey'],
                              issuer_ref=ref('issuer'))

    async def test_handoff_precedes_subscription_and_receipts_distinguish_completion(self):
        async def subscribe(*args, **kwargs):
            self.assertIsNotNone(self.owner._writer)
            with self.assertRaises(ccboard.Refused):
                self.service.legacy_save(None, {'name': 'other', 'scope': 'repo'})
            self.callback = kwargs['cb']
            return self.subscription
        self.connection.subscribe.side_effect = subscribe
        await self.receiver.start()
        request = self.request()
        receipt = self.receipt(await self.receiver.handle(request), request)
        self.assertEqual(receipt['status'], 'intent-committed')
        self.assertIsNone(receipt['observedAt'])
        self.assertTrue(self.path.exists())
        self.assertEqual(self.history.verified_cursor, 1)
        self.effect_request('definition-effect-complete')
        request = self.request()
        receipt = self.receipt(await self.receiver.handle(request), request)
        self.assertEqual((receipt['status'], receipt['receiptSequence']), ('applied', 2))
        self.assertIsNotNone(receipt['observedAt'])
        self.assertEqual(self.owner._observations, {})
        self.receiver._cadence._dirty_since = 0
        self.receiver._checkpoint_if_due()
        await self.receiver._checkpoint_work
        self.assertEqual(self.checkpoints[-1].cursor, 2)
        self.assertTrue(Path(self.checkpoints[-1].manifest_path).exists())
        await self.receiver.close()
        self.assertTrue(self.history._closed)
        self.subscription.drain.assert_awaited_once()
        with self.assertRaises(ccboard.Refused):
            self.service.legacy_save(None, {'name': 'other', 'scope': 'repo'})

    async def test_local_browser_edit_uses_same_owner_and_returns_saved_definition(self):
        await self.receiver.start()
        context = support.DefinitionCommandTests.browser_context(self)
        saved = await self.receiver.handle_local_browser(context, '/api/board/agentdef',
            {'name': 'worker', 'scope': 'repo', 'description': 'Review changes'})
        self.assertEqual((saved['name'], saved['scope'], saved['description']),
                         ('worker', 'repo', 'Review changes'))
        self.assertTrue(self.path.exists())
        stored = strict_loads(self.js.messages[0].data)
        self.assertEqual(stored['effects'][0]['contractId'], 'definition-save')
        self.assertNotIn('actor', stored['effects'][0]['payload'])
        self.assertEqual(len(self.js.messages), 2)
        completed = strict_loads(self.js.messages[1].data)
        self.assertEqual(completed['effects'], [])
        self.assertEqual(completed['definitionEffectReceipt']['status'], 'applied')
        original = strict_loads(self.js.messages[0].data)
        self.owner = self.new_owner()
        query = self.effect_request('definition-effect-query', original=original)
        progress = await self.owner.execute(query)
        self.assertEqual((progress.status, progress.receipt_sequence), ('applied', 2))
        self.assertEqual(len(self.js.messages), 2)
        with self.assertRaisesRegex(ContractError, 'local_browser_context_invalid'):
            await self.receiver.handle_local_browser(object(), '/api/board/agentdef',
                {'name': 'other', 'scope': 'repo', 'description': 'Other'})

    async def test_local_browser_completion_obeys_its_own_current_hard_denial(self):
        await self.receiver.start()
        denied = copy.deepcopy(self.authority_record['state']['grants'][1])
        denied.update(ref=ref('completion-deny'), decision='denied')
        self.authority_record['state']['grants'].append(denied)
        context = support.DefinitionCommandTests.browser_context(self)
        with self.assertRaises(LocalDefinitionOutcomeUnconfirmed) as raised:
            await self.receiver.handle_local_browser(context, '/api/board/agentdef',
                {'name': 'worker', 'scope': 'repo', 'description': 'Review changes'})
        self.assertEqual(raised.exception.code, 'definition_not_authorized')
        self.assertRegex(raised.exception.operation_id, r'^browser_[a-f0-9]{32}$')
        self.assertTrue(self.path.exists())
        self.assertEqual(len(self.js.messages), 1)
        retained = strict_loads(self.js.messages[0].data)
        self.assertEqual(retained['authorizationDecision']['contractId'], 'definition-save')
        self.assertNotIn('effectReceiptRef', retained['state']['definitions'][0])

    async def test_local_browser_non_applied_receipt_keeps_original_recovery_identity(self):
        await self.receiver.start()
        operation_id = 'browser_' + 'a' * 32
        receipt = DefinitionReceipt(operation_id, 1, 1, False,
                                    'reconciliation-required')
        context = support.DefinitionCommandTests.browser_context(self)
        with patch.object(self.owner, 'execute_local_browser',
                          AsyncMock(return_value=receipt)):
            with self.assertRaises(LocalDefinitionOutcomeUnconfirmed) as raised:
                await self.receiver.handle_local_browser(context, '/api/board/agentdef',
                    {'name': 'worker', 'scope': 'repo'}, operation_id=operation_id)
        self.assertEqual(raised.exception.operation_id, operation_id)

    async def test_signed_reply_subject_and_exact_request_binding(self):
        await self.receiver.start()
        reply = '_INBOX.' + 'a' * 22
        request = self.request(reply=reply)
        await self.receiver._receive(SimpleNamespace(reply=reply, data=request))
        destination, response = self.connection.publish.await_args.args
        self.assertEqual(destination, reply)
        self.assertEqual(self.receipt(response, request)['status'], 'intent-committed')
        self.env['operation']['operationId'] = 'another-operation'
        with self.assertRaisesRegex(ContractError, 'definition_receipt_binding'):
            self.receipt(response, self.request(reply=reply))
        self.connection.publish.reset_mock()
        await self.receiver._receive(SimpleNamespace(reply='_INBOX.' + 'b' * 22, data=request))
        self.connection.publish.assert_not_awaited()

    async def test_invalid_possession_and_revocation_cannot_write(self):
        await self.receiver.start()
        request = strict_loads(self.request())
        request['signature'] = sign_claims(request['claims'], SEED)
        with self.assertRaisesRegex(ContractError, 'credential_possession_invalid'):
            await self.receiver.handle(canonical_bytes(request))
        self.authority_record['state']['transports'][0]['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, 'credential_unavailable'):
            await self.receiver.handle(self.request())
        self.assertEqual(self.js.messages, [])
        self.assertFalse(self.path.exists())

    async def test_no_receiving_before_start_or_after_close(self):
        with self.assertRaisesRegex(ContractError, 'definition_service_unavailable'):
            await self.receiver.handle(self.request())
        await self.receiver.start()
        await self.receiver.close()
        with self.assertRaisesRegex(ContractError, 'definition_service_unavailable'):
            await self.receiver.handle(self.request())

    async def test_close_joins_original_subscription_allocation(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def subscribe(*args, **kwargs):
            entered.set()
            await release.wait()
            return self.subscription
        self.connection.subscribe.side_effect = subscribe
        startup = asyncio.create_task(self.receiver.start())
        await asyncio.wait_for(entered.wait(), 3)
        startup.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await startup
        closing = asyncio.create_task(self.receiver.close())
        await asyncio.sleep(0)
        self.assertFalse(closing.done())
        self.assertFalse(self.history._closed)
        release.set()
        await closing
        self.subscription.drain.assert_awaited_once()
        self.assertTrue(self.history._closed)

    async def test_close_joins_inflight_physical_effect(self):
        await self.receiver.start()
        entered, release = asyncio.Event(), asyncio.Event()
        execute = self.owner._execute_effect
        async def delayed(*args, **kwargs):
            entered.set()
            await release.wait()
            return await execute(*args, **kwargs)
        with patch.object(self.owner, '_execute_effect', delayed):
            command = asyncio.create_task(self.receiver.handle(self.request()))
            await asyncio.wait_for(entered.wait(), 3)
            closing = asyncio.create_task(self.receiver.close())
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            self.assertFalse(self.history._closed)
            release.set()
            await command
            await closing
        self.assertTrue(self.path.exists())
        self.assertTrue(self.history._closed)

    async def test_close_during_recovery_does_not_claim_or_subscribe(self):
        entered = asyncio.Event()
        async def page():
            entered.set()
            await asyncio.sleep(0)
            return SimpleNamespace(ready=False)
        self.ledger.prepare_history = page
        startup = asyncio.create_task(self.receiver.start())
        await asyncio.wait_for(entered.wait(), 3)
        await asyncio.wait_for(self.receiver.close(), 1)
        with self.assertRaisesRegex(ContractError, 'definition_service_closed'):
            await startup
        self.assertIsNone(self.owner._writer)
        self.connection.subscribe.assert_not_awaited()

    async def test_uncertain_fence_flush_does_not_subscribe_or_restore_legacy(self):
        with patch('definition_service.os.fsync', side_effect=OSError('test flush failure')):
            with self.assertRaises(OSError):
                await self.receiver.start()
        self.connection.subscribe.assert_not_awaited()
        self.assertIsNone(self.owner._writer)
        with self.assertRaises(ccboard.Refused):
            self.service.legacy_save(None, {'name': 'other', 'scope': 'repo'})
        self.assertEqual(self.js.messages, [])

    async def test_conflicting_persisted_owner_is_preserved_and_not_subscribed(self):
        directory = self.repo / '.agentmux/agents'
        directory.mkdir(parents=True)
        fence = directory / '.owner-fence'
        fence.write_bytes(b'another-owner')
        with self.assertRaises(ccboard.Refused):
            await self.receiver.start()
        self.assertEqual(fence.read_bytes(), b'another-owner')
        self.connection.subscribe.assert_not_awaited()
        self.assertIsNone(self.owner._writer)

    async def test_exact_signed_request_replays_without_another_record_or_effect(self):
        await self.receiver.start()
        request = self.request()
        first = self.receipt(await self.receiver.handle(request), request)
        before = self.path.stat()
        self.authority_record['state']['grants'][0]['expiresAt'] = (
            self.now + timedelta(seconds=10)).isoformat().replace('+00:00', 'Z')
        with patch('definition_commands.apply_exact_source', side_effect=AssertionError('duplicate effect')):
            replay = self.receipt(await self.receiver.handle(request), request)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['catalogSequence'], first['catalogSequence'])
        self.assertEqual(self.history.verified_cursor, 1)
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(self.service._file_identity(self.path.stat()), self.service._file_identity(before))
        self.effect_request('definition-effect-complete')
        completion = self.request()
        first = self.receipt(await self.receiver.handle(completion), completion)
        replay = self.receipt(await self.receiver.handle(completion), completion)
        self.assertTrue(replay['replayed'])
        self.assertEqual(replay['receiptSequence'], first['receiptSequence'])
        self.assertEqual(len(self.js.messages), 2)
        self.assertEqual(self.owner._observations, {})

    async def test_close_joins_callback_reply_and_ignores_queued_messages(self):
        await self.receiver.start()
        entered, release = asyncio.Event(), asyncio.Event()
        async def publish(*args):
            entered.set()
            await release.wait()
        self.connection.publish.side_effect = publish
        reply = '_INBOX.' + 'c' * 22
        message = SimpleNamespace(reply=reply, data=self.request(reply=reply))
        callback = asyncio.create_task(self.receiver._receive(message))
        await asyncio.wait_for(entered.wait(), 3)
        self.assertEqual(len(self.receiver._callbacks), 1)
        self.assertEqual(len(self.receiver._active), 0)
        closing = asyncio.create_task(self.receiver.close())
        await asyncio.sleep(.01)
        self.assertFalse(closing.done())
        self.assertFalse(self.history._closed)
        await self.receiver._receive(message)
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(self.connection.publish.await_count, 1)
        closing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await closing
        release.set()
        await callback
        await self.receiver.close()
        self.assertTrue(self.history._closed)
        self.assertEqual(self.receiver._callbacks, set())

    async def test_cancelled_callback_keeps_its_actual_worker_until_joined(self):
        await self.receiver.start()
        entered, release = threading.Event(), threading.Event()
        from definition_service import DefinitionService
        mutate = DefinitionService._mutate_file_locked
        def delayed(service, *args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise AssertionError('worker was not released')
            return mutate(service, *args, **kwargs)
        reply = '_INBOX.' + 'd' * 22
        message = SimpleNamespace(reply=reply, data=self.request(reply=reply))
        with patch.object(DefinitionService, '_mutate_file_locked', delayed):
            callback = asyncio.create_task(self.receiver._receive(message))
            try:
                for _ in range(300):
                    if entered.is_set():
                        break
                    await asyncio.sleep(.005)
                self.assertTrue(entered.is_set())
                callback.cancel()
                closing = asyncio.create_task(self.receiver.close())
                await asyncio.sleep(.01)
                callback.cancel()
                await asyncio.sleep(.01)
                self.assertFalse(callback.done())
                self.assertFalse(closing.done())
                self.assertFalse(self.history._closed)
            finally:
                release.set()
            with self.assertRaises(asyncio.CancelledError):
                await callback
            await closing
        self.assertTrue(self.path.exists())
        self.assertEqual(len(self.js.messages), 1)
        self.connection.publish.assert_not_awaited()
        self.assertTrue(self.history._closed)
        self.assertEqual(self.receiver._callbacks, set())

    async def test_unenrolled_or_revoked_issuer_does_not_claim_fence(self):
        self.authority_record['state']['issuers'][0]['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, 'definition_issuer_unavailable'):
            await self.receiver.start()
        self.assertIsNone(self.owner._writer)
        self.assertFalse((self.repo / '.agentmux').exists())
        self.connection.subscribe.assert_not_awaited()

    async def test_wrong_signing_key_does_not_claim_fence(self):
        self.receiver._seed = bytes(reversed(SEED))
        with self.assertRaisesRegex(ContractError, 'credential_possession_invalid'):
            await self.receiver.start()
        self.assertIsNone(self.owner._writer)
        self.assertFalse((self.repo / '.agentmux').exists())
        self.connection.subscribe.assert_not_awaited()

    async def test_intermediate_symlink_is_rejected_before_control_file_creation(self):
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        (self.repo / '.agentmux').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ccboard.Invalid):
            await self.receiver.start()
        self.assertEqual(list(outside.iterdir()), [])
        self.connection.subscribe.assert_not_awaited()

    async def test_host_composition_uses_retained_authority_and_owns_the_command_route(self):
        # The host provides its already enrolled authority stream and private
        # resources; composition creates neither credentials nor broker streams.
        scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        binding = OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority', canonical_bytes(scope))
        authority_js = FakeJetStream(self.policy)
        authority_js.config = self.policy.stream_config(stream='AUTH', subject=owner_subject(binding))
        record = copy.deepcopy(self.authority_record)
        record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None)
        record['operation'].update(expectedVersion=0, scope=scope)
        authority_js.messages = [SimpleNamespace(subject=owner_subject(binding), seq=1, data=canonical_bytes(record))]
        authority_ledger = OwnerLedger(authority_js, stream='AUTH', subject=owner_subject(binding), binding=binding,
            retention=self.policy, stream_identity=StreamIdentity(authority_js.created, 1))
        authority = LedgerAuthorityReader(authority_ledger, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        self.connection.jetstream = Mock(return_value=self.js)
        receiver = DefinitionCommandService.from_enrolled_host(self.connection, scope=self.service.scope,
            authority=authority, binding=self.binding, stream='OWNER', stream_identity=self.ledger._identity,
            retention=self.policy, history=self.history, artifacts=self.artifacts, issuer_ref=ref('issuer'),
            signing_seed=SEED, checkpoint_path=self.receiver._checkpoint_path,
            checkpoint_committed=self.receiver._checkpoint_committed, jetstream_domain='enrolled-domain')
        self.connection.jetstream.assert_called_once_with(domain='enrolled-domain')
        self.receiver = receiver
        self.addAsyncCleanup(receiver.close)
        await receiver.start()
        subject, = self.connection.subscribe.await_args.args
        self.assertEqual(subject, receiver.subject)
        reply = '_INBOX.' + 'e' * 22
        request = self.request(reply=reply)
        callback = self.connection.subscribe.await_args.kwargs['cb']
        await callback(SimpleNamespace(reply=reply, data=request))
        destination, response = self.connection.publish.await_args.args
        self.assertEqual(destination, reply)
        self.assertEqual(self.receipt(response, request)['status'], 'intent-committed')
        self.assertTrue(self.path.exists())
        self.assertEqual(self.history.verified_cursor, 1)
