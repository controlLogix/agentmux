"""Private command diagnostics preserve the original future and public failure."""
from concurrent.futures import Future
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import json
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError
from hub.client_launch_binding import BindingError
from hub.client_launch_connection import ConnectionFailure, MessageOutcomeUnconfirmed, PolicyOutcomeUnconfirmed
from hub.client_launch_session import ApplicationClientSession, ApplicationSessionFailure
from hub.tests import test_client_launch_connection as connection_fixture


class CommandFailureDiagnosticTests(unittest.TestCase):
    def session(self, future):
        session = object.__new__(ApplicationClientSession)
        session._command_identity = ('original',)
        session._command_future = future
        return session

    def test_pending_timeout_preserves_future_and_same_identity_can_consume(self):
        future = Future()
        session = self.session(future)
        submit = Mock(side_effect=AssertionError('must not submit another command'))
        deadline = time.monotonic() - .01
        with self.assertRaises(ApplicationSessionFailure) as caught:
            session._wait_command(('original',), submit, deadline)
        self.assertEqual(str(caught.exception), 'application_connection_unavailable')
        self.assertIs(session._command_future, future)
        self.assertFalse(future.cancelled())
        diagnostic = caught.exception._command_diagnostic
        self.assertEqual(diagnostic['stage'], 'wait')
        self.assertEqual(diagnostic['futureState'], 'pending')
        self.assertLessEqual(diagnostic['deadlineRemaining'], 0)
        self.assertEqual(diagnostic['futureChain'], [])
        self.assertEqual(diagnostic['waiterChain'], [{'type': 'TimeoutError', 'code': None}])
        future.set_result({'original': True})
        self.assertEqual(session._wait_command(('original',), submit, time.monotonic() + 1),
            {'original': True})
        submit.assert_not_called()
        self.assertIsNone(session._command_future)
        self.assertIsNone(session._command_identity)

    def failed_wait(self, session, identity=('original',)):
        submit = Mock(side_effect=AssertionError('must not submit another command'))
        with self.assertRaises(ApplicationSessionFailure) as caught:
            session._wait_command(identity, submit, time.monotonic() + 1)
        submit.assert_not_called()
        self.assertEqual(str(caught.exception), 'application_connection_unavailable')
        self.assertIs(caught.exception.owner, session)
        return caught.exception

    def test_completed_timeout_is_distinct_from_pending_wait_timeout(self):
        future = Future()
        original = TimeoutError('private timeout detail')
        future.set_exception(original)
        session = self.session(future)
        failure = self.failed_wait(session)
        diagnostic = failure._command_diagnostic
        self.assertEqual(diagnostic['futureState'], 'done')
        self.assertEqual(diagnostic['waiterChain'], [{'type': 'TimeoutError', 'code': None}])
        self.assertEqual(diagnostic['futureChain'], diagnostic['waiterChain'])
        self.assertGreater(diagnostic['deadlineRemaining'], 0)
        self.assertIs(session._command_future, future)
        self.assertIs(future.exception(), original)
        self.assertNotIn('private timeout detail', json.dumps(diagnostic))

    def test_connection_private_cause_keeps_only_closed_type_and_code(self):
        secret = RuntimeError('credential=private-value')
        schema = ContractError('schema_invalid')
        schema.__cause__ = secret
        original = ConnectionFailure('application_binding_unavailable', object(), schema)
        future = Future()
        future.set_exception(original)
        session = self.session(future)
        diagnostic = self.failed_wait(session)._command_diagnostic
        expected = [{'type': 'ConnectionFailure', 'code': 'application_binding_unavailable'},
            {'type': 'ContractError', 'code': 'schema_invalid'},
            {'type': 'other', 'code': None}]
        self.assertEqual(diagnostic['waiterChain'], expected)
        self.assertEqual(diagnostic['futureChain'], expected)
        self.assertNotIn('credential', json.dumps(diagnostic))
        self.assertNotIn('private-value', json.dumps(diagnostic))
        self.assertIs(session._command_future, future)

    def test_exception_cycle_and_long_chain_are_bounded(self):
        for cycle in (True, False):
            with self.subTest(cycle=cycle):
                errors = [RuntimeError('private chain value') for _ in range(12)]
                for left, right in zip(errors, errors[1:]):
                    left.__cause__ = right
                if cycle:
                    errors[1].__cause__ = errors[0]
                future = Future()
                future.set_exception(errors[0])
                diagnostic = self.failed_wait(self.session(future))._command_diagnostic
                self.assertEqual(len(diagnostic['futureChain']), 2 if cycle else 8)
                self.assertTrue(all(entry == {'type': 'other', 'code': None}
                    for entry in diagnostic['futureChain']))
                self.assertEqual(diagnostic['waiterChain'], diagnostic['futureChain'])

    def test_live_binding_codes_and_known_outcome_causes_are_retained(self):
        binding_codes = ('application_binding_budget', 'application_lifetime_ended',
            'application_lease_invalid', 'application_response_binding')
        for kind, code in ((MessageOutcomeUnconfirmed, 'application_message_outcome_unconfirmed'),
                (PolicyOutcomeUnconfirmed, 'application_policy_outcome_unconfirmed')):
            for binding_code in binding_codes:
                with self.subTest(kind=kind.__name__, binding_code=binding_code):
                    cause = BindingError(binding_code)
                    original = kind(code, object(), cause)
                    future = Future()
                    future.set_exception(original)
                    session = self.session(future)
                    diagnostic = self.failed_wait(session)._command_diagnostic
                    expected = [{'type': kind.__name__, 'code': code},
                        {'type': 'BindingError', 'code': binding_code}]
                    self.assertEqual(diagnostic['waiterChain'], expected)
                    self.assertEqual(diagnostic['futureChain'], expected)
                    self.assertIs(session._command_future, future)
                    self.assertIs(original._cause, cause)

    def test_identity_mismatch_does_not_consume_completed_future(self):
        future = Future()
        future.set_result('original result')
        session = self.session(future)
        with patch.object(future, 'exception', wraps=future.exception) as exception:
            failure = self.failed_wait(session, ('different-private-identity',))
        exception.assert_called_once_with(timeout=0)
        self.assertEqual(failure._command_diagnostic['stage'], 'identity-mismatch')
        self.assertEqual(failure._command_diagnostic['waiterChain'], [])
        self.assertEqual(failure._command_diagnostic['futureChain'], [])
        self.assertIs(session._command_future, future)
        self.assertEqual(session._command_identity, ('original',))
        self.assertNotIn('different-private-identity', json.dumps(failure._command_diagnostic))
        self.assertEqual(session._wait_command(('original',), Mock(), time.monotonic() + 1),
            'original result')

    def test_identity_mismatch_observes_closed_error_without_releasing_original(self):
        from agentmux_contracts import canonical_bytes
        future = Future()
        original = ContractError('private original detail')
        future.set_exception(original)
        session = self.session(future)
        identity = ('work-command', canonical_bytes({
            'contract_id': 'federation-work-inspect', 'operation_id': 'private operation',
            'payload': {'private': 'original payload'}}))
        session._command_identity = identity
        failure = self.failed_wait(session, ('different-private-identity',))
        diagnostic = failure._command_diagnostic
        self.assertEqual(diagnostic['futureChain'], [{'type': 'ContractError', 'code': None}])
        self.assertEqual(diagnostic['futureContract'], 'federation-work-inspect')
        self.assertNotIn('private', json.dumps(diagnostic))
        self.assertIs(future.exception(), original)
        self.assertIs(session._command_future, future)
        self.assertIs(session._command_identity, identity)

    def test_identity_mismatch_does_not_inspect_pending_or_cancelled_future(self):
        for cancelled in (False, True):
            future = Future()
            if cancelled:
                future.cancel()
            session = self.session(future)
            with self.subTest(cancelled=cancelled), \
                    patch.object(future, 'exception', side_effect=AssertionError('must not inspect')) as exception:
                failure = self.failed_wait(session, ('different',))
            exception.assert_not_called()
            self.assertEqual(failure._command_diagnostic['futureState'],
                'cancelled' if cancelled else 'pending')
            self.assertIs(session._command_future, future)

    def test_cancelled_future_is_not_queried_for_exception(self):
        future = Future()
        future.cancel()
        session = self.session(future)
        with patch.object(future, 'exception', side_effect=AssertionError('cancelled future')) as exception:
            failure = self.failed_wait(session)
        exception.assert_not_called()
        self.assertEqual(failure._command_diagnostic['futureState'], 'cancelled')
        self.assertEqual(failure._command_diagnostic['waiterChain'],
            [{'type': 'CancelledError', 'code': None}])
        self.assertEqual(failure._command_diagnostic['futureChain'], [])
        self.assertIs(session._command_future, future)

    def test_capture_failure_preserves_original_owner_future_and_public_error(self):
        for method in ('done', 'exception'):
            with self.subTest(method=method):
                future = Future()
                original = ConnectionFailure('application_connection_unavailable', object())
                future.set_exception(original)
                session = self.session(future)
                with patch.object(future, method, side_effect=RuntimeError('private capture failure')):
                    failure = self.failed_wait(session)
                self.assertFalse(hasattr(failure, '_command_diagnostic'))
                self.assertIs(session._command_future, future)
                self.assertIs(future.exception(), original)
                self.assertFalse(future.cancelled())
                self.assertEqual(session._command_identity, ('original',))

    def test_timing_copies_only_closed_finite_fields(self):
        valid = {'contract': 'federation-work-outcome', 'bindingRefreshed': True,
            'bindingStart': {'at': 12.0, 'remaining': 2.0},
            'exchangeJoined': {'at': 14.1, 'remaining': -.1}}
        invalid = [
            {**valid, 'private': 'credential'},
            {**valid, 'contract': 'private-contract'},
            {**valid, 'bindingRefreshed': 1},
            {**valid, 'publish': {'at': float('nan'), 'remaining': 1}},
            {**valid, 'publish': {'at': 1, 'remaining': float('inf')}},
            {**valid, 'publish': {'at': True, 'remaining': 1}},
            {**valid, 'publish': {'at': 1, 'remaining': 1, 'payload': 'private'}},
        ]
        for value in [valid, *invalid]:
            with self.subTest(value=value):
                original = MessageOutcomeUnconfirmed('application_message_outcome_unconfirmed', object())
                original._storage_command_timing = copy.deepcopy(value)
                future = Future()
                future.set_exception(original)
                diagnostic = self.failed_wait(self.session(future))._command_diagnostic
                if value is valid:
                    self.assertEqual(diagnostic['timing'], valid)
                    original._storage_command_timing['bindingStart']['at'] = 100
                    self.assertEqual(diagnostic['timing']['bindingStart']['at'], 12)
                else:
                    self.assertNotIn('timing', diagnostic)


class CommandTimingTests(unittest.IsolatedAsyncioTestCase):
    deadline = connection_fixture.ClientLaunchConnection.deadline
    connect = connection_fixture.ClientLaunchConnection.connect

    async def asyncSetUp(self):
        await connection_fixture.ClientLaunchConnection.asyncSetUp(self)
        await self.connect()
        async def close():
            await self.owner.close(deadline=self.deadline(3))
        self.addAsyncCleanup(close)

    async def test_storage_outcome_keeps_original_failure_and_clears_timing(self):
        for refreshed in (False, True):
            with self.subTest(refreshed=refreshed):
                contract = 'federation-work-outcome'
                signer = SimpleNamespace(selection={'hubId': 'hub', 'profileId': 'profile',
                    'authorityId': 'authority', 'workCommands': {
                        'grantRefs': {contract: {}}, 'transportRef': {}}},
                    command_subject=Mock(return_value='selected-subject'),
                    sign_command=Mock(return_value=b'original-request'))
                original = MessageOutcomeUnconfirmed('application_message_outcome_unconfirmed', self.owner)
                async def binding(**kwargs):
                    if refreshed:
                        self.owner.binding._epoch = object()
                    return {'validUntil': (datetime.now(timezone.utc) + timedelta(seconds=5)).isoformat()}
                with patch.object(self.owner, '_signer', signer), \
                        patch.object(self.owner, '_terminal_claim', return_value={}), \
                        patch.object(self.owner, '_current_command_binding', side_effect=binding), \
                        patch.object(self.owner, '_exchange_message', new=AsyncMock(side_effect=original)):
                    with self.assertRaises(MessageOutcomeUnconfirmed) as caught:
                        await self.owner._storage_command('workCommands', contract_id=contract,
                            operation_id='original', payload={'resourceRef': {'revision': 1}},
                            expires_at=(datetime.now(timezone.utc) + timedelta(seconds=3)).isoformat(),
                            deadline=self.deadline(3), cleanup_deadline=self.deadline(4))
                self.assertIs(caught.exception, original)
                self.assertIsNone(self.owner._storage_timing)
                timing = original._storage_command_timing
                self.assertEqual(timing['bindingRefreshed'], refreshed)
                stages = ['bindingStart', 'bindingComplete', 'exchangeStart', 'exchangeJoined']
                self.assertEqual(sorted(timing[key]['at'] for key in stages),
                    [timing[key]['at'] for key in stages])
                self.assertTrue(all(timing[key]['remaining'] > 0 for key in stages))
                self.assertEqual(self.owner._command_request, b'original-request')

    async def test_actual_exchange_records_publish_and_reply_without_changing_bytes(self):
        reply_subject = '_INBOX.fixed'
        subscription = SimpleNamespace(unsubscribe=AsyncMock(),
            next_msg=AsyncMock(return_value=SimpleNamespace(subject=reply_subject, data=b'original-reply')))
        self.client.subscribe = AsyncMock(return_value=subscription)
        self.client.flush = AsyncMock()
        self.client.publish = AsyncMock()
        self.owner._storage_timing = {'contract': 'federation-work-outcome',
            'bindingComplete': {'at': time.monotonic(), 'remaining': 3}}
        result = await self.owner._run_exchange(b'original-request', reply_subject,
            self.deadline(3), 'selected-subject', None)
        self.assertEqual(result, b'original-reply')
        self.client.publish.assert_awaited_once_with('selected-subject', b'original-request', reply=reply_subject)
        self.assertLessEqual(self.owner._storage_timing['publish']['at'],
            self.owner._storage_timing['replyReceived']['at'])
        subscription.unsubscribe.assert_awaited_once()
        self.assertEqual(self.owner._subscriptions, {})
