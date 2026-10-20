"""Event-loop lifetime with an injected owner; no client or service is connected."""
import asyncio
from datetime import datetime, timedelta, timezone
import time
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hub.client_launch_connection import ConnectionFailure
from hub.client_launch_selection import SelectionError
from hub.client_launch_session import ApplicationClientSession, ApplicationSessionFailure
from agentmux_contracts import canonical_bytes
from identity.legacy_identity import LegacyIdentityBinding, VerifiedLegacyAliasResolution
from state_owner.authority_switch_service import VerifiedEnrolledRecovery


class ClientLaunchSession(unittest.TestCase):
    def test_work_completion_after_wait_timeout_preserves_original_custody(self):
        from hub.client_launch_connection import MessageOutcomeUnconfirmed
        from identity.test_authority import ref
        for outcome in ('result', 'connection-failure', 'joined-timeout'):
            with self.subTest(outcome=outcome):
                enrollment = {'hubId': 'hub-one', 'profileId': 'profile-one',
                    'authorityId': 'authority-one', 'callerRef': ref('human'),
                    'scope': {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None},
                    'workCommands': {'grantRefs': {'federation-work-inspect': ref('inspect')}}}
                owned = self.owner(enrollment=enrollment)
                session = ApplicationClientSession(self.selected())
                entered, completed = threading.Event(), threading.Event()
                release, calls = [], []
                retained_error = (ConnectionFailure('application_command_unconfirmed', owned)
                    if outcome == 'connection-failure' else
                    MessageOutcomeUnconfirmed('application_message_outcome_unconfirmed', owned))
                async def command(**arguments):
                    self.assertIs(asyncio.get_running_loop(), session._loop)
                    calls.append(arguments)
                    if len(calls) == 1:
                        gate = asyncio.Event()
                        release.append(gate)
                        entered.set()
                        await gate.wait()
                        if outcome != 'result':
                            raise retained_error
                    return {'resourceRef': ref('work-one')}
                owned.work_command = command
                async def open_client(*_args, **_kwargs):
                    return owned
                with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
                    session.start(deadline=time.monotonic() + 4)
                try:
                    arguments = {'contract_id': 'federation-work-inspect',
                        'operation_id': 'original-query',
                        'payload': {'resourceRef': ref('work-one'), 'input': {}},
                        'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat()}
                    # Load the schema before measuring the controlled waiter.
                    from agentmux_contracts import validate
                    validate(arguments['contract_id'], arguments['payload'])
                    with self.assertRaises(ApplicationSessionFailure):
                        session.work_command(**arguments, deadline=time.monotonic() + 0.25)
                    self.assertTrue(entered.wait(1))
                    original, identity = session._command_future, session._command_identity
                    original.add_done_callback(lambda _future: completed.set())
                    self.assertFalse(original.done())
                    session._loop.call_soon_threadsafe(release[0].set)
                    self.assertTrue(completed.wait(1))
                    changed = {**arguments, 'operation_id': 'fresh-query'}
                    if outcome == 'joined-timeout':
                        session.work_command(**changed)
                        self.assertEqual(len(calls), 2)
                        self.assertIsNone(session._command_future)
                    else:
                        with self.assertRaises(ApplicationSessionFailure) as refused:
                            session.work_command(**changed)
                        diagnostic = refused.exception._command_diagnostic
                        self.assertEqual(diagnostic['stage'], 'identity-mismatch')
                        self.assertEqual(diagnostic['futureState'], 'done')
                        self.assertEqual(diagnostic['futureContract'], 'federation-work-inspect')
                        self.assertEqual(bool(diagnostic['futureChain']), outcome == 'connection-failure')
                        self.assertIs(session._command_future, original)
                        self.assertIs(session._command_identity, identity)
                        self.assertEqual(len(calls), 1)
                        if outcome == 'result':
                            self.assertEqual(session.work_command(**arguments),
                                {'resourceRef': ref('work-one')})
                            self.assertIsNone(session._command_future)
                        else:
                            with self.assertRaises(ApplicationSessionFailure):
                                session.work_command(**arguments)
                            self.assertIs(original.exception(), retained_error)
                            self.assertIs(session._command_future, original)
                        self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0]['operation_id'], arguments['operation_id'])
                    self.assertEqual(calls[0]['expires_at'], arguments['expires_at'])
                    self.assertEqual(calls[0]['payload'], arguments['payload'])
                    self.assertEqual(owned.close_calls, 0)
                finally:
                    if release:
                        session._loop.call_soon_threadsafe(release[0].set)
                    session.close(deadline=time.monotonic() + 4)
                    session.join_final()
                    self.assertFalse(session._thread.is_alive())

    def test_completed_message_timeout_allows_fresh_outcome_on_the_same_session_thread(self):
        from hub.client_launch_connection import MessageOutcomeUnconfirmed
        from identity.test_authority import ref
        enrollment = {'hubId': 'hub-one', 'profileId': 'profile-one', 'authorityId': 'authority-one',
            'callerRef': ref('human'), 'scope': {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None},
            'messageCommands': {'grantRefs': {'federation-message-inspect': ref('inspect')}}}
        owned = self.owner(enrollment=enrollment)
        calls = []
        async def message_command(**arguments):
            calls.append(arguments['operation_id'])
            if len(calls) == 1:
                raise MessageOutcomeUnconfirmed('application_message_outcome_unconfirmed', owned)
            return {'resourceRef': ref('messages-one')}
        owned.message_command = message_command
        session = ApplicationClientSession(self.selected())
        async def open_client(*_args, **_kwargs):
            return owned
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            kwargs = {'contract_id': 'federation-message-inspect',
                'payload': {'resourceRef': ref('messages-one'), 'input': {}},
                'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat()}
            with self.assertRaises(ApplicationSessionFailure):
                session.message_command(operation_id='first-message', **kwargs)
            result = session.message_command(operation_id='fresh-query', **kwargs)
            self.assertEqual(result['resourceRef'], ref('messages-one'))
            self.assertEqual(calls, ['first-message', 'fresh-query'])
            self.assertIsNone(session._command_future)
            self.assertEqual(owned.close_calls, 0)
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            self.assertFalse(session._thread.is_alive())
        finally:
            session.join_final()

    def recovery(self, seal, *, seconds):
        value = object.__new__(VerifiedEnrolledRecovery)
        object.__setattr__(value, '_seal', seal)
        object.__setattr__(value, '_request', b'{}')
        object.__setattr__(value, '_response', b'{}')
        object.__setattr__(value, '_valid_until',
            datetime.now(timezone.utc) + timedelta(seconds=seconds))
        return value

    def receipt(self):
        return {'operationId': 'query-one', 'originalOperationId': 'intent-one',
            'originalPayloadDigest': 'sha256:' + 'a' * 64, 'sequence': 1,
            'attemptOperationId': None, 'phase': 'intent-committed'}

    def selected(self):
        return SimpleNamespace(application_client='/private/client-key', application_connection='/private/connection')

    def owner(self, *, failed_close=False, enrollment=None):
        client = object()
        value = SimpleNamespace(_close_task=None, close_calls=0)
        value._signer = SimpleNamespace(selection={} if enrollment is None else enrollment)
        value.require_connection = lambda: client
        value.binding = SimpleNamespace(current=lambda _connection, **_: {'hubId': 'hub-one'})
        async def finish():
            if failed_close:
                raise OSError('PRIVATE_SENTINEL')
        async def close(**_):
            if value._close_task is None:
                value.close_calls += 1
                value._close_task = asyncio.create_task(finish())
            try:
                await value._close_task
            except OSError as error:
                raise ConnectionFailure('application_connection_cleanup_pending', value, error) from None
        value.close = close
        return value

    def registration(self):
        return {'requestedAddress': 'agent:alpha-worker-w1',
            'canonicalSession': 'alpha-worker-w1', 'registrationGeneration': 3,
            'repository': 'alpha', 'role': 'worker', 'agent': 'w1',
            'state': 'ready', 'legacyAlias': None}

    def resolution(self, *, valid_until=None, local=True):
        binding = LegacyIdentityBinding('old-w1', 'alpha-worker-w1',
            'hub-one' if local else 'remote-hub', 3,
            canonical_bytes({'ownerHubId': 'hub-one', 'id': 'identity-one', 'revision': 1}),
            canonical_bytes({'organizationId': 'org-one', 'projectId': 'project-one',
                             'workspaceId': None}), canonical_bytes(None),
            canonical_bytes({'ownerHubId': 'hub-one', 'id': 'alias-one', 'revision': 1}),
            1, local)
        return VerifiedLegacyAliasResolution((binding,), valid_until or
            datetime.now(timezone.utc) + timedelta(minutes=1))

    def test_session_keeps_loop_until_original_owner_closes(self):
        owned = self.owner()
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            self.assertEqual(session.status(), {'state': 'verified', 'hubId': 'hub-one'})
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            self.assertFalse(session._thread.is_alive())
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            self.assertEqual(owned.close_calls, 1)
        finally:
            session.join_final()

    def test_failed_original_close_stays_failed_after_loop_joins(self):
        owned = self.owner(failed_close=True)
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            self.assertFalse(session.close(deadline=time.monotonic() + 4))
            self.assertFalse(session.join_final())
            self.assertFalse(session.close(deadline=time.monotonic() + 4))
            self.assertEqual(owned.close_calls, 1)
        finally:
            if session._thread.is_alive():
                session.join_final()

    def test_private_selection_cleanup_remains_failed_after_thread_join(self):
        cleanup = SimpleNamespace(finish_cleanup=lambda: False)
        async def unavailable(*_args, **_kwargs):
            raise SelectionError('selection_cleanup_pending', cleanup=cleanup)
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=unavailable):
            with self.assertRaises(ApplicationSessionFailure):
                session.start(deadline=time.monotonic() + 4)
        try:
            self.assertFalse(session.close(deadline=time.monotonic() + 4))
            self.assertFalse(session._thread.is_alive())
            self.assertFalse(session.join_final())
        finally:
            if session._thread.is_alive():
                session.join_final()

    def test_interrupted_final_wait_keeps_original_future_and_loop(self):
        from unittest.mock import Mock
        session = ApplicationClientSession(self.selected())
        session._started = True
        session._ready.set()
        session._thread = Mock()
        session._thread.is_alive.return_value = True
        session._loop = Mock()
        original = Mock()
        original.result.side_effect = KeyboardInterrupt
        original.done.return_value = False
        session._final_closing = original
        with self.assertRaises(ApplicationSessionFailure):
            session.join_final()
        self.assertIs(session._final_closing, original)
        session._loop.call_soon_threadsafe.assert_not_called()
        session._thread.join.assert_not_called()

    def test_status_timeout_reuses_owned_future_and_exhausted_budget_does_not_queue(self):
        from unittest.mock import Mock
        session = ApplicationClientSession(self.selected())
        session._thread = Mock()
        session._thread.is_alive.return_value = True
        session._loop = Mock()
        original = Mock()
        original.done.return_value = False
        original.result.side_effect = TimeoutError
        session._status_future = original
        with patch('hub.client_launch_session.asyncio.run_coroutine_threadsafe') as submit:
            for _ in range(2):
                self.assertEqual(session.status(), {'state': 'unavailable', 'hubId': None})
            self.assertEqual(session.status(deadline=0), {'state': 'unavailable', 'hubId': None})
        submit.assert_not_called()
        self.assertIs(session._status_future, original)
        self.assertEqual(original.result.call_count, 2)

    def test_explicit_query_uses_same_owner_loop_and_only_closed_receipt(self):
        owned = self.owner(enrollment={'integrationEffectQuery': {}})
        calls = []
        async def query(**kwargs):
            self.assertIs(asyncio.get_running_loop(), session._loop)
            calls.append(kwargs)
            return self.receipt()
        owned.query_integration_effect = query
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            self.assertTrue(session.query_enabled())
            arguments = {'operationId': 'query-one', 'expectedVersion': 1}
            self.assertEqual(session.query_effect(arguments), self.receipt())
            self.assertEqual((calls[0]['operation_id'], calls[0]['expected_version']), ('query-one', 1))
            self.assertLess(calls[0]['deadline'], calls[0]['cleanup_deadline'])
            self.assertIsNone(session._command_future)
        finally:
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            session.join_final()
        self.assertFalse(session.query_enabled())

    def test_recovery_same_operation_runs_again_after_local_result_expires(self):
        enrollment = {'authoritySwitchRecovery': {}}
        owned = self.owner(enrollment=enrollment)
        seal = object()
        owned._signer._authority_switch_seal = seal
        results = [self.recovery(seal, seconds=.03), self.recovery(seal, seconds=5)]
        calls = []

        async def recover(**kwargs):
            self.assertIs(asyncio.get_running_loop(), session._loop)
            calls.append(kwargs)
            return results.pop(0)

        owned.authority_switch_recovery = recover
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            operation = 'recover_' + 'a' * 32
            first = session.request_authority_switch_recovery(operation)
            self.assertIsNone(session._command_future)
            time.sleep(.04)
            second = session.request_authority_switch_recovery(operation)
            self.assertIsNot(first, second)
            self.assertEqual([call['operation_id'] for call in calls], [operation, operation])
            self.assertIsNone(session._command_future)
        finally:
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            session.join_final()

    def test_terminal_session_gates_enrolled_application_operations(self):
        enrollment = {'integrationEffectQuery': {}, 'oidcTerminalSession': {}}
        owned = self.owner(enrollment=enrollment)
        calls = []
        async def terminal(**kwargs):
            self.assertIs(asyncio.get_running_loop(), session._loop)
            calls.append(kwargs)
            if kwargs['contract_id'] == 'oidc-terminal-session-open':
                return {'attemptId': 'oidc_attempt_' + 'a' * 32}
            if kwargs['contract_id'] == 'oidc-terminal-session-status':
                return {'outcome': 'approved', 'sessionId': 'oidc_session_' + 'b' * 32}
            return {'outcome': 'closed', 'sessionId': 'oidc_session_' + 'b' * 32}
        owned.oidc_terminal_command = terminal
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            self.assertTrue(session.oidc_terminal_enabled())
            self.assertFalse(session.query_enabled())
            opened = session.oidc_terminal_start()
            self.assertEqual(opened['attemptId'], 'oidc_attempt_' + 'a' * 32)
            approved = session.oidc_terminal_status(opened['attemptId'])
            self.assertEqual(approved['sessionId'], 'oidc_session_' + 'b' * 32)
            self.assertTrue(session.query_enabled())
            closed = session.oidc_terminal_logout(approved['sessionId'])
            self.assertEqual(closed['outcome'], 'closed')
            self.assertFalse(session.query_enabled())
            self.assertEqual([call['contract_id'] for call in calls], [
                'oidc-terminal-session-open', 'oidc-terminal-session-status',
                'oidc-terminal-session-close'])
        finally:
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            session.join_final()

    def test_terminal_waiter_retry_reuses_each_hidden_operation_id(self):
        from unittest.mock import Mock
        session = ApplicationClientSession(self.selected())
        session._terminal_enrolled = True
        session._thread = Mock()
        session._thread.is_alive.return_value = True
        session._loop = Mock()
        attempt_id = 'oidc_attempt_' + 'a' * 32
        session_id = 'oidc_session_' + 'b' * 32
        responses = [
            {'attemptId': attempt_id},
            {'outcome': 'approved', 'sessionId': session_id},
            {'outcome': 'closed', 'sessionId': session_id},
        ]
        futures = []

        def submitted(coroutine, _loop):
            coroutine.close()
            future = Mock()
            future.result.side_effect = [TimeoutError(), responses[len(futures)]]
            futures.append(future)
            return future

        calls = [
            lambda: session.oidc_terminal_start(),
            lambda: session.oidc_terminal_status(attempt_id),
            lambda: session.oidc_terminal_logout(session_id),
        ]
        with patch('hub.client_launch_session.asyncio.run_coroutine_threadsafe',
                   side_effect=submitted) as submit:
            for expected, call in zip(responses, calls):
                with self.assertRaises(ApplicationSessionFailure):
                    call()
                retained_identity = session._command_identity
                self.assertEqual(call(), expected)
                self.assertIsNone(session._command_future)
                self.assertIsNone(session._command_identity)
                self.assertIsInstance(retained_identity[-1], str)
        self.assertEqual(submit.call_count, 3)

    def test_publish_subject_count_does_not_enable_unselected_queries(self):
        owned = self.owner()
        owned._publish_subjects = ('identity', 'another-subject')
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            self.assertFalse(session.query_enabled())
            self.assertFalse(session.legacy_alias_query_enabled())
        finally:
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            session.join_final()

    def test_dynamic_integration_command_uses_enrolled_purpose_and_exact_owner_future(self):
        enrollment = {'integrationEffectCommands': {'contracts': ['integration-effect-query']}}
        owned = self.owner(enrollment=enrollment)
        calls = []
        async def command(**kwargs):
            self.assertIs(asyncio.get_running_loop(), session._loop)
            calls.append(kwargs)
            return self.receipt()
        owned.integration_command = command
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        arguments = {'contractId': 'integration-effect-query', 'operationId': 'query-one',
            'expectedVersion': 1,
            'grantRef': {'id': 'query-grant', 'ownerHubId': 'hub-one', 'revision': 1},
            'approvalRefs': [], 'payload': {
                'effectRef': {'id': 'effect-' + 'a' * 64, 'ownerHubId': 'hub-one', 'revision': 1},
                'originalOperationId': 'intent-one',
                'originalPayloadDigest': 'sha256:' + 'a' * 64}}
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            self.assertTrue(session.integration_command_enabled('integration-effect-query'))
            self.assertEqual(session.integration_command(arguments), self.receipt())
            self.assertEqual(calls[0]['grant_ref'], arguments['grantRef'])
            self.assertEqual(calls[0]['payload'], arguments['payload'])
            self.assertIsNone(session._command_future)
        finally:
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            session.join_final()

    def test_dynamic_command_timeout_retains_exact_future_and_refuses_changed_request(self):
        from unittest.mock import Mock
        from agentmux_contracts import canonical_bytes
        session = ApplicationClientSession(self.selected())
        session._integration_commands = frozenset({'integration-effect-query'})
        session._thread = Mock()
        session._thread.is_alive.return_value = True
        session._loop = Mock()
        arguments = {'contractId': 'integration-effect-query', 'operationId': 'query-one',
            'expectedVersion': 1,
            'grantRef': {'id': 'query-grant', 'ownerHubId': 'hub-one', 'revision': 1},
            'approvalRefs': [], 'payload': {
                'effectRef': {'id': 'effect-' + 'a' * 64, 'ownerHubId': 'hub-one', 'revision': 1},
                'originalOperationId': 'intent-one',
                'originalPayloadDigest': 'sha256:' + 'a' * 64}}
        original = Mock()
        original.result.side_effect = [TimeoutError(), self.receipt()]
        session._command_future = original
        session._command_identity = ('integration-command', arguments['contractId'],
            arguments['operationId'], arguments['expectedVersion'],
            canonical_bytes(arguments['grantRef']), canonical_bytes(arguments['payload']),
            canonical_bytes(arguments['approvalRefs']))
        with patch('hub.client_launch_session.asyncio.run_coroutine_threadsafe') as submit:
            with self.assertRaises(ApplicationSessionFailure):
                session.integration_command(arguments)
            changed = {**arguments, 'grantRef': {
                'id': 'other-grant', 'ownerHubId': 'hub-one', 'revision': 1}}
            with self.assertRaises(ApplicationSessionFailure):
                session.integration_command(changed)
            self.assertEqual(session.integration_command(arguments), self.receipt())
        submit.assert_not_called()
        original.cancel.assert_not_called()

    def test_query_timeout_retains_exact_future_and_refuses_another_identity(self):
        from unittest.mock import Mock
        session = ApplicationClientSession(self.selected())
        session._query_enrolled = True
        session._thread = Mock()
        session._thread.is_alive.return_value = True
        session._loop = Mock()
        original = Mock()
        original.result.side_effect = [TimeoutError(), KeyboardInterrupt(), self.receipt()]
        session._command_future = original
        session._command_identity = ('integration-effect-query', 'query-one', 1)
        with patch('hub.client_launch_session.asyncio.run_coroutine_threadsafe') as submit:
            for _ in range(2):
                with self.assertRaises(ApplicationSessionFailure):
                    session.query_effect({'operationId': 'query-one', 'expectedVersion': 1})
                self.assertIs(session._command_future, original)
            with self.assertRaises(ApplicationSessionFailure):
                session.query_effect({'operationId': 'query-two', 'expectedVersion': 1})
            self.assertEqual(session.query_effect({'operationId': 'query-one', 'expectedVersion': 1}), self.receipt())
        submit.assert_not_called()
        original.cancel.assert_not_called()
        self.assertIsNone(session._command_future)

    def test_close_joins_pending_query_before_original_connection(self):
        entered = threading.Event()
        release = None
        owned = self.owner(enrollment={'integrationEffectQuery': {}})
        calls = []
        async def query(**kwargs):
            nonlocal release
            release = asyncio.Event()
            calls.append(kwargs)
            entered.set()
            await release.wait()
            return self.receipt()
        owned.query_integration_effect = query
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            with self.assertRaises(ApplicationSessionFailure):
                session.query_effect({'operationId': 'query-one', 'expectedVersion': 1},
                                     deadline=time.monotonic() + 0.05)
            self.assertTrue(entered.wait(1))
            original = session._command_future
            self.assertFalse(session.close(deadline=time.monotonic() + 0.02))
            self.assertEqual(owned.close_calls, 0)
            self.assertIs(session._command_future, original)
            session._loop.call_soon_threadsafe(release.set)
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            self.assertEqual((len(calls), owned.close_calls), (1, 1))
        finally:
            if release is not None and session._thread.is_alive():
                session._loop.call_soon_threadsafe(release.set)
            session.join_final()

    def test_query_refuses_unenrolled_route_invalid_fields_and_deadlines(self):
        session = ApplicationClientSession(self.selected())
        valid = {'operationId': 'query-one', 'expectedVersion': 1}
        with self.assertRaises(ApplicationSessionFailure):
            session.query_effect(valid)
        for arguments in ({}, {**valid, 'subject': 'PRIVATE'}, {**valid, 'expectedVersion': True},
                          {**valid, 'expectedVersion': -1}, {**valid, 'operationId': '1invalid'}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                session.query_effect(arguments)

    def test_legacy_alias_query_uses_explicit_enrollment_and_same_owner_loop(self):
        local_resolution = self.resolution()
        remote_resolution = self.resolution(local=False)
        owned = self.owner(enrollment={
            'integrationEffectQuery': {}, 'legacyAliasResolve': {}})
        calls = []
        async def query(**kwargs):
            self.assertIs(asyncio.get_running_loop(), session._loop)
            calls.append(kwargs)
            return remote_resolution if 'remote_address' in kwargs else local_resolution
        owned.query_legacy_aliases = query
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            self.assertTrue(session.query_enabled())
            self.assertTrue(session.legacy_alias_query_enabled())
            registration = self.registration()
            self.assertIs(session.query_legacy_aliases([registration],
                operation_id='resolve-legacy-one'), local_resolution)
            self.assertEqual(calls[0]['registrations'], [registration])
            self.assertEqual(calls[0]['operation_id'], 'resolve-legacy-one')
            self.assertLess(calls[0]['deadline'], calls[0]['cleanup_deadline'])
            self.assertIs(session.query_legacy_aliases(remote_address='agent:alpha-worker-w1',
                operation_id='resolve-remote-one'), remote_resolution)
            self.assertEqual(calls[1]['remote_address'], 'agent:alpha-worker-w1')
            self.assertNotIn('registrations', calls[1])
            self.assertIsNone(session._command_future)
        finally:
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            session.join_final()
        self.assertFalse(session.legacy_alias_query_enabled())

    def test_legacy_alias_waiters_retain_exact_future_without_replay(self):
        from unittest.mock import Mock
        resolution = self.resolution()
        registration = self.registration()
        session = ApplicationClientSession(self.selected())
        session._legacy_alias_query_enrolled = session._query_enrolled = True
        session._thread = Mock()
        session._thread.is_alive.return_value = True
        session._loop = Mock()
        original = Mock()
        original.result.side_effect = [TimeoutError(), KeyboardInterrupt(), resolution]
        session._command_future = original
        session._command_identity = ('identity-legacy-alias-resolve',
            'resolve-legacy-one', canonical_bytes({'registrations': [registration]}))
        with patch('hub.client_launch_session.asyncio.run_coroutine_threadsafe') as submit:
            for _ in range(2):
                with self.assertRaises(ApplicationSessionFailure):
                    session.query_legacy_aliases([registration], operation_id='resolve-legacy-one')
                self.assertIs(session._command_future, original)
            changed = {**registration, 'state': 'busy'}
            for action in (
                    lambda: session.query_legacy_aliases([changed], operation_id='resolve-legacy-one'),
                    lambda: session.query_legacy_aliases([registration], operation_id='resolve-legacy-two'),
                    lambda: session.query_effect({'operationId': 'query-one', 'expectedVersion': 1})):
                with self.assertRaises(ApplicationSessionFailure):
                    action()
            self.assertIs(session.query_legacy_aliases([registration],
                operation_id='resolve-legacy-one'), resolution)
        submit.assert_not_called()
        original.cancel.assert_not_called()
        self.assertIsNone(session._command_future)

    def test_remote_alias_waiter_keeps_exact_address_identity(self):
        from unittest.mock import Mock
        remote_address = 'agent:alpha-worker-w1'
        resolution = self.resolution(local=False)
        session = ApplicationClientSession(self.selected())
        session._legacy_alias_query_enrolled = True
        session._thread = Mock()
        session._thread.is_alive.return_value = True
        session._loop = Mock()
        original = Mock()
        original.result.side_effect = [TimeoutError(), resolution]
        session._command_future = original
        session._command_identity = ('identity-legacy-alias-resolve',
            'resolve-remote-one', canonical_bytes({'remoteAddress': remote_address}))
        with patch('hub.client_launch_session.asyncio.run_coroutine_threadsafe') as submit:
            with self.assertRaises(ApplicationSessionFailure):
                session.query_legacy_aliases(remote_address=remote_address,
                    operation_id='resolve-remote-one')
            self.assertIs(session._command_future, original)
            for action in (
                    lambda: session.query_legacy_aliases(
                        remote_address='agent:alpha-worker-w2', operation_id='resolve-remote-one'),
                    lambda: session.query_legacy_aliases([self.registration()],
                        operation_id='resolve-remote-one'),
                    lambda: session.query_legacy_aliases(
                        remote_address=remote_address, operation_id='resolve-remote-two')):
                with self.assertRaises(ApplicationSessionFailure):
                    action()
            self.assertIs(session.query_legacy_aliases(remote_address=remote_address,
                operation_id='resolve-remote-one'), resolution)
        submit.assert_not_called()
        original.cancel.assert_not_called()
        self.assertIsNone(session._command_future)

    def test_delayed_same_identity_cannot_consume_expired_alias_resolution(self):
        from unittest.mock import Mock
        registration = self.registration()
        expired = self.resolution(valid_until=datetime.now(timezone.utc) - timedelta(microseconds=1))
        session = ApplicationClientSession(self.selected())
        session._legacy_alias_query_enrolled = True
        session._thread = Mock()
        session._thread.is_alive.return_value = True
        session._loop = Mock()
        original = Mock()
        original.result.side_effect = [TimeoutError(), expired]
        session._command_future = original
        session._command_identity = ('identity-legacy-alias-resolve',
            'resolve-legacy-one', canonical_bytes({'registrations': [registration]}))
        with patch('hub.client_launch_session.asyncio.run_coroutine_threadsafe') as submit:
            with self.assertRaises(ApplicationSessionFailure):
                session.query_legacy_aliases([registration], operation_id='resolve-legacy-one')
            self.assertIs(session._command_future, original)
            with self.assertRaises(ApplicationSessionFailure):
                session.query_legacy_aliases([registration], operation_id='resolve-legacy-one')
        submit.assert_not_called()
        original.cancel.assert_not_called()
        self.assertIsNone(session._command_future)

    def test_close_joins_pending_legacy_alias_query_before_connection(self):
        entered = threading.Event()
        release = None
        owned = self.owner(enrollment={'legacyAliasResolve': {}})
        calls = []
        async def query(**kwargs):
            nonlocal release
            release = asyncio.Event()
            calls.append(kwargs)
            entered.set()
            await release.wait()
            return self.resolution()
        owned.query_legacy_aliases = query
        async def open_client(*_args, **_kwargs):
            return owned
        session = ApplicationClientSession(self.selected())
        with patch('hub.client_launch_session.open_application_client', side_effect=open_client):
            session.start(deadline=time.monotonic() + 4)
        try:
            with self.assertRaises(ApplicationSessionFailure):
                session.query_legacy_aliases([self.registration()], operation_id='resolve-legacy-one',
                                             deadline=time.monotonic() + 0.05)
            self.assertTrue(entered.wait(1))
            original = session._command_future
            self.assertFalse(session.close(deadline=time.monotonic() + 0.02))
            self.assertEqual(owned.close_calls, 0)
            self.assertIs(session._command_future, original)
            session._loop.call_soon_threadsafe(release.set)
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            self.assertEqual((len(calls), owned.close_calls), (1, 1))
        finally:
            if release is not None and session._thread.is_alive():
                session._loop.call_soon_threadsafe(release.set)
            session.join_final()

    def test_legacy_alias_query_refuses_missing_mixed_or_invalid_selectors(self):
        session = ApplicationClientSession(self.selected())
        session._legacy_alias_query_enrolled = True
        registration = self.registration()
        for invoke in (
                lambda: session.query_legacy_aliases(operation_id='resolve-one'),
                lambda: session.query_legacy_aliases([registration],
                    remote_address='agent:alpha-worker-w1', operation_id='resolve-one'),
                lambda: session.query_legacy_aliases(remote_address='agent:Alpha-worker-w1',
                    operation_id='resolve-one'),
                lambda: session.query_legacy_aliases(remote_address='repo-worker-agent',
                    operation_id='resolve-one')):
            with self.assertRaisesRegex(ValueError, '^legacy_alias_query_arguments_invalid$'):
                invoke()
