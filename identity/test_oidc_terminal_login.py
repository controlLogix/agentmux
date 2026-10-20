"""Terminal OIDC confirms only the human already selected by enrollment."""
import asyncio
import base64
import copy
from datetime import datetime, timezone, timedelta
import json
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs

from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes
from identity.application_binding import _LocalBrowserApplicationBinding
from identity.authority import AuthoritySnapshot
from identity.local_browser_session import LocalBrowserSession
from identity.oidc_adapter import OIDCProvider
from identity.oidc_device_authorization import (
    BoundedOIDCDeviceHTTP, OIDCDeviceAuthorizationFlow,
    OIDCDeviceAuthorizationProvider)
from identity.oidc_terminal_login import OIDCTerminalLoginOwner
from identity.service import IdentityService
from identity.test_authority import NOW, fixture


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


class Runner:
    marker = b'\nagentmux-oidc-device-response:'

    def __init__(self, key, provider, *, pending=False):
        self.key, self.provider, self.pending = key, provider, pending
        self.calls, self.nonce = [], None

    def __call__(self, command, **options):
        self.calls.append((command, options))
        form = {key: value[0] for key, value in parse_qs(
            options['input'].decode()).items()}
        if 'scope' in form:
            self.nonce = form['nonce']
            status, document = 200, {'device_code': 'private-device-code',
                'user_code': 'ABCD-EFGH',
                'verification_uri': self.provider.issuer + '/device',
                'expires_in': 60, 'interval': 1}
        elif self.pending:
            status, document = 400, {'error': 'authorization_pending'}
        else:
            claims = {'iss': self.provider.issuer, 'sub': 'keycloak-user-184',
                'aud': self.provider.audience, 'iat': int(NOW.timestamp()),
                'exp': int((NOW + timedelta(minutes=4)).timestamp()),
                'nonce': self.nonce}
            header = {'alg': 'EdDSA', 'kid': 'key-one', 'typ': 'JWT'}
            parts = [encoded(canonical_bytes(header)), encoded(canonical_bytes(claims))]
            token = '.'.join((*parts, encoded(self.key.sign(
                '.'.join(parts).encode()).signature)))
            status, document = 200, {'id_token': token}
        output = json.dumps(document).encode() + self.marker + \
            str(status).encode() + b'\napplication/json'
        return subprocess.CompletedProcess(command, 0, stdout=output)


class TerminalLoginTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        self.provider = OIDCProvider('https://identity.example/realms/team',
            'agentmux', 'key-one', encoded(bytes(self.key.verify_key)))
        self.configuration = OIDCDeviceAuthorizationProvider(self.provider,
            self.provider.issuer + '/protocol/openid-connect/auth/device',
            self.provider.issuer + '/protocol/openid-connect/token')
        record, _ = fixture()
        self.record = copy.deepcopy(record)
        self.human = self.record['state']['identities'][0]
        self.human['externalIdentity'] = {'issuer': self.provider.issuer,
                                           'subject': 'keycloak-user-184'}
        self.reader = SimpleNamespace(current=AsyncMock(return_value=AuthoritySnapshot(
            canonical_bytes(self.record), 7)))
        self.identity = object.__new__(IdentityService)
        self.identity.reader = self.reader
        self.scope = {'organizationId': 'org-one', 'projectId': 'project-one',
                      'workspaceId': None}
        self.current = {'callerRef': self.human['ref'], 'scope': self.scope,
            'instanceId': 'instance-one', 'generation': 1, 'lifetimeId': 'life-one',
            'authorityRef': {'id': self.record['entityId'],
                'ownerHubId': self.record['ownerHubId'],
                'revision': self.record['entityVersion']},
            'authoritySequence': 7,
            'validUntil': (NOW + timedelta(minutes=5)).isoformat()}
        provider = SimpleNamespace(_current_local_browser_binding=AsyncMock(
            return_value=self.current))
        self.binding = _LocalBrowserApplicationBinding(provider,
            self.human['ref'], self.scope)
        self.monotonic = 100.0

    def owner(self, *, pending=False, production_wait=False):
        runner = Runner(self.key, self.provider, pending=pending)
        transport = BoundedOIDCDeviceHTTP(_runner=runner,
            _monotonic=lambda: self.monotonic)

        def sleep(seconds):
            self.monotonic += seconds

        flow = OIDCDeviceAuthorizationFlow(self.configuration,
            transport=transport, _clock=lambda: NOW,
            _monotonic=lambda: self.monotonic,
            _sleep=None if production_wait else sleep)
        return OIDCTerminalLoginOwner(self.configuration, self.identity,
                                      _flow=flow), runner

    async def completed(self, owner, attempt):
        for _ in range(100):
            result = await owner.status(attempt)
            if result is not None:
                return result
            await asyncio.sleep(0.001)
        self.fail('device login did not complete')

    async def test_linked_enrolled_caller_gets_finite_current_session(self):
        owner, runner = self.owner()
        inner = Mock(spec=LocalBrowserSession)
        inner.expires_at = NOW + timedelta(minutes=15)
        inner.verify_identity = AsyncMock(return_value='current-context')
        with patch('identity.oidc_terminal_login.LocalBrowserSession.open_server_binding',
                   AsyncMock(return_value=inner)) as opened:
            attempt = await owner.begin(self.binding)
            self.assertEqual((attempt.user_code, attempt.verification_uri),
                ('ABCD-EFGH', self.provider.issuer + '/device'))
            session = await self.completed(owner, attempt)
            self.assertEqual(await session.authorize(), 'current-context')
            self.assertEqual(await session.authorize(), 'current-context')
        opened.assert_awaited_once_with(self.binding, self.reader)
        self.assertEqual(inner.verify_identity.await_count, 2)
        self.assertNotIn('private-device-code', repr(attempt))
        session.close()
        inner.close.assert_called_once_with()
        with self.assertRaisesRegex(ContractError, 'oidc_terminal_session_closed'):
            await session.authorize()
        await owner.close()

    async def test_unlinked_result_cannot_replace_the_enrolled_caller(self):
        self.human['externalIdentity'] = None
        self.reader.current.return_value = AuthoritySnapshot(
            canonical_bytes(self.record), 8)
        owner, _runner = self.owner()
        attempt = await owner.begin(self.binding)
        with self.assertRaisesRegex(ContractError, 'oidc_account_not_linked'):
            await self.completed(owner, attempt)
        self.assertIsNone(self.human['externalIdentity'])
        await owner.close()

    async def test_close_cancels_and_joins_owned_provider_poll(self):
        owner, runner = self.owner(pending=True, production_wait=True)
        attempt = await owner.begin(self.binding)
        await owner.close()
        self.assertTrue(attempt._task.done())
        self.assertLessEqual(len(runner.calls), 2)
        with self.assertRaisesRegex(ContractError, 'oidc_terminal_unavailable'):
            await owner.status(attempt)

    async def test_concurrent_begin_reserves_capacity_before_network_returns(self):
        owner, _runner = self.owner(pending=True, production_wait=True)
        entered, release = threading.Event(), threading.Event()
        original = OIDCDeviceAuthorizationFlow.begin

        def held(flow):
            entered.set()
            release.wait(1)
            return original(flow)

        with patch.object(OIDCDeviceAuthorizationFlow, 'begin', held):
            callers = [asyncio.create_task(owner.begin(self.binding)) for _ in range(4)]
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            for _ in range(100):
                if len(owner._begins) == 4:
                    break
                await asyncio.sleep(0.001)
            self.assertEqual(len(owner._begins), 4)
            with self.assertRaisesRegex(ContractError, 'oidc_terminal_unavailable'):
                await owner.begin(self.binding)
            release.set()
            attempts = await asyncio.gather(*callers)
        await owner.close()
        self.assertTrue(all(item._task.done() for item in attempts))

    async def test_cancelled_begin_is_retained_and_close_consumes_its_result(self):
        owner, _runner = self.owner(pending=True, production_wait=True)
        entered, release = threading.Event(), threading.Event()
        original = OIDCDeviceAuthorizationFlow.begin

        def held(flow):
            entered.set()
            release.wait(1)
            return original(flow)

        with patch.object(OIDCDeviceAuthorizationFlow, 'begin', held):
            caller = asyncio.create_task(owner.begin(self.binding))
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            caller.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await caller
            self.assertEqual(len(owner._begins), 1)
            release.set()
            await owner.close()
        self.assertEqual(owner._begins, set())
        self.assertEqual(owner._pending, set())

    async def test_concurrent_begin_does_not_prune_completed_live_caller(self):
        owner, _runner = self.owner(pending=True, production_wait=True)
        first_waiting, release_first = asyncio.Event(), asyncio.Event()
        original_wait = asyncio.wait
        calls = 0

        async def held_first(awaitables, *args, **kwargs):
            nonlocal calls
            calls += 1
            result = await original_wait(awaitables, *args, **kwargs)
            if calls == 1:
                first_waiting.set()
                await release_first.wait()
            return result

        with patch('identity.oidc_terminal_login.asyncio.wait', held_first):
            first = asyncio.create_task(owner.begin(self.binding))
            await asyncio.wait_for(first_waiting.wait(), 1)
            second = asyncio.create_task(owner.begin(self.binding))
            for _ in range(100):
                if second.done():
                    break
                await asyncio.sleep(0.001)
            release_first.set()
            first_attempt, second_attempt = await asyncio.gather(first, second)
        self.assertFalse(first_attempt._request._cancel.is_set())
        self.assertFalse(second_attempt._request._cancel.is_set())
        await owner.close()

    async def test_cancelled_close_is_retained_and_a_retry_joins_it(self):
        owner, _runner = self.owner()
        release = asyncio.Event()

        async def active_operation():
            await release.wait()

        operation = asyncio.create_task(active_operation())
        owner._operations.add(operation)
        closing = asyncio.create_task(owner.close())
        await asyncio.sleep(0)
        closing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await closing
        self.assertIsNotNone(owner._close_task)
        self.assertFalse(owner._close_task.done())
        release.set()
        await owner.close()
        self.assertTrue(owner._close_task.done())

    async def test_cancelled_status_reuses_owned_completion(self):
        owner, _runner = self.owner()
        inner = Mock(spec=LocalBrowserSession)
        inner.expires_at = NOW + timedelta(minutes=15)
        entered, release = asyncio.Event(), asyncio.Event()

        async def held_session(_binding, _reader):
            entered.set()
            await release.wait()
            return inner

        with patch('identity.oidc_terminal_login.LocalBrowserSession.open_server_binding',
                   side_effect=held_session):
            attempt = await owner.begin(self.binding)
            while not attempt._task.done():
                await asyncio.sleep(0.001)
            first = asyncio.create_task(owner.status(attempt))
            await entered.wait()
            first.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await first
            self.assertIsNotNone(attempt._status_task)
            self.assertFalse(attempt._status_task.done())
            release.set()
            session = await owner.status(attempt)
        self.assertTrue(attempt._used)
        self.assertNotIn(attempt, owner._pending)
        self.assertIs(session._session, inner)
        await owner.close()

    async def test_cancelled_attempt_cancel_reuses_owned_cleanup(self):
        owner, _runner = self.owner(pending=True, production_wait=True)
        attempt = await owner.begin(self.binding)
        first = asyncio.create_task(owner.cancel(attempt))
        await asyncio.sleep(0)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        self.assertIsNotNone(attempt._cancel_task)
        await owner.cancel(attempt)
        self.assertTrue(attempt._cancel_task.done())
        self.assertNotIn(attempt, owner._pending)
        await owner.close()


class TerminalReceiverTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.caller = {'id': 'human-one', 'ownerHubId': 'hub-one', 'revision': 1}
        self.scope = {'organizationId': 'org-one', 'projectId': 'project-one',
                      'workspaceId': None}
        self.operation = canonical_bytes({'effectiveActorRef': self.caller,
                                          'scope': self.scope})
        decision = SimpleNamespace(outcome='allowed', operation=self.operation,
            valid_until=self.now + timedelta(seconds=30))
        self.service = object.__new__(IdentityService)
        self.service._hub, self.service._profile = 'hub-one', 'profile-one'
        self.service._entity = 'authority-one'
        self.service._issuer = canonical_bytes(
            {'id': 'issuer-one', 'ownerHubId': 'hub-one', 'revision': 1})
        self.service._seed = b'1' * 32
        self.service.ingress = SimpleNamespace(admit=AsyncMock(
            return_value=SimpleNamespace(envelope=b'admitted', decision=decision)))
        self.service.application = SimpleNamespace(
            open_local_browser_binding=AsyncMock(return_value=object()))
        self.service._oidc_terminal_attempts = {}
        self.service._oidc_terminal_sessions = {}
        self.service._oidc_terminal_results = {}
        self.service._oidc_terminal_lock = asyncio.Lock()
        self.begin_entered, self.release_begin = asyncio.Event(), asyncio.Event()
        self.attempt = SimpleNamespace(user_code='ABCD-EFGH', interval=1,
            verification_uri='https://identity.example/device',
            expires_at=self.now + timedelta(minutes=5))

        async def begin(_binding):
            self.begin_entered.set()
            await self.release_begin.wait()
            return self.attempt

        self.session = SimpleNamespace(expires_at=self.now + timedelta(minutes=10),
            close=Mock(), authorize=AsyncMock(return_value=SimpleNamespace(
                caller_ref=self.caller, scope=self.scope)))
        self.owner = SimpleNamespace(begin=AsyncMock(side_effect=begin),
            status=AsyncMock(return_value=self.session), cancel=AsyncMock())
        self.service._oidc_terminal = self.owner

    def request(self, contract, operation_id, payload):
        return {'claims': {'contractId': contract, 'operationId': operation_id,
            'payload': payload,
            'expiresAt': (self.now + timedelta(seconds=30)).isoformat()}}

    async def test_duplicate_open_is_serialized_and_logout_removes_stale_status(self):
        request = self.request('oidc-terminal-session-open', 'terminal-open-one', {})
        first = asyncio.create_task(self.service._oidc_terminal_command(b'one', request))
        await self.begin_entered.wait()
        second = asyncio.create_task(self.service._oidc_terminal_command(b'one', request))
        await asyncio.sleep(0)
        self.assertEqual(self.owner.begin.await_count, 1)
        self.release_begin.set()
        first_raw, second_raw = await asyncio.gather(first, second)
        self.assertEqual(first_raw, second_raw)
        self.assertEqual(self.owner.begin.await_count, 1)
        attempt_id = json.loads(first_raw)['claims']['attemptId']

        status = self.request('oidc-terminal-session-status', 'terminal-status-one',
                              {'attemptId': attempt_id})
        approved = json.loads(await self.service._oidc_terminal_command(b'two', status))
        session_id = approved['claims']['sessionId']
        close = self.request('oidc-terminal-session-close', 'terminal-close-one',
                             {'sessionId': session_id})
        closed = json.loads(await self.service._oidc_terminal_command(b'three', close))
        self.assertEqual(closed['claims']['outcome'], 'closed')
        self.session.close.assert_called_once_with()
        stale = self.request('oidc-terminal-session-status', 'terminal-status-two',
                             {'attemptId': attempt_id})
        with self.assertRaisesRegex(ContractError, 'oidc_terminal_unavailable'):
            await self.service._oidc_terminal_command(b'four', stale)

    async def test_expired_attempt_is_cancelled_and_pruned(self):
        attempt = SimpleNamespace()
        self.service._oidc_terminal_attempts['oidc_attempt_' + 'a' * 32] = {
            'attempt': attempt, 'caller': self.caller, 'scope': self.scope,
            'sessionId': None, 'expiresAt': self.now - timedelta(seconds=1)}
        await self.service._prune_oidc_terminal(self.now)
        self.owner.cancel.assert_awaited_once_with(attempt)
        self.assertFalse(self.service._oidc_terminal_attempts)

    async def test_expired_open_response_cancels_undisclosed_attempt(self):
        decision = self.service.ingress.admit.return_value.decision
        decision.valid_until = self.now - timedelta(seconds=1)
        request = self.request('oidc-terminal-session-open', 'terminal-open-expired', {})
        opened = asyncio.create_task(
            self.service._oidc_terminal_command(b'expired', request))
        await self.begin_entered.wait()
        self.release_begin.set()
        with self.assertRaisesRegex(ContractError, 'oidc_terminal_unavailable'):
            await opened
        self.owner.cancel.assert_awaited_once_with(self.attempt)
        self.assertFalse(self.service._oidc_terminal_attempts)
        self.assertFalse(self.service._oidc_terminal_results)

    async def test_session_map_is_bounded_and_overflow_session_is_closed(self):
        for index in range(4):
            self.service._oidc_terminal_sessions['oidc_session_' + str(index) * 32] = {
                'session': SimpleNamespace(close=Mock()), 'caller': self.caller,
                'scope': self.scope, 'expiresAt': self.now + timedelta(minutes=10)}
        attempt_id = 'oidc_attempt_' + 'a' * 32
        self.service._oidc_terminal_attempts[attempt_id] = {
            'attempt': self.attempt, 'caller': self.caller, 'scope': self.scope,
            'sessionId': None, 'expiresAt': self.attempt.expires_at}
        request = self.request('oidc-terminal-session-status', 'terminal-status-full',
                               {'attemptId': attempt_id})
        with self.assertRaisesRegex(ContractError, 'oidc_terminal_unavailable'):
            await self.service._oidc_terminal_command(b'full', request)
        self.session.close.assert_called_once_with()
        self.assertNotIn(attempt_id, self.service._oidc_terminal_attempts)
        self.assertEqual(len(self.service._oidc_terminal_sessions), 4)


if __name__ == '__main__':
    unittest.main()
