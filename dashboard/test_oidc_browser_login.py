"""OIDC browser login maps only a pre-linked current local human."""
import base64
import asyncio
import copy
from datetime import timedelta
import json
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes
from identity.authority import AuthoritySnapshot
from identity.oidc_adapter import OIDCProvider
from identity.oidc_authorization_code import (
    BoundedOIDCTokenHTTP, OIDCAuthorizationCodeFlow,
    OIDCAuthorizationCodeProvider)
from identity.service import IdentityService
from identity.application_service_selection import ApplicationServiceSelection
import identity.test_application_service_selection as selection_tests
from identity.test_authority import NOW, fixture
from application_service_host import ApplicationServiceHost
from local_browser_auth import LocalBrowserAuth
from oidc_browser_login import OIDCBrowserLogin


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


class Runner:
    def __init__(self):
        self.token = None

    def __call__(self, command, **options):
        body = json.dumps({'id_token': self.token}).encode()
        output = body + b'\nagentmux-oidc-response:200\napplication/json'
        return subprocess.CompletedProcess(command, 0, stdout=output)


class OIDCBrowserLoginTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.port = 42131
        self.host = f'127.0.0.1:{self.port}'
        self.origin = 'http://' + self.host
        self.key = SigningKey.generate()
        self.provider = OIDCProvider('https://identity.example/realms/team',
            'agentmux', 'key-one', encoded(bytes(self.key.verify_key)))
        self.configuration = OIDCAuthorizationCodeProvider(self.provider,
            self.provider.issuer + '/protocol/openid-connect/auth',
            self.provider.issuer + '/protocol/openid-connect/token',
            self.origin + '/api/local-auth/oidc/callback')
        self.runner = Runner()
        transport = BoundedOIDCTokenHTTP(_runner=self.runner, _monotonic=lambda: 100)
        self.flow = OIDCAuthorizationCodeFlow(self.configuration,
            transport=transport, _clock=lambda: NOW)
        record, _ = fixture()
        self.record = copy.deepcopy(record)
        self.record['state']['identities'][0]['externalIdentity'] = {
            'issuer': self.provider.issuer, 'subject': 'keycloak-user-184'}
        self.reader = SimpleNamespace(current=AsyncMock(return_value=AuthoritySnapshot(
            canonical_bytes(self.record), 7)))
        self.binding = object()
        self.application = SimpleNamespace(open_local_browser_binding=AsyncMock(
            return_value=self.binding))
        self.identity = object.__new__(IdentityService)
        self.identity.reader = self.reader
        self.identity.application = self.application
        self.auth = LocalBrowserAuth(self.port, clock=lambda: NOW)
        self.scope = {'organizationId': 'org-one', 'projectId': 'project-one',
                      'workspaceId': None}
        self.login = Mock()
        self.session = Mock()
        self.bootstrap = Mock()
        self.bootstrap.take_for_post_body.return_value = 'b' * 43
        self.auth.issue_bootstrap = Mock(return_value=self.bootstrap)
        self.auth.redeem = AsyncMock(return_value=self.login)
        self.monotonic = 100.0
        self.owner = OIDCBrowserLogin(self.configuration, self.identity, self.auth,
            self.scope, self.origin, _flow=self.flow,
            _monotonic=lambda: self.monotonic)

    def token(self, nonce):
        claims = {'iss': self.provider.issuer, 'sub': 'keycloak-user-184',
            'aud': self.provider.audience, 'iat': int(NOW.timestamp()),
            'exp': int((NOW + timedelta(minutes=4)).timestamp()), 'nonce': nonce,
            'email': 'mutable@example.test'}
        header = {'alg': 'EdDSA', 'kid': 'key-one', 'typ': 'JWT'}
        parts = [encoded(canonical_bytes(header)), encoded(canonical_bytes(claims))]
        return '.'.join((*parts, encoded(self.key.sign(
            '.'.join(parts).encode()).signature)))

    def begin(self):
        headers, result = self.owner.begin(method='POST', target='/api/local-auth/oidc/start',
            host=self.host, origin=self.origin)
        query = {key: value[0] for key, value in parse_qs(
            urlsplit(result['authorizationUrl']).query).items()}
        self.runner.token = self.token(query['nonce'])
        target = '/api/local-auth/oidc/callback?' + urlencode({
            'state': query['state'], 'session_state': 'keycloak-session',
            'iss': self.provider.issuer, 'code': 'private-code'})
        cookie = headers['Set-Cookie'].split(';', 1)[0]
        return result, target, cookie

    async def test_prelinked_identity_opens_current_browser_session_and_cookie(self):
        result, target, cookie = self.begin()
        self.assertTrue(result['authorizationUrl'].startswith(
            self.configuration.authorization_endpoint + '?'))
        with patch('oidc_browser_login.LocalBrowserSession.open_server_binding',
                   AsyncMock(return_value=self.session)) as opened:
            login = await self.owner.complete(target, cookie, method='GET', host=self.host)
        self.assertIs(login, self.login)
        self.application.open_local_browser_binding.assert_awaited_once_with(
            self.record['state']['identities'][0]['ref'], self.scope)
        opened.assert_awaited_once_with(self.binding, self.reader)
        self.auth.issue_bootstrap.assert_called_once_with(self.session)
        self.auth.redeem.assert_awaited_once_with('b' * 43, method='POST',
            target='/api/local-auth/bootstrap', host=self.host, origin=self.origin)

    async def test_unlinked_identity_never_enrolls_links_or_issues_cookie(self):
        self.record['state']['identities'][0]['externalIdentity'] = None
        self.reader.current.return_value = AuthoritySnapshot(canonical_bytes(self.record), 8)
        _result, target, cookie = self.begin()
        with self.assertRaisesRegex(ContractError, 'oidc_account_not_linked'):
            await self.owner.complete(target, cookie, method='GET', host=self.host)
        self.application.open_local_browser_binding.assert_not_awaited()
        self.auth.issue_bootstrap.assert_not_called()
        self.assertIsNone(self.record['state']['identities'][0]['externalIdentity'])

    async def test_origin_state_and_callback_are_exact_and_one_use(self):
        with self.assertRaisesRegex(ContractError, 'oidc_browser_unavailable'):
            self.owner.begin(method='POST', target='/api/local-auth/oidc/start',
                host=self.host, origin='http://evil.example')
        _result, target, cookie = self.begin()
        with self.assertRaisesRegex(ContractError, 'oidc_browser_unavailable'):
            await self.owner.complete(target, cookie, method='GET', host='localhost:42131')
        with patch('oidc_browser_login.LocalBrowserSession.open_server_binding',
                   AsyncMock(return_value=self.session)):
            await self.owner.complete(target, cookie, method='GET', host=self.host)
        with self.assertRaisesRegex(ContractError, 'oidc_browser_unavailable'):
            await self.owner.complete(target, cookie, method='GET', host=self.host)

    async def test_close_discards_pending_login(self):
        _result, target, cookie = self.begin()
        await self.owner.close()
        with self.assertRaisesRegex(ContractError, 'oidc_browser_unavailable'):
            await self.owner.complete(target, cookie, method='GET', host=self.host)

    async def test_abandoned_attempts_expire_and_capacity_recovers(self):
        for _ in range(8):
            self.owner.begin(method='POST', target='/api/local-auth/oidc/start',
                host=self.host, origin=self.origin)
        with self.assertRaisesRegex(ContractError, 'oidc_browser_unavailable'):
            self.owner.begin(method='POST', target='/api/local-auth/oidc/start',
                host=self.host, origin=self.origin)
        self.monotonic += 301
        headers, result = self.owner.begin(method='POST',
            target='/api/local-auth/oidc/start', host=self.host, origin=self.origin)
        self.assertIn('agentmux_oidc_login=', headers['Set-Cookie'])
        self.assertIn('authorizationUrl', result)

    async def test_callback_cookie_is_bound_to_the_browser_that_started_login(self):
        _result_a, target_a, cookie_a = self.begin()
        token_a = self.runner.token
        _result_b, _target_b, cookie_b = self.begin()
        with self.assertRaisesRegex(ContractError, 'oidc_browser_unavailable'):
            await self.owner.complete(target_a, cookie_b, method='GET', host=self.host)
        self.runner.token = token_a
        with patch('oidc_browser_login.LocalBrowserSession.open_server_binding',
                   AsyncMock(return_value=self.session)):
            await self.owner.complete(target_a, cookie_a, method='GET', host=self.host)

    async def test_close_during_exchange_joins_before_any_session_or_cookie(self):
        _result, target, cookie = self.begin()
        entered, release = threading.Event(), threading.Event()

        def held(_flow, _request, _callback):
            entered.set()
            release.wait(2)
            return SimpleNamespace(external_identity={
                'issuer': self.provider.issuer, 'subject': 'keycloak-user-184'})

        with patch.object(OIDCAuthorizationCodeFlow, 'complete', held):
            completing = asyncio.create_task(self.owner.complete(
                target, cookie, method='GET', host=self.host))
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            closing = asyncio.create_task(self.owner.close())
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            release.set()
            await closing
            with self.assertRaisesRegex(ContractError, 'oidc_browser_unavailable'):
                await completing
        self.application.open_local_browser_binding.assert_not_awaited()
        self.auth.issue_bootstrap.assert_not_called()

    async def test_repeated_cancellation_retains_exchange_for_close_retry(self):
        _result, target, cookie = self.begin()
        entered, release = threading.Event(), threading.Event()

        def held(_flow, _request, _callback):
            entered.set()
            release.wait(2)
            return SimpleNamespace(external_identity={
                'issuer': self.provider.issuer, 'subject': 'keycloak-user-184'})

        with patch.object(OIDCAuthorizationCodeFlow, 'complete', held):
            completing = asyncio.create_task(self.owner.complete(
                target, cookie, method='GET', host=self.host))
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            completing.cancel()
            completing.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await completing
            self.assertEqual(len(self.owner._exchanges), 1)

            interrupted_close = asyncio.create_task(self.owner.close())
            await asyncio.sleep(0)
            interrupted_close.cancel()
            interrupted_close.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await interrupted_close
            self.assertEqual(len(self.owner._exchanges), 1)

            retry = asyncio.create_task(self.owner.close())
            await asyncio.sleep(0)
            self.assertFalse(retry.done())
            release.set()
            await retry
        self.assertEqual(self.owner._exchanges, set())
        self.application.open_local_browser_binding.assert_not_awaited()
        self.auth.issue_bootstrap.assert_not_called()

    async def test_close_joins_callback_after_exchange_before_session_or_cookie(self):
        _result, target, cookie = self.begin()
        entered, release = asyncio.Event(), asyncio.Event()

        async def held(_owner, _external_identity):
            entered.set()
            await release.wait()
            return self.session

        with patch.object(OIDCBrowserLogin, '_linked_session', held):
            completing = asyncio.create_task(self.owner.complete(
                target, cookie, method='GET', host=self.host))
            await asyncio.wait_for(entered.wait(), 1)
            self.assertEqual(self.owner._exchanges, set())
            closing = asyncio.create_task(self.owner.close())
            await asyncio.sleep(0)
            self.assertFalse(closing.done())
            release.set()
            await closing
            with self.assertRaisesRegex(ContractError, 'oidc_browser_unavailable'):
                await completing
        self.session.close.assert_called_once_with()
        self.auth.issue_bootstrap.assert_not_called()


class OIDCHostWiringTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        selection_tests.ServiceSelectionTests.setUp(self)
        self.selection = ApplicationServiceSelection(canonical_bytes(self.value))

    async def asyncSetUp(self):
        self.host = ApplicationServiceHost(self.selection, browser_port=0)

    async def asyncTearDown(self):
        await self.host.close()

    async def test_explicit_configuration_builds_exact_runtime_redirect(self):
        key = SigningKey.generate()
        provider = OIDCProvider('https://identity.example/realms/team', 'agentmux',
            'key-one', encoded(bytes(key.verify_key)))
        self.host.configure_oidc_browser(provider,
            provider.issuer + '/protocol/openid-connect/auth',
            provider.issuer + '/protocol/openid-connect/token')
        self.host._identity = object.__new__(IdentityService)
        self.host._identity._application_lease = None
        self.host._start_local_browser()
        self.assertIsNotNone(self.host._oidc_login)
        self.assertEqual(self.host._oidc_login._flow._configuration.redirect_uri,
            self.host._browser_origin + '/api/local-auth/oidc/callback')
        with self.assertRaisesRegex(ContractError, 'oidc_browser_configuration_invalid'):
            self.host.configure_oidc_browser(provider,
                provider.issuer + '/protocol/openid-connect/auth',
                provider.issuer + '/protocol/openid-connect/token')


if __name__ == '__main__':
    unittest.main()
