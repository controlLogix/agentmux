"""Focused local browser credential handoff and HTTP authentication checks."""
import asyncio
from datetime import timedelta
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes
from dashboard.local_browser_auth import LocalBrowserAuth
from identity.local_browser_session import LocalBrowserPairingAuthority
from identity import test_local_browser_session as session_support
from identity.test_authority import NOW


HOST = '127.0.0.1:8787'
ORIGIN = 'http://127.0.0.1:8787'
LOCALHOST = 'localhost:8787'
LOCALHOST_ORIGIN = 'http://localhost:8787'
BOOTSTRAP = '/api/local-auth/bootstrap'
PAIR = '/api/local-auth/pair'
LOGOUT = '/api/local-auth/logout'
ACTION = '/api/board/agentdef'
CHALLENGE = '2345-6789-ABCD-EFGH-JKMP'


class LocalBrowserAuthTests(unittest.IsolatedAsyncioTestCase):
    setUp = session_support.LocalBrowserSessionTests.setUp
    make_provider = session_support.LocalBrowserSessionTests.make_provider
    key = session_support.LocalBrowserSessionTests.key
    session = session_support.LocalBrowserSessionTests.session

    async def approve(self, auth, challenge, session, *, origin):
        authority = object.__new__(LocalBrowserPairingAuthority)
        with patch.object(LocalBrowserPairingAuthority, 'recheck', AsyncMock()):
            return await auth.approve_pairing(
                challenge, session, authority, origin=origin)

    async def login(self, auth, session=None):
        bootstrap = auth.issue_bootstrap(session or await self.session())
        credential = bootstrap.take_for_post_body()
        login = await auth.redeem(credential, method='POST', target=BOOTSTRAP,
            host=HOST, origin=ORIGIN)
        headers, body = login.take_response()
        return bootstrap, credential, login, headers, body,

    async def test_owner_bootstrap_becomes_http_only_session_and_current_action(self):
        auth = LocalBrowserAuth(8787, clock=lambda: NOW)
        bootstrap, credential, login, headers, response = await self.login(auth)
        cookie = headers['Set-Cookie'].split(';', 1)[0]
        csrf = response['csrfToken']
        self.assertIn('Path=/', headers['Set-Cookie'])
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        self.assertIn('Max-Age=900', headers['Set-Cookie'])
        self.assertNotIn('Secure', headers['Set-Cookie'])
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertEqual(headers['Cache-Control'], 'no-store')
        context = await auth.authorize(cookie, csrf, method='POST', target=ACTION,
            host=HOST, origin=ORIGIN, body={'name': 'writer', 'scope': 'repo'})
        self.assertEqual(context.scope['projectId'], 'project-one')
        private = repr(auth) + repr(bootstrap) + repr(login)
        self.assertNotIn(credential, private)
        self.assertNotIn(cookie.split('=', 1)[1], private)
        self.assertNotIn(csrf, private)
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            login.take_response()
        auth.close()
        auth.close()
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await auth.authorize(cookie, csrf, method='POST', target=ACTION,
                host=HOST, origin=ORIGIN, body={'name': 'writer', 'scope': 'repo'})

    async def test_dashboard_auth_refreshes_identity_with_exact_http_guards(self):
        auth = LocalBrowserAuth(8787, clock=lambda: NOW)
        _bootstrap, _credential, _login, headers, response = await self.login(auth)
        cookie = headers['Set-Cookie'].split(';', 1)[0]
        csrf = response['csrfToken']
        target = '/api/board/config'
        context = await auth.authenticate_dashboard(cookie, csrf, method='POST',
            target=target, host=HOST, origin=ORIGIN)
        self.assertEqual(context.caller_ref['id'], 'human')
        for changed in (
                {'method': 'GET', 'target': target, 'host': HOST, 'origin': ORIGIN},
                {'method': 'POST', 'target': target + '?x=1', 'host': HOST,
                 'origin': ORIGIN},
                {'method': 'POST', 'target': target, 'host': LOCALHOST,
                 'origin': ORIGIN},
                {'method': 'POST', 'target': target, 'host': HOST,
                 'origin': LOCALHOST_ORIGIN}):
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    ContractError, 'local_browser_auth_unavailable'):
                await auth.authenticate_dashboard(cookie, csrf, **changed)

    async def test_bootstrap_is_one_use_body_only_and_requires_exact_local_request(self):
        auth = LocalBrowserAuth(8787, clock=lambda: NOW)
        bootstrap = auth.issue_bootstrap(await self.session())
        credential = bootstrap.take_for_post_body()
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            bootstrap.take_for_post_body()
        for changed in (
                {'method': 'GET', 'target': BOOTSTRAP, 'host': HOST, 'origin': ORIGIN},
                {'method': 'POST', 'target': BOOTSTRAP + '?token=' + credential,
                 'host': HOST, 'origin': ORIGIN},
                {'method': 'POST', 'target': BOOTSTRAP, 'host': 'evil.example:8787',
                 'origin': ORIGIN},
                {'method': 'POST', 'target': BOOTSTRAP, 'host': HOST,
                 'origin': 'http://evil.example'}):
            with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable') as refused:
                await auth.redeem(credential, **changed)
            self.assertNotIn(credential, str(refused.exception))
        login = await auth.redeem(credential, method='POST', target=BOOTSTRAP,
            host=HOST, origin=ORIGIN)
        login.take_response()
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await auth.redeem(credential, method='POST', target=BOOTSTRAP,
                host=HOST, origin=ORIGIN)

    async def test_cookie_csrf_origin_logout_and_current_revocation_fail_closed(self):
        auth = LocalBrowserAuth(8787, clock=lambda: NOW)
        _bootstrap, _credential, _login, headers, response = await self.login(auth)
        cookie, csrf = headers['Set-Cookie'].split(';', 1)[0], response['csrfToken']
        body = {'name': 'writer', 'scope': 'repo'}
        for changed in (
                {'cookie_header': cookie + '; ' + cookie, 'csrf_header': csrf,
                 'host': HOST, 'origin': ORIGIN},
                {'cookie_header': cookie, 'csrf_header': 'a' * 43,
                 'host': HOST, 'origin': ORIGIN},
                {'cookie_header': cookie, 'csrf_header': csrf,
                 'host': HOST, 'origin': None}):
            with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
                await auth.authorize(method='POST', target=ACTION, body=body, **changed)
        self.record['state']['grants'][1]['status'] = 'revoked'
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, 'application_permission_unavailable'):
            await auth.authorize(cookie, csrf, method='POST', target=ACTION,
                host=HOST, origin=ORIGIN, body=body)
        self.record['state']['grants'][1]['status'] = 'active'
        self.js.messages[0].data = canonical_bytes(self.record)
        cleared = auth.logout(cookie, csrf, method='POST', target=LOGOUT,
            host=HOST, origin=ORIGIN)
        self.assertIn('Max-Age=0', cleared['Set-Cookie'])
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await auth.authorize(cookie, csrf, method='POST', target=ACTION,
                host=HOST, origin=ORIGIN, body=body)

    async def test_expiry_and_redeem_recheck_close_the_owned_session(self):
        current = [NOW]
        auth = LocalBrowserAuth(8787, clock=lambda: current[0])
        first = await self.session()
        bootstrap = auth.issue_bootstrap(first)
        credential = bootstrap.take_for_post_body()
        current[0] += timedelta(seconds=30)
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await auth.redeem(credential, method='POST', target=BOOTSTRAP,
                host=HOST, origin=ORIGIN)
        with self.assertRaisesRegex(ContractError, 'local_browser_session_closed'):
            await first.verify_identity()

        current[0] = NOW
        auth = LocalBrowserAuth(8787, clock=lambda: current[0])
        second = await self.session()
        _bootstrap, _credential, _login, headers, response = await self.login(auth, second)
        cookie, csrf = headers['Set-Cookie'].split(';', 1)[0], response['csrfToken']
        current[0] += timedelta(minutes=15)
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await auth.authorize(cookie, csrf, method='POST', target=ACTION,
                host=HOST, origin=ORIGIN, body={'name': 'writer', 'scope': 'repo'})
        with self.assertRaisesRegex(ContractError, 'local_browser_session_closed'):
            await second.verify_identity()

    async def test_redeem_rechecks_current_grant_and_never_falls_back(self):
        auth = LocalBrowserAuth(8787, clock=lambda: NOW)
        session = await self.session()
        bootstrap = auth.issue_bootstrap(session)
        credential = bootstrap.take_for_post_body()
        self.record['state']['memberships'][0]['status'] = 'revoked'
        self.js.messages[0].data = canonical_bytes(self.record)
        with self.assertRaisesRegex(ContractError, 'application_permission_unavailable'):
            await auth.redeem(credential, method='POST', target=BOOTSTRAP,
                host=HOST, origin=ORIGIN)
        with self.assertRaisesRegex(ContractError, 'local_browser_session_closed'):
            await session.verify_identity()

    async def test_redeem_latency_and_parallel_bootstrap_cannot_duplicate_session(self):
        current = [NOW]
        auth = LocalBrowserAuth(8787, clock=lambda: current[0])
        session = await self.session()
        bootstrap = auth.issue_bootstrap(session)
        credential = bootstrap.take_for_post_body()
        original = session.verify_identity
        entered, release = asyncio.Event(), asyncio.Event()

        async def held_identity():
            entered.set()
            await release.wait()
            context = await original()
            current[0] += timedelta(seconds=30)
            return context

        session.verify_identity = held_identity
        task = asyncio.create_task(auth.redeem(credential,
            method='POST', target=BOOTSTRAP, host=HOST, origin=ORIGIN))
        await entered.wait()
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            auth.issue_bootstrap(session)
        release.set()
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await task
        with self.assertRaisesRegex(ContractError, 'local_browser_session_closed'):
            await original()

    async def test_browser_challenge_waits_for_verified_owner_and_logs_in_once(self):
        auth = LocalBrowserAuth(8787, clock=lambda: NOW)
        session = await self.session()
        waiting = asyncio.create_task(auth.pair(CHALLENGE, method='POST', target=PAIR,
            host=HOST, origin=ORIGIN))
        await asyncio.sleep(0)
        self.assertFalse(waiting.done())
        await self.approve(auth, CHALLENGE, session, origin=ORIGIN)
        login = await waiting
        headers, response = login.take_response()
        cookie, csrf = headers['Set-Cookie'].split(';', 1)[0], response['csrfToken']
        context = await auth.authorize(cookie, csrf, method='POST', target=ACTION,
            host=HOST, origin=ORIGIN, body={'name': 'writer', 'scope': 'repo'})
        self.assertEqual(context.caller_ref['id'], 'human')
        self.assertNotIn(CHALLENGE, repr(auth) + repr(login))
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await self.approve(auth, CHALLENGE, await self.session(), origin=ORIGIN)

    async def test_pairing_approval_requires_the_pending_request_origin(self):
        auth = LocalBrowserAuth(8787, clock=lambda: NOW)
        waiting = asyncio.create_task(auth.pair(CHALLENGE, method='POST', target=PAIR,
            host=LOCALHOST, origin=LOCALHOST_ORIGIN))
        await asyncio.sleep(0)
        refused = await self.session()
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await self.approve(auth, CHALLENGE, refused, origin=ORIGIN)
        refused.close()
        session = await self.session()
        await self.approve(auth, CHALLENGE, session, origin=LOCALHOST_ORIGIN)
        login = await waiting
        headers, response = login.take_response()
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertEqual(len(response['csrfToken']), 43)

    async def test_final_pairing_authority_failure_after_identity_check_issues_no_cookie(self):
        auth = LocalBrowserAuth(8787, clock=lambda: NOW)
        waiting = asyncio.create_task(auth.pair(CHALLENGE, method='POST', target=PAIR,
            host=HOST, origin=ORIGIN))
        await asyncio.sleep(0)
        session = await self.session()
        original = session.verify_identity
        entered, release = asyncio.Event(), asyncio.Event()

        async def held_identity():
            entered.set()
            await release.wait()
            return await original()

        async def denied(_context):
            raise ContractError('local_browser_not_authorized')

        session.verify_identity = held_identity
        authority = object.__new__(LocalBrowserPairingAuthority)
        with patch.object(LocalBrowserPairingAuthority, 'recheck', side_effect=denied):
            approval = asyncio.create_task(auth.approve_pairing(
                CHALLENGE, session, authority, origin=ORIGIN))
            await asyncio.wait_for(entered.wait(), 1)
            release.set()
            with self.assertRaisesRegex(ContractError, 'local_browser_not_authorized'):
                await approval
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await waiting
        self.assertEqual(auth._sessions, {})
        with self.assertRaisesRegex(ContractError, 'local_browser_session_closed'):
            await original()

    async def test_pairing_refuses_bad_request_duplicate_and_expired_approval(self):
        current = [NOW]
        auth = LocalBrowserAuth(8787, clock=lambda: current[0])
        for challenge, changed in (
                ('2345-6789-ABCD-EFGH-ILOU', {}),
                (CHALLENGE, {'target': PAIR + '?code=' + CHALLENGE}),
                (CHALLENGE, {'origin': 'http://evil.example'}),
                (CHALLENGE, {'host': 'evil.example:8787'})):
            request = {'method': 'POST', 'target': PAIR, 'host': HOST, 'origin': ORIGIN}
            request.update(changed)
            with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
                await auth.pair(challenge, **request)
        waiting = asyncio.create_task(auth.pair(CHALLENGE, method='POST', target=PAIR,
            host=HOST, origin=ORIGIN))
        await asyncio.sleep(0)
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await auth.pair(CHALLENGE, method='POST', target=PAIR, host=HOST, origin=ORIGIN)
        current[0] += timedelta(seconds=30)
        session = await self.session()
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await self.approve(auth, CHALLENGE, session, origin=ORIGIN)
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await waiting

    async def test_pairing_cancellation_and_close_release_pending_and_owner(self):
        auth = LocalBrowserAuth(8787, clock=lambda: NOW)
        waiting = asyncio.create_task(auth.pair(CHALLENGE, method='POST', target=PAIR,
            host=HOST, origin=ORIGIN))
        await asyncio.sleep(0)
        waiting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiting
        replacement = asyncio.create_task(auth.pair(CHALLENGE, method='POST', target=PAIR,
            host=HOST, origin=ORIGIN))
        await asyncio.sleep(0)
        auth.close()
        with self.assertRaisesRegex(ContractError, 'local_browser_auth_unavailable'):
            await replacement


if __name__ == '__main__':
    unittest.main()
