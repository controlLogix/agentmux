"""HTTP routing checks for the local enrolled browser owner."""
from http.client import HTTPConnection
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from agentmux_contracts import ContractError
import server
from definition_commands import LocalDefinitionOutcomeUnconfirmed
from dashboard_commands import DashboardOutcomeUnconfirmed


class LocalBrowserServerTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.owner = Mock()
        self.login = Mock()
        self.login.take_response.return_value = ({
            'Set-Cookie': 'agentmux_local_session=private; Path=/; HttpOnly; SameSite=Strict',
            'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'},
            {'csrfToken': 'c' * 43})
        self.owner.browser_pair.return_value = self.login
        self.owner.browser_oidc_start.return_value = ({
            'Set-Cookie': 'agentmux_oidc_login=browser-private; '
                'Path=/api/local-auth/oidc/callback; HttpOnly; SameSite=Lax; Max-Age=300',
            'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'}, {
            'authorizationUrl': 'https://identity.example/realms/team/auth?state=private'})
        self.owner.browser_oidc_callback.return_value = self.login
        self.owner.browser_logout.return_value = {
            'Set-Cookie': 'agentmux_local_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
            'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'}
        self.owner.browser_definition.return_value = {'ok': True, 'name': 'writer'}
        self.owner.browser_dashboard_command.return_value = {'ok': True,
            'operationId': 'dashboard_' + 'a' * 64, 'outcome': 'applied'}
        self.home_patch = patch.object(server, 'HOME_DIR', Path(self.home.name))
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)
        self.httpd = server.BacklogServer(('127.0.0.1', 0), server.Handler,
            application_host=self.owner)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        self.host = f'127.0.0.1:{self.httpd.server_port}'
        self.origin = 'http://' + self.host

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def request(self, path, body, *, headers=None):
        connection = HTTPConnection('127.0.0.1', self.httpd.server_port, timeout=3)
        selected = {'Content-Type': 'application/json', 'Origin': self.origin,
                    'Host': self.host, **(headers or {})}
        connection.request('POST', path, json.dumps(body), selected)
        response = connection.getresponse()
        raw = response.read()
        result = response.status, dict(response.getheaders()), json.loads(raw)
        connection.close()
        return result

    def get(self, path, *, headers=None):
        connection = HTTPConnection('127.0.0.1', self.httpd.server_port, timeout=3)
        selected = {'Host': self.host, **(headers or {})}
        connection.request('GET', path, headers=selected)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_pairing_body_reaches_only_the_injected_owner(self):
        challenge = '2345-6789-ABCD-EFGH-JKMP'
        status, headers, body = self.request('/api/local-auth/pair', {'challenge': challenge})
        self.assertEqual((status, body), (200, {'csrfToken': 'c' * 43}))
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.owner.browser_pair.assert_called_once_with(challenge, method='POST',
            target='/api/local-auth/pair', host=self.host, origin=self.origin)
        self.login.take_response.assert_called_once_with()

    def test_oidc_start_and_callback_keep_credentials_out_of_urls_and_storage(self):
        status, headers, body = self.request('/api/local-auth/oidc/start', {})
        self.assertEqual(status, 200)
        self.assertEqual(body['authorizationUrl'],
                         'https://identity.example/realms/team/auth?state=private')
        self.assertEqual((headers['Cache-Control'], headers['Referrer-Policy']),
                         ('no-store', 'no-referrer'))
        self.owner.browser_oidc_start.assert_called_once_with(method='POST',
            target='/api/local-auth/oidc/start', host=self.host, origin=self.origin)

        callback = '/api/local-auth/oidc/callback?state=public-state&code=private-code'
        binding_cookie = headers['Set-Cookie'].split(';', 1)[0]
        status, headers, raw = self.get(callback, headers={'Cookie': binding_cookie})
        self.assertEqual(status, 200)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertEqual((headers['Cache-Control'], headers['Referrer-Policy']),
                         ('no-store', 'no-referrer'))
        self.assertIn("default-src 'none'", headers['Content-Security-Policy'])
        self.assertIn(b'BroadcastChannel', raw)
        self.assertNotIn(b'private-code', raw)
        self.owner.browser_oidc_callback.assert_called_once_with(
            callback, binding_cookie, method='GET', host=self.host)

    def test_unconfigured_oidc_start_is_not_changed_to_local_pairing(self):
        self.owner.browser_oidc_start.side_effect = ContractError(
            'oidc_browser_not_configured')
        status, headers, body = self.request('/api/local-auth/oidc/start', {})
        self.assertEqual((status, body), (404, {'error': 'hosted sign-in unavailable'}))
        self.assertEqual((headers['Cache-Control'], headers['Referrer-Policy']),
                         ('no-store', 'no-referrer'))
        self.owner.browser_pair.assert_not_called()

    def test_authenticated_definition_route_does_not_use_legacy_actor(self):
        body = {'name': 'writer', 'scope': 'repo'}
        status, _headers, response = self.request('/api/board/agentdef', body,
            headers={'Cookie': 'agentmux_local_session=private', 'X-Agentmux-CSRF': 'c' * 43})
        self.assertEqual((status, response), (200, {'ok': True, 'name': 'writer'}))
        self.owner.browser_definition.assert_called_once_with(
            'agentmux_local_session=private', 'c' * 43, method='POST',
            target='/api/board/agentdef', host=self.host, origin=self.origin, body=body)

    def test_definition_business_errors_keep_existing_http_status(self):
        for error, expected in (
                (server.ccboard.Refused('definition revision changed; reload before editing', []), 409),
                (server.ccboard.Invalid('definition must be a regular file'), 400),
                (server.ccboard.NotFound('definition not found'), 404)):
            with self.subTest(status=expected):
                self.owner.browser_definition.side_effect = error
                status, _, response = self.request('/api/board/agentdef',
                    {'name': 'writer', 'scope': 'repo'},
                    headers={'Cookie': 'agentmux_local_session=private',
                             'X-Agentmux-CSRF': 'c' * 43})
                self.assertEqual(status, expected)
                self.assertEqual(response['error'], str(error))
                if expected == 409:
                    self.assertEqual(response['missing'], [])

    def test_uncertain_definition_outcome_is_not_changed_to_sign_in_failure(self):
        self.owner.browser_definition.side_effect = LocalDefinitionOutcomeUnconfirmed(
            'owner_commit_uncertain', 'browser_stable_operation')
        status, headers, response = self.request('/api/board/agentdef',
            {'name': 'writer', 'scope': 'repo'},
            headers={'Cookie': 'agentmux_local_session=private',
                     'X-Agentmux-CSRF': 'c' * 43})
        self.assertEqual(status, 503)
        self.assertEqual(response, {'error': 'definition outcome unconfirmed',
            'outcome': 'uncertain', 'operationId': 'browser_stable_operation'})
        self.assertEqual((headers['Cache-Control'], headers['Referrer-Policy']),
                         ('no-store', 'no-referrer'))
        self.owner.browser_definition.assert_called_once()

    def test_denied_completion_keeps_operation_and_does_not_prompt_sign_in(self):
        self.owner.browser_definition.side_effect = LocalDefinitionOutcomeUnconfirmed(
            'definition_not_authorized', 'browser_denied_completion')
        status, headers, response = self.request('/api/board/agentdef',
            {'name': 'writer', 'scope': 'repo'},
            headers={'Cookie': 'agentmux_local_session=private',
                     'X-Agentmux-CSRF': 'c' * 43})
        self.assertEqual(status, 409)
        self.assertEqual(response, {'error': 'definition completion denied',
            'outcome': 'completion-denied', 'operationId': 'browser_denied_completion'})
        self.assertEqual((headers['Cache-Control'], headers['Referrer-Policy']),
                         ('no-store', 'no-referrer'))
        self.owner.browser_definition.assert_called_once()

    def test_pairing_and_definition_require_exact_origin_and_credentials(self):
        status, _headers, _body = self.request('/api/local-auth/pair',
            {'challenge': '2345-6789-ABCD-EFGH-JKMP'}, headers={'Origin': 'http://evil.example'})
        self.assertEqual(status, 403)
        status, headers, _body = self.request('/api/board/agentdrop',
            {'name': 'writer', 'scope': 'repo'})
        self.assertEqual(status, 401)
        self.assertEqual((headers['Cache-Control'], headers['Referrer-Policy']),
                         ('no-store', 'no-referrer'))
        self.owner.browser_definition.assert_not_called()

    def test_general_write_requires_identity_and_refuses_payload_actor(self):
        status, headers, body = self.request('/api/board/config',
            {'name': 'orchestratorEnabled', 'value': False})
        self.assertEqual((status, body), (401, {'error': 'local sign-in required'}))
        self.assertEqual((headers['Cache-Control'], headers['Referrer-Policy']),
                         ('no-store', 'no-referrer'))
        self.owner.browser_dashboard_command.assert_not_called()
        status, _headers, body = self.request('/api/board/config',
            {'name': 'orchestratorEnabled', 'value': False, 'actor': 'forged'},
            headers={'Cookie': 'agentmux_local_session=private',
                     'X-Agentmux-CSRF': 'c' * 43})
        self.assertEqual((status, body),
                         (400, {'error': 'actor is supplied by the signed-in identity'}))
        self.owner.browser_dashboard_command.assert_not_called()

    def test_authenticated_general_write_uses_exact_owner_route(self):
        body = {'name': 'orchestratorEnabled', 'value': False}
        status, _headers, response = self.request('/api/board/config', body,
            headers={'Cookie': 'agentmux_local_session=private',
                     'X-Agentmux-CSRF': 'c' * 43})
        self.assertEqual(status, 200)
        self.assertEqual(response['outcome'], 'applied')
        self.owner.browser_dashboard_command.assert_called_once_with(
            'agentmux_local_session=private', 'c' * 43, method='POST',
            target='/api/board/config', host=self.host, origin=self.origin, body=body)

    def test_uncertain_general_write_preserves_original_operation(self):
        self.owner.browser_dashboard_command.side_effect = DashboardOutcomeUnconfirmed(
            'dashboard_' + 'b' * 64)
        status, headers, response = self.request('/api/board/config',
            {'name': 'orchestratorEnabled', 'value': False}, headers={
                'Cookie': 'agentmux_local_session=private',
                'X-Agentmux-CSRF': 'c' * 43})
        self.assertEqual((status, response), (503, {'error': 'dashboard outcome unconfirmed',
            'outcome': 'uncertain', 'operationId': 'dashboard_' + 'b' * 64}))
        self.assertEqual((headers['Cache-Control'], headers['Referrer-Policy']),
                         ('no-store', 'no-referrer'))

    def test_run_review_requires_identity_and_records_through_owner(self):
        body = {'decision': 'approved', 'note': 'read'}
        status, _headers, response = self.request('/api/runs/abcdef/review', body)
        self.assertEqual((status, response), (401, {'error': 'local sign-in required'}))
        status, _headers, response = self.request('/api/runs/abcdef/review', body,
            headers={'Cookie': 'agentmux_local_session=private',
                     'X-Agentmux-CSRF': 'c' * 43})
        self.assertEqual(status, 200)
        self.owner.browser_dashboard_command.assert_called_once_with(
            'agentmux_local_session=private', 'c' * 43, method='POST',
            target='/api/runs/abcdef/review', host=self.host, origin=self.origin, body=body)

    def test_server_without_application_owner_keeps_legacy_route_shape(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        with server.BacklogServer(('127.0.0.1', 0), server.Handler) as legacy:
            self.assertIsNone(legacy.application_host)


if __name__ == '__main__':
    unittest.main()
