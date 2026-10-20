"""Authorization-code PKCE flow around the bounded OIDC identity adapter."""
import base64
from datetime import timedelta
import hashlib
import json
import subprocess
import sys
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes
from identity.oidc_adapter import OIDCProvider
from identity.oidc_authorization_code import (
    BoundedOIDCTokenHTTP, OIDCAuthorizationCodeFlow,
    OIDCAuthorizationCodeProvider, OIDCAuthorizationRequest, OIDCTokenRequest)
from identity.test_authority import NOW


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


class Runner:
    marker = b'\nagentmux-oidc-response:'

    def __init__(self, document=None, *, status=200, content_type='application/json', raw=None,
                 returncode=0, side_effect=None):
        self.body = raw if raw is not None else json.dumps(document).encode()
        self.status, self.content_type = status, content_type
        self.returncode, self.side_effect = returncode, side_effect
        self.calls = []

    def __call__(self, command, **options):
        self.calls.append((command, options))
        if self.side_effect is not None:
            if callable(self.side_effect):
                return self.side_effect()
            raise self.side_effect
        output = self.body + self.marker + str(self.status).encode() + b'\n' \
            + self.content_type.encode()
        return subprocess.CompletedProcess(command, self.returncode, stdout=output)


class AuthorizationCodeFlowTests(unittest.TestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        provider = OIDCProvider('https://identity.example/realms/team', 'agentmux', 'key-one',
            encoded(bytes(self.key.verify_key)))
        self.configuration = OIDCAuthorizationCodeProvider(provider,
            'https://identity.example/realms/team/protocol/openid-connect/auth',
            'https://identity.example/realms/team/protocol/openid-connect/token',
            'http://127.0.0.1:42131/oidc/callback')
        self.now = NOW
        self.monotonic = 100.0
        self.runner = Runner()
        self.transport = BoundedOIDCTokenHTTP(_runner=self.runner,
            _monotonic=lambda: self.monotonic)
        self.flow = OIDCAuthorizationCodeFlow(self.configuration,
            transport=self.transport, _clock=lambda: self.now)

    def token(self, nonce, **changes):
        claims = {'iss': self.configuration.provider.issuer,
            'sub': 'keycloak-user-184', 'aud': self.configuration.provider.audience,
            'iat': int(self.now.timestamp()),
            'exp': int((self.now + timedelta(minutes=4)).timestamp()), 'nonce': nonce,
            'email': 'mutable@example.test', **changes}
        header = {'alg': 'EdDSA', 'kid': 'key-one', 'typ': 'JWT'}
        parts = [encoded(canonical_bytes(header)), encoded(canonical_bytes(claims))]
        signature = self.key.sign('.'.join(parts).encode()).signature
        return '.'.join((*parts, encoded(signature)))

    def begin(self):
        request = self.flow.begin()
        query = parse_qs(urlsplit(request.authorization_url).query)
        return request, {key: value[0] for key, value in query.items()}

    def callback(self, query):
        return self.configuration.redirect_uri + '?' + urlencode(query)

    def test_complete_keycloak_flow_uses_exact_pkce_form_and_stable_identity(self):
        request, authorization = self.begin()
        self.assertEqual(urlsplit(request.authorization_url)._replace(query='').geturl(),
                         self.configuration.authorization_endpoint)
        self.assertEqual(authorization['response_type'], 'code')
        self.assertEqual(authorization['client_id'], 'agentmux')
        self.assertEqual(authorization['redirect_uri'], self.configuration.redirect_uri)
        self.assertEqual(authorization['scope'], 'openid')
        self.assertEqual(authorization['code_challenge_method'], 'S256')
        self.runner.body = json.dumps({'id_token': self.token(authorization['nonce']),
            'access_token': 'ignored-secret', 'refresh_token': 'ignored-secret',
            'session_state': 'ignored'}).encode()
        callback = self.callback({'state': authorization['state'], 'session_state': 'session-one',
            'iss': self.configuration.provider.issuer, 'code': 'authorization-code'})

        verified = self.flow.complete(request, callback)

        self.assertEqual(verified.external_identity, {'issuer': self.configuration.provider.issuer,
                                                       'subject': 'keycloak-user-184'})
        command, options = self.runner.calls[0]
        form = {key: value[0] for key, value in parse_qs(options['input'].decode()).items()}
        self.assertEqual(command[-1], self.configuration.token_endpoint)
        self.assertEqual(command[command.index('--request') + 1], 'POST')
        self.assertLessEqual(options['timeout'], 5)
        self.assertEqual(options['stderr'], subprocess.DEVNULL)
        self.assertEqual(set(form), {'grant_type', 'client_id', 'code', 'redirect_uri',
                                     'code_verifier'})
        self.assertEqual(form['grant_type'], 'authorization_code')
        self.assertEqual(form['client_id'], 'agentmux')
        self.assertEqual(form['code'], 'authorization-code')
        self.assertEqual(form['redirect_uri'], self.configuration.redirect_uri)
        self.assertEqual(len(form['code_verifier']), 43)
        challenge = encoded(hashlib.sha256(form['code_verifier'].encode('ascii')).digest())
        self.assertEqual(challenge, authorization['code_challenge'])
        self.assertNotIn('client_secret', form)

    def test_state_request_and_error_callback_are_one_use(self):
        request, authorization = self.begin()
        wrong = self.callback({'state': 'x' * 43, 'code': 'authorization-code'})
        with self.assertRaisesRegex(ContractError, 'oidc_authorization_request_invalid'):
            self.flow.complete(request, wrong)
        self.assertEqual(self.runner.calls, [])
        with self.assertRaisesRegex(ContractError, 'oidc_authorization_request_invalid'):
            self.flow.complete(request, self.callback({
                'state': authorization['state'], 'code': 'authorization-code'}))

        refused, authorization = self.begin()
        with self.assertRaisesRegex(ContractError, 'oidc_authorization_refused'):
            self.flow.complete(refused, self.callback({
                'state': authorization['state'], 'error': 'access_denied',
                'error_description': 'must not escape'}))
        with self.assertRaisesRegex(ContractError, 'oidc_authorization_request_invalid'):
            self.flow.complete(refused, self.callback({
                'state': authorization['state'], 'code': 'authorization-code'}))

    def test_callback_target_duplicates_and_issuer_are_exact(self):
        cases = (
            lambda state: 'http://127.0.0.1:42132/oidc/callback?state=' + state + '&code=a',
            lambda state: self.configuration.redirect_uri + '?state=' + state + '&state=' + state + '&code=a',
            lambda state: self.callback({'state': state, 'code': 'a', 'extra': 'value'}),
            lambda state: self.callback({'state': state, 'code': 'a', 'iss': 'https://other.example'}),
            lambda state: self.configuration.redirect_uri + '?state=' + state + '&code=',
        )
        for callback in cases:
            request, authorization = self.begin()
            with self.subTest(callback=callback), self.assertRaisesRegex(
                    ContractError, 'oidc_authorization_request_invalid'):
                self.flow.complete(request, callback(authorization['state']))
        self.assertEqual(self.runner.calls, [])

    def test_token_exchange_failure_is_bounded_generic_and_one_use(self):
        failures = (
            Runner({'error': 'invalid_grant'}, status=400),
            Runner({'id_token': 'secret'}, content_type='text/plain'),
            Runner(raw=b'x' * 65537),
            Runner(raw=b'{"id_token":"first","id_token":"second"}'),
            Runner({'id_token': 'secret'}, content_type='a' * 4097),
            Runner(returncode=47),
        )
        for runner in failures:
            flow = OIDCAuthorizationCodeFlow(self.configuration,
                transport=BoundedOIDCTokenHTTP(_runner=runner,
                    _monotonic=lambda: self.monotonic), _clock=lambda: self.now)
            request = flow.begin()
            state = parse_qs(urlsplit(request.authorization_url).query)['state'][0]
            callback = self.callback({'state': state, 'code': 'private-code'})
            with self.subTest(runner=runner), self.assertRaisesRegex(
                    ContractError, '^oidc_token_exchange_refused$'):
                flow.complete(request, callback)
            with self.assertRaisesRegex(ContractError, 'oidc_authorization_request_invalid'):
                flow.complete(request, callback)

    def test_network_latency_cannot_extend_login_lifetime(self):
        request, authorization = self.begin()
        token = self.token(authorization['nonce'])

        def delayed():
            self.now += timedelta(minutes=5)
            output = json.dumps({'id_token': token}).encode() + Runner.marker \
                + b'200\napplication/json'
            return subprocess.CompletedProcess([], 0, stdout=output)

        self.runner.side_effect = delayed
        with self.assertRaisesRegex(ContractError, 'oidc_login_binding_invalid'):
            self.flow.complete(request, self.callback({
                'state': authorization['state'], 'code': 'authorization-code'}))

    def test_slow_body_is_stopped_by_one_total_deadline(self):
        observed = []

        def stalled_body(command, **options):
            observed.append((command, options))
            return subprocess.run([sys.executable, '-c',
                'import sys,time;sys.stdout.write("partial-private-token");'
                'sys.stdout.flush();time.sleep(10)'], **options)

        monotonic = iter((100.0, 104.95))
        transport = BoundedOIDCTokenHTTP(_runner=stalled_body,
            _monotonic=lambda: next(monotonic))
        flow = OIDCAuthorizationCodeFlow(self.configuration, transport=transport,
                                         _clock=lambda: self.now)
        request = flow.begin()
        authorization = {key: value[0] for key, value in parse_qs(
            urlsplit(request.authorization_url).query).items()}
        started = time.monotonic()
        with self.assertRaisesRegex(ContractError, '^oidc_token_exchange_refused$'):
            flow.complete(request, self.callback({
                'state': authorization['state'], 'code': 'private-code'}))
        self.assertLess(time.monotonic() - started, 1)
        command, options = observed[0]
        self.assertLess(options['timeout'], 0.1)
        self.assertLessEqual(float(command[command.index('--max-time') + 1]), 5)
        self.assertLessEqual(float(command[command.index('--connect-timeout') + 1]), 5)
        self.assertEqual(command[command.index('--max-filesize') + 1], '65536')
        self.assertNotIn('private-code', ' '.join(command))

    def test_missing_code_or_state_with_optional_fields_is_closed(self):
        request, authorization = self.begin()
        with self.assertRaisesRegex(ContractError, 'oidc_authorization_request_invalid'):
            self.flow.complete(request, self.callback({
                'state': authorization['state'], 'iss': self.configuration.provider.issuer}))
        self.assertEqual(self.runner.calls, [])
        request, _ = self.begin()
        with self.assertRaisesRegex(ContractError, 'oidc_authorization_request_invalid'):
            self.flow.complete(request, self.callback({
                'code': 'authorization-code', 'session_state': 'session-one'}))
        self.assertEqual(self.runner.calls, [])

    def test_configuration_and_representations_do_not_expose_secrets(self):
        request, authorization = self.begin()
        self.assertEqual(repr(self.configuration), '<OIDCAuthorizationCodeProvider configured>')
        self.assertEqual(repr(self.flow), '<OIDCAuthorizationCodeFlow configured>')
        self.assertEqual(repr(self.transport), '<BoundedOIDCTokenHTTP configured>')
        self.assertNotIn(authorization['state'], repr(request))
        for values in (
            ('http://identity.example/auth', self.configuration.token_endpoint,
             self.configuration.redirect_uri),
            ('https://identity.example/other/auth', self.configuration.token_endpoint,
             self.configuration.redirect_uri),
            (self.configuration.authorization_endpoint, 'https://other.example/token',
             self.configuration.redirect_uri),
            (self.configuration.authorization_endpoint, self.configuration.token_endpoint,
             'http://localhost:42131/oidc/callback'),
            (self.configuration.authorization_endpoint, self.configuration.token_endpoint,
             'http://127.0.0.1/oidc/callback'),
        ):
            with self.assertRaisesRegex(ContractError,
                    'oidc_authorization_code_configuration_invalid'):
                OIDCAuthorizationCodeProvider(self.configuration.provider, *values)
        with self.assertRaisesRegex(ContractError, 'oidc_authorization_request_invalid'):
            OIDCAuthorizationRequest(self.flow, object(), 'secret', self.now, 'url', object())
        with self.assertRaisesRegex(ContractError, 'oidc_token_exchange_refused'):
            OIDCTokenRequest('https://identity.example/token', {}, object())


if __name__ == '__main__':
    unittest.main()
