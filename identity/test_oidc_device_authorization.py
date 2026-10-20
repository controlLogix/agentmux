"""Device authorization keeps polling secrets private and respects RFC 8628."""
import base64
from datetime import timedelta
import json
import subprocess
import threading
import unittest
from urllib.parse import parse_qs

from nacl.signing import SigningKey

from agentmux_contracts import ContractError, canonical_bytes
from identity.oidc_adapter import OIDCProvider
from identity.oidc_device_authorization import (
    BoundedOIDCDeviceHTTP, OIDCDeviceAuthorizationFlow,
    OIDCDeviceAuthorizationProvider, OIDCDeviceAuthorizationRequest)
from identity.test_authority import NOW


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


class Runner:
    marker = b'\nagentmux-oidc-device-response:'

    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, command, **options):
        self.calls.append((command, options))
        response = self.responses.pop(0)
        if callable(response):
            response = response(options['input'])
        status, document = response
        output = json.dumps(document).encode() + self.marker + \
            str(status).encode() + b'\napplication/json'
        return subprocess.CompletedProcess(command, 0, stdout=output)


class DeviceAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        self.provider = OIDCProvider('https://identity.example/realms/team',
            'agentmux', 'key-one', encoded(bytes(self.key.verify_key)))
        self.configuration = OIDCDeviceAuthorizationProvider(self.provider,
            self.provider.issuer + '/protocol/openid-connect/auth/device',
            self.provider.issuer + '/protocol/openid-connect/token')
        self.monotonic, self.sleeps = 100.0, []

    def token(self, nonce, **changes):
        claims = {'iss': self.provider.issuer, 'sub': 'keycloak-user-184',
            'aud': self.provider.audience, 'iat': int(NOW.timestamp()),
            'exp': int((NOW + timedelta(minutes=4)).timestamp()),
            'nonce': nonce, **changes}
        header = {'alg': 'EdDSA', 'kid': 'key-one', 'typ': 'JWT'}
        parts = [encoded(canonical_bytes(header)), encoded(canonical_bytes(claims))]
        return '.'.join((*parts, encoded(self.key.sign(
            '.'.join(parts).encode()).signature)))

    def flow(self, responses):
        runner = Runner(responses)
        transport = BoundedOIDCDeviceHTTP(_runner=runner,
                                           _monotonic=lambda: self.monotonic)

        def sleep(seconds):
            self.sleeps.append(seconds)
            self.monotonic += seconds

        return OIDCDeviceAuthorizationFlow(self.configuration,
            transport=transport, _clock=lambda: NOW,
            _monotonic=lambda: self.monotonic, _sleep=sleep), runner

    def begin_response(self, **changes):
        return {'device_code': 'private-device-code', 'user_code': 'ABCD-EFGH',
            'verification_uri': self.provider.issuer + '/device',
            'verification_uri_complete': self.provider.issuer + '/device?user_code=ABCD-EFGH',
            'expires_in': 60, 'interval': 2, **changes}

    def test_pending_slow_down_and_success_keep_codes_out_of_arguments(self):
        nonce = {}

        def begin(body):
            form = {key: value[0] for key, value in parse_qs(body.decode()).items()}
            nonce['value'] = form['nonce']
            self.assertEqual(form['client_id'], 'agentmux')
            self.assertEqual(form['scope'], 'openid')
            self.assertEqual(form['code_challenge_method'], 'S256')
            self.assertEqual(len(form['code_challenge']), 43)
            return 200, self.begin_response()

        def success(body):
            form = {key: value[0] for key, value in parse_qs(body.decode()).items()}
            self.assertEqual(form['grant_type'],
                'urn:ietf:params:oauth:grant-type:device_code')
            self.assertEqual(form['device_code'], 'private-device-code')
            self.assertEqual(form['client_id'], 'agentmux')
            self.assertGreaterEqual(len(form['code_verifier']), 43)
            return 200, {'id_token': self.token(nonce['value']),
                         'access_token': 'ignored', 'refresh_token': 'ignored'}

        flow, runner = self.flow([begin,
            (400, {'error': 'authorization_pending'}),
            (400, {'error': 'slow_down', 'error_description': 'wait'}), success])
        request = flow.begin()
        self.assertEqual((request.user_code, request.verification_uri),
            ('ABCD-EFGH', self.provider.issuer + '/device'))
        verified = flow.complete(request)
        self.assertEqual(verified.external_identity, {'issuer': self.provider.issuer,
                                                       'subject': 'keycloak-user-184'})
        self.assertEqual(self.sleeps, [2.0, 2.0, 7.0])
        for command, options in runner.calls:
            joined = ' '.join(command)
            self.assertNotIn('private-device-code', joined)
            self.assertNotIn('ABCD-EFGH', joined)
            self.assertEqual(options['stderr'], subprocess.DEVNULL)
            self.assertLessEqual(options['timeout'], 5)
        self.assertNotIn('private-device-code', repr(request))
        with self.assertRaisesRegex(ContractError, 'oidc_device_request_invalid'):
            flow.complete(request)

    def test_denied_expired_and_unknown_errors_stop_without_retry(self):
        for error, expected in (('access_denied', 'oidc_device_authorization_refused'),
                                ('expired_token', 'oidc_device_authorization_expired'),
                                ('invalid_grant', 'oidc_device_exchange_refused')):
            self.monotonic, self.sleeps = 100.0, []
            flow, runner = self.flow([(200, self.begin_response()),
                                      (400, {'error': error})])
            request = flow.begin()
            with self.subTest(error=error), self.assertRaisesRegex(
                    ContractError, '^' + expected + '$'):
                flow.complete(request)
            self.assertEqual(len(runner.calls), 2)

    def test_expiry_prevents_another_poll(self):
        response = self.begin_response(expires_in=3, interval=2)
        flow, runner = self.flow([(200, response),
            (400, {'error': 'authorization_pending'})])
        request = flow.begin()
        with self.assertRaisesRegex(ContractError,
                '^oidc_device_authorization_expired$'):
            flow.complete(request)
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(self.sleeps, [2.0, 1.0])

    def test_slow_down_cannot_sleep_past_device_expiry(self):
        response = self.begin_response(expires_in=8, interval=2)
        flow, runner = self.flow([(200, response), (400, {'error': 'slow_down'})])
        request = flow.begin()
        with self.assertRaisesRegex(ContractError,
                '^oidc_device_authorization_expired$'):
            flow.complete(request)
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(self.sleeps, [2.0, 6.0])

    def test_cancel_wakes_the_production_wait_without_another_poll(self):
        runner = Runner([(200, self.begin_response(interval=30))])
        transport = BoundedOIDCDeviceHTTP(_runner=runner,
                                           _monotonic=lambda: self.monotonic)
        flow = OIDCDeviceAuthorizationFlow(self.configuration,
            transport=transport, _clock=lambda: NOW,
            _monotonic=lambda: self.monotonic)
        request = flow.begin()
        outcome = []

        def complete():
            try:
                flow.complete(request)
            except ContractError as error:
                outcome.append(error.code)

        worker = threading.Thread(target=complete)
        worker.start()
        request.cancel()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome, ['oidc_device_authorization_refused'])
        self.assertEqual(len(runner.calls), 1)

    def test_start_response_and_verification_uri_are_closed(self):
        cases = (
            self.begin_response(verification_uri='https://evil.example/device'),
            self.begin_response(verification_uri='https://identity.example:bad/device'),
            self.begin_response(expires_in=901),
            self.begin_response(interval=0),
            self.begin_response(extra='field'),
            self.begin_response(device_code=''),
            self.begin_response(verification_uri_complete='http://identity.example/code'),
        )
        for document in cases:
            flow, runner = self.flow([(200, document)])
            with self.subTest(document=document), self.assertRaisesRegex(
                    ContractError, '^oidc_device_request_invalid$'):
                flow.begin()
            self.assertEqual(len(runner.calls), 1)

    def test_success_requires_nonce_bound_signed_id_token(self):
        flow, _runner = self.flow([(200, self.begin_response()),
            (200, {'id_token': self.token('wrong-nonce')})])
        request = flow.begin()
        with self.assertRaisesRegex(ContractError, '^oidc_identity_invalid$'):
            flow.complete(request)

    def test_configuration_and_private_constructors_refuse_misuse(self):
        self.assertEqual(repr(self.configuration),
                         '<OIDCDeviceAuthorizationProvider configured>')
        flow, _runner = self.flow([])
        self.assertEqual(repr(flow), '<OIDCDeviceAuthorizationFlow configured>')
        with self.assertRaisesRegex(ContractError, 'oidc_device_configuration_invalid'):
            OIDCDeviceAuthorizationProvider(self.provider,
                'https://other.example/device', self.configuration.token_endpoint)
        with self.assertRaisesRegex(ContractError, 'oidc_device_configuration_invalid'):
            OIDCDeviceAuthorizationProvider(self.provider,
                self.configuration.token_endpoint, self.configuration.token_endpoint)
        with self.assertRaisesRegex(ContractError, 'oidc_device_request_invalid'):
            OIDCDeviceAuthorizationRequest(flow, object(), 'secret', 'CODE',
                'https://identity.example/device', 'verifier', 100, 5,
                NOW + timedelta(minutes=1), object())


if __name__ == '__main__':
    unittest.main()
