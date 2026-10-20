"""Fixed account-check transport with an owned HTTPS fixture and real owner reader.

The identity owner uses its existing offline JetStream boundary here. Actual NATS
and complete owner recovery qualification belong to AMUX-626.
"""
import asyncio
import base64
import copy
from dataclasses import replace
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims
from capability_owner.secret_consumer import (
    AtlassianAccountCheckConsumer, AtlassianAccountCheckEnrollment, SecretConsumerObservation)
from identity import test_service as service_fixture
from identity.test_authority import NOW, SEED
from identity.test_ordinary_secret import resolution_fixture
from native_security.secret_custody import PrivateSecret

_TOKEN = b'fixture-token-do-not-log'


class _Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def do_GET(self):
        expected = ('Basic ' + base64.b64encode(b'fixture@example.test:' + _TOKEN).decode()
                    if self.server.cloud else 'Bearer ' + _TOKEN.decode())
        self.server.requests.append((self.command, self.path, self.headers.get('Authorization') == expected))
        self.server.received.set()
        if self.server.hold:
            self.server.release.wait(6)
        try:
            self.send_response(self.server.status)
            self.send_header('Content-Type', self.server.content_type)
            self.send_header('Connection', 'close')
            if self.server.status == 302:
                self.send_header('Location', '/credential-must-not-arrive')
            if not self.server.unknown_length:
                self.send_header('Content-Length', str(len(self.server.body)))
            self.end_headers()
            self.wfile.write(self.server.body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        finally:
            self.close_connection = True


@unittest.skipUnless(Path('/usr/bin/openssl').is_file() and Path('/usr/bin/curl').is_file(),
                     'existing system OpenSSL and curl required')
class SecretConsumerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        service_fixture.ServiceTests.setUp(self)
        self.record['state'], self.outer = self._authority_state()
        self.store()
        self.addAsyncCleanup(self.service.close)
        clock = patch('identity.ordinary_secret.datetime', service_fixture._Clock)
        clock.start()
        self.addCleanup(clock.stop)
        clock = patch('capability_owner.secret_consumer._now', return_value=NOW)
        clock.start()
        self.addCleanup(clock.stop)
        self.directory = tempfile.TemporaryDirectory(prefix='agentmux-secret-consumer-https-')
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        config = root / 'fixture.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n'
            '[dn]\nCN=localhost\n[v3]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
            'basicConstraints=critical,CA:TRUE\n'
            'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n'
            'extendedKeyUsage=serverAuth\n')
        key, certificate = root / 'key.pem', root / 'certificate.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(certificate), '-days', '1', '-config', str(config)],
            check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15, env={'PATH': '/usr/bin:/bin'})
        key.chmod(0o600)
        certificate.chmod(0o600)
        self.pem = certificate.read_bytes()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        self.server.daemon_threads = False
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.server.received, self.server.release = threading.Event(), threading.Event()
        self.server.requests, self.server.hold, self.server.cloud = [], False, True
        self.server.body, self.server.status = b'{"accountId":"expected-account"}', 200
        self.server.content_type, self.server.unknown_length = 'application/json', False
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.02})
        self.thread.start()
        self.consumers = []
        self.addAsyncCleanup(self.cleanup_owned)
        self.enrollment = AtlassianAccountCheckEnrollment(
            canonical_bytes(self.record['state']['ordinarySecretReferences'][0]),
            f'https://127.0.0.1:{self.server.server_port}', 'cloud',
            'fixture@example.test', 'expected-account', self.pem)
        self.consumer = self.new_consumer()

    def _authority_state(self):
        record, outer, _ = resolution_fixture()
        return record['state'], outer

    def store(self):
        self.js.messages = [SimpleNamespace(subject=self.service.ledger._subject, seq=1,
            data=canonical_bytes(self.record))]

    def new_consumer(self, enrollment=None):
        consumer = AtlassianAccountCheckConsumer(self.service.reader, enrollment or self.enrollment)
        self.consumers.append(consumer)
        return consumer

    async def cleanup_owned(self):
        self.server.release.set()
        try:
            for consumer in self.consumers:
                await consumer.close()
                self.assertTrue(all(e.task is None or e.task.done() for e in consumer._entries.values()))
        finally:
            await asyncio.to_thread(self.server.shutdown)
            await asyncio.to_thread(self.thread.join, 5)
            self.assertFalse(self.thread.is_alive())
            self.server.server_close()

    def resign(self):
        for envelope in (self.outer['payload']['originalEnvelope'], self.outer):
            envelope['operation']['payloadDigest'] = payload_digest(envelope['payload'])
            claims = envelope['ingressAttestation']['claims']
            claims['operation'] = copy.deepcopy(envelope['operation'])
            envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)

    async def prepare(self, consumer=None, **changes):
        original = self.outer['payload']['originalEnvelope']['operation']
        args = {'operation_id': original['operationId'], 'payload_digest': original['payloadDigest'],
                'claim_ref': 'claim-original'}
        args.update(changes)
        return await (consumer or self.consumer).prepare(canonical_bytes(self.outer),
            PrivateSecret(_TOKEN), **args)

    async def run_check(self, consumer=None):
        consumer = consumer or self.consumer
        handle = await self.prepare(consumer)
        consumer.start(handle)
        return handle, await consumer.wait(handle)

    async def received(self):
        self.assertTrue(await asyncio.to_thread(self.server.received.wait, 2))

    async def test_real_cloud_get_matches_and_original_claim_never_repeats(self):
        handle, result = await self.run_check()
        self.assertEqual(result, SecretConsumerObservation('accepted', 'account_matched'))
        self.assertEqual(self.server.requests, [('GET', '/rest/api/3/myself', True)])
        self.assertIs(await self.prepare(), handle)
        self.consumer.start(handle)
        self.assertIs(await self.consumer.wait(handle), result)
        self.assertEqual(len(self.server.requests), 1)
        for changes in ({'claim_ref': 'different'}, {'payload_digest': 'sha256:' + '0' * 64}):
            with self.assertRaises(ContractError):
                await self.prepare(**changes)
        self.assertNotIn(_TOKEN.decode(), repr(result) + repr(self.consumer) + repr(handle))
        self.assertNotIn('expected-account', repr(result))
        await self.consumer.release(handle)
        with self.assertRaises(ContractError): self.consumer.start(handle)
        with self.assertRaises(ContractError): await self.prepare()
        self.assertEqual(len(self.server.requests), 1)

    async def test_real_server_get_uses_fixed_server_account_and_bearer(self):
        self.server.cloud = False
        self.server.body = b'{"name":"expected-account"}'
        consumer = self.new_consumer(replace(self.enrollment, deployment='server', email=None))
        _, result = await self.run_check(consumer)
        self.assertEqual(result.status, 'accepted')
        self.assertEqual(self.server.requests, [('GET', '/rest/api/2/myself', True)])

    async def test_wrong_account_is_rejected_without_private_account_response(self):
        self.server.body = b'{"accountId":"private-wrong-account","token":"fixture-token-do-not-log"}'
        _, result = await self.run_check()
        self.assertEqual((result.status, result.reason), ('rejected', 'account_mismatch'))
        self.assertNotIn('private-wrong-account', repr(result))
        self.assertNotIn(_TOKEN.decode(), repr(result))

    async def test_redirect_never_receives_another_request(self):
        self.server.status = 302
        _, result = await self.run_check()
        self.assertEqual(result, SecretConsumerObservation('rejected', 'http_refused'))
        self.assertEqual(len(self.server.requests), 1)

    async def test_environment_proxy_and_curl_configuration_cannot_redirect_credentials(self):
        with patch.dict(os.environ, {'HTTPS_PROXY': 'http://127.0.0.1:1',
                'ALL_PROXY': 'http://127.0.0.1:1', 'CURL_HOME': self.directory.name,
                'SSL_CERT_FILE': '/does/not/exist'}):
            Path(self.directory.name, '.curlrc').write_text('url = "http://127.0.0.1:1/stolen"\n')
            _, result = await self.run_check()
        self.assertEqual(result.status, 'accepted')
        self.assertEqual(self.server.requests, [('GET', '/rest/api/3/myself', True)])

    async def test_invalid_selection_and_wrong_current_bindings_never_transmit(self):
        for changes in ({'base_url': 'http://127.0.0.1'}, {'base_url': 'https://user:password@localhost'},
                        {'trust_pem': b'not a certificate'},
                        {'trust_pem': self.pem + b'-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----\n'},
                        {'expected_account': 'bad\nvalue'}):
            with self.subTest(changes=list(changes)), self.assertRaisesRegex(ContractError, '^secret_consumer_refused$'):
                replace(self.enrollment, **changes)
        record = copy.deepcopy(self.record['state']['ordinarySecretReferences'][0])
        record['purposeRef']['id'] = 'other-purpose'
        consumer = self.new_consumer(replace(self.enrollment, record=canonical_bytes(record)))
        with self.assertRaises(ContractError): await self.prepare(consumer)
        with self.assertRaises(ContractError): await self.prepare(operation_id='substituted')
        self.assertEqual(self.server.requests, [])

    async def test_other_enrolled_ca_cannot_authenticate_the_selected_destination(self):
        root = Path(self.directory.name)
        other_key, other_ca = root / 'other-key.pem', root / 'other-ca.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(other_key), '-out', str(other_ca), '-days', '1',
            '-config', str(root / 'fixture.cnf')], check=True, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            env={'PATH': '/usr/bin:/bin'})
        other_key.chmod(0o600)
        consumer = self.new_consumer(replace(self.enrollment, trust_pem=other_ca.read_bytes()))
        _, result = await self.run_check(consumer)
        self.assertEqual(result.status, 'uncertain')
        self.assertEqual(self.server.requests, [])

    async def test_current_revocation_before_start_refuses_without_transmission(self):
        handle = await self.prepare()
        next(g for g in self.record['state']['grants'] if g['ref']['id'] == 'ordinary-use-grant')['status'] = 'revoked'
        self.store()
        self.consumer.start(handle)
        with self.assertRaises(ContractError): await self.consumer.wait(handle)
        self.assertEqual(self.consumer.private_observation(handle),
                         SecretConsumerObservation('rejected', 'authority_refused'))
        self.assertEqual(self.server.requests, [])

    async def test_post_use_revocation_keeps_physical_observation_without_disclosure(self):
        self.server.hold = True
        handle = await self.prepare()
        self.consumer.start(handle)
        await self.received()
        next(g for g in self.record['state']['grants'] if g['ref']['id'] == 'ordinary-use-grant')['status'] = 'revoked'
        self.store()
        self.server.release.set()
        with self.assertRaises(ContractError): await self.consumer.wait(handle)
        self.assertEqual(self.consumer.private_observation(handle),
                         SecretConsumerObservation('accepted', 'account_matched'))
        with self.assertRaises(ContractError): await self.consumer.observation(handle)
        self.assertEqual(len(self.server.requests), 1)

    async def test_cancelled_observer_and_release_retain_original_worker_and_material(self):
        self.server.hold = True
        handle = await self.prepare()
        self.consumer.start(handle)
        await self.received()
        entry = self.consumer._entry(handle)
        original = entry.task
        observer = asyncio.create_task(self.consumer.wait(handle))
        await asyncio.sleep(0)
        observer.cancel()
        with self.assertRaises(asyncio.CancelledError): await observer
        release = asyncio.create_task(self.consumer.release(handle))
        await asyncio.sleep(0)
        release.cancel()
        with self.assertRaises(asyncio.CancelledError): await release
        self.assertFalse(original.done())
        self.assertIsNotNone(entry.material)
        self.assertIs(self.consumer.start(handle), handle)
        self.server.release.set()
        result = await self.consumer.wait(handle)
        self.assertEqual(result.status, 'accepted')
        self.assertIs(entry.task, original)
        await self.consumer.release(handle)
        self.assertTrue(original.done())
        self.assertIsNone(entry.material)
        self.assertEqual(len(self.server.requests), 1)

    async def test_original_short_deadline_bounds_slow_response_and_never_renews(self):
        expires = (NOW + timedelta(seconds=0.5)).isoformat().replace('+00:00', 'Z')
        for envelope in (self.outer['payload']['originalEnvelope'], self.outer):
            envelope['operation']['deadline'] = expires
            envelope['ingressAttestation']['claims']['expiresAt'] = expires
        self.resign()
        self.server.hold = True
        handle = await self.prepare()
        start = time.monotonic()
        self.consumer.start(handle)
        with self.assertRaises(ContractError): await self.consumer.wait(handle)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.5)
        entry = self.consumer._entry(handle)
        self.assertTrue(entry.task.done())
        self.assertEqual(self.consumer.private_observation(handle).status, 'uncertain')
        self.server.release.set()
        with self.assertRaises(ContractError): await self.prepare()
        self.assertEqual(len(self.server.requests), 1)

    async def test_oversized_unknown_length_response_is_bounded_and_joined(self):
        self.server.body = b'x' * 80000
        self.server.unknown_length = True
        handle, result = await self.run_check()
        self.assertEqual(result.status, 'uncertain')
        self.assertTrue(self.consumer._entry(handle).task.done())
        self.assertEqual(len(self.server.requests), 1)

    async def test_private_error_body_and_unreadable_response_are_sanitized(self):
        self.server.body = b'fixture-token-do-not-log private provider account'
        handle, result = await self.run_check()
        self.assertEqual(result.status, 'uncertain')
        self.assertNotIn(_TOKEN.decode(), repr(result))
        self.assertEqual(self.consumer.private_observation(handle), result)

    async def test_reader_is_exact_and_no_unrestricted_resolver_is_accepted(self):
        with self.assertRaises(ContractError):
            AtlassianAccountCheckConsumer(SimpleNamespace(resolve=lambda: True), self.enrollment)
        with self.assertRaises(ContractError):
            await self.consumer.prepare(canonical_bytes(self.outer), _TOKEN,
                operation_id='operation-one', payload_digest='sha256:' + '0' * 64, claim_ref='claim')
        self.assertEqual(self.server.requests, [])
