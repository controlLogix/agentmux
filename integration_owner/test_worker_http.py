"""Opt-in native worker tests; run only in the serialized local-test slot.

Uses an ephemeral HTTPS server, temporary synthetic credentials and a temporary
self-signed fixture certificate made by the existing system OpenSSL. Importing
this module creates no processes, servers, credentials or environment changes.
"""
import asyncio
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from agentmux_contracts import ContractError
from integration_owner import test_admission, test_commands
from integration_owner.credentials import pin_atlassian_config, AtlassianCredentialResolver
from integration_owner.receiver import IntegrationOwner
from integration_owner.test_intent import payload
from taskmgmt.test_atlassian_safety import CLOUD


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def write_request(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.server.writes += 1
        self.server.last_write = (self.command, self.path, body)
        self.server.received.set()
        if not self.server.release.wait(8):
            self.close_connection = True
            return
        if self.server.lose_reply:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.close_connection = True
            return
        self.send_response(204)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    do_POST = write_request
    do_PUT = write_request

    def do_GET(self):
        self.server.reads += 1
        body = (b'{"id":"42","version":{"number":8}}'
                if '/content/42' in self.path else b'{"key":"AMUX-66"}')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


@unittest.skipUnless(Path('/usr/bin/openssl').is_file(), 'existing system OpenSSL unavailable')
class WorkerHTTPTests(unittest.IsolatedAsyncioTestCase):
    resign = test_admission.AdmissionTests.resign
    execute = test_admission.AdmissionTests.execute
    command = test_commands.CommandTests.command

    def setUp(self):
        test_admission.AdmissionTests.setUp(self)
        fixture = tempfile.TemporaryDirectory(prefix='agentmux-managed-worker-http-')
        self.addCleanup(fixture.cleanup)
        self.root = Path(fixture.name)
        environment = patch.dict(os.environ, {'HOME': str(self.root),
            'AGENTMUX_HOME': str(self.root / 'agentmux'), 'PATH': '/usr/bin:/bin',
            'NO_PROXY': '127.0.0.1,localhost'}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        openssl_config = self.root / 'fixture.cnf'
        openssl_config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n'
            '[dn]\nCN=localhost\n[v3]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
            'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n'
            'extendedKeyUsage=serverAuth\n')
        key, certificate = self.root / 'fixture-key.pem', self.root / 'fixture-cert.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(certificate), '-days', '1', '-config', str(openssl_config)],
            check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15, env=dict(os.environ))
        key.chmod(0o600)
        certificate.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        client_context = ssl.create_default_context(cafile=str(certificate))
        server = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
        server.daemon_threads = False
        try:
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.received, server.release = threading.Event(), threading.Event()
            server.writes, server.reads, server.lose_reply, server.last_write = 0, 0, False, None
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05})
            thread.start()
        except BaseException:
            server.server_close()
            raise
        self.server, self.server_thread = server, thread
        self.addAsyncCleanup(self.stop_owned_resources)
        site = f'https://127.0.0.1:{server.server_address[1]}'
        self.site = site
        config_path = self.root / 'atlassian.json'
        config_path.write_text(json.dumps({**CLOUD, 'base_url': site}))
        config_path.chmod(0o600)
        self.config_path = config_path
        metadata = dict(provider='jira', config_path=config_path, site_url=site, config_version=1)
        reference = payload()['credentialRef']
        self.reference = reference
        pin = pin_atlassian_config(reference, **metadata)
        resolver = AtlassianCredentialResolver(reference, **metadata, config_pin=pin)
        self.owner = IntegrationOwner(self.authority, self.ledger, self.binding,
            provider='jira', credential_ref=reference, credentials=resolver)
        trust = patch('taskmgmt.atlassian.ssl.create_default_context', return_value=client_context)
        trust.start()
        self.addCleanup(trust.stop)

    async def stop_owned_resources(self):
        self.server.release.set()
        try:
            await self.owner.close(timeout=5)
        finally:
            self.server.shutdown()
            self.server_thread.join(timeout=5)
            self.assertFalse(self.server_thread.is_alive(), 'original HTTPS server is still running')
            self.server.server_close()
        self.assertTrue(all(task.done() for task in self.owner._worker._tasks.values()),
                        'original provider I/O is still owned and running')

    async def claimed(self):
        initial = await self.execute()
        digest = initial.original_payload_digest
        self.command('integration-attempt-start', 'attempt-one', 1, digest)
        original_start = json.loads(json.dumps(self.envelope))
        reply = await self.execute()
        self.assertEqual(reply.status, 'dispatch-claimed')
        self.assertTrue(await asyncio.to_thread(self.server.received.wait, 5))
        return digest, original_start

    async def test_cancelled_completion_keeps_original_http_worker_until_joined(self):
        digest, _ = await self.claimed()
        original = self.owner._worker._tasks['attempt-one']
        self.assertFalse(original.done())
        self.command('integration-attempt-complete', 'complete-one', 2, digest)
        completion = asyncio.create_task(self.execute())
        await asyncio.sleep(0)
        completion.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await completion
        self.assertIs(self.owner._worker._tasks['attempt-one'], original)
        self.assertFalse(original.done())
        self.server.release.set()
        reply = await self.execute()
        self.assertEqual((reply.status, reply.attempt_operation_id), ('applied', 'attempt-one'))
        self.assertTrue(original.done())
        self.assertEqual(self.server.writes, 1)
        self.assertEqual(len(self.js.messages), 3)

    async def test_lost_http_reply_stays_uncertain_without_redispatch(self):
        self.server.lose_reply = True
        self.server.release.set()
        digest, original_start = await self.claimed()
        self.command('integration-attempt-complete', 'complete-one', 2, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.command('integration-effect-reconcile', 'reconcile-one', 3, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.assertEqual(self.server.reads, 1)
        self.envelope = original_start
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.assertEqual(self.server.writes, 1)

    async def test_confluence_update_lost_http_reply_retains_page_version_without_second_put(self):
        await test_commands.CommandTests.configure_confluence_update(self)
        self.server.lose_reply = True
        self.server.release.set()
        digest, original_start = await self.claimed()
        self.command('integration-attempt-complete', 'complete-one', 2, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.command('integration-effect-reconcile', 'reconcile-one', 3, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.envelope = original_start
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        method, path, body = self.server.last_write
        self.assertEqual((method, path), ('PUT', '/wiki/rest/api/content/42'))
        self.assertEqual(json.loads(body)['version'], {'number': 8})
        self.assertEqual((self.server.writes, self.server.reads), (1, 1))


if __name__ == '__main__':
    unittest.main()
