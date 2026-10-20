"""Release shutdown teardown only after the original client socket closes."""
import asyncio
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from agentmux_contracts import canonical_bytes, strict_loads
from hub.core_endpoint import CoreConnection, _ReplyWriter, _mac, _socket_identity
from hub.core_profile import CoreRoute, CoreSetupRequired


@unittest.skipUnless(os.uname().sysname == 'Darwin', 'native descriptor checks require macOS')
class ShutdownClientCloseTests(unittest.TestCase):
    def exchange(self, *, changed_record=False):
        # Match the existing transport fixture: only central route admission is
        # substituted; the socket peer and private record checks remain real.
        with tempfile.TemporaryDirectory(prefix='a714-', dir=Path.home()/'.cache') as directory:
            root = Path(directory)
            (root/'hub').mkdir(mode=0o700)
            route = object.__new__(CoreRoute)
            route.home, route.socket = str(root), str(root/'hub'/'hub.sock')
            route.repository = '/approved'
            route.binding = {'repositories': {'/approved': 'falcon'}}
            listener = socket.socket(socket.AF_UNIX)
            listener.settimeout(3)
            listener.bind(route.socket)
            os.chmod(route.socket, 0o600)
            listener.listen(1)
            value = {'version': 1, 'binding': route.binding, 'source': {},
                'pid': os.getpid(), 'socket': _socket_identity(route.socket), 'key': 'ab'*32}
            path = root/'hub'/'selected-endpoint.json'
            path.write_bytes(canonical_bytes(value))
            path.chmod(0o600)
            eof, failures, requests = threading.Event(), [], []
            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(3)
                        raw = bytearray()
                        while not raw.endswith(b'\n'):
                            chunk = connection.recv(65536)
                            if not chunk:
                                raise AssertionError('request missing')
                            raw.extend(chunk)
                        payload = strict_loads(bytes(raw))['core']
                        requests.append(payload['request'])
                        body = {'nonce': payload['nonce'], 'binding': payload['binding'],
                            'response': {'ok': True, 'result': {'stopping': True}}}
                        connection.sendall(canonical_bytes({'core': body,
                            'mac': _mac(value['key'], body)}) + b'\n')
                        if connection.recv(1) != b'':
                            raise AssertionError('unexpected client data')
                        eof.set()
                except BaseException as error:
                    failures.append(error)
            worker = threading.Thread(target=serve)
            worker.start()
            try:
                with patch.object(CoreRoute, 'check'):
                    client = CoreConnection(route)
                    original = client.record.check
                    checks = []
                    def check():
                        checks.append(len(checks) + 1)
                        self.assertFalse(eof.is_set())
                        if len(checks) == 3 and changed_record:
                            path.write_bytes(canonical_bytes({**value, 'key': 'cd'*32}))
                        original()
                    try:
                        with patch.object(client.record, 'check', side_effect=check):
                            if changed_record:
                                with self.assertRaises(CoreSetupRequired):
                                    client.exchange({'verb': 'shutdown'}, 2)
                            else:
                                self.assertEqual(client.exchange({'verb': 'shutdown'}, 2),
                                    {'ok': True, 'result': {'stopping': True}})
                        self.assertEqual(checks, [1, 2, 3])
                    finally:
                        client.close()
            finally:
                worker.join(4)
                listener.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            self.assertTrue(eof.is_set())
            self.assertEqual(requests, [{'verb': 'shutdown'}])

    def test_client_final_record_check_precedes_same_connection_eof(self):
        self.exchange()

    def test_changed_final_record_refuses_then_releases_connection(self):
        self.exchange(changed_record=True)


class ShutdownReplyTransportTests(unittest.IsolatedAsyncioTestCase):
    async def streams(self, *, verb='shutdown', ok=True):
        first, second = socket.socketpair()
        first.setblocking(False)
        second.setblocking(False)
        reader, writer = await asyncio.open_connection(sock=first)
        remote_reader, remote_writer = await asyncio.open_connection(sock=second)
        async def close():
            writer.close()
            remote_writer.close()
            await asyncio.gather(writer.wait_closed(), remote_writer.wait_closed(),
                return_exceptions=True)
        self.addAsyncCleanup(close)
        endpoint = SimpleNamespace(check=Mock(), value={'key': 'ab'*32})
        request = {'nonce': 'cd'*32, 'binding': 'binding', 'request': {'verb': verb},
            'expires': time.monotonic() + 10}
        framed = _ReplyWriter(endpoint, writer, request, reader)
        self.assertIs(framed.get_extra_info('socket'), writer.get_extra_info('socket'))
        framed.write(canonical_bytes({'ok': ok, 'result': {'stopping': ok}}) + b'\n')
        await asyncio.wait_for(remote_reader.readline(), 1)
        return framed, remote_writer

    async def test_successful_shutdown_waits_for_original_connection_eof(self):
        framed, remote = await self.streams()
        task = asyncio.create_task(framed.drain())
        try:
            await asyncio.sleep(.02)
            self.assertFalse(task.done())
            remote.close()
            await remote.wait_closed()
            await asyncio.wait_for(task, 1)
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_unexpected_client_data_refuses_release(self):
        framed, remote = await self.streams()
        remote.write(b'x')
        await remote.drain()
        with self.assertRaises(CoreSetupRequired):
            await asyncio.wait_for(framed.drain(), 1)

    async def test_denied_shutdown_and_other_verbs_do_not_wait_for_eof(self):
        for verb, ok in (('shutdown', False), ('ping', True)):
            with self.subTest(verb=verb, ok=ok):
                framed, remote = await self.streams(verb=verb, ok=ok)
                await asyncio.wait_for(framed.drain(), 1)
                self.assertFalse(remote.is_closing())

    async def test_cancellation_joins_original_eof_wait(self):
        framed, remote = await self.streams()
        task = asyncio.create_task(framed.drain())
        try:
            await asyncio.sleep(.02)
            self.assertFalse(task.done())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.assertTrue(task.done())
        self.assertFalse(remote.is_closing())
