"""Shared paired-client factory compatibility without opening a connection."""
import asyncio
import hashlib
import ssl
from types import SimpleNamespace
from urllib.parse import urlsplit
import unittest
from unittest.mock import AsyncMock, Mock

from hub import nats_transport
from hub.fed import conn


class SharedTransport(unittest.IsolatedAsyncioTestCase):
    async def test_receiver_callback_does_not_own_shared_reply_subscription(self):
        from hub.fed.session import FederationSession
        from nats.aio.msg import Msg
        client = nats_transport.new_client()
        receiver, connection = FederationSession(), FederationSession()
        client._agentmux_session = connection
        client._status = client.CONNECTED
        client._flush_queue = asyncio.Queue()
        client._send_command = AsyncMock()
        client._flush_pending = AsyncMock()
        reply_ready = asyncio.get_running_loop().create_future()

        async def receive(message):
            reply_ready.set_result(await client.subscribe('_INBOX.shared'))

        try:
            subscription = await client.subscribe_owned(receiver, 'service.command', cb=receive)
            await subscription._pending_queue.put(Msg(_client=client, subject='service.command', data=b''))
            reply = await asyncio.wait_for(reply_ready, 1)
            await receiver.close()
            self.assertNotIn(subscription._id, client._subs)
            self.assertIn(reply._id, client._subs)
            await connection.close()
            self.assertNotIn(reply._id, client._subs)
        finally:
            await receiver.close()
            await connection.close()
            await client.close()

    async def _assert_late_pong_preserves_reader(self, *, cancel):
        from nats.errors import FlushTimeoutError
        client = nats_transport.new_client()
        incoming, processed = asyncio.Queue(), asyncio.Queue()
        ping = asyncio.Event()
        async def read(size):
            return await incoming.get()
        raw = SimpleNamespace(_io_writer=None, write=Mock(side_effect=lambda data: ping.set()),
            read=AsyncMock(side_effect=read), at_eof=lambda: False,
            close=Mock(), wait_closed=AsyncMock())
        client._transport = nats_transport.PairedTCPTransport(raw, True)
        client._status = client.CONNECTED
        client._flush_pending = AsyncMock()
        client._flusher_task = asyncio.create_task(asyncio.Event().wait())
        original_pong = client._process_pong
        async def observed_pong():
            try:
                return await original_pong()
            finally:
                processed.put_nowait(None)
        client._process_pong = observed_pong
        reader = client._reading_task = asyncio.create_task(client._read_loop())
        first = asyncio.create_task(client.flush(timeout=1 if cancel else .01))
        second = None
        try:
            await asyncio.wait_for(ping.wait(), 1)
            abandoned = client._pongs[0]
            if cancel:
                first.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await first
            else:
                with self.assertRaises(FlushTimeoutError):
                    await first
            self.assertTrue(abandoned.cancelled())
            ping.clear()
            second = asyncio.create_task(client.flush(timeout=1))
            await asyncio.wait_for(ping.wait(), 1)
            pending = client._pongs[1]
            client._pings_outstanding = 2

            # A delayed reply belongs to the canceled flush, not the next one.
            incoming.put_nowait(b'PONG\r\n')
            await asyncio.wait_for(processed.get(), 1)
            self.assertFalse(reader.done())
            self.assertEqual(client._pongs, [pending])
            self.assertFalse(pending.done())
            self.assertFalse(second.done())
            self.assertEqual(client._pongs_received, 1)
            self.assertEqual(client._pings_outstanding, 0)

            incoming.put_nowait(b'PONG\r\n')
            await asyncio.wait_for(processed.get(), 1)
            await second
            self.assertTrue(pending.result())
            self.assertEqual(client._pongs, [])
            self.assertEqual(client._pongs_received, 2)
            self.assertFalse(reader.done())
            incoming.put_nowait(b'PONG\r\n')
            await asyncio.wait_for(processed.get(), 1)
            self.assertEqual(client._pongs_received, 2)
            self.assertFalse(reader.done())
        finally:
            calls = [call for call in (first, second) if call is not None]
            for call in calls:
                if not call.done():
                    call.cancel()
            await asyncio.gather(*calls, return_exceptions=True)
            await client.close()
            await asyncio.gather(reader, client._flusher_task, return_exceptions=True)
            self.assertTrue(reader.done())
            self.assertTrue(client._flusher_task.done())

    async def test_cancelled_flush_late_pong_preserves_original_reader_and_next_flush(self):
        await self._assert_late_pong_preserves_reader(cancel=True)

    async def test_timed_out_flush_late_pong_preserves_original_reader_and_next_flush(self):
        await self._assert_late_pong_preserves_reader(cancel=False)

    async def test_public_factory_requires_tls_before_any_websocket_authentication(self):
        client = nats_transport.new_client()
        try:
            with self.assertRaises(ssl.SSLError):
                await client._connect_to_server(SimpleNamespace(uri=urlsplit('ws://127.0.0.1:4222')))
            self.assertIsNone(client._transport)
            self.assertIs(conn._PairedTCPTransport, nats_transport.PairedTCPTransport)
        finally:
            await client.close()
            self.assertTrue(client.is_closed)

    async def test_actual_client_allocates_subscription_to_its_owner_before_failed_send(self):
        client = nats_transport.new_client()
        owned = []
        client._status = client.CONNECTED
        client._send_command = AsyncMock(side_effect=OSError('private test send failure'))
        client._flush_pending = AsyncMock()
        client._error_cb = AsyncMock()
        client._agentmux_session = SimpleNamespace(own_subscription=owned.append, check_open=lambda: None)
        try:
            with self.assertRaises(OSError):
                await client.subscribe('_INBOX.abcdefghijklmnop.reply')
            self.assertEqual(len(owned), 1)
            self.assertIs(client._subs[owned[0]._id], owned[0])
            self.assertEqual(owned[0].subject, '_INBOX.abcdefghijklmnop.reply')
        finally:
            client._send_command.side_effect = None
            await client.close()

    async def test_leaf_pin_is_checked_before_actual_nats_connect_authentication(self):
        # Control TLS completion at the writer boundary. The real pinned NATS
        # method must not build or send CONNECT until the fixed pin check returns.
        certificate = b'controlled DER peer leaf bytes'
        matching = 'sha256:' + hashlib.sha256(certificate).hexdigest()
        for pin in ('sha256:' + '0' * 64, matching):
            with self.subTest(matches=pin == matching):
                client = nats_transport.new_client(leaf_certificate_sha256=pin)
                peer = SimpleNamespace(getpeercert=lambda **kwargs: certificate)
                writer = SimpleNamespace(_reader=None, _protocol=SimpleNamespace(), transport=object(),
                    start_tls=AsyncMock(), get_extra_info=lambda name: peer,
                    wait_closed=AsyncMock(), close=Mock())
                raw = SimpleNamespace(_io_writer=writer, drain=AsyncMock(), write=Mock(), close=Mock(),
                    readline=AsyncMock(side_effect=[b'INFO {"tls_required":true,"auth_required":true}\r\n',
                                                   b'PONG\r\n']))
                transport = nats_transport.PairedTCPTransport(raw, True, pin)
                client._transport = transport
                client._current_server = SimpleNamespace(uri=urlsplit('tls://127.0.0.1:4222'), tls_name=None)
                token = Mock(return_value='PRIVATE_TEST_AUTH_TOKEN')
                client.options.update(tls=ssl.create_default_context(), tls_hostname='broker.example',
                    tls_handshake_first=False, connect_timeout=1, verbose=False, pedantic=False,
                    user=None, password=None, token=token, name='controlled-pin', no_echo=True)
                client._flush_queue = asyncio.Queue()
                client._error_cb = AsyncMock()
                client._read_loop = AsyncMock()
                client._ping_interval = AsyncMock()
                client._flusher = AsyncMock()
                try:
                    if pin != matching:
                        with self.assertRaises(ssl.SSLError):
                            await client._process_connect_init()
                        self.assertFalse(transport.tls_established)
                        token.assert_not_called()
                        raw.write.assert_not_called()
                    else:
                        await client._process_connect_init()
                        self.assertTrue(transport.tls_established)
                        token.assert_called_once_with()
                        connect = raw.write.call_args_list[0].args[0]
                        self.assertTrue(connect.startswith(b'CONNECT '))
                        self.assertIn(b'PRIVATE_TEST_AUTH_TOKEN', connect)
                    writer.start_tls.assert_awaited_once()
                finally:
                    await client.close()

    async def test_pin_cannot_select_insecure_tls_or_an_unchecked_websocket_path(self):
        pin = 'sha256:' + '1' * 64
        with self.assertRaises(ValueError):
            nats_transport.new_client(require_tls=False, leaf_certificate_sha256=pin)
        client = nats_transport.new_client(leaf_certificate_sha256=pin)
        try:
            with self.assertRaises(ssl.SSLError):
                await client._connect_to_server(SimpleNamespace(uri=urlsplit('wss://127.0.0.1:4222')))
            self.assertIsNone(client._transport)
            writer = SimpleNamespace(start_tls=AsyncMock())
            transport = nats_transport.PairedTCPTransport(SimpleNamespace(_io_writer=writer), True, pin)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with self.assertRaises(ssl.SSLError):
                await transport.connect_tls('broker.example', context, 65536, 1)
            writer.start_tls.assert_not_awaited()
        finally:
            await client.close()
