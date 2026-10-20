"""Initial federation connection budgets and exact failed-client ownership."""
from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import socket
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from hub.fed import conn


class ConnectionOwnership(unittest.IsolatedAsyncioTestCase):
    async def test_established_reconnect_policy_and_callbacks_are_unchanged(self):
        class Client:
            closes = 0

            async def connect(self, **options):
                self.options = options

            async def close(self):
                self.closes += 1

        async def supplied_error(error):
            pass

        async def supplied_closed():
            pass

        client = Client()
        with patch.object(conn, "nats_mod", return_value=SimpleNamespace()), patch.object(conn, "_new_client", return_value=client), patch.object(conn, "INITIAL_CONNECT_TIMEOUT", 0.02):
            received = await conn.connect("nats://fixture", None, None, "fixture", reconnect=True,
                                          error_cb=supplied_error, closed_cb=supplied_closed)
        self.assertIs(received, client)
        self.assertIs(client.options["error_cb"], supplied_error)
        self.assertIs(client.options["closed_cb"], supplied_closed)
        self.assertTrue(client.options["allow_reconnect"])
        self.assertEqual(client.options["max_reconnect_attempts"], -1)
        await asyncio.sleep(0.03)
        self.assertEqual(client.closes, 0)
        await received.close()

    async def test_tls_localhost_override_uses_only_the_exact_parsed_host(self):
        class Client:
            async def connect(self, **options):
                self.options = options

            async def close(self):
                pass

        context = object()
        for url, expected in [
            ("tls://127.0.0.1:4222", "localhost"),
            ("tls://localhost:4222", "localhost"),
            ("tls://localhost.example:4222", None),
            ("tls://127.0.0.1.example:4222", None),
            ("tls://localhost@example.invalid:4222", None),
            ("tls://example.invalid:4222/localhost", None),
            ("tls://127.0.0.1@example.invalid:4222", None),
        ]:
            with self.subTest(url=url):
                client = Client()
                with patch.object(conn, "nats_mod", return_value=SimpleNamespace()), patch.object(conn, "_new_client", return_value=client), patch.object(conn, "tls_context", return_value=context):
                    await conn.connect(url, None, "fixture-ca", "fixture")
                self.assertIs(client.options["tls"], context)
                self.assertEqual(client.options.get("tls_hostname"), expected)

    async def test_initial_deadline_includes_local_tls_admission_time(self):
        factory = unittest.mock.Mock()

        def slow_tls(ca):
            time.sleep(0.03)
            return object()

        with patch.object(conn, "nats_mod", return_value=SimpleNamespace(NATS=factory)), patch.object(conn, "tls_context", side_effect=slow_tls), patch.object(conn, "INITIAL_CONNECT_TIMEOUT", 0.02):
            with self.assertRaises(conn.InitialConnectTimeout):
                await conn.connect("tls://127.0.0.1:4222", None, "fixture-ca", "fixture")
        factory.assert_not_called()

    async def test_late_synchronous_connect_completion_is_not_accepted(self):
        class Client:
            closes = 0

            async def connect(self, **options):
                time.sleep(0.03)

            async def close(self):
                self.closes += 1

        client = Client()
        with patch.object(conn, "nats_mod", return_value=SimpleNamespace()), patch.object(conn, "_new_client", return_value=client), patch.object(conn, "INITIAL_CONNECT_TIMEOUT", 0.02):
            with self.assertRaises(conn.InitialConnectTimeout):
                await conn.connect("nats://fixture", None, None, "fixture")
        self.assertEqual(client.closes, 1)

    async def test_initial_timeout_closes_the_owned_client(self):
        class Client:
            closes = 0

            async def connect(self, **options):
                self.options = options
                await asyncio.Future()

            async def close(self):
                self.closes += 1

        for reconnect in (False, True):
            with self.subTest(reconnect=reconnect):
                client = Client()
                with patch.object(conn, "nats_mod", return_value=SimpleNamespace()), patch.object(conn, "_new_client", return_value=client), patch.object(conn, "INITIAL_CONNECT_TIMEOUT", 0.02):
                    with self.assertRaises(conn.InitialConnectTimeout):
                        await conn.connect("nats://fixture", None, None, "fixture", reconnect=reconnect)
                self.assertEqual(client.closes, 1)
                self.assertIs(client.options["error_cb"], conn._quiet_error)
                self.assertEqual(client.options["max_reconnect_attempts"], -1 if reconnect else 1)

    async def test_consumed_close_failure_keeps_exact_client_without_false_retry_success(self):
        original = ValueError("private initial failure")

        class Client:
            closes = 0

            async def connect(self, **options):
                raise original

            async def close(self):
                self.closes += 1
                if self.closes == 1:
                    raise OSError("private close failure")

            def __repr__(self):
                return "private credential-bearing client"

        client = Client()
        with patch.object(conn, "nats_mod", return_value=SimpleNamespace()), patch.object(conn, "_new_client", return_value=client):
            with self.assertRaises(conn.ConnectionCleanupFailure) as caught:
                await conn.connect("nats://fixture", None, None, "fixture")
        owned = caught.exception
        self.assertIs(owned.client, client)
        self.assertIs(owned.operation_error, original)
        self.assertIs(owned.__cause__.exceptions[0], original)
        self.assertNotIn("private", str(owned))
        self.assertNotIn("private", repr(owned))
        with self.assertRaises(conn.ConnectionCleanupFailure) as retried:
            await owned.retry_close()
        self.assertIs(retried.exception, owned)
        self.assertEqual(client.closes, 1)

    async def test_close_timeout_keeps_the_same_pending_cleanup_attempt(self):
        original = asyncio.CancelledError("initial cancellation")
        finished = asyncio.Event()

        class Client:
            closes = 0

            async def connect(self, **options):
                raise original

            async def close(self):
                self.closes += 1
                await finished.wait()

        client = Client()
        with patch.object(conn, "nats_mod", return_value=SimpleNamespace()), patch.object(conn, "_new_client", return_value=client), patch.object(conn, "FAILED_CONNECT_CLOSE_TIMEOUT", 0.02):
            with self.assertRaises(conn.ConnectionCleanupFailure) as caught:
                await conn.connect("nats://fixture", None, None, "fixture")
        owned = caught.exception
        self.assertIs(owned.operation_error, original)
        self.assertFalse(owned.close_task.done())
        finished.set()
        await owned.retry_close()
        self.assertEqual(client.closes, 1)

    async def test_cancellation_during_cleanup_keeps_initial_and_cleanup_causes(self):
        original = OSError("initial failure")
        began, finished = asyncio.Event(), asyncio.Event()

        class Client:
            async def connect(self, **options):
                raise original

            async def close(self):
                began.set()
                await finished.wait()

        client = Client()
        with patch.object(conn, "nats_mod", return_value=SimpleNamespace()), patch.object(conn, "_new_client", return_value=client):
            owner = asyncio.create_task(conn.connect("nats://fixture", None, None, "fixture"))
            await began.wait()
            owner.cancel()
            with self.assertRaises(conn.ConnectionCleanupFailure) as caught:
                await owner
        owned = caught.exception
        self.assertIs(owned.operation_error, original)
        self.assertIsInstance(owned.cleanup_errors[0], asyncio.CancelledError)
        self.assertFalse(owned.close_task.cancelled())
        finished.set()
        await owned.retry_close()


class RuntimeConnectionOwnership(unittest.IsolatedAsyncioTestCase):
    def runtime(self):
        from hub.fed.runtime import Federation
        runtime = Federation.__new__(Federation)
        runtime.connection_cleanup = None
        runtime.cfg = {"federation": {"url": "nats://fixture", "peer": "fixture"}}
        runtime.node = "fixture"
        runtime.log = lambda *args: None
        return runtime

    async def test_runtime_does_not_reconnect_until_exact_cleanup_completes(self):
        from unittest.mock import AsyncMock
        finished = asyncio.Event()

        async def close():
            await finished.wait()

        owned = conn.ConnectionCleanupFailure(SimpleNamespace(close=close), OSError("initial failure"))
        runtime = self.runtime()
        connected = object()
        with patch.object(conn, "connect", AsyncMock(side_effect=[owned, connected])) as connect:
            with self.assertRaises(conn.ConnectionCleanupFailure):
                await runtime._connect_owned()
            self.assertIs(runtime.connection_cleanup, owned)
            with patch.object(conn, "FAILED_CONNECT_CLOSE_TIMEOUT", 0.02):
                with self.assertRaises(conn.ConnectionCleanupFailure):
                    await runtime._connect_owned()
            self.assertEqual(connect.await_count, 1)
            self.assertIs(runtime.connection_cleanup, owned)
            finished.set()
            self.assertIs(await runtime._connect_owned(), connected)
            self.assertEqual(connect.await_count, 2)
            self.assertIsNone(runtime.connection_cleanup)

    async def test_runtime_cancellation_preserves_pending_cleanup_owner(self):
        from unittest.mock import AsyncMock
        began, finished = asyncio.Event(), asyncio.Event()

        async def close():
            began.set()
            await finished.wait()

        owned = conn.ConnectionCleanupFailure(SimpleNamespace(close=close), OSError("initial failure"))
        runtime = self.runtime()
        runtime.connection_cleanup = owned
        with patch.object(conn, "connect", AsyncMock()) as connect:
            operation = asyncio.create_task(runtime._connect_owned())
            await began.wait()
            operation.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await operation
            self.assertIs(runtime.connection_cleanup, owned)
            self.assertFalse(owned.close_task.cancelled())
            connect.assert_not_awaited()
        finished.set()
        await owned.retry_close()

    async def test_runtime_retains_failed_initial_client_when_connect_was_cancelled(self):
        from unittest.mock import AsyncMock
        finished = asyncio.Event()

        async def close():
            await finished.wait()

        original = asyncio.CancelledError("initial cancellation")
        owned = conn.ConnectionCleanupFailure(SimpleNamespace(close=close), original)
        runtime = self.runtime()
        with patch.object(conn, "connect", AsyncMock(side_effect=owned)):
            with self.assertRaises(asyncio.CancelledError) as caught:
                await runtime._connect_owned()
        self.assertIs(caught.exception, original)
        self.assertIs(runtime.connection_cleanup, owned)
        finished.set()
        await owned.retry_close()


@unittest.skipUnless(importlib.util.find_spec("nats"), "needs pinned nats-py")
class LiveInitialConnection(unittest.IsolatedAsyncioTestCase):
    async def test_current_writer_failure_survives_actual_client_and_public_close(self):
        import nats
        from unittest.mock import AsyncMock

        import ssl
        for mode in ("os-error", "separate-tls-error", "cancelled"):
            with self.subTest(mode=mode):
                cancelled = mode == "cancelled"
                failure = (ssl.SSLCertVerificationError("private independent TLS close failure")
                           if mode == "separate-tls-error" else OSError("private current writer close failure"))
                calls = []

                async def failed_close():
                    calls.append("wait")
                    if cancelled:
                        raise asyncio.CancelledError()
                    raise failure

                writer = SimpleNamespace(close=lambda: None, wait_closed=failed_close)
                adapter = conn._PairedTCPTransport(SimpleNamespace(_io_writer=writer, close=writer.close), False)
                adapter.failed_tls_writer = writer
                adapter.failed_tls_error = ssl.SSLCertVerificationError("private original TLS handshake failure")
                client = conn._new_client(nats, False)
                client._transport = adapter
                client._flush_queue = asyncio.Queue()
                reported = []

                async def error_cb(error):
                    reported.append(error)

                client._error_cb = error_cb
                runtime = RuntimeConnectionOwnership.runtime(self)
                runtime.nc, runtime.js = client, object()
                await runtime._close_session_owned()
                owned = runtime.connection_cleanup
                self.assertIsInstance(owned, conn.ConnectionCleanupFailure)
                self.assertIs(owned.client, client)
                self.assertIs(adapter.current_close_writer, writer)
                self.assertTrue(adapter.current_close_task.done())
                if cancelled:
                    self.assertIsInstance(owned.cleanup_errors[0], asyncio.CancelledError)
                    self.assertTrue(adapter.current_close_task.cancelled())
                else:
                    # The actual pinned NATS.close swallowed and reported it;
                    # the paired client must still fail with that exact cause.
                    self.assertEqual(reported, [failure])
                    self.assertIs(owned.cleanup_errors[0], failure)
                with self.assertRaises(conn.ConnectionCleanupFailure) as repeated:
                    await conn.close(client)
                self.assertIs(repeated.exception, owned)
                with self.assertRaises(conn.ConnectionCleanupFailure):
                    await owned.retry_close()
                with patch.object(conn, "connect", AsyncMock()) as connect:
                    with self.assertRaises(conn.ConnectionCleanupFailure):
                        await runtime._connect_owned()
                    connect.assert_not_awaited()
                self.assertEqual(calls, ["wait"])

    async def test_current_writer_timeout_rejoins_same_actual_close_attempt(self):
        import nats

        finished = asyncio.Event()
        calls = []

        async def wait_closed():
            calls.append("wait")
            await finished.wait()

        writer = SimpleNamespace(close=lambda: None, wait_closed=wait_closed)
        adapter = conn._PairedTCPTransport(SimpleNamespace(_io_writer=writer, close=writer.close), False)
        client = conn._new_client(nats, False)
        client._transport = adapter
        client._flush_queue = asyncio.Queue()
        client._error_cb = conn._quiet_error
        with patch.object(conn, "FAILED_CONNECT_CLOSE_TIMEOUT", 0.02):
            with self.assertRaises(conn.ConnectionCleanupFailure) as caught:
                await conn.close(client)
        owned = caught.exception
        self.assertIs(owned.client, client)
        task = adapter.current_close_task
        self.assertFalse(task.done())
        finished.set()
        await owned.retry_close()
        await conn.close(client)
        self.assertIs(adapter.current_close_task, task)
        self.assertEqual(calls, ["wait"])

    async def test_consumed_prior_writer_failure_is_retained_by_actual_client_close(self):
        import nats
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                failure = OSError("private prior writer close failure")

                async def failed_close():
                    if cancelled:
                        raise asyncio.CancelledError()
                    raise failure

                async def empty_close_wait():
                    pass

                transport = SimpleNamespace(_io_writer=None, close=lambda: None, wait_closed=empty_close_wait)
                adapter = conn._PairedTCPTransport(transport, False)
                adapter.prior_close_task = asyncio.create_task(failed_close())
                await asyncio.sleep(0)
                client = conn._new_client(nats, False)
                client._transport = adapter
                client._flush_queue = asyncio.Queue()
                client._error_cb = conn._quiet_error
                original = ValueError("private initial failure")
                with self.assertRaises(conn.ConnectionCleanupFailure) as caught:
                    await conn._close_failed_connection(client, original)
                owned = caught.exception
                self.assertIs(owned.client, client)
                self.assertIs(owned.operation_error, original)
                if cancelled:
                    self.assertIsInstance(owned.cleanup_errors[0], asyncio.CancelledError)
                else:
                    self.assertIs(owned.cleanup_errors[0], failure)
                with self.assertRaises(conn.ConnectionCleanupFailure) as retried:
                    await owned.retry_close()
                self.assertIs(retried.exception, owned)

    async def test_public_close_and_runtime_finally_retain_actual_failed_client(self):
        import nats
        from unittest.mock import AsyncMock

        failure = OSError("private consumed writer failure")

        async def failed_close():
            raise failure

        async def empty_close_wait():
            pass

        adapter = conn._PairedTCPTransport(SimpleNamespace(_io_writer=None, close=lambda: None, wait_closed=empty_close_wait), False)
        adapter.prior_close_task = asyncio.create_task(failed_close())
        await asyncio.sleep(0)
        client = conn._new_client(nats, False)
        client._transport = adapter
        client._flush_queue = asyncio.Queue()
        client._error_cb = conn._quiet_error
        runtime = RuntimeConnectionOwnership.runtime(self)
        runtime.nc, runtime.js = client, object()
        await runtime._close_session_owned()
        owned = runtime.connection_cleanup
        self.assertIsInstance(owned, conn.ConnectionCleanupFailure)
        self.assertIs(owned.client, client)
        self.assertIs(owned.cleanup_errors[0], failure)
        self.assertIs(client._agentmux_close_owner, owned)
        first_close = owned.close_task
        with self.assertRaises(conn.ConnectionCleanupFailure) as repeated:
            await conn.close(client)
        self.assertIs(repeated.exception, owned)
        self.assertIs(owned.close_task, first_close)
        self.assertIsNone(runtime.nc)
        self.assertIsNone(runtime.js)
        with patch.object(conn, "connect", AsyncMock()) as connect:
            with self.assertRaises(conn.ConnectionCleanupFailure):
                await runtime._connect_owned()
            connect.assert_not_awaited()
        self.assertIs(runtime.connection_cleanup, owned)

    async def test_absent_endpoint_is_bounded_and_default_errors_are_quiet(self):
        import nats.errors
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        output = io.StringIO()
        started = time.monotonic()
        with contextlib.redirect_stderr(output):
            with self.assertRaises((nats.errors.NoServersError, conn.InitialConnectTimeout)):
                await asyncio.wait_for(conn.connect(f"nats://127.0.0.1:{port}", None, None, "absent-endpoint"), 6)
        self.assertLess(time.monotonic() - started, 5.5)
        self.assertEqual(output.getvalue(), "")

    async def test_established_tcp_reset_reconnects_and_joins_closed_transport(self):
        await self.established_reset()

    async def test_established_tls_reset_reconnects_and_joins_closed_transport(self):
        import ssl
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path

        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("needs the prepared certificate tool")
        with tempfile.TemporaryDirectory(prefix="agentmux-reset-tls-") as directory:
            cert, key = Path(directory) / "server.pem", Path(directory) / "server.key"
            subprocess.run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt",
                            "ec_paramgen_curve:P-256", "-days", "1", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-subj", "/CN=localhost", "-addext",
                            "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            key.chmod(0o600)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            await self.established_reset(context, str(cert))

    async def established_reset(self, server_tls=None, ca=None):
        import json
        import struct

        reset, reconnected = asyncio.Event(), asyncio.Event()
        handlers, writers, handshakes = [], [], []

        async def peer(reader, writer):
            handlers.append(asyncio.current_task())
            writers.append(writer)
            first = len(writers) == 1
            try:
                info = {"server_id": "owned-reset-peer", "version": "2.15.0", "proto": 1,
                        "auth_required": False, "tls_required": server_tls is not None, "max_payload": 1048576}
                writer.write(b"INFO " + json.dumps(info).encode() + b"\r\n")
                await writer.drain()
                if server_tls is not None:
                    await writer.start_tls(server_tls, ssl_handshake_timeout=2)
                connected = False
                while line := await reader.readline():
                    if line.startswith(b"CONNECT "):
                        connected = True
                    elif line == b"PING\r\n":
                        self.assertTrue(connected)
                        writer.write(b"PONG\r\n")
                        await writer.drain()
                        if first:
                            handshakes.append("first")
                            await reset.wait()
                            writer.get_extra_info("socket").setsockopt(
                                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                            writer.transport.abort()
                            return
                        handshakes.append("replacement")
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        client = None
        cleanup_error = None

        async def on_reconnected():
            reconnected.set()

        try:
            port = server.sockets[0].getsockname()[1]
            scheme = "tls" if server_tls is not None else "nats"
            client = await conn.connect(f"{scheme}://127.0.0.1:{port}", None, ca, "owned-reset",
                                        reconnect=True, reconnected_cb=on_reconnected)
            original_writer = client._transport.transport._io_writer
            original_transport = original_writer.transport
            original_socket_transport = (original_transport._ssl_protocol._transport
                                         if server_tls is not None else original_transport)
            original_tls_binding = client._transport.tls_binding
            if server_tls is not None:
                self.assertIs(original_tls_binding[0], original_writer)
                self.assertIs(original_tls_binding[3], original_transport)
                self.assertIs(original_tls_binding[5], original_socket_transport)
            self.assertEqual(handshakes, ["first"])
            reset.set()
            await asyncio.wait_for(reconnected.wait(), 7)
            await asyncio.wait_for(client.flush(timeout=1), 2)
            self.assertTrue(client.is_connected)
            self.assertEqual(len(writers), 2)
            self.assertIn("replacement", handshakes)
            self.assertIsNot(client._transport.transport._io_writer, original_writer)
            self.assertTrue(original_writer._protocol._closed.done())
            self.assertIsNone(original_writer._protocol._transport)
            self.assertIsNone(original_socket_transport._sock)
            adapter = client._transport
            self.assertTrue(adapter.prior_close_task.done())
            self.assertIsNone(adapter.prior_close_task.exception())
            if server_tls is not None:
                original_tls_protocol = original_tls_binding[4]
                self.assertIsNone(original_tls_protocol._transport)
                self.assertIsNone(original_tls_protocol._app_protocol)
                self.assertIsNone(original_tls_protocol._app_transport)
            failed_read = adapter.failed_read
            self.assertIs(failed_read[0], original_writer)
            self.assertIsInstance(failed_read[3], ConnectionResetError)
            self.assertIs(original_writer._protocol._closed.exception(), failed_read[3])
            current_tls_binding = adapter.tls_binding
            adapter.tls_binding = original_tls_binding
            await adapter._wait_writer_closed(original_writer)
            adapter.failed_read = (*failed_read[:3], ConnectionResetError("a separate network failure"))
            reader_error = original_writer._reader._exception
            original_writer._reader._exception = ConnectionResetError("a separate paired reader failure")
            try:
                with self.assertRaises(ConnectionResetError) as separate:
                    await adapter._wait_writer_closed(original_writer)
                self.assertIs(separate.exception, failed_read[3])
            finally:
                adapter.failed_read = failed_read
                original_writer._reader._exception = reader_error
                adapter.tls_binding = current_tls_binding
        finally:
            reset.set()
            try:
                if client is not None:
                    try:
                        await conn.close(client)
                    except conn.ConnectionCleanupFailure as error:
                        # Keep a failed owner available; never replace it with
                        # a second close or abandon a still-pending attempt.
                        self.connection_cleanup = cleanup_error = error
                        if not error.close_task.done():
                            await error.retry_close()
            finally:
                server.close()
                await server.wait_closed()
                for writer in writers:
                    writer.close()
                if handlers:
                    await asyncio.wait_for(asyncio.gather(*handlers), 2)
            if cleanup_error is not None:
                raise cleanup_error

    async def stalled_peer(self):
        accepted, eof = asyncio.Event(), asyncio.Event()
        handlers, writers = [], []

        async def peer(reader, writer):
            handlers.append(asyncio.current_task())
            writers.append(writer)
            accepted.set()
            try:
                await reader.read()
                eof.set()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)

        async def cleanup():
            server.close()
            await server.wait_closed()
            for writer in writers:
                writer.close()
            if handlers:
                await asyncio.wait_for(asyncio.gather(*handlers), 1)

        self.addAsyncCleanup(cleanup)
        port = server.sockets[0].getsockname()[1]
        return f"nats://127.0.0.1:{port}", accepted, eof

    async def test_cancelled_partial_handshake_closes_actual_transport(self):
        url, accepted, eof = await self.stalled_peer()
        connection = asyncio.create_task(conn.connect(url, None, None, "cancelled-handshake"))
        await asyncio.wait_for(accepted.wait(), 1)
        connection.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await connection
        await asyncio.wait_for(eof.wait(), 1)

    async def test_initial_handshake_total_deadline_closes_actual_transport(self):
        url, accepted, eof = await self.stalled_peer()
        started = time.monotonic()
        with self.assertRaises(conn.InitialConnectTimeout):
            await asyncio.wait_for(conn.connect(url, None, None, "stalled-handshake"), 6)
        self.assertTrue(accepted.is_set())
        self.assertLess(time.monotonic() - started, 5.5)
        await asyncio.wait_for(eof.wait(), 1)

    async def test_plaintext_info_cannot_induce_authentication_when_tls_is_requested(self):
        import json
        import ssl

        for scheme, with_ca, flag in [("tls", False, False), ("tls", False, None), ("nats", True, False)]:
            with self.subTest(scheme=scheme, ca=with_ca, tls_required=flag):
                received, handlers, writers = [], [], []
                finished = asyncio.Event()

                async def peer(reader, writer):
                    handlers.append(asyncio.current_task())
                    writers.append(writer)
                    info = {"server_id": "synthetic-peer", "auth_required": True, "version": "2.15.0", "max_payload": 1048576}
                    if flag is not None:
                        info["tls_required"] = flag
                    writer.write(b"INFO " + json.dumps(info).encode() + b"\r\n")
                    await writer.drain()
                    try:
                        received.append(await reader.read())
                        finished.set()
                    finally:
                        writer.close()
                        await writer.wait_closed()

                server = await asyncio.start_server(peer, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                endpoint = f"{scheme}://synthetic-user:synthetic-password@127.0.0.1:{port}"
                try:
                    context = ssl.create_default_context() if with_ca else None
                    with patch.object(conn, "tls_context", return_value=context):
                        with self.assertRaises(ssl.SSLError):
                            await asyncio.wait_for(conn.connect(endpoint, None, "requested-ca" if with_ca else None, "false-tls-info"), 2)
                    await asyncio.wait_for(finished.wait(), 1)
                    self.assertEqual(received, [b""])
                finally:
                    server.close()
                    await server.wait_closed()
                    for writer in writers:
                        writer.close()
                    if handlers:
                        await asyncio.wait_for(asyncio.gather(*handlers), 1)

    async def test_real_tls_wrong_ca_closes_the_paired_native_transport(self):
        import json
        import os
        from pathlib import Path
        import shutil
        import ssl
        import subprocess
        import tempfile

        binary = os.environ.get("NATS_SERVER") or shutil.which("nats-server")
        openssl = shutil.which("openssl")
        if not binary or not openssl:
            self.skipTest("needs native NATS and the prepared certificate tool")
        with tempfile.TemporaryDirectory(prefix="agentmux-conn-tls-") as directory:
            root = Path(directory)
            for name in ("server", "wrong"):
                subprocess.run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                                "-days", "1", "-nodes", "-keyout", str(root / (name + ".key")),
                                "-out", str(root / (name + ".pem")), "-subj", "/CN=localhost",
                                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                (root / (name + ".key")).chmod(0o600)
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1", 0))
                port = reserved.getsockname()[1]
            config = root / "nats.json"
            config.write_text(json.dumps({"listen": f"127.0.0.1:{port}", "tls": {
                "cert_file": str(root / "server.pem"), "key_file": str(root / "server.key"), "timeout": 1}}))
            process = subprocess.Popen([binary, "-c", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 3
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            self.fail("owned native TLS broker did not start")
                        await asyncio.sleep(0.01)
                endpoint = f"tls://127.0.0.1:{port}"
                accepted = await conn.connect(endpoint, None, str(root / "server.pem"), "trusted-ca")
                await asyncio.wait_for(accepted.close(), 2)
                failed_clients = []
                failed_operations = []
                original_close = conn._close_failed_connection

                async def record_close(client, operation_error):
                    failed_clients.append(client)
                    failed_operations.append(operation_error)
                    await original_close(client, operation_error)

                with patch.object(conn, "_close_failed_connection", record_close):
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        await asyncio.wait_for(conn.connect(endpoint, None, str(root / "wrong.pem"), "wrong-ca"), 3)
                self.assertEqual(len(failed_clients), 1)
                self.assertTrue(failed_clients[0].is_closed)
                adapter = failed_clients[0]._transport
                self.assertIs(adapter.failed_tls_error, failed_operations[0])
                self.assertIs(adapter.failed_tls_protocol._closed.exception(), failed_operations[0])
                self.assertIsNone(adapter.failed_tls_protocol._transport)
                self.assertIsNone(adapter.failed_tls_transport._sock)
                self.assertTrue(adapter.current_close_task.done())
                self.assertIsNone(adapter.current_close_task.exception())
                original_tls_error = adapter.failed_tls_error
                adapter.failed_tls_error = ssl.SSLCertVerificationError("a separate TLS operation failure")
                reader_error = adapter.failed_tls_writer._reader._exception
                adapter.failed_tls_writer._reader._exception = ssl.SSLCertVerificationError(
                    "a separate paired reader failure")
                try:
                    with self.assertRaises(ssl.SSLCertVerificationError) as separate:
                        await adapter._wait_writer_closed(adapter.failed_tls_writer)
                    self.assertIs(separate.exception, original_tls_error)
                finally:
                    adapter.failed_tls_error = original_tls_error
                    adapter.failed_tls_writer._reader._exception = reader_error
                await conn.close(failed_clients[0])
                reconnecting = await conn.connect(endpoint, None, str(root / "server.pem"), "reconnect-tls", reconnect=True)
                process.terminate()
                process.wait(timeout=5)
                received, handlers, writers = [], [], []
                refused = asyncio.Event()

                async def plaintext_peer(reader, writer):
                    handlers.append(asyncio.current_task())
                    writers.append(writer)
                    writer.write(b'INFO {"server_id":"synthetic-peer","auth_required":true,"tls_required":false}\r\n')
                    await writer.drain()
                    captured = bytearray()
                    try:
                        while chunk := await reader.read(4096):
                            captured.extend(chunk)
                    except ConnectionResetError:
                        pass
                    finally:
                        received.append(bytes(captured))
                        refused.set()
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except ConnectionResetError:
                            pass

                malicious = await asyncio.start_server(plaintext_peer, "127.0.0.1", port)
                try:
                    await asyncio.wait_for(refused.wait(), 5)
                    self.assertTrue(received)
                    self.assertTrue(all(data == b"" for data in received))
                finally:
                    await asyncio.wait_for(reconnecting.close(), 3)
                    malicious.close()
                    await malicious.wait_closed()
                    for writer in writers:
                        writer.close()
                    if handlers:
                        await asyncio.wait_for(asyncio.gather(*handlers), 1)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
