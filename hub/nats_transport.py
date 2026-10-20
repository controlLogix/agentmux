"""Shared paired NATS transport; callers own trust, admission and lifetime.

Importing this module does not import nats-py or open a connection. It preserves
one reader/protocol pairing through TLS upgrade and exact transport cleanup.
"""
from __future__ import annotations

import asyncio
from contextvars import ContextVar
import json
import hashlib
import hmac
import re
import ssl


class PairedTCPTransport:
    """Keep Python's paired reader/protocol through the pinned TLS upgrade.

    nats-py 2.16 creates a new protocol during upgrade. After a rejected TLS
    handshake its old writer's close waiter can never finish. The standard
    stream upgrade keeps the protocol that owns that waiter's actual transport.
    Other transport operations stay with the pinned NATS implementation.
    """

    def __init__(self, transport, require_tls, leaf_certificate_sha256=None):
        self.transport = transport
        self.require_tls = require_tls
        self.leaf_certificate_sha256 = leaf_certificate_sha256
        self.tls_established = False
        self.prior_writer = None
        self.prior_close_task = None
        self.current_close_writer = None
        self.current_close_task = None
        self.failed_tls_writer = self.failed_tls_error = None
        self.failed_tls_protocol = self.failed_tls_transport = None
        self.failed_read = None
        self.tls_binding = None
        self.reader_binding = None
        self._bind_reader()

    def _bind_reader(self):
        writer = self.transport._io_writer
        if isinstance(writer, asyncio.StreamWriter):
            reader, protocol = writer._reader, writer._protocol
            if isinstance(reader, asyncio.StreamReader) and protocol._stream_reader is reader:
                self.reader_binding = (writer, reader, protocol, writer.transport)

    def __bool__(self):
        return bool(self.transport)

    def __getattr__(self, name):
        return getattr(self.transport, name)

    async def connect(self, *args, **kwargs):
        # The pinned reconnect loop can retry after rejected INFO without
        # closing that attempt. Join its exact writer before replacing it.
        writer = self.transport._io_writer
        if writer is not None:
            if writer is not self.prior_writer:
                self.prior_writer = writer
                writer.close()
                if writer is self.current_close_writer and self.current_close_task is not None:
                    self.prior_close_task = self.current_close_task
                else:
                    self.prior_close_task = asyncio.create_task(self._wait_writer_closed(writer))
            await asyncio.shield(self.prior_close_task)
        self.current_close_writer = None
        self.current_close_task = None
        self.tls_binding = None
        self.tls_established = False
        result = await self.transport.connect(*args, **kwargs)
        self._bind_reader()
        return result

    async def wait_closed(self):
        if self.current_close_task is None:
            self.current_close_writer = self.transport._io_writer
            wait = (self._wait_writer_closed(self.current_close_writer) if self.current_close_writer is not None
                    else self.transport.wait_closed())
            self.current_close_task = asyncio.create_task(wait)
        # The pinned client swallows transport exceptions. Retain both exact
        # attempts so its public close can observe the same result again.
        tasks = list(dict.fromkeys(task for task in
                     (self.prior_close_task, self.current_close_task) if task is not None))
        results = await asyncio.gather(*(asyncio.shield(task) for task in tasks), return_exceptions=True)
        errors = [result for result in results if isinstance(result, BaseException)]
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise BaseExceptionGroup("owned transport cleanup causes", errors)

    async def _wait_writer_closed(self, writer):
        try:
            await writer.wait_closed()
        except OSError as error:
            # Python reports an original handshake/read error through the paired
            # protocol's close future too. Accept only that exact error after
            # connection_lost cleared the protocol and closed its original
            # selector socket. A separate close failure remains a failure.
            from asyncio.selector_events import _SelectorSocketTransport
            operations = [(self.failed_tls_writer, self.failed_tls_protocol,
                           self.failed_tls_transport, self.failed_tls_error)]
            if self.failed_read is not None:
                operations.append(self.failed_read)
            # A broker can send -ERR and reset before another read is issued.
            # Python still records that exact network failure on the paired
            # reader and close future through connection_lost.
            if self.reader_binding is not None:
                owner, reader, protocol, transport = self.reader_binding
                if (owner.transport is transport and owner._reader is reader
                        and reader._exception is error):
                    operations.append((owner, protocol, transport, error))
            if self.tls_binding is not None:
                owner, reader, protocol, application, tls_protocol, transport = self.tls_binding
                read_error = (self.failed_read is not None
                              and self.failed_read[0] is owner and self.failed_read[1] is protocol
                              and self.failed_read[2] is application and self.failed_read[3] is error)
                reader_error = owner._reader is reader and reader._exception is error
                # SSLProtocol.connection_lost clears these exact links before
                # the application protocol completes its paired close future.
                if (owner.transport is application and (read_error or reader_error)
                        and tls_protocol._transport is None and tls_protocol._app_protocol is None
                        and tls_protocol._app_transport is None):
                    operations.append((owner, protocol, transport, error))
            for owner, protocol, transport, operation_error in operations:
                if (writer is owner and error is operation_error
                        and isinstance(writer, asyncio.StreamWriter)
                        and isinstance(protocol, asyncio.StreamReaderProtocol)
                        and writer._protocol is protocol
                        and isinstance(transport, _SelectorSocketTransport)
                        and transport._sock is None and protocol._transport is None
                        and protocol._closed.done() and not protocol._closed.cancelled()
                        and protocol._closed.exception() is error):
                    return
            raise

    async def read(self, buffer_size):
        writer = self.transport._io_writer
        try:
            return await self.transport.read(buffer_size)
        except OSError as error:
            self.failed_read = (writer, writer._protocol, writer.transport, error)
            raise

    async def readline(self):
        line = await self.transport.readline()
        if self.require_tls and not self.tls_established:
            try:
                info = json.loads(line.removeprefix(b"INFO ").strip())
            except (ValueError, UnicodeDecodeError):
                info = None
            if not line.startswith(b"INFO ") or not isinstance(info, dict) or info.get("tls_required") is not True:
                raise ssl.SSLError("NATS requires TLS before authentication")
        return line

    async def connect_tls(self, uri, ssl_context, buffer_size, connect_timeout):
        hostname = uri if isinstance(uri, str) else uri.hostname
        if self.leaf_certificate_sha256 is not None and (
                ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname):
            raise ssl.SSLError('NATS peer pin requires verified TLS')
        writer = self.transport._io_writer
        protocol, transport = writer._protocol, writer.transport
        try:
            await asyncio.wait_for(writer.start_tls(
                ssl_context, server_hostname=hostname, ssl_handshake_timeout=connect_timeout), connect_timeout)
        except ssl.SSLError as error:
            self.failed_tls_writer, self.failed_tls_error = writer, error
            self.failed_tls_protocol, self.failed_tls_transport = protocol, transport
            raise
        from asyncio.selector_events import _SelectorSocketTransport
        from asyncio.sslproto import _SSLProtocolTransport, SSLProtocol
        application = writer.transport
        tls_protocol = application._ssl_protocol if isinstance(application, _SSLProtocolTransport) else None
        reader = writer._reader
        # Capture the complete live pairing before TLS connection_lost clears
        # it. Later cleanup cannot reconstruct ownership from a closed flag.
        if (isinstance(transport, _SelectorSocketTransport) and isinstance(tls_protocol, SSLProtocol)
                and isinstance(reader, asyncio.StreamReader) and protocol._stream_reader is reader
                and tls_protocol._transport is transport and transport._protocol is tls_protocol
                and tls_protocol._app_protocol is protocol and tls_protocol._app_transport is application):
            self.tls_binding = (writer, reader, protocol, application, tls_protocol, transport)
        # Returning from this method lets nats-py construct and send CONNECT,
        # including authentication. Check the enrolled pin before returning.
        if self.leaf_certificate_sha256 is not None:
            peer = writer.get_extra_info('ssl_object')
            certificate = None if peer is None else peer.getpeercert(binary_form=True)
            if (type(certificate) is not bytes or not certificate
                    or not hmac.compare_digest('sha256:' + hashlib.sha256(certificate).hexdigest(),
                                               self.leaf_certificate_sha256)):
                raise ssl.SSLError('NATS peer certificate pin mismatch')
        self.tls_established = True


_subscription_owner = ContextVar("nats_subscription_owner", default=None)

def _new_client(nats, require_tls, leaf_certificate_sha256=None):
    # Keep the dependency lazy and retain this client's transport/subscriptions.
    from nats.aio.transport import TcpTransport

    class PairedClient(nats.NATS):
        async def subscribe_owned(self, owner, *args, **kwargs):
            """Bind early subscription ownership to this task and connection."""
            token = _subscription_owner.set((self, owner, asyncio.current_task()))
            try:
                return await self.subscribe(*args, **kwargs)
            finally:
                _subscription_owner.reset(token)

        async def _process_pong(self):
            # The pinned client's flush timeout/cancellation leaves its future
            # queued. Consume its own reply without completing a later flush.
            if self._pongs:
                future = self._pongs.pop(0)
                if not future.done():
                    future.set_result(True)
                self._pongs_received += 1
                self._pings_outstanding = 0

        async def _send_subscribe(self, subscription):
            # Subscribe creates the local callback before awaiting this send.
            # Its connection-session owner must retain it even if that send
            # fails or the requesting coroutine is cancelled.
            allocation = _subscription_owner.get()
            # Callback tasks inherit context variables. Their later requests
            # belong to the connection, not the receiver's setup operation.
            owner = (allocation[1] if allocation is not None and allocation[0] is self
                     and allocation[2] is asyncio.current_task()
                     else getattr(self, "_agentmux_session", None))
            if owner is not None:
                owner.own_subscription(subscription)
                owner.check_open()
            return await super()._send_subscribe(subscription)

        async def close(self):
            # Allocation can be cancelled before connect initializes its flusher.
            # With no transport allocated, let the pinned close run its normal
            # lifecycle instead of failing its uninitialized-queue assertion.
            if self._flush_queue is None and self._transport is None:
                self._flush_queue = asyncio.Queue()
            await super().close()
            # Rejoin the same current and prior attempts, including failures
            # swallowed by the pinned client's internal close/reconnect paths.
            if isinstance(self._transport, PairedTCPTransport):
                await self._transport.wait_closed()

        async def _connect_to_server(self, server):
            if leaf_certificate_sha256 is not None and server.uri.scheme not in ('nats', 'tls'):
                raise ssl.SSLError('NATS peer pin requires the paired TCP transport')
            if require_tls and server.uri.scheme == "ws":
                raise ssl.SSLError("NATS requires TLS before authentication")
            await super()._connect_to_server(server)
            if type(self._transport) is TcpTransport:
                self._transport = PairedTCPTransport(self._transport, require_tls, leaf_certificate_sha256)

    return PairedClient()


def new_client(*, require_tls=True, leaf_certificate_sha256=None):
    """Allocate one unconnected paired client, with TLS required by default.

    This factory admits no credentials or endpoints. The caller supplies its
    separately checked TLS/authentication options and retains the client through
    connect, cancellation, reconnect policy and joined close. Session owners can
    use the existing _agentmux_session subscription allocation hook. An optional
    enrolled SHA-256 leaf pin is checked after verified TLS and before CONNECT;
    it is not a substitute for the caller's trusted CA and hostname policy.
    """
    if (type(require_tls) is not bool or (leaf_certificate_sha256 is not None
            and (require_tls is not True or type(leaf_certificate_sha256) is not str
                 or not re.fullmatch(r'sha256:[a-f0-9]{64}', leaf_certificate_sha256)))):
        raise ValueError('nats_tls_policy_invalid')
    import nats
    return _new_client(nats, require_tls, leaf_certificate_sha256)
