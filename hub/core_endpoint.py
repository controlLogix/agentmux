"""Bind selected core requests to one admitted local Hub lifetime.

The endpoint key authenticates routing, not the caller. Hub.handle_conn still
classifies the real socket peer and applies the original domain permissions.
"""
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import time
from contextvars import ContextVar
from dataclasses import dataclass

from agentmux_contracts import canonical_bytes, strict_loads
from hub.core_profile import CoreRoute, CoreSetupRequired, PrivateFile, digest

# Streaming and configuration administration are outside this explicit MVP route.
CORE_VERBS = frozenset(('ping', 'status', 'whoami', 'agents', 'events', 'resolve',
    'spawn', 'kill', 'adopt', 'inbox', 'ack', 'post', 'claim', 'heartbeat', 'release',
    'claim_path', 'work_add', 'work_show', 'work_list', 'work_cancel', 'shutdown'))


@dataclass(frozen=True)
class SelectedCoreRequest:
    endpoint: object
    repository: str
    root: str
    task: object
    expires_monotonic: float | None = None


selected_core_request = ContextVar('selected_core_request', default=None)


def _mac(key, value):
    return hmac.new(bytes.fromhex(key), canonical_bytes(value), hashlib.sha256).hexdigest()


def _peer(sock):
    if hasattr(socket, 'SO_PEERCRED'):
        pid, uid, _ = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        return pid, uid
    pid = struct.unpack('i', sock.getsockopt(0, 2, 4))[0]
    _, uid = struct.unpack('2I', sock.getsockopt(0, socket.LOCAL_PEERCRED, 76)[:8])
    return pid, uid


def _socket_identity(path):
    info = os.lstat(path)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise CoreSetupRequired()
    return [info.st_dev, info.st_ino]


def _request(route, repository, request):
    if (repository not in route.binding['repositories'] or type(request) is not dict
            or set(request) - {'verb', 'args', 'as', 'operationId'} or request.get('verb') not in CORE_VERBS
            or type(request.get('args', {})) is not dict):
        raise CoreSetupRequired()
    name = route.binding['repositories'][repository]
    args = request.get('args', {})
    if 'repo' in args and args['repo'] not in (None, name):
        raise CoreSetupRequired()
    if 'cwd' in args and args['cwd'] is not None:
        cwd = os.path.realpath(args['cwd'])
        if os.path.commonpath((repository, cwd)) != repository:
            raise CoreSetupRequired()
    return request


class CoreConnection:
    def __init__(self, route):
        if type(route) is not CoreRoute:
            raise CoreSetupRequired()
        self.route, self.record = route, None
        self.record = PrivateFile(str(Path(route.home)/'hub'/'selected-endpoint.json'))
        try:
            self.value = strict_loads(self.record.raw)
            value = self.value
            if (type(value) is not dict or set(value) != {'version', 'binding', 'source', 'pid', 'socket', 'key'}
                    or value['version'] != 1 or value['binding'] != route.binding
                    or type(value['pid']) is not int or value['pid'] <= 1
                    or type(value['key']) is not str or len(value['key']) != 64
                    or len(bytes.fromhex(value['key'])) != 32
                    or value['socket'] != _socket_identity(route.socket)):
                raise CoreSetupRequired()
        except BaseException:
            self.close()
            raise

    def exchange(self, request, timeout):
        deadline = time.monotonic() + timeout
        self.route.check(); self.record.check()
        _request(self.route, self.route.repository, request)
        if _socket_identity(self.route.socket) != self.value['socket']:
            raise CoreSetupRequired()
        sock = socket.socket(socket.AF_UNIX)
        try:
            def remaining():
                value = deadline - time.monotonic()
                if value <= 0:
                    raise TimeoutError()
                sock.settimeout(value)
            remaining()
            sock.connect(self.route.socket)
            if (_peer(sock) != (self.value['pid'], os.getuid())
                    or _socket_identity(self.route.socket) != self.value['socket']):
                raise CoreSetupRequired()
            self.route.check(); self.record.check()
            payload = {'binding': digest(canonical_bytes(self.value)), 'nonce': secrets.token_hex(32),
                'expires': time.monotonic() + min(timeout, 10), 'repository': self.route.repository, 'request': request}
            remaining()
            sock.sendall(canonical_bytes({'core': payload, 'mac': _mac(self.value['key'], payload)}) + b'\n')
            result = bytearray()
            while not result.endswith(b'\n'):
                remaining()
                chunk = sock.recv(65536)
                if not chunk or len(result) + len(chunk) > 8 * 1024 * 1024:
                    raise CoreSetupRequired()
                result.extend(chunk)
            reply = strict_loads(bytes(result))
            body = reply.get('core') if type(reply) is dict else None
            if (type(body) is not dict or set(reply) != {'core', 'mac'}
                    or set(body) != {'nonce', 'binding', 'response'}
                    or body['nonce'] != payload['nonce'] or body['binding'] != payload['binding']
                    or type(reply['mac']) is not str or not hmac.compare_digest(reply['mac'], _mac(self.value['key'], body))):
                raise CoreSetupRequired()
            self.route.check(); self.record.check()
            return body['response']
        finally:
            sock.close()

    def close(self):
        if self.record is not None:
            self.record.close()


class _ReplyWriter:
    def __init__(self, endpoint, writer, request, reader):
        self.endpoint, self.writer, self.request = endpoint, writer, request
        self.reader, self.shutdown_reply = reader, False

    def get_extra_info(self, *args):
        return self.writer.get_extra_info(*args)

    def is_closing(self):
        return self.writer.is_closing()

    def write(self, raw):
        self.endpoint.check()
        if time.monotonic() >= self.request['expires']:
            raise CoreSetupRequired()
        response = strict_loads(raw)
        body = {'nonce': self.request['nonce'], 'binding': self.request['binding'],
            'response': response}
        self.shutdown_reply = (self.request['request'].get('verb') == 'shutdown'
            and response.get('ok') is True)
        self.writer.write(canonical_bytes({'core': body, 'mac': _mac(self.endpoint.value['key'], body)}) + b'\n')

    async def drain(self):
        await self.writer.drain()
        if self.shutdown_reply:
            # The client closes this exact socket after its final record checks.
            # EOF only releases teardown; it is not authorization or delivery proof.
            if await self.reader.read(1):
                raise CoreSetupRequired()

    def close(self):
        self.writer.close()

    async def wait_closed(self):
        await self.writer.wait_closed()


class CoreEndpoint:
    def __init__(self, route):
        if type(route) is not CoreRoute:
            raise CoreSetupRequired()
        self.route, self.record, self.hub = route, None, None
        self.path = str(Path(route.home)/'hub'/'selected-endpoint.json')
        self.tasks, self.nonces = set(), {}

    async def publish(self, hub):
        self.route.check()
        if hub._work_source_binding is None or hub._legacy_identity is None or hub._message_commands is None:
            raise CoreSetupRequired()
        # A worker may query shared infrastructure but may not start another owner.
        session, in_pane = await hub.db(hub.identify_qualified, os.getpid())
        if session is not None or in_pane:
            raise CoreSetupRequired()
        hub._work_source_binding.check()
        self.hub = hub
        self.value = {'version': 1, 'binding': self.route.binding,
            'source': hub._work_source_binding.pin.identity, 'pid': os.getpid(),
            'socket': _socket_identity(self.route.socket), 'key': secrets.token_hex(32)}
        if os.path.lexists(self.path):
            previous = PrivateFile(self.path)
            try:
                old = strict_loads(previous.raw)
                if old.get('binding') != self.route.binding or type(old.get('pid')) is not int or old['pid'] <= 1:
                    raise CoreSetupRequired()
                try:
                    os.kill(old['pid'], 0)
                except ProcessLookupError:
                    previous.check()
                    os.rename(self.path, self.path + '.retained-' + secrets.token_hex(12))
                else:
                    raise CoreSetupRequired()
            finally:
                previous.close()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = os.fstat(fd)
        try:
            raw = canonical_bytes(self.value)
            if os.write(fd, raw) != len(raw):
                raise CoreSetupRequired()
            os.fsync(fd)
            self.record = PrivateFile(self.path)
            self.check()
        except BaseException:
            try:
                current = os.lstat(self.path)
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(self.path)
            finally:
                if self.record is not None:
                    self.record.close()
                    self.record = None
            raise
        finally:
            os.close(fd)

    def check(self):
        self.route.check()
        if self.record is None or self.hub is None:
            raise CoreSetupRequired()
        self.record.check()
        self.hub._work_source_binding.check()
        if (self.hub._work_source_binding.pin.identity != self.value['source']
                or _socket_identity(self.route.socket) != self.value['socket']):
            raise CoreSetupRequired()

    async def serve(self, reader, writer):
        task = asyncio.current_task(); self.tasks.add(task)
        stage = 'initial-check'
        try:
            self.check()
            stage = 'read-envelope'
            raw = await asyncio.wait_for(reader.readline(), 10)
            stage = 'validate-envelope'
            envelope = strict_loads(raw)
            body = envelope.get('core') if type(envelope) is dict else None
            now = time.monotonic()
            if (type(body) is not dict or set(envelope) != {'core', 'mac'}
                    or set(body) != {'binding', 'nonce', 'expires', 'repository', 'request'}
                    or body['binding'] != digest(self.record.raw)
                    or type(body['nonce']) is not str or len(body['nonce']) != 64
                    or type(body['expires']) not in (int, float) or not now < body['expires'] <= now + 10
                    or type(envelope['mac']) is not str or not hmac.compare_digest(envelope['mac'], _mac(self.value['key'], body))
                    or _peer(writer.get_extra_info('socket'))[1] != os.getuid()):
                raise CoreSetupRequired()
            self.nonces = {nonce: expires for nonce, expires in self.nonces.items() if expires > now}
            if body['nonce'] in self.nonces or len(self.nonces) >= 8192:
                raise CoreSetupRequired()
            self.nonces[body['nonce']] = body['expires']
            stage = 'validate-request'
            request = _request(self.route, body['repository'], body['request'])
            # Adoption, native spawn and selected discovery verify the source before caller
            # authentication in handle_conn. Do not repeat that remote read.
            # Shutdown and native kill retain their required remote check in dispatch, after
            # caller authentication, within this original envelope.
            native_spawn = (request['verb'] == 'spawn'
                            and getattr(self.hub, '_native_core', None) is not None)
            native_kill = (request['verb'] == 'kill'
                           and getattr(self.hub, '_native_core', None) is not None)
            if request['verb'] not in ('adopt', 'ping', 'shutdown') and not (native_spawn or native_kill):
                stage = 'verify-source'
                await self.hub._work_source_binding.verify()
            stage = 'current-check'
            self.check()
            stage = 'envelope-deadline'
            if time.monotonic() >= body['expires']:
                raise CoreSetupRequired()
            # Only framing changes. The original socket supplies kernel caller identity.
            selected_reader = asyncio.StreamReader()
            selected_reader.feed_data(canonical_bytes(request) + b'\n')
            token = selected_core_request.set(SelectedCoreRequest(self,
                self.route.binding['repositories'][body['repository']], body['repository'], task,
                body['expires']))
            try:
                stage = 'handle-connection'
                await self.hub.handle_conn(selected_reader, _ReplyWriter(self, writer, body, reader))
            finally:
                selected_core_request.reset(token)
        except Exception as error:
            # Keep private refusal evidence closed: no request, claims, or
            # exception text. Logging must not change connection cleanup.
            try:
                from agentmux_contracts import ContractError
                from hub.client_launch_session import ApplicationSessionFailure
                from hub.server import log
                category = {
                    CoreSetupRequired: 'core-setup-required',
                    ContractError: 'contract-refused',
                    ApplicationSessionFailure: 'application-session-failure',
                    TimeoutError: 'timeout',
                    ValueError: 'invalid-value',
                    OSError: 'os-error',
                }.get(type(error), 'other')
                log('selected core refusal', json.dumps(
                    {'stage': stage, 'category': category}))
            except BaseException:
                pass
            writer.close()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            finally:
                self.tasks.discard(task)

    async def drain(self):
        while self.tasks:
            await asyncio.gather(*tuple(self.tasks), return_exceptions=True)

    def close(self):
        if self.record is not None:
            record, self.record = self.record, None
            try:
                record.check()
                os.unlink(self.path)
            finally:
                record.close()
