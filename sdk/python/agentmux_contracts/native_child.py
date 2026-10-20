"""Pinned, single-owner native child connections. No discovery or reconnect.

The host supplies the bootstrap path. This client authenticates the selected
brokers and keeps exact subjects; it does not authenticate business operations.
"""
import asyncio
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import ssl
import stat
from types import MappingProxyType
from urllib.parse import urlsplit

from nacl.signing import SigningKey
from .wire import ContractError, strict_loads
from .validation import validate, DEFAULT_SCHEMA_DIR
from pathlib import Path


def _fail():
    raise ContractError("native_child_invalid")


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


def _plain(value):
    if isinstance(value, (dict, MappingProxyType)):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    return value


def _private_file(path):
    if type(path) is not str or not os.path.isabs(path) or os.path.normpath(path) != path or path.startswith("//"):
        _fail()
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    leaf = None
    try:
        parts = path.split("/")[1:]
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        parent = os.fstat(current)
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            _fail()
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        before = os.fstat(leaf)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 1048576:
            _fail()
        raw = os.read(leaf, 1048577)
        after = os.fstat(leaf)
        if len(raw) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            _fail()
        return raw
    finally:
        if leaf is not None:
            os.close(leaf)
        os.close(current)


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _trust(url, name, leaf):
    if type(url) is not str or type(name) is not str or type(leaf) is not str:
        _fail()
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        _fail()
    if (parsed.scheme != "tls" or parsed.hostname != "127.0.0.1" or not port
            or url != f"tls://127.0.0.1:{port}" or not re.fullmatch(r"sha256:[0-9a-f]{64}", leaf)
            or len(name) > 253 or not name or re.fullmatch(r"[0-9.]+", name)
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in name.split("."))):
        _fail()
    return port


def _deadline(value):
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)", value):
        _fail()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail()


def _credentials(raw):
    text = raw.decode("ascii")
    jwt = re.findall(r"-----BEGIN NATS USER JWT-----\s+([A-Za-z0-9_.-]+)\s+------END NATS USER JWT------", text)
    seeds = re.findall(r"-----BEGIN USER NKEY SEED-----\s+([A-Z2-7]+)\s+------END USER NKEY SEED------", text)
    if len(jwt) != 1 or len(seeds) != 1:
        _fail()
    encoded = seeds[0]
    decoded = base64.b32decode(encoded + "=" * (-len(encoded) % 8))
    if (len(decoded) != 36 or decoded[0] & 248 != 144 or ((decoded[0] & 7) << 5 | decoded[1] >> 3) != 160
            or int.from_bytes(decoded[-2:], "little") != binascii.crc_hqx(decoded[:-2], 0)):
        _fail()
    return jwt[0], SigningKey(decoded[2:34])


@dataclass(frozen=True, repr=False)
class NativeChildBootstrap:
    """Private snapshots. Formatting never displays paths, credentials or values."""
    _document: object
    _configuration: bytes
    _descriptor: object
    _resources: object
    _schema_dir: object

    def __repr__(self):
        return "<NativeChildBootstrap private>"

    @property
    def configuration(self):
        return self._configuration

    @property
    def context(self):
        return self._descriptor


def load_native_bootstrap(path, *, schema_dir=None):
    """Read exact Go bootstrap frames; the new child path requires both pins."""
    try:
        schema_dir = Path(schema_dir or DEFAULT_SCHEMA_DIR).resolve()
        document = strict_loads(_private_file(path))
        required = {"schemaVersion", "serverURL", "caFile", "credentialsFile", "configurationFile", "controlSubject", "eventSubject", "prepare", "serverName", "leafCertificateSha256"}
        if type(document) is not dict or set(document) not in (required, required | {"context"}):
            _fail()
        prepare = document["prepare"]
        validate("ordinary-plugin-lifecycle", prepare, **({"schema_dir": schema_dir} if schema_dir else {}))
        if prepare["kind"] != "ordinary-plugin-control" or prepare["action"] != "prepare" or document["schemaVersion"] != prepare["schemaVersion"]:
            _fail()
        _deadline(prepare["deadline"])
        _trust(document["serverURL"], document["serverName"], document["leafCertificateSha256"])
        control = document["controlSubject"]
        instance = prepare["owner"]["instanceId"]
        if not re.fullmatch(r"amx\.v1\.h\.[a-z][a-z0-9_-]{0,95}\.plugins\." + re.escape(instance) + r"\.lifecycle\.control", control) or document["eventSubject"] != control[:-7] + "event":
            _fail()
        configuration = _private_file(document["configurationFile"])
        if _digest(configuration) != prepare["configurationChecksum"]:
            _fail()
        descriptor = None
        if "context" in document:
            context = document["context"]
            if set(context) != {"contextFile", "credentialsFile", "caFile", "transport"}:
                _fail()
            transport = context["transport"]
            if set(transport) != {"schemaVersion", "serverURL", "serverName", "leafCertificateSha256", "requestSubject", "replySubject", "invokeSubject", "resultSubject", "cancelSubject"} or transport["schemaVersion"] != "1.0.0":
                _fail()
            _trust(transport["serverURL"], transport["serverName"], transport["leafCertificateSha256"])
            prefix = control[:-len("lifecycle.control")]
            for key, suffix in (("requestSubject", "context.request"), ("replySubject", "context.reply"), ("invokeSubject", "operation.invoke"), ("resultSubject", "operation.result"), ("cancelSubject", "operation.cancel")):
                if transport[key] != prefix + suffix:
                    _fail()
            raw = _private_file(context["contextFile"])
            if _digest(raw) != prepare.get("contextChecksum"):
                _fail()
            descriptor = strict_loads(raw)
            validate("plugin-context", descriptor, **({"schema_dir": schema_dir} if schema_dir else {}))
            if descriptor["instanceId"] != instance or descriptor["hubId"] != control.split(".")[3] or any(descriptor[key] != prepare["owner"]["pin"][pin] for key, pin in (("packageId", "packageId"), ("packageVersion", "version"), ("packageDigest", "packageChecksum"))):
                _fail()
        elif prepare["schemaVersion"] == "1.2.0":
            _fail()
        resources = {path: _private_file(path) for path in (document["caFile"], document["credentialsFile"])}
        if "context" in document:
            context = document["context"]
            resources.update({path: _private_file(path) for path in (context["caFile"], context["credentialsFile"])})
        return NativeChildBootstrap(_freeze(document), configuration, _freeze(descriptor), _freeze(resources), schema_dir)
    except (ContractError, OSError, ValueError, KeyError, TypeError, UnicodeError):
        raise ContractError("native_child_invalid") from None


class _Connection:
    def __repr__(self):
        return "<NativeChildConnection private>"

    def __init__(self, reader, writer, publish, subscribe):
        self.reader, self.writer = reader, writer
        self.publish_subjects = frozenset(publish)
        self.queues = {subject: asyncio.Queue(64) for subject in subscribe}
        self.sids = {str(index): subject for index, subject in enumerate(subscribe, 1)}
        self.closed = asyncio.Event()
        self.pong = asyncio.Event()
        self.flush_lock = asyncio.Lock()
        self.task = None
        self._close_task = None
        self._abort_on_close = False

    async def _read(self):
        try:
            while True:
                line = await self.reader.readuntil(b"\r\n")
                if len(line) > 65536:
                    _fail()
                if line == b"PING\r\n":
                    self.writer.write(b"PONG\r\n")
                    await self.writer.drain()
                elif line == b"PONG\r\n":
                    self.pong.set()
                elif line.startswith(b"MSG "):
                    fields = line[:-2].decode("ascii").split(" ")
                    if len(fields) != 4 or fields[2] not in self.sids or fields[1] != self.sids[fields[2]] or not fields[3].isdigit() or int(fields[3]) > 1048576:
                        _fail()
                    raw = await self.reader.readexactly(int(fields[3]) + 2)
                    if raw[-2:] != b"\r\n":
                        _fail()
                    self.queues[fields[1]].put_nowait(raw[:-2])
                elif not line.startswith((b"+OK", b"INFO ")):
                    _fail()
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            self.closed.set()
            self.writer.close()

    async def flush(self):
        async with self.flush_lock:
            self.pong.clear()
            self.writer.write(b"PING\r\n")
            await self.writer.drain()
            pong = asyncio.create_task(self.pong.wait())
            closed = asyncio.create_task(self.closed.wait())
            try:
                await asyncio.wait_for(asyncio.wait((pong, closed), return_when=asyncio.FIRST_COMPLETED), 2)
                if self.closed.is_set() or not self.pong.is_set():
                    _fail()
            finally:
                pong.cancel(); closed.cancel()
                await asyncio.gather(pong, closed, return_exceptions=True)

    async def publish(self, subject, raw):
        if subject not in self.publish_subjects or type(raw) is not bytes or len(raw) > 1048576 or self.closed.is_set():
            _fail()
        self.writer.write(f"PUB {subject} {len(raw)}\r\n".encode() + raw + b"\r\n")
        await self.writer.drain()

    async def receive(self, subject):
        if subject not in self.queues or self.closed.is_set():
            _fail()
        item = asyncio.create_task(self.queues[subject].get())
        closed = asyncio.create_task(self.closed.wait())
        try:
            await asyncio.wait((item, closed), return_when=asyncio.FIRST_COMPLETED)
            if self.closed.is_set():
                _fail()
            return item.result()
        finally:
            item.cancel(); closed.cancel()
            await asyncio.gather(item, closed, return_exceptions=True)

    async def close(self):
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close_original())
        await asyncio.shield(self._close_task)

    async def _close_original(self):
        self.closed.set()
        if self._abort_on_close:
            self.writer.transport.abort()
        else:
            self.writer.close()
        if self.task is not None:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        await self.writer.wait_closed()


async def _connect(transport, roots_raw, credentials_raw, publish, subscribe):
    port = _trust(transport["serverURL"], transport["serverName"], transport["leafCertificateSha256"])
    roots = roots_raw.decode("ascii")
    if roots.count("-----BEGIN CERTIFICATE-----") != 1:
        _fail()
    config = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    config.minimum_version = ssl.TLSVersion.TLSv1_3
    config.load_verify_locations(cadata=roots)
    jwt, key = _credentials(credentials_raw)
    writer = None
    connection = None
    try:
        async with asyncio.timeout(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=config, server_hostname=transport["serverName"], ssl_handshake_timeout=2, ssl_shutdown_timeout=2, limit=65536)
            connection = _Connection(reader, writer, publish, subscribe)
            peer = writer.get_extra_info("ssl_object")
            if peer.version() != "TLSv1.3" or _digest(peer.getpeercert(binary_form=True)) != transport["leafCertificateSha256"]:
                _fail()
            info = await reader.readuntil(b"\r\n")
            if not info.startswith(b"INFO "):
                _fail()
            nonce = strict_loads(info[5:-2]).get("nonce")
            if type(nonce) is not str or not nonce or len(nonce) > 1024:
                _fail()
            signature = base64.urlsafe_b64encode(key.sign(nonce.encode()).signature).rstrip(b"=").decode()
            auth = json.dumps({"jwt": jwt, "sig": signature, "verbose": False, "pedantic": True, "echo": False, "protocol": 1}).encode()
            writer.write(b"CONNECT " + auth + b"\r\n")
            for sid, subject in connection.sids.items():
                writer.write(f"SUB {subject} {sid}\r\n".encode())
            connection.task = asyncio.create_task(connection._read())
            await connection.flush()
            return connection
    except BaseException as error:
        if connection is not None:
            connection._abort_on_close = connection.task is None
            try:
                await connection.close()
            except BaseException:
                raise NativeChildCleanupError(connection) from None
        elif writer is not None:
            writer.close()
            await writer.wait_closed()
        if isinstance(error, asyncio.CancelledError):
            raise
        raise ContractError("native_child_connection_failed") from None


class NativeChildCleanupError(ContractError):
    """The retained owner must be closed again before cleanup is complete."""
    def __init__(self, owner):
        super().__init__("native_child_cleanup_failed")
        self.owner = owner


class NativeChild:
    """Owns both original connections until close joins them.

    Receive controls and context messages explicitly. Report readiness only after
    the plugin's own preparation completes; this class never grants authority.
    """
    def __repr__(self):
        return "<NativeChild private>"

    def __init__(self, bootstrap):
        if type(bootstrap) is not NativeChildBootstrap:
            _fail()
        self.bootstrap = bootstrap
        self.lifecycle = self.context_connection = None
        self._prepared = False
        self._control = _plain(bootstrap._document["prepare"])
        self._opening = None
        self._pending_cleanup = []
        self._closing = False
        self._seen_commands = {bootstrap._document["prepare"]["commandId"]}
        self._stopping = False

    async def connect(self):
        if self.lifecycle is not None or self._opening is not None or self._closing:
            _fail()
        self._opening = asyncio.current_task()
        d = self.bootstrap._document
        try:
            self.lifecycle = await _connect(d, self.bootstrap._resources[d["caFile"]], self.bootstrap._resources[d["credentialsFile"]], [d["eventSubject"]], [d["controlSubject"]])
            if "context" in d:
                c = d["context"]; t = c["transport"]
                self.context_connection = await _connect(t, self.bootstrap._resources[c["caFile"]], self.bootstrap._resources[c["credentialsFile"]], [t["requestSubject"], t["resultSubject"]], [t["replySubject"], t["invokeSubject"], t["cancelSubject"]])
            await self.report("registered")
            return self
        except NativeChildCleanupError as error:
            self._pending_cleanup.append(error.owner)
            await self._close_connections(include_pending=False)
            raise NativeChildCleanupError(self) from None
        except asyncio.CancelledError:
            await self._close_connections()
            raise
        except Exception:
            await self._close_connections()
            raise ContractError("native_child_connection_failed") from None
        finally:
            self._opening = None

    async def next_control(self):
        raw = await self.lifecycle.receive(self.bootstrap._document["controlSubject"])
        control = strict_loads(raw)
        validate("ordinary-plugin-lifecycle", control, schema_dir=self.bootstrap._schema_dir)
        expected = _plain(self.bootstrap._document["prepare"])
        if self._stopping and control.get("action") != "stop":
            _fail()
        if control.get("action") == "stop":
            if control["commandId"] in self._seen_commands or len(self._seen_commands) >= 64:
                _fail()
            expected["action"] = "stop"
            expected["deadline"] = control["deadline"]
            expected["commandId"] = control["commandId"]
        if control != expected or _deadline(control["deadline"]) < datetime.now(timezone.utc):
            _fail()
        if control["action"] == "prepare":
            self._prepared = True
        if control["action"] == "stop":
            self._seen_commands.add(control["commandId"])
            self._stopping = True
        self._control = control
        return _freeze(control)

    async def report(self, status):
        if (status not in ("registered", "ready", "failed", "stopped")
                or (status == "ready" and (not self._prepared or self._control["action"] != "prepare"))
                or (status == "stopped" and self._control["action"] != "stop")):
            _fail()
        report = dict(self._control)
        del report["action"]; del report["deadline"]
        report.update(kind="ordinary-plugin-report", status=status, observedAt=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        await self.lifecycle.publish(self.bootstrap._document["eventSubject"], json.dumps(report).encode())
        await self.lifecycle.flush()

    async def close(self):
        self._closing = True
        opening = self._opening
        if opening is not None and opening is not asyncio.current_task():
            opening.cancel()
            await asyncio.shield(asyncio.gather(opening, return_exceptions=True))
        await self._close_connections()

    async def _close_connections(self, *, include_pending=True):
        # Keep references after failed cleanup so the original owner can retry.
        errors = []
        for connection in (self.context_connection, self.lifecycle, *(self._pending_cleanup if include_pending else ())):
            if connection is not None:
                try:
                    await connection.close()
                except BaseException as error:
                    errors.append(error)
        if errors:
            raise NativeChildCleanupError(self) from None
