"""Controlled TLS-first NATS peer: real sockets, public test keys, no live broker."""
import asyncio
import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from agentmux_contracts import native_child as child_module

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, NativeChild, load_native_bootstrap

ROOT = Path(__file__).resolve().parents[3]


def write(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)
    return str(path)


class NativeChildSockets(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        openssl = shutil.which("openssl")
        if openssl is None:
            self.fail("prepared openssl required")
        def run(*args):
            subprocess.run([openssl, *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ca, cakey, leaf, key, csr = (self.root / name for name in ("ca.pem", "ca.key", "leaf.pem", "leaf.key", "leaf.csr"))
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cakey), "-out", str(ca), "-days", "1", "-subj", "/CN=Test CA")
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=child.agentmux.invalid")
        ext = self.root / "ext"
        ext.write_text("subjectAltName=DNS:child.agentmux.invalid\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
        run("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(cakey), "-CAcreateserial", "-out", str(leaf), "-days", "1", "-extfile", str(ext))
        ca.chmod(0o600)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(leaf, key)
        self.seed = bytes(range(32))
        encoded = bytes([149, 0]) + self.seed
        encoded += binascii.crc_hqx(encoded, 0).to_bytes(2, "little")
        nkey = base64.b32encode(encoded).rstrip(b"=").decode()
        creds = f"-----BEGIN NATS USER JWT-----\na.b.c\n------END NATS USER JWT------\n-----BEGIN USER NKEY SEED-----\n{nkey}\n------END USER NKEY SEED------\n".encode()
        self.credentials = write(self.root / "child.creds", creds)
        self.reports, self.subscriptions, self.auths, self.connections = [], [], [], set()
        self.handlers = set()
        self.errors = []
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        def exception_handler(_, context):
            if isinstance(context.get("exception"), ConnectionResetError) and getattr(self, "allow_tls_reset", False):
                return
            self.errors.append("asyncio:" + type(context.get("exception")).__name__)
        loop.set_exception_handler(exception_handler)
        self.addCleanup(loop.set_exception_handler, previous_handler)
        self.server = await asyncio.start_server(self.peer, "127.0.0.1", 0, ssl=tls)
        self.addAsyncCleanup(self.shutdown)
        port = self.server.sockets[0].getsockname()[1]
        digest = lambda raw: "sha256:" + hashlib.sha256(raw).hexdigest()
        pin = {key: digest(b"pin") for key in ("manifestChecksum", "packageChecksum", "provenanceChecksum")}
        pin.update(packageId="example", version="1.0.0")
        self.prepare = {"schemaVersion": "1.2.0", "kind": "ordinary-plugin-control", "action": "prepare", "commandId": "c" * 64, "owner": {"pin": pin, "instanceId": "child_one", "epoch": "a" * 64, "generation": 1}, "configurationChecksum": digest(b"{}"), "contributionsChecksum": digest(b"[]"), "deadline": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")}
        ref = {"id": "scope", "ownerHubId": "fixture", "revision": 1}
        issued = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        descriptor = {"schemaVersion": "1.0.0", "instanceId": "child_one", "packageId": "example", "packageVersion": "1.0.0", "packageDigest": pin["packageChecksum"], "hubId": "fixture", "parent": None, "effectiveGrant": {"grantId": "grant", "issuerHubId": "fixture", "subjectInstanceId": "child_one", "scope": {"organizationId": "org", "projectId": None, "workspaceId": None}, "actions": ["inspect"], "resourceIds": ["resource"], "issuedAt": issued, "expiresAt": expires, "policyRef": ref, "parentGrantRef": None, "revision": 1}, "services": {}, "secretReferences": [], "configurationRevision": 1, "profileContext": {"project": "Display project"}}
        for name in ("logger", "config", "lifecycle", "clock", "tracing", "metrics", "domainGateway"):
            descriptor["services"][name] = {"interfaceId": "plugin-domain-gateway" if name == "domainGateway" else "plugin-" + name, "apiMajor": 1, "scopeRef": ref, "handleId": "service_" + name.lower(), "transport": "nats"}
        raw = json.dumps(descriptor).encode()
        self.prepare["contextChecksum"] = digest(raw)
        self.prefix = "amx.v1.h.fixture.plugins.child_one."
        leafder = ssl.PEM_cert_to_DER_cert(leaf.read_text())
        trust = {"serverURL": f"tls://127.0.0.1:{port}", "serverName": "child.agentmux.invalid", "leafCertificateSha256": digest(leafder)}
        transport = {"schemaVersion": "1.0.0", **trust, **{key: self.prefix + value for key, value in {"requestSubject": "context.request", "replySubject": "context.reply", "invokeSubject": "operation.invoke", "resultSubject": "operation.result", "cancelSubject": "operation.cancel"}.items()}}
        self.document = {"schemaVersion": "1.2.0", **trust, "caFile": str(ca), "credentialsFile": self.credentials, "configurationFile": write(self.root / "config.json", b"{}"), "controlSubject": self.prefix + "lifecycle.control", "eventSubject": self.prefix + "lifecycle.event", "prepare": self.prepare, "context": {"contextFile": write(self.root / "context.json", raw), "caFile": str(ca), "credentialsFile": self.credentials, "transport": transport}}
        self.path = self.root / "bootstrap.json"
        self.save()

    def save(self):
        write(self.path, json.dumps(self.document).encode())

    async def peer(self, reader, writer):
        task = asyncio.current_task(); self.handlers.add(task); self.connections.add(writer)
        subscriptions = {}
        async def message(subject, value):
            raw = json.dumps(value).encode()
            writer.write(f"MSG {subject} {subscriptions[subject]} {len(raw)}\r\n".encode() + raw + b"\r\n")
            await writer.drain()
        try:
            writer.write(('INFO {"nonce":"' + ('' if getattr(self, "bad_nonce", False) else 'test-nonce') + '","max_payload":1048576}\r\n').encode()); await writer.drain()
            while line := await reader.readline():
                if line.startswith(b"CONNECT "):
                    auth = json.loads(line[8:]); self.auths.append(auth)
                    signature = base64.urlsafe_b64decode(auth["sig"] + "=" * (-len(auth["sig"]) % 4))
                    SigningKey(self.seed).verify_key.verify(b"test-nonce", signature)
                elif line.startswith(b"SUB "):
                    _, subject, sid = line.decode().strip().split(" "); subscriptions[subject] = sid; self.subscriptions.append(subject)
                elif line == b"PING\r\n":
                    writer.write(b"PONG\r\n"); await writer.drain()
                elif line.startswith(b"PUB "):
                    _, subject, size = line.decode().strip().split(" "); payload = await reader.readexactly(int(size) + 2); value = json.loads(payload[:-2])
                    if subject.endswith("lifecycle.event"):
                        self.reports.append(value)
                        if value["status"] == "registered":
                            await message(self.prefix + "lifecycle.control", self.prepare)
                        elif value["status"] == "ready":
                            stop = dict(self.prepare, action="stop", commandId="d" * 64, deadline=(datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"))
                            if getattr(self, "stop_variant", None) == "same":
                                stop["commandId"] = self.prepare["commandId"]
                            if getattr(self, "stop_variant", None) == "invalid-time":
                                stop["deadline"] = "not-a-valid-timestamp"
                            if getattr(self, "stop_variant", None) == "invalid-calendar":
                                stop["deadline"] = "2099-02-30T12:00:00Z"
                            await message(self.prefix + "lifecycle.control", stop)
                            if getattr(self, "stop_variant", None) == "replay":
                                await message(self.prefix + "lifecycle.control", stop)
                    elif subject.endswith("context.request"):
                        await message(self.prefix + "context.reply", {"received": value})
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as error:
            self.errors.append(type(error).__name__)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            self.connections.discard(writer); self.handlers.discard(task)

    async def shutdown(self):
        self.server.close()
        for writer in tuple(self.connections):
            writer.close()
        await asyncio.gather(*tuple(self.handlers), return_exceptions=True)
        await self.server.wait_closed()
        self.assertEqual(self.errors, [])

    async def test_real_lifecycle_context_and_join(self):
        bootstrap = load_native_bootstrap(str(self.path))
        self.assertEqual(bootstrap.context["profileContext"]["project"], "Display project")
        with self.assertRaises(TypeError):
            bootstrap.context["profileContext"]["project"] = "changed"
        child = NativeChild(bootstrap)
        try:
            await child.connect()
            self.assertEqual((await child.next_control())["action"], "prepare")
            await child.report("ready")
            self.assertEqual((await child.next_control())["action"], "stop")
            await child.report("stopped")
            self.assertEqual(self.reports[-1]["commandId"], "d" * 64)
            t = self.document["context"]["transport"]
            await child.context_connection.publish(t["requestSubject"], b'{"request":"fixture"}')
            self.assertEqual(json.loads(await child.context_connection.receive(t["replySubject"])), {"received": {"request": "fixture"}})
            waiting = asyncio.create_task(child.context_connection.receive(t["cancelSubject"]))
            await asyncio.sleep(0)
            await child.close()
            with self.assertRaises(ContractError):
                await waiting
            self.assertTrue(child.lifecycle.task.done())
            self.assertTrue(child.context_connection.task.done())
            self.assertEqual([r["status"] for r in self.reports], ["registered", "ready", "stopped"])
            self.assertEqual(len(self.auths), 2)
        finally:
            await child.close()

    async def test_wrong_lifecycle_pin_sends_no_credentials(self):
        self.allow_tls_reset = True
        self.document["leafCertificateSha256"] = "sha256:" + "0" * 64; self.save()
        child = NativeChild(load_native_bootstrap(str(self.path)))
        with self.assertRaises(ContractError):
            await child.connect()
        self.assertEqual(self.auths, [])
        await child.close()

    async def test_wrong_context_pin_never_reports_registered(self):
        self.allow_tls_reset = True
        self.document["context"]["transport"]["leafCertificateSha256"] = "sha256:" + "0" * 64; self.save()
        child = NativeChild(load_native_bootstrap(str(self.path)))
        with self.assertRaises(ContractError):
            await child.connect()
        self.assertEqual(len(self.auths), 1)
        self.assertEqual(self.reports, [])
        self.assertTrue(child.lifecycle.task.done())
        await child.close()

    async def test_missing_pins_and_credential_subject_override_refuse(self):
        del self.document["serverName"]; self.save()
        with self.assertRaises(ContractError):
            load_native_bootstrap(str(self.path))
        self.document["serverName"] = "child.agentmux.invalid"
        self.document["context"]["transport"]["requestSubject"] = "other.subject"; self.save()
        with self.assertRaises(ContractError):
            load_native_bootstrap(str(self.path))

    async def test_typescript_real_lifecycle_context_and_pin_refusal(self):
        module = os.environ.get("AGENTMUX_NATIVE_CHILD_TS_MODULE")
        node = os.environ.get("AGENTMUX_NATIVE_CHILD_NODE")
        if not module or not node:
            self.skipTest("prepared TypeScript native-child build and Node required")
        code = r"""
import {pathToFileURL} from 'node:url';
import {dirname} from 'node:path';
import {unlinkSync} from 'node:fs';
const {NativeChild,loadNativeBootstrap}=await import(pathToFileURL(process.argv[1]).href);
const child=new NativeChild(loadNativeBootstrap(process.argv[2],process.env.AGENTMUX_SCHEMA_DIR));
process.env.AGENTMUX_SCHEMA_DIR='/nonexistent-selected-schema-must-not-change';process.chdir(dirname(process.argv[2]));
if(process.argv[3]==='snapshot'){unlinkSync(child.bootstrap.document.caFile);unlinkSync(child.bootstrap.document.credentialsFile);}
let passed=false;
try {
 await child.connect();
 if(process.argv[3]==='refuse')throw new Error('pin accepted');
 const control=await child.nextControl();if(control.action!=='prepare')throw new Error('prepare');
 await child.report('ready');
 if(process.argv[3]==='bad-control'){try{await child.nextControl();}catch(error){if(error.code==='native_child_invalid')passed=true;}if(!passed)throw new Error('invalid stop accepted');}
 else if(process.argv[3]==='replay'){await child.nextControl();try{await child.nextControl();}catch(error){if(error.code==='native_child_invalid')passed=true;}if(!passed)throw new Error('replay accepted');}
 else {const stop=await child.nextControl();if(stop.action!=='stop'||stop.commandId===control.commandId)throw new Error('stop nonce');}
 if(passed){await child.close();}else {
 const t=child.bootstrap.document.context.transport;
 await child.contextConnection.publish(t.requestSubject,Buffer.from('{"request":"typescript"}'));
 const reply=JSON.parse((await child.contextConnection.receive(t.replySubject)).toString());
 if(reply.received.request!=='typescript')throw new Error('reply');
 const waiting=child.contextConnection.receive(t.cancelSubject).then(()=>false,()=>true);
 await child.report('stopped');
 await child.close();if(!await waiting)throw new Error('pending reader survived');passed=true;} 
} catch(error) {if(process.argv[3]==='refuse'&&error.code==='native_child_connection_failed')passed=true;else console.error(error.code??error.message);}
finally {await child.close();}
process.exitCode=passed?0:1;
"""
        async def run(mode):
            process = await asyncio.create_subprocess_exec(node, "--input-type=module", "-e", code, module, str(self.path), mode,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            completion = asyncio.create_task(process.communicate())
            try:
                stdout, stderr = await asyncio.wait_for(asyncio.shield(completion), 8)
            finally:
                if process.returncode is None:
                    process.kill()
                await completion
            self.assertEqual(process.returncode, 0, mode + ":" + str(getattr(self, "stop_variant", None)) + ":" + stderr.decode()[:1500])
        await run("success")
        self.assertEqual(len(self.auths), 2)
        self.assertEqual([r["status"] for r in self.reports], ["registered", "ready", "stopped"])
        self.assertEqual(self.reports[-1]["commandId"], "d" * 64)
        self.assertNotEqual(self.reports[-1]["commandId"], self.prepare["commandId"])
        for variant, mode in (("same", "bad-control"), ("invalid-time", "bad-control"), ("invalid-calendar", "bad-control"), ("replay", "replay")):
            self.stop_variant = variant
            await run(mode)
        self.stop_variant = None
        self.allow_tls_reset = True
        self.auths.clear(); self.reports.clear()
        self.document["leafCertificateSha256"] = "sha256:" + "0" * 64; self.save()
        await run("refuse")
        self.assertEqual(self.auths, [])
        self.document["leafCertificateSha256"] = self.document["context"]["transport"]["leafCertificateSha256"]
        self.document["context"]["transport"]["leafCertificateSha256"] = "sha256:" + "0" * 64; self.save()
        await run("refuse")
        self.assertEqual(len(self.auths), 1)
        self.assertEqual(self.reports, [])
        self.document["context"]["transport"]["leafCertificateSha256"] = self.document["leafCertificateSha256"]; self.save()
        await run("snapshot")

    async def test_stop_nonce_replay_and_invalid_time_refuse(self):
        for variant in ("same", "invalid-time", "invalid-calendar", "replay"):
            self.stop_variant = variant
            child = NativeChild(load_native_bootstrap(str(self.path)))
            try:
                await child.connect(); await child.next_control(); await child.report("ready")
                if variant == "replay":
                    await child.next_control()
                with self.assertRaises(ContractError):
                    await child.next_control()
            finally:
                await child.close()

    async def test_close_cancellation_retains_original_socket_join(self):
        child = NativeChild(load_native_bootstrap(str(self.path)))
        await child.connect()
        connection = child.context_connection
        original = connection.writer.wait_closed
        entered, release = asyncio.Event(), asyncio.Event()
        async def delayed():
            entered.set(); await release.wait(); await original()
        connection.writer.wait_closed = delayed
        try:
            for _ in range(2):
                closing = asyncio.create_task(child.close())
                await asyncio.wait_for(entered.wait(), 3); await asyncio.sleep(0)
                original_task = connection._close_task
                closing.cancel()
                result = await asyncio.gather(closing, return_exceptions=True)
                self.assertIsInstance(result[0], child_module.NativeChildCleanupError)
                self.assertIs(result[0].owner, child)
                self.assertIs(connection._close_task, original_task)
                self.assertFalse(original_task.cancelled())
            release.set(); await child.close()
            self.assertTrue(original_task.done())
            self.assertTrue(connection.task.done())
        finally:
            release.set(); await child.close()

    async def test_cancelled_preassignment_cleanup_retains_owner(self):
        self.bad_nonce = True
        child = NativeChild(load_native_bootstrap(str(self.path)))
        original = child_module._Connection._close_original
        entered, release = asyncio.Event(), asyncio.Event()
        async def delayed(connection):
            entered.set(); await release.wait(); await original(connection)
        with patch.object(child_module._Connection, "_close_original", delayed):
            opening = asyncio.create_task(child.connect())
            try:
                await asyncio.wait_for(entered.wait(), 3); opening.cancel()
                result = await asyncio.gather(opening, return_exceptions=True)
                self.assertIsInstance(result[0], child_module.NativeChildCleanupError)
                self.assertIs(result[0].owner, child)
                self.assertEqual(len(child._pending_cleanup), 1)
                original_task = child._pending_cleanup[0]._close_task
                self.assertFalse(original_task.cancelled())
                release.set(); await child.close(); self.assertTrue(original_task.done())
            finally:
                release.set(); await child.close()

    async def test_schema_source_and_resource_snapshots_survive_ambient_changes(self):
        schema = ROOT / "contracts/v1/schemas"
        child = NativeChild(load_native_bootstrap(str(self.path), schema_dir=schema))
        Path(self.credentials).unlink()
        Path(self.document["caFile"]).unlink()
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            await child.connect()
            self.assertEqual((await child.next_control())["action"], "prepare")
        finally:
            os.chdir(previous); await child.close()
