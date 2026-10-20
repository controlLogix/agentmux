"""Storage policy checks and disposable live provisioning checks.

Live checks need pinned nats-py and NATS_SERVER (or nats-server on PATH).
They use their own loopback server and temporary store, never a shared circle.
"""
from __future__ import annotations

import asyncio
import copy
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace

from hub.fed import admin, conn


class StoragePolicy(unittest.TestCase):
    def test_each_declared_policy_difference_requires_migration(self):
        fields = dict(subjects=["am.msg.>"], retention="limits", storage="file", max_age=120,
                      num_replicas=1, duplicate_window=120, discard="old", max_msgs_per_subject=16)
        expected = SimpleNamespace(name="AM_MSG", **fields)
        for field, value in fields.items():
            with self.subTest(field=field):
                actual = copy.deepcopy(expected)
                setattr(actual, field, ["private.value"] if isinstance(value, list) else "private.value")
                with self.assertRaises(admin.LayoutMismatch) as caught:
                    admin._check_policy(actual, expected, fields)
                self.assertIn(field, str(caught.exception))
                self.assertIn("reviewed migration", str(caught.exception))
                self.assertNotIn("private.value", str(caught.exception))

    def test_subject_order_and_zero_duration_defaults_are_equivalent(self):
        actual = SimpleNamespace(name="AM_SHARE", subjects=["am.code.>", "am.know.>"], max_age=None)
        expected = SimpleNamespace(name="AM_SHARE", subjects=["am.know.>", "am.code.>"], max_age=0)
        admin._check_policy(actual, expected, ("subjects", "max_age"))

    def test_cli_failure_keeps_private_cause_out_of_output(self):
        import contextlib
        import io
        from unittest.mock import patch

        async def refused(*args):
            try:
                raise OSError("private credential and endpoint details")
            except OSError as error:
                raise admin.ProvisionFailure("check the endpoint and current credentials") from error

        output = io.StringIO()
        with patch.object(admin, "provision", refused), contextlib.redirect_stderr(output):
            result = admin.main(["provision", "--url", "fixture", "--creds", "fixture"])
        self.assertEqual(result, 1)
        self.assertIn("check the endpoint and current credentials", output.getvalue())
        self.assertNotIn("private", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())

    def test_dependency_failure_has_a_setup_action(self):
        from unittest.mock import patch
        with patch.dict("sys.modules", {"nats": None}):
            with self.assertRaisesRegex(conn.MissingDependency, "agentmux hub fed setup"):
                conn.nats_mod()


class AccountUpdate(unittest.IsolatedAsyncioTestCase):
    async def test_refused_reply_keeps_private_body_out_of_error_and_closes_client(self):
        from unittest.mock import patch
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix="agentmux-account-update-") as directory:
            jwt = Path(directory) / "account.jwt"
            jwt.write_text("synthetic.account.jwt")
            class Client:
                closed = False
                async def request(self, *args, **kwargs):
                    return SimpleNamespace(data=b'{"error":"private reflected credential"}')
                async def close(self):
                    self.closed = True
            client = Client()
            async def connect(*args, **kwargs):
                return client
            with patch.object(conn, "connect", connect):
                with self.assertRaises(admin.ProvisionFailure) as caught:
                    await admin.push("fixture", "fixture", None, str(jwt))
            self.assertTrue(client.closed)
            self.assertNotIn("private", str(caught.exception))
            self.assertNotIn("synthetic", str(caught.exception))

    def test_cli_reports_safe_success_without_echoing_broker_payload(self):
        from unittest.mock import patch
        import contextlib
        import io
        async def pushed(*args):
            return {"data": {"code": 200, "message": "private reflected credential"}}
        output = io.StringIO()
        with patch.object(admin, "push", pushed), contextlib.redirect_stdout(output):
            result = admin.main(["push", "--url", "fixture", "--creds", "fixture", "--jwt", "fixture"])
        self.assertIsNone(result)
        self.assertEqual(json.loads(output.getvalue()), {"updated": True})


class ProvisionCleanup(unittest.IsolatedAsyncioTestCase):
    async def test_failed_close_keeps_client_and_refuses_false_retry_success(self):
        class Client:
            calls = 0

            async def close(self):
                self.calls += 1
                if self.calls == 1:
                    raise OSError("private close details")

            def __repr__(self):
                return "private client credentials"

        client = Client()
        operation = admin.LayoutMismatch("private operation details")
        with self.assertRaises(admin.ProvisionCleanupFailure) as caught:
            await admin._close_provision(client, operation)
        owned = caught.exception
        self.assertIs(owned.client, client)
        self.assertIs(owned.operation_error, operation)
        self.assertIs(owned.__cause__.exceptions[0], operation)
        self.assertNotIn("private", str(owned))
        self.assertNotIn("private", repr(owned))
        with self.assertRaises(admin.ProvisionCleanupFailure) as retried:
            await owned.retry_close()
        self.assertIs(retried.exception, owned)
        self.assertEqual(client.calls, 1)
        self.assertGreaterEqual(len(owned.cleanup_errors), 1)

    async def test_timeout_keeps_one_close_attempt_for_retry(self):
        from unittest.mock import patch
        finished = asyncio.Event()
        calls = []

        async def close():
            calls.append("close")
            await finished.wait()

        client = SimpleNamespace(close=close)
        with patch.object(admin, "PROVISION_CLOSE_TIMEOUT", 0.02):
            with self.assertRaises(admin.ProvisionCleanupFailure) as caught:
                await admin._close_provision(client, None)
        owned = caught.exception
        self.assertFalse(owned.close_task.done())
        finished.set()
        await owned.retry_close()
        self.assertEqual(calls, ["close"])
        self.assertTrue(owned.close_task.done())

    async def test_cleanup_cancellation_keeps_original_cancellation_and_owned_task(self):
        finished = asyncio.Event()
        began = asyncio.Event()

        async def close():
            began.set()
            await finished.wait()

        original = asyncio.CancelledError("original cancellation")
        owner = asyncio.create_task(admin._close_provision(SimpleNamespace(close=close), original))
        await began.wait()
        owner.cancel()
        with self.assertRaises(admin.ProvisionCleanupFailure) as caught:
            await owner
        owned = caught.exception
        self.assertIs(owned.operation_error, original)
        self.assertIs(owned.__cause__.exceptions[0], original)
        self.assertIsInstance(owned.cleanup_errors[0], asyncio.CancelledError)
        self.assertFalse(owned.close_task.cancelled())
        finished.set()
        await owned.retry_close()


NATS_SERVER = os.environ.get("NATS_SERVER") or shutil.which("nats-server")
HAVE_NATS = importlib.util.find_spec("nats") is not None


@unittest.skipUnless(NATS_SERVER and HAVE_NATS, "needs pinned nats-py and a native nats-server")
class LiveProvision(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="agentmux-provision-")
        self.addCleanup(self.tmp.cleanup)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.url = f"nats://127.0.0.1:{port}"
        self.proc = subprocess.Popen(
            [NATS_SERVER, "-js", "-a", "127.0.0.1", "-p", str(port), "-sd", self.tmp.name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_server)
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                if self.proc.poll() is not None or time.monotonic() >= deadline:
                    self.fail("owned test broker did not start")
                await asyncio.sleep(0.02)
        self.nc = await conn.connect(self.url, None, None, "provision-regression")
        self.addAsyncCleanup(conn.close, self.nc)
        self.js = self.nc.jetstream(timeout=2)

    def stop_server(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    async def test_repeated_provision_preserves_messages_consumers_and_kv_revisions(self):
        from nats.js.api import AckPolicy, ConsumerConfig
        await admin.provision(self.url, None, None)
        # Keep this approved target independent of the provisioner's declarations.
        targets = {
            "AM_MSG": dict(subjects=["am.msg.>"], retention="limits", max_age=14 * 86400,
                           duplicate_window=120),
            "AM_WORK": dict(subjects=["am.work.>"], retention="workqueue", max_age=30 * 86400,
                            duplicate_window=120),
            "AM_SHARE": dict(subjects=["am.know.>", "am.code.>"], retention="limits",
                             max_age=365 * 86400, duplicate_window=120),
            "KV_am_board": dict(subjects=["$KV.am_board.>"], retention="limits",
                                max_age=0, max_msgs_per_subject=16),
            "KV_am_presence": dict(subjects=["$KV.am_presence.>"], retention="limits",
                                   max_age=90, max_msgs_per_subject=1),
        }

        async def approved_layout():
            observed = {}
            for name, target in targets.items():
                cfg = (await self.js.stream_info(name)).config
                self.assertEqual(cfg.name, name)
                self.assertEqual(cfg.storage, "file")
                self.assertEqual(cfg.num_replicas, 1)
                for field, expected in target.items():
                    actual = getattr(cfg, field)
                    if field == "subjects":
                        actual, expected = sorted(actual), sorted(expected)
                    elif field == "max_age":
                        actual = actual or 0
                    self.assertEqual(actual, expected, f"{name}.{field}")
                observed[name] = cfg.as_dict()
            return observed

        await self.js.publish("am.msg.preservation", b"keep this record")
        await self.js.add_consumer("AM_MSG", ConsumerConfig(durable_name="preserved"))
        work = await self.js.pull_subscribe(
            "am.work.preservation", durable="preserved_work", stream="AM_WORK",
            config=ConsumerConfig(ack_policy=AckPolicy.EXPLICIT, ack_wait=60))
        delivered = await self.js.publish("am.work.preservation", b"unacknowledged work")
        pending = await self.js.publish("am.work.preservation", b"undelivered work")
        received = (await work.fetch(1, timeout=2))[0]
        self.assertEqual(received.data, b"unacknowledged work")
        self.assertEqual(received.metadata.sequence.stream, delivered.seq)
        work_before = await self.js.consumer_info("AM_WORK", "preserved_work")
        self.assertEqual(work_before.num_ack_pending, 1)
        self.assertEqual(work_before.num_pending, 1)
        board = await self.js.key_value("am_board")
        first = await board.put("preserved", b"first")
        second = await board.put("preserved", b"second")
        before = await approved_layout()
        made = await admin.provision(self.url, None, None)
        self.assertTrue(all("(exists)" in row for row in made))
        after = await approved_layout()
        self.assertEqual(before, after)
        self.assertEqual((await self.js.get_msg("AM_MSG", seq=1)).data, b"keep this record")
        self.assertEqual((await self.js.consumer_info("AM_MSG", "preserved")).name, "preserved")
        work_after = await self.js.consumer_info("AM_WORK", "preserved_work")
        for field in ("name", "created", "config", "delivered", "ack_floor", "num_ack_pending",
                      "num_pending", "num_redelivered"):
            self.assertEqual(getattr(work_before, field), getattr(work_after, field), field)
        self.assertEqual((await self.js.get_msg("AM_WORK", seq=delivered.seq)).data, b"unacknowledged work")
        self.assertEqual((await self.js.get_msg("AM_WORK", seq=pending.seq)).data, b"undelivered work")
        next_work = (await work.fetch(1, timeout=2))[0]
        self.assertEqual(next_work.data, b"undelivered work")
        self.assertEqual(next_work.metadata.sequence.stream, pending.seq)
        await received.ack_sync(timeout=2)
        await next_work.ack_sync(timeout=2)
        finished = await self.js.consumer_info("AM_WORK", "preserved_work")
        self.assertEqual(finished.num_ack_pending, 0)
        self.assertEqual(finished.num_pending, 0)
        self.assertEqual([entry.revision for entry in await board.history("preserved")], [first, second])
        self.assertEqual((await board.get("preserved")).value, b"second")

    async def test_stream_mismatch_is_refused_before_creating_missing_resources(self):
        from nats.js.api import StreamConfig
        from nats.js.errors import NotFoundError
        await self.js.add_stream(StreamConfig(name="AM_SHARE", subjects=["different.>"]))
        before = (await self.js.stream_info("AM_SHARE")).config.as_dict()
        with self.assertRaises(admin.LayoutMismatch):
            await admin.provision(self.url, None, None)
        self.assertEqual(before, (await self.js.stream_info("AM_SHARE")).config.as_dict())
        with self.assertRaises(NotFoundError):
            await self.js.stream_info("AM_MSG")

    async def test_bucket_mismatch_is_refused_without_changing_history(self):
        from nats.js.api import KeyValueConfig
        board = await self.js.create_key_value(KeyValueConfig(bucket="am_board", history=2))
        revision = await board.put("preserved", b"keep")
        with self.assertRaisesRegex(admin.LayoutMismatch, "max_msgs_per_subject"):
            await admin.provision(self.url, None, None)
        self.assertEqual((await board.get("preserved")).revision, revision)
        self.assertEqual((await self.js.stream_info("KV_am_board")).config.max_msgs_per_subject, 2)

    async def test_policy_change_during_creation_is_detected_before_success(self):
        from unittest.mock import patch
        original_connect = conn.connect

        async def raced_connect(*args, **kwargs):
            nc = await original_connect(*args, **kwargs)
            js = nc.jetstream()
            original_add = js.add_stream

            async def raced_add(cfg):
                result = await original_add(cfg)
                if cfg.name == "AM_MSG":
                    changed = (await self.js.stream_info(cfg.name)).config
                    changed.max_age = conn.DUPE_WINDOW_S + 60
                    await self.js.update_stream(changed)
                return result

            js.add_stream = raced_add
            nc.jetstream = lambda **kwargs: js
            return nc

        with patch.object(conn, "connect", raced_connect):
            with self.assertRaisesRegex(admin.LayoutMismatch, "max_age"):
                await admin.provision(self.url, None, None)
        self.assertEqual((await self.js.stream_info("AM_MSG")).config.max_age, conn.DUPE_WINDOW_S + 60)

    async def test_interruption_closes_connection_and_rerun_keeps_partial_data(self):
        from unittest.mock import patch
        original_connect = conn.connect
        connections = []

        async def interrupted_connect(*args, **kwargs):
            nc = await original_connect(*args, **kwargs)
            connections.append(nc)
            js = nc.jetstream()
            original_add = js.add_stream

            async def interrupted_add(cfg):
                await original_add(cfg)
                await js.publish("am.msg.preserved", b"partial data")
                raise asyncio.CancelledError()

            js.add_stream = interrupted_add
            nc.jetstream = lambda **kwargs: js
            return nc

        with patch.object(conn, "connect", interrupted_connect):
            with self.assertRaises(asyncio.CancelledError):
                await admin.provision(self.url, None, None)
        self.assertTrue(connections[0].is_closed)
        await admin.provision(self.url, None, None)
        self.assertEqual((await self.js.get_msg("AM_MSG", seq=1)).data, b"partial data")


@unittest.skipUnless(NATS_SERVER and HAVE_NATS and shutil.which("nsc"),
                     "needs pinned nats-py, nsc and a native nats-server")
class LiveAdministration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from hub.tests.fedharness import Circle
        self.circle = Circle(peers=("member",))
        self.addCleanup(self.circle.close)

    def nsc(self, *args, stdout=subprocess.DEVNULL):
        subprocess.run([shutil.which("nsc"), "--config-dir", os.path.join(self.circle.dir, "cfg"),
                        "--data-dir", os.path.join(self.circle.dir, "store"),
                        "--keystore-dir", os.path.join(self.circle.dir, "keys"), *args],
                       check=True, stdout=stdout, stderr=subprocess.DEVNULL, timeout=10)

    async def test_system_account_update_and_revoked_provisioner(self):
        from pathlib import Path
        import re
        # Live account updates need a resolver that owns writable JWT storage.
        # The legacy harness starts with a read-only memory resolver.
        conf = Path(self.circle.tmp) / "nats.conf"
        resolver = Path(self.circle.tmp) / "resolver"
        resolver.mkdir(mode=0o700)
        rewritten, count = re.subn(r"resolver:\s*MEMORY", f'resolver {{ type: full, dir: "{resolver}" }}', conf.read_text())
        self.assertEqual(count, 1)
        conf.write_text(rewritten)
        self.circle.proc.terminate()
        self.circle.proc.wait(timeout=10)
        self.circle.proc = subprocess.Popen([NATS_SERVER, "-c", str(conf)],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        from urllib.parse import urlparse
        port = urlparse(self.circle.url).port
        deadline = time.monotonic() + 3
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    self.fail("owned account-resolver broker did not start")
                await asyncio.sleep(0.01)
        jwt = Path(self.circle.tmp) / "account.jwt"
        with jwt.open("w") as target:
            self.nsc("describe", "account", "testcircle", "--raw", stdout=target)
        reply = await admin.push(self.circle.url, self.circle.creds("sys"), None, str(jwt))
        self.assertEqual(reply["data"]["code"], 200)
        # Claims use whole-second issue times. Produce a later signed revision.
        await asyncio.sleep(1.05)
        self.nsc("revocations", "add-user", "-a", "testcircle", "-n", "admin")
        with jwt.open("w") as target:
            self.nsc("describe", "account", "testcircle", "--raw", stdout=target)
        await admin.push(self.circle.url, self.circle.creds("sys"), None, str(jwt))
        async with asyncio.timeout(8):
            with self.assertRaises(admin.ProvisionFailure) as caught:
                await admin.provision(self.circle.url, self.circle.creds("admin"), None)
        self.assertNotIn(self.circle.dir, str(caught.exception))

    async def test_missing_credentials_wrong_endpoint_and_denied_creation_are_bounded(self):
        async with asyncio.timeout(8):
            with self.assertRaises(admin.ProvisionFailure):
                await admin.provision(self.circle.url, os.path.join(self.circle.tmp, "missing.creds"), None)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            endpoint = "nats://127.0.0.1:" + str(reserved.getsockname()[1])
            async with asyncio.timeout(8):
                with self.assertRaises(admin.ProvisionFailure):
                    await admin.provision(endpoint, self.circle.creds("admin"), None)
        nc = await conn.connect(self.circle.url, self.circle.creds("admin"), None, "owned-negative-test")
        try:
            await nc.jetstream().delete_stream("AM_SHARE")
        finally:
            await nc.close()
        async with asyncio.timeout(8):
            with self.assertRaises(admin.ProvisionFailure):
                await admin.provision(self.circle.url, self.circle.creds("member"), None)
        # A corrected authorized retry fills only the missing stream.
        await admin.provision(self.circle.url, self.circle.creds("admin"), None)

    @unittest.skipUnless(shutil.which("openssl"), "needs the prepared certificate tool")
    async def test_custom_ca_acceptance_and_wrong_ca_refusal(self):
        from pathlib import Path
        from urllib.parse import urlparse
        paths = []
        for name in ("server", "other"):
            cert, key = Path(self.circle.tmp) / (name + ".pem"), Path(self.circle.tmp) / (name + ".key")
            subprocess.run([shutil.which("openssl"), "req", "-x509", "-newkey", "ec",
                            "-pkeyopt", "ec_paramgen_curve:P-256", "-days", "1", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            key.chmod(0o600)
            paths.append((cert, key))
        cert, key = paths[0]
        conf = Path(self.circle.tmp) / "nats.conf"
        with conf.open("a") as target:
            target.write(f'\ntls {{ cert_file: "{cert}", key_file: "{key}", timeout: 1 }}\n')
        self.circle.proc.terminate()
        self.circle.proc.wait(timeout=10)
        self.circle.proc = subprocess.Popen([NATS_SERVER, "-c", str(conf)],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        port = urlparse(self.circle.url).port
        deadline = time.monotonic() + 3
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    self.fail("owned TLS broker did not start")
                await asyncio.sleep(0.01)
        endpoint = self.circle.url.replace("nats://", "tls://")
        await admin.provision(endpoint, self.circle.creds("admin"), str(cert))
        async with asyncio.timeout(8):
            with self.assertRaises(admin.ProvisionFailure) as caught:
                await admin.provision(endpoint, self.circle.creds("admin"), str(paths[1][0]))
        self.assertNotIn(self.circle.dir, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
