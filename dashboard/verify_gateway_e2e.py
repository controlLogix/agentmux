#!/usr/bin/env python3
"""Opt-in HTTP checks against an owned synthetic loopback Bedrock fixture.

Run only in the coordinator's serialized test slot:
    python -B dashboard/verify_gateway_e2e.py

No provider account or external network is used. Credentials are synthetic,
ports are ephemeral, and original server/thread handles are joined on cleanup.
Importing this module starts no server and changes no environment. CPython 3.12
also runs the preserved-bytecode differential; other versions explicitly skip it.
"""
import http.client
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = Path(__file__).resolve().parent.parent
TOKEN = "synthetic-local-test-token-not-a-cloud-key-1234"
SECRET = "synthetic-cloud-key-for-loopback-only"
PRIVATE = "synthetic-private-provider-error"


class FakeBedrock(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.observed.append((self.headers.get("Authorization"), json.loads(body)))
        mode = self.server.mode
        status, content_type = 200, "application/json"
        if mode == "http_error":
            status, payload = 400, json.dumps({"message": PRIVATE + SECRET}).encode()
        elif mode == "bad_json":
            payload = b"{broken"
        elif mode in ("stream", "lost_stream", "tool_stream"):
            chunks = [{"choices": [{"delta": {"content": "hel"}}]},
                      {"choices": [{"delta": {"content": "lo"}}]},
                      {"usage": {"prompt_tokens": 2, "completion_tokens": 3}}]
            if mode == "tool_stream":
                chunks += [{"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call1",
                    "function": {"name": "shell", "arguments": '{"a":1}'}}]}}]}]
            payload = b"".join(b"data: " + json.dumps(chunk).encode() + b"\n\n" for chunk in chunks)
            if mode != "lost_stream":
                payload += b"data: [DONE]\n\n"
            content_type = "text/event-stream"
        else:
            payload = json.dumps({"id": "up_1", "choices": [{"message": {"content": "hello from bedrock"}}],
                "usage": {"prompt_tokens": 2, "completion_tokens": 3}}).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True


def load(name, path, sourceless=False):
    loader = importlib.machinery.SourcelessFileLoader(name, str(path)) if sourceless else None
    spec = importlib.util.spec_from_file_location(name, path, loader=loader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalized(raw):
    """Omit clocks and the explicitly added usage/outcome extension only."""
    def clean(value):
        if isinstance(value, dict):
            if value.get("object") == "response":
                value.pop("agentmux", None)
                value.pop("created_at", None)
            return {key: clean(item) for key, item in value.items()}
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, str):
            return re.sub(r"resp_gw_[0-9]+", "resp_gw_X", value)
        return value
    text = raw.decode()
    if text.startswith("event:"):
        return [clean(json.loads(line[6:])) for line in text.splitlines() if line.startswith("data: ")]
    return clean(json.loads(text))


class GatewayHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owned = []
        cls.home = tempfile.TemporaryDirectory(prefix="agentmux-gateway-http-")
        cls.addClassCleanup(cls.home.cleanup)
        cls.environment = patch.dict(os.environ, {"HOME": cls.home.name,
            "AWS_BEARER_TOKEN_BEDROCK": SECRET, "AGENTMUX_BEDROCK_GATEWAY_TOKEN": TOKEN}, clear=True)
        cls.environment.start()
        cls.addClassCleanup(cls.environment.stop)
        cls.addClassCleanup(cls.stop_servers)
        cls.current = load("gateway_current_http", REPO / "taskmgmt/bedrock_gateway.py")
        try:
            cls.original = load("gateway_original_http",
                REPO / "taskmgmt/recovered/bedrock_gateway.cpython-312.pyc.bin", True)
        except (ImportError, OSError, ValueError):
            cls.original = None
        cls.upstream = cls.start_server(FakeBedrock)
        cls.upstream.mode, cls.upstream.observed = "once", []
        upstream_url = f"http://127.0.0.1:{cls.upstream.server_address[1]}/chat"
        cls.gateways = {}
        for name, module in (("current", cls.current), ("original", cls.original)):
            if module is None:
                continue
            module.bedrock_url = lambda: upstream_url
            module.STATE.update(region="us-west-2", model_default="fixture-model", verbose=False,
                log=None, allowed_models=("fixture-model",))
            cls.gateways[name] = cls.start_server(module.Gateway,
                getattr(module, "GatewayServer", ThreadingHTTPServer))

    @classmethod
    def start_server(cls, handler, server_class=ThreadingHTTPServer):
        server = server_class(("127.0.0.1", 0), handler)
        server.daemon_threads = False
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        try:
            thread.start()
        except BaseException:
            server.server_close()
            raise
        cls.owned.append((server, thread))
        return server

    @classmethod
    def stop_servers(cls):
        failures = []
        for server, thread in reversed(cls.owned):
            server.shutdown()
            thread.join(timeout=5)
            if thread.is_alive():
                failures.append("gateway fixture thread did not stop; original handle retained")
            else:
                server.server_close()
        if failures:
            raise RuntimeError("; ".join(failures))

    def setUp(self):
        self.upstream.mode = "once"
        self.upstream.observed.clear()

    def fetch(self, method="POST", path="/v1/responses", body=None, *,
              token=TOKEN, headers=None, which="current"):
        values = {"Connection": "close"}
        if token is not None:
            values["Authorization"] = "Bearer " + token
        if body is not None:
            body = body if isinstance(body, bytes) else json.dumps(body).encode()
            values["Content-Type"] = "application/json"
        values.update(headers or {})
        server = self.gateways[which]
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        try:
            connection.request(method, path, body=body, headers=values)
            response = connection.getresponse()
            return response.status, response.read(self.current.MAX_UPSTREAM_BODY + 1)
        finally:
            connection.close()

    def test_health_aliases(self):
        for path in ("/health", "/v1/health", "/health/", "/health?x=1"):
            status, body = self.fetch("GET", path, token=None)
            self.assertEqual(status, 200)
            self.assertFalse(json.loads(body)["managed_project_access"])
        self.assertEqual(self.upstream.observed, [])

    def test_authentication_and_browser_refusals(self):
        for token, headers, expected in ((None, {}, 401), (SECRET, {}, 401),
                (TOKEN, {"Origin": "https://example.invalid"}, 403)):
            status, body = self.fetch(body={"input": "hi"}, token=token, headers=headers)
            self.assertEqual(status, expected)
            self.assertNotIn(SECRET.encode(), body)
        self.assertEqual(self.upstream.observed, [])

    def test_models_and_capabilities(self):
        status, body = self.fetch("GET", "/v1/models")
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in json.loads(body)["data"]], ["fixture-model"])
        status, body = self.fetch("GET", "/v1/capabilities")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["managed_project_access"])

    def test_response_aliases(self):
        for path in ("/v1/responses", "/responses", "/v1/responses?x=1", "/v1/responses/"):
            status, body = self.fetch(path=path, body={"input": "hi"})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["status"], "completed")
        self.assertTrue(all(auth == "Bearer " + SECRET for auth, _ in self.upstream.observed))

    def test_missing_paths_do_not_echo_request(self):
        for method in ("GET", "POST"):
            status, body = self.fetch(method, "/missing?private=" + PRIVATE, {"input": "hi"})
            self.assertEqual(status, 404)
            self.assertNotIn(PRIVATE.encode(), body)

    def test_invalid_and_oversized_bodies(self):
        for body in (b"{not-json", b"", b"[]", b"null", b'{"input":"a","input":"b"}'):
            self.assertEqual(self.fetch(body=body)[0], 400)
        for headers, expected in (({"Content-Length": str(self.current.MAX_BODY + 1)}, 413),
                ({"Transfer-Encoding": "chunked"}, 400), ({"Content-Type": "text/plain"}, 415)):
            self.assertEqual(self.fetch(body=b"{}", headers=headers)[0], expected)
        self.assertEqual(self.upstream.observed, [])

    def test_unsupported_input_models_and_project_claims(self):
        for fields in ({"model": "other-model"}, {"projectId": "unrelated-project"},
                {"input": [{"type": "item_reference", "id": "other"}]},
                {"tools": [{"type": "web_search"}]}):
            self.assertEqual(self.fetch(body={"input": "hi", **fields})[0], 422)
        self.assertEqual(self.upstream.observed, [])

    def test_namespaced_function_tools(self):
        status, _ = self.fetch(body={"input": "hi", "tools": [{"type": "namespace", "name": "ns",
            "tools": [{"type": "function", "name": "shell", "parameters": {}}]}]})
        self.assertEqual(status, 200)
        self.assertEqual(self.upstream.observed[0][1]["tools"][0]["function"]["name"], "shell")

    def test_stream_text_tools_and_usage(self):
        for mode in ("stream", "tool_stream"):
            self.upstream.mode = mode
            status, body = self.fetch(body={"input": "hi", "stream": True})
            self.assertEqual(status, 200)
            final = normalized(body)[-1]
            self.assertEqual(final["type"], "response.completed")
            self.assertEqual(final["response"]["output"][0]["content"][0]["text"], "hello")
            self.assertEqual(final["response"]["usage"]["total_tokens"], 5)
            if mode == "tool_stream":
                self.assertEqual(final["response"]["output"][1]["arguments"], '{"a":1}')

    def test_lost_stream_reply_remains_unknown(self):
        self.upstream.mode = "lost_stream"
        status, body = self.fetch(body={"input": "hi", "stream": True})
        self.assertEqual(status, 200)
        self.assertNotIn(b'"type": "response.completed"', body)
        self.assertEqual(normalized(body)[-1]["error"]["upstream_outcome"], "unknown")

    def test_provider_errors_are_bounded_and_redacted(self):
        for mode, expected in (("http_error", "upstream_http_error"), ("bad_json", "invalid_upstream_json")):
            self.upstream.mode = mode
            status, body = self.fetch(body={"input": "hi"})
            self.assertEqual(status, 502)
            self.assertNotIn(PRIVATE.encode(), body)
            self.assertNotIn(SECRET.encode(), body)
            self.assertEqual(json.loads(body)["error"]["code"], expected)

    def test_retained_http_differential(self):
        if self.original is None:
            self.skipTest("preserved CPython 3.12 bytecode cannot load; current HTTP cases still run")
        cases = [(path, {"input": "hi"}, "once") for path in
            ("/v1/responses", "/responses", "/v1/responses?x=1", "/v1/responses/")]
        cases.extend([("/responses", {"input": "hi", "stream": True}, "stream"),
            ("/responses", {"input": "hi", "stream": True}, "tool_stream"),
            ("/responses", {"input": "hi", "tools": [{"type": "namespace", "name": "ns",
                "tools": [{"type": "function", "name": "shell", "parameters": {}}]}]}, "once")])
        for path, body, mode in cases:
            with self.subTest(path=path, mode=mode):
                self.upstream.mode = mode
                old_status, old_body = self.fetch(path=path, body=body, which="original")
                status, current_body = self.fetch(path=path, body=body)
                self.assertEqual((status, normalized(current_body)), (old_status, normalized(old_body)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
