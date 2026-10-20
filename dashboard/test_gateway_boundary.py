"""Offline HTTP-handler and stream checks using only synthetic credentials.

Run with: python -B -m unittest dashboard.test_gateway_boundary
No sockets, subprocesses, user settings or provider calls are used.
"""
import contextlib
import io
import json
import os
from email.message import Message
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from taskmgmt import bedrock_gateway as gw


TOKEN = "synthetic-local-token-for-tests-only-123456"
SECRET = "synthetic-cloud-secret-private-123456789"
PRIVATE = "synthetic-private-provider-error-or-reasoning"


def completion(**changes):
    result = {"id": "response-fixture", "choices": [{"message": {"content": "hello"}}],
              "usage": {"prompt_tokens": 2, "completion_tokens": 3}}
    result.update(changes)
    return result


def upstream(value):
    return io.BytesIO(json.dumps(value).encode())


def stream(chunks, *, done=True):
    data = b"".join(b"data: " + json.dumps(chunk).encode() + b"\n\n" for chunk in chunks)
    return io.BytesIO(data + (b"data: [DONE]\n\n" if done else b""))


def delta(text=None, **fields):
    if text is not None:
        fields["content"] = text
    return {"choices": [{"delta": fields}]}


def handler(body=None, *, raw=None, path="/v1/responses", token=TOKEN, headers=()):
    result = gw.Gateway.__new__(gw.Gateway)
    result.path = path
    result.headers = Message()
    if token is not None:
        result.headers["Authorization"] = "Bearer " + token
    encoded = raw if raw is not None else json.dumps(body if body is not None else {"input": "hello"}).encode()
    result.headers["Content-Type"] = "application/json"
    result.headers["Content-Length"] = str(len(encoded))
    for name, value in headers:
        result.headers[name] = value
    result.rfile = io.BytesIO(encoded)
    result.wfile = io.BytesIO()
    result.sent = []
    result.http_codes = []
    result.close_connection = False
    result.send_json = lambda code, value: result.sent.append((code, value))
    result.send_response = lambda code: result.http_codes.append(code)
    result.send_header = lambda *args: None
    result.end_headers = lambda: None
    return result


def events(result):
    return [json.loads(line[6:]) for line in result.wfile.getvalue().decode().splitlines()
            if line.startswith("data: ")]


class GatewayBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.state = patch.dict(gw.STATE, {"region": "us-west-2", "log": None,
            "verbose": False, "model_default": "fixture-model", "allowed_models": ("fixture-model",)}, clear=True)
        self.env = patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": SECRET,
            "AGENTMUX_BEDROCK_GATEWAY_TOKEN": TOKEN}, clear=True)
        self.state.start()
        self.env.start()
        self.addCleanup(self.state.stop)
        self.addCleanup(self.env.stop)

    def post(self, result, reply=None, error=None):
        with patch.object(gw, "call_bedrock", side_effect=error, return_value=reply or upstream(completion())) as call:
            result.do_POST()
        return call

    def test_anonymous_or_wrong_client_is_refused_before_body_or_provider(self):
        for token in (None, SECRET, "incorrect"):
            with self.subTest(token=token):
                result = handler(token=token)
                call = self.post(result)
                self.assertEqual(result.sent[0][0], 401)
                self.assertEqual(result.rfile.tell(), 0)
                call.assert_not_called()

    def test_separate_configured_token_is_required(self):
        for token in ("", "short", SECRET, TOKEN + " "):
            with patch.dict(os.environ, {"AGENTMUX_BEDROCK_GATEWAY_TOKEN": token}):
                result = handler()
                call = self.post(result)
                self.assertEqual(result.sent[0][0], 503)
                call.assert_not_called()

    def test_control_and_oversized_tokens_are_refused_at_startup_and_on_requests(self):
        for token in (TOKEN + "\x00", TOKEN + "\x01", TOKEN + "\x7f", TOKEN + "é", "x" * 4097):
            with self.subTest(suffix=repr(token[-1:]), length=len(token)), patch.object(gw.os, "environ", {
                    "AGENTMUX_BEDROCK_GATEWAY_TOKEN": token, "AWS_BEARER_TOKEN_BEDROCK": SECRET}):
                result = handler()
                self.post(result).assert_not_called()
                self.assertEqual(result.sent[0][0], 503)
                with patch.object(gw.sys, "argv", ["bedrock_gateway.py"]), patch.object(gw, "GatewayServer") as server:
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                        gw.main()
                self.assertEqual(stopped.exception.code, 2)
                server.assert_not_called()
        self.assertTrue(gw._valid_local_token("!" * 32))
        self.assertTrue(gw._valid_local_token("~" * 4096))

    def test_duplicate_auth_and_browser_origin_are_refused(self):
        for header, status in ((("Authorization", "Bearer " + TOKEN), 401), (("Origin", "https://example.invalid"), 403)):
            result = handler(headers=[header])
            call = self.post(result)
            self.assertEqual(result.sent[0][0], status)
            call.assert_not_called()

    def test_aliases_and_query_string_keep_valid_translation(self):
        for path in ("/v1/responses", "/responses", "/responses/", "/v1/responses?x=1"):
            result = handler(path=path)
            reply = upstream(completion())
            call = self.post(result, reply)
            self.assertEqual(result.sent[0][0], 200)
            self.assertEqual(call.call_args.args, ({"model": "fixture-model", "messages": [{"role": "user", "content": "hello"}]}, False))
            self.assertTrue(reply.closed)
            self.assertTrue(result.close_connection)
            self.assertEqual(result.sent[0][1]["agentmux"]["usage_provenance"], "provider_reported")

    def test_invalid_json_and_shape_never_dispatch(self):
        for raw in (b"{bad", b"[]", b"null", b'"text"', b'{"input":"a","input":"b"}',
                    b'{"input":"a","temperature":NaN}', b'{"input":"a","temperature":1e999}'):
            with self.subTest(raw=raw):
                result = handler(raw=raw)
                call = self.post(result)
                self.assertEqual(result.sent[0][0], 400)
                call.assert_not_called()

    def test_json_depth_is_bounded(self):
        result = handler(raw=b'{"input":' + b"[" * 40 + b'"private"' + b"]" * 40 + b"}")
        self.post(result).assert_not_called()
        self.assertEqual(result.sent[0][1]["error"]["code"], "json_limit")

    def test_invalid_and_ambiguous_lengths_are_refused(self):
        for value, status in ((None, 411), ("-1", 400), ("+2", 400), ("1" * 100, 400), (str(gw.MAX_BODY + 1), 413)):
            result = handler()
            del result.headers["Content-Length"]
            if value is not None:
                result.headers["Content-Length"] = value
            self.post(result).assert_not_called()
            self.assertEqual(result.sent[0][0], status)
        for headers in ([('Content-Length', '1')], [('Transfer-Encoding', 'chunked')]):
            result = handler(headers=headers)
            self.post(result).assert_not_called()
            self.assertEqual(result.sent[0][0], 400)

    def test_short_body_and_read_timeout_are_explicit(self):
        result = handler()
        result.headers.replace_header("Content-Length", "999")
        self.post(result).assert_not_called()
        self.assertEqual(result.sent[0][1]["error"]["code"], "incomplete_body")
        result = handler()
        result.rfile.read = lambda size: (_ for _ in ()).throw(TimeoutError(PRIVATE))
        self.post(result).assert_not_called()
        self.assertEqual(result.sent[0][0], 408)

    def test_unsupported_semantics_and_models_are_explicit(self):
        cases = [dict(model="other-model"), dict(projectId="other-project"),
                 dict(previous_response_id="stored"), dict(store=True), dict(parallel_tool_calls=False),
                 dict(text={"format": {"type": "json_schema"}}), dict(tool_choice={"type": "function", "name": "f"}),
                 dict(input=[{"type": "item_reference", "id": "item"}]),
                 dict(input=[{"type": "message", "content": [{"type": "input_image", "image_url": "private"}]}]),
                 dict(tools=[{"type": "web_search"}]), dict(tools=[{"type": "function", "name": "f", "strict": True}])]
        for fields in cases:
            with self.subTest(fields=fields):
                result = handler({"input": "hello", **fields})
                self.post(result).assert_not_called()
                self.assertEqual(result.sent[0][0], 422)

    def test_namespace_depth_duplicate_names_and_reasoning_stay_compatible(self):
        tool = {"type": "function", "name": "f", "description": "first", "parameters": {}}
        duplicate = {**tool, "description": "second"}
        tree = tool
        for index in range(3):
            tree = {"type": "namespace", "name": str(index), "tools": [tree]}
        body = {"input": ["hello", {"type": "reasoning", "private": PRIVATE}], "tools": [tree, duplicate]}
        result = handler(body)
        call = self.post(result)
        self.assertEqual(result.sent[0][0], 200)
        self.assertEqual(call.call_args.args[0]["tools"][0]["function"]["description"], "first")
        self.assertNotIn(PRIVATE, json.dumps(call.call_args.args))
        result = handler({"input": "hello", "tools": [{"type": "namespace", "tools": [tree]}]})
        self.post(result).assert_not_called()
        self.assertEqual(result.sent[0][0], 422)

    def test_invalid_numeric_and_input_fields_are_refused(self):
        for fields in ({"model": 0}, {"stream": "yes"}, {"input": 7}, {"input": [{"type": "function_call", "arguments": {}}]},
                       {"input": [{"type": "message", "content": [{"type": "input_text", "text": []}]}]},
                       {"max_output_tokens": True}, {"max_output_tokens": 0}, {"temperature": 3}, {"top_p": -1}):
            result = handler({"input": "hello", **fields})
            self.post(result).assert_not_called()
            self.assertEqual(result.sent[0][0], 400)

    def test_missing_provider_credential_does_not_dispatch(self):
        with patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": ""}):
            result = handler()
            self.post(result).assert_not_called()
        self.assertEqual(result.sent[0][1]["error"]["upstream_outcome"], "not_dispatched")

    def test_provider_errors_are_fixed_and_never_read_error_bodies(self):
        private_body = io.BytesIO((SECRET + PRIVATE).encode())
        error = urllib.error.HTTPError("https://example.invalid/" + SECRET, 403, PRIVATE, {}, private_body)
        result = handler()
        self.post(result, error=error)
        self.assertTrue(private_body.closed)
        self.assertEqual(result.sent[0][0], 502)
        self.assertNotIn(PRIVATE, json.dumps(result.sent))
        self.assertNotIn(SECRET, json.dumps(result.sent))
        self.assertEqual(result.sent[0][1]["error"]["upstream_outcome"], "unknown")

    def test_timeout_and_lost_reply_remain_unknown_without_retry(self):
        for error, status in ((TimeoutError(PRIVATE), 504), (OSError(PRIVATE), 502),
                              (urllib.error.URLError(TimeoutError(PRIVATE)), 504)):
            result = handler()
            call = self.post(result, error=error)
            call.assert_called_once()
            self.assertEqual(result.sent[0][0], status)
            self.assertFalse(result.sent[0][1]["error"]["retryable"])
            self.assertEqual(result.sent[0][1]["error"]["upstream_outcome"], "unknown")
            self.assertNotIn(PRIVATE, json.dumps(result.sent))

    def test_bad_upstream_json_and_types_are_refused(self):
        for value in (None, [], {}, {"choices": []}, {"choices": [None]},
                      completion(usage={"completion_tokens": "secret"}),
                      completion(choices=[{"message": {"content": [PRIVATE]}}]),
                      completion(choices=[{"message": {"tool_calls": [{"function": []}]}}])):
            result = handler()
            reply = upstream(value)
            self.post(result, reply)
            self.assertEqual(result.sent[0][0], 502)
            self.assertTrue(reply.closed)

    def test_upstream_byte_limit_is_checked(self):
        result = handler()
        reply = io.BytesIO(b"x" * 100)
        with patch.object(gw, "MAX_UPSTREAM_BODY", 32):
            self.post(result, reply)
        self.assertEqual(result.sent[0][1]["error"]["code"], "upstream_limit")
        self.assertTrue(reply.closed)

    def test_missing_usage_is_distinct_from_reported_zero(self):
        for usage, expected in ((None, "unavailable"), ({"prompt_tokens": 0}, "provider_partial"),
                                ({"prompt_tokens": 0, "completion_tokens": 0}, "provider_reported")):
            result = handler()
            self.post(result, upstream(completion(usage=usage)))
            self.assertEqual(result.sent[0][1]["agentmux"]["usage_provenance"], expected)

    def test_stream_keeps_short_text_tool_fragments_usage_and_event_order(self):
        chunks = [delta("MODEL OK"), delta(tool_calls=[{"index": 0, "id": "c1", "function": {"name": "f", "arguments": '{"x"'}}]),
                  delta(tool_calls=[{"index": 0, "function": {"arguments": ':1}'}}]),
                  {"usage": {"prompt_tokens": 1, "completion_tokens": 2}}]
        result = handler({"input": "hello", "stream": True})
        reply = stream(chunks)
        self.post(result, reply)
        values = events(result)
        self.assertEqual(values[-1]["type"], "response.completed")
        output = values[-1]["response"]["output"]
        self.assertEqual(output[0]["content"][0]["text"], "MODEL OK")
        self.assertEqual(output[1]["arguments"], '{"x":1}')
        tool_events = [value for value in values if value.get("item", {}).get("type") == "function_call"]
        self.assertEqual([value["type"] for value in tool_events], ["response.output_item.added", "response.output_item.done"])
        self.assertEqual(tool_events[0]["output_index"], 1)
        self.assertEqual(values[-1]["response"]["agentmux"]["usage_provenance"], "provider_reported")
        self.assertTrue(reply.closed)

    def test_stream_eof_is_failure_not_completion(self):
        result = handler({"input": "hello", "stream": True})
        self.post(result, stream([delta("partial text")], done=False))
        values = events(result)
        self.assertNotIn("response.completed", [value["type"] for value in values])
        self.assertEqual(values[-1]["error"]["code"], "upstream_incomplete")
        self.assertEqual(values[-1]["response"]["agentmux"]["upstream_outcome"], "unknown")

    def test_malformed_stream_event_is_failure_not_completion(self):
        for raw in (b"data: {private\n\n", b"data: []\n\n", b"data: \xff\n\n"):
            result = handler({"input": "hello", "stream": True})
            self.post(result, io.BytesIO(raw))
            self.assertEqual(events(result)[-1]["type"], "response.failed")

    def test_stream_event_count_and_bytes_are_bounded(self):
        for name, limit, raw in (("MAX_EVENT", 32, b"data: " + b"x" * 33 + b"\n"),
                                 ("MAX_EVENTS", 1, b": comment\n: comment\n")):
            result = handler({"input": "hello", "stream": True})
            with patch.object(gw, name, limit):
                self.post(result, io.BytesIO(raw))
            self.assertEqual(events(result)[-1]["error"]["code"], "upstream_limit")

    def test_elapsed_deadline_refuses_a_late_reply(self):
        result = handler()
        with patch.object(gw.time, "monotonic", side_effect=[0, 0, gw.UPSTREAM_TIMEOUT + 1]):
            self.post(result, upstream(completion()))
        self.assertEqual(result.sent[0][0], 504)

    def test_truncated_generation_does_not_emit_executable_tool_call(self):
        choice = {"message": {"content": "partial", "tool_calls": [{"function": {"name": "f", "arguments": "{"}}]}, "finish_reason": "length"}
        result = handler()
        self.post(result, upstream(completion(choices=[choice])))
        self.assertEqual(result.sent[0][1]["status"], "incomplete")
        self.assertFalse(any(item["type"] == "function_call" for item in result.sent[0][1]["output"]))
        result = handler({"input": "hello", "stream": True})
        self.post(result, stream([{"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "f", "arguments": "{"}}]}, "finish_reason": "length"}]}]))
        self.assertEqual(events(result)[-1]["type"], "response.incomplete")
        self.assertEqual(events(result)[-1]["response"]["output"], [])

    def test_client_disconnect_closes_original_upstream(self):
        class Disconnected:
            def write(self, raw):
                raise BrokenPipeError(PRIVATE)
            def flush(self):
                pass
        result = handler({"input": "hello", "stream": True})
        result.wfile = Disconnected()
        reply = stream([delta("hello")])
        self.post(result, reply)
        self.assertTrue(reply.closed)
        self.assertEqual(result.sent, [])

    def test_private_error_and_reasoning_are_absent_from_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "gateway.jsonl"
            with patch.dict(gw.STATE, {"log": str(log), "verbose": True}):
                result = handler({"input": ["hello", {"type": "reasoning", "summary": PRIVATE}], "stream": True})
                with contextlib.redirect_stderr(io.StringIO()) as output:
                    result.log_message(PRIVATE + SECRET)
                    self.post(result, io.BytesIO(("data: {" + PRIVATE).encode()))
                    gw.log_event("upstream_error", {"detail": SECRET + PRIVATE})
                stored = log.read_text() + output.getvalue()
            self.assertNotIn(SECRET, stored)
            self.assertNotIn(PRIVATE, stored)
            self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
            self.assertTrue(all(set(json.loads(line)) == {"at", "kind", "payload"} for line in log.read_text().splitlines()))

    def test_logs_refuse_symlinks_and_shared_files(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original"
            original.write_text("unchanged")
            link = Path(directory) / "link"
            link.symlink_to(original)
            for path in (original, link):
                with patch.dict(gw.STATE, {"log": str(path)}):
                    gw.log_event("stream_done", {"chars": 4})
            self.assertEqual(original.read_text(), "unchanged")

    def test_nonregular_log_is_opened_nonblocking_and_never_written(self):
        def open_log(path, flags, mode):
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertTrue(flags & os.O_NOFOLLOW)
            return 17
        info = os.stat_result((stat.S_IFIFO | 0o600, 0, 0, 1, os.getuid(), os.getgid(), 0, 0, 0, 0))
        with patch.dict(gw.STATE, {"log": "synthetic-fifo"}), patch.object(gw.os, "open", side_effect=open_log), \
                patch.object(gw.os, "fstat", return_value=info), patch.object(gw.os, "fdopen") as opened:
            handle = opened.return_value.__enter__.return_value
            handle.fileno.return_value = 17
            gw.log_event("stream_done", {"chars": 4})
            handle.write.assert_not_called()
            opened.return_value.__exit__.assert_called_once()

    def test_capability_and_model_list_do_not_claim_project_or_live_support(self):
        result = handler(path="/v1/capabilities")
        result.do_GET()
        value = result.sent[0][1]
        self.assertFalse(value["managed_project_access"])
        self.assertEqual(value["models"], ["fixture-model"])
        self.assertIn("offline", value["qualification"])
        result = handler(path="/v1/models")
        result.do_GET()
        self.assertEqual([item["id"] for item in result.sent[0][1]["data"]], ["fixture-model"])

    def test_redirects_are_refused_and_proxy_settings_are_not_used(self):
        self.assertIsNone(gw._NoRedirect().redirect_request(None, None, 307, PRIVATE, {}, "https://example.invalid/"))
        fake_reply = upstream(completion())
        with patch.object(gw.urllib.request, "build_opener") as builder:
            builder.return_value.open.return_value = fake_reply
            self.assertIs(gw.call_bedrock({"input": "fixture"}, False), fake_reply)
        proxy_handler = builder.call_args.args[0]
        self.assertEqual(proxy_handler.proxies, {})
        request = builder.return_value.open.call_args.args[0]
        self.assertEqual(request.headers["Authorization"], "Bearer " + SECRET)
        self.assertNotIn(TOKEN, repr(request.headers))

    def test_http_fixture_import_never_opens_sockets_or_changes_environment(self):
        before = dict(os.environ)
        with patch("socket.socket", side_effect=AssertionError("fixture opened a socket during import")):
            from dashboard import verify_gateway_e2e
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(verify_gateway_e2e.REPO, Path(__file__).resolve().parent.parent)


if __name__ == "__main__":
    unittest.main()
