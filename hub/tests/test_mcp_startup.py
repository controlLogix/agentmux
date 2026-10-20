"""Offline checks for the MCP client boundary; no startup qualification is claimed."""
import io
import json
import unittest
from unittest.mock import patch

from hub.fed import mcp


class McpBoundary(unittest.TestCase):
    def exchange(self, messages, call=None):
        output = io.StringIO()
        with patch.object(mcp.cli, "call", side_effect=call) as invoked:
            mcp.main(io.StringIO("".join(json.dumps(m) + "\n" for m in messages)), output)
        return [json.loads(line) for line in output.getvalue().splitlines()], invoked

    def request(self, **overrides):
        return {"jsonrpc": "2.0", "id": 1, "method": "ping", **overrides}

    def test_invalid_envelopes_recover_without_hub_calls(self):
        for bad in (None, [], 42, "secret", {}, {"id": 1, "method": "ping"},
                    self.request(jsonrpc="1.0"), self.request(method=[]),
                    self.request(id=True), self.request(id={}), self.request(id=None)):
            with self.subTest(bad=bad):
                output, invoked = self.exchange([bad, self.request(id=2)])
                self.assertEqual(output[0]["error"]["code"], -32600)
                self.assertEqual(output[1], {"jsonrpc": "2.0", "id": 2, "result": {}})
                invoked.assert_not_called()

    def test_string_and_numeric_ids_round_trip(self):
        for mid in ("request-1", 0, 1.5):
            output, invoked = self.exchange([self.request(id=mid)])
            self.assertEqual(output, [{"jsonrpc": "2.0", "id": mid, "result": {}}])
            invoked.assert_not_called()

    def test_bad_params_never_fetch_registry_or_invoke_tools(self):
        for params in (None, [], 42, {}, {"name": []}, {"name": ""},
                       {"name": "hub_post", "arguments": []},
                       {"name": "hub_post", "arguments": None}):
            with self.subTest(params=params):
                output, invoked = self.exchange([self.request(method="tools/call", params=params)])
                self.assertEqual(output[0]["error"]["code"], -32602)
                invoked.assert_not_called()

    def test_notifications_have_no_reply_or_hub_effect(self):
        messages = [{"jsonrpc": "2.0", "method": method, "params": params}
                    for method in ("notifications/initialized", "tools/list", "tools/call")
                    for params in ({}, {"name": "hub_post", "arguments": {"body": "private"}}, [])]
        output, invoked = self.exchange(messages + [self.request(id=0)])
        self.assertEqual(output, [{"jsonrpc": "2.0", "id": 0, "result": {}}])
        invoked.assert_not_called()

    def test_failures_do_not_echo_private_details(self):
        for failure in (RuntimeError("PRIVATE_SENTINEL"), KeyError("PRIVATE_SENTINEL"),
                        IndexError("PRIVATE_SENTINEL"), mcp.cli.Fail("PRIVATE_SENTINEL")):
            def call(verb, *args, **kwargs):
                if verb == "fed_verbs":
                    return {"result": []}
                raise failure
            with self.subTest(failure=type(failure).__name__):
                output, _ = self.exchange([
                    self.request(method="tools/call", params={"name": "hub_whoami"}),
                    self.request(id=2),
                ], call)
                self.assertNotIn("PRIVATE_SENTINEL", json.dumps(output))
                if isinstance(failure, mcp.cli.Fail):
                    self.assertTrue(output[0]["result"]["isError"])
                else:
                    self.assertEqual(output[0]["error"]["code"], -32603)
                self.assertEqual(output[1]["result"], {})

    def test_unknown_method_does_not_echo_input(self):
        output, invoked = self.exchange([self.request(method="PRIVATE_SENTINEL")])
        self.assertEqual(output[0]["error"], {"code": -32601, "message": "method not found"})
        invoked.assert_not_called()

    def test_invalid_json_recovers(self):
        for invalid in ("{", "NaN", "[" * 2000):
            output = io.StringIO()
            mcp.main(io.StringIO(invalid + '\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'), output)
            messages = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(messages[0]["error"]["code"], -32700)
            self.assertEqual(messages[1]["result"], {})

    def test_oversized_frame_closes_without_draining_or_dispatch(self):
        stream = io.StringIO("x" * (mcp.MAX_FRAME_CHARS + 100) + "\n")
        output = io.StringIO()
        with patch.object(mcp.cli, "call") as invoked:
            mcp.main(stream, output)
        self.assertEqual(stream.tell(), mcp.MAX_FRAME_CHARS + 1)
        self.assertEqual(json.loads(output.getvalue())["error"]["message"], "request too large")
        invoked.assert_not_called()

    def test_invalid_utf8_closes_with_safe_protocol_error(self):
        output = io.StringIO()
        with io.TextIOWrapper(io.BytesIO(b"\xffPRIVATE_SENTINEL\n"), encoding="utf-8") as stream:
            with patch.object(mcp.cli, "call") as invoked:
                mcp.main(stream, output)
        self.assertEqual(json.loads(output.getvalue()), {
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32700, "message": "parse error"}})
        invoked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
