"""Offline enrolled MCP boundary checks; application binding is not qualified."""
import io
import json
import unittest
from unittest.mock import patch

from hub.client_launch_coordinator import human_summary, result
from hub.fed import mcp


class EnrolledMcp(unittest.TestCase):
    def request(self, method, params=None, mid=1):
        return {"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}

    def exchange(self, started, messages):
        output = io.StringIO()
        with patch.object(mcp.cli, "call") as call, \
                patch.object(mcp, "fed_tools") as registry, \
                patch("hub.client_launch_coordinator.startup") as startup, \
                patch.object(started, "finish_cleanup") as cleanup:
            mcp.main(io.StringIO("".join(json.dumps(m) + "\n" for m in messages)),
                     output, startup_result=started)
        call.assert_not_called()
        registry.assert_not_called()
        startup.assert_not_called()
        cleanup.assert_not_called()  # The adapter owns cleanup, including EOF.
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_status_only_for_every_startup_outcome(self):
        for outcome in ("setup_required", "failed", "observed", "progress"):
            with self.subTest(outcome=outcome):
                started = result("ensure", outcome)
                messages = [self.request("initialize"), self.request("tools/list", mid=2)]
                messages += [self.request("tools/call", {"name": "agentmux_startup_status"}, mid=i)
                             for i in (3, 4)]
                replies = self.exchange(started, messages)
                self.assertIn("Application access is unavailable", replies[0]["result"]["instructions"])
                tools = replies[1]["result"]["tools"]
                self.assertEqual([t["name"] for t in tools], ["agentmux_startup_status"])
                self.assertFalse(tools[0]["inputSchema"]["additionalProperties"])
                for reply in replies[2:]:
                    self.assertEqual(reply["result"]["structuredContent"], started.public)
                    self.assertEqual(reply["result"]["content"],
                                     [{"type": "text", "text": human_summary(started)}])
                    self.assertFalse(reply["result"]["isError"])

    def test_application_tools_refused_even_with_legacy_cache(self):
        started = result("status", "observed")
        for name in ("hub_whoami", "hub_post", "fed_verbs", "unknown"):
            request = self.request("tools/call", {"name": name, "arguments": {"secret": "PRIVATE"}})
            response = self.exchange(started, [request])[0]["result"]
            self.assertEqual(response, {"content": [{"type": "text", "text":
                                                     "Application access is unavailable."}], "isError": True})
            with patch.object(mcp.cli, "call") as call:
                self.assertEqual(mcp.handle(request, dict(mcp.CORE), startup_result=started), response)
            call.assert_not_called()

    def test_notifications_do_not_return_status_or_dispatch(self):
        started = result("status", "observed")
        notifications = [{"jsonrpc": "2.0", "method": method, "params": params}
                         for method in ("tools/list", "tools/call")
                         for params in ({"name": "agentmux_startup_status"}, {"name": "hub_post"})]
        self.assertEqual(self.exchange(started, notifications + [self.request("ping")]),
                         [{"jsonrpc": "2.0", "id": 1, "result": {}}])

    def test_status_arguments_and_malformed_requests_fail_safely(self):
        started = result("ensure", "failed")
        messages = [self.request("tools/call", {"name": "agentmux_startup_status", "arguments": args})
                    for args in ({"selection": "PRIVATE"}, [], None)]
        messages += [[], self.request("ping", mid=5)]
        replies = self.exchange(started, messages)
        self.assertEqual([r["error"]["code"] for r in replies[:-1]], [-32602] * 3 + [-32600])
        self.assertNotIn("PRIVATE", json.dumps(replies))
        self.assertEqual(replies[-1]["result"], {})


if __name__ == "__main__":
    unittest.main()
