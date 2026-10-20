"""Offline transport and log-export checks using synthetic credentials only."""

import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock, patch

from taskmgmt import atlassian as atl
from taskmgmt import task


CLOUD = {"deployment": "cloud", "base_url": "https://example.atlassian.net",
         "email": "fixture@example.invalid", "api_token": "synthetic-secret-never-log",
         "jira_project": "TEST", "confluence_space": "DOCS"}
SERVER = {**CLOUD, "deployment": "server", "base_url": "https://jira.example.invalid/jira"}


class TransportTests(unittest.TestCase):
    def response(self, raw=b"{}"):
        response = Mock()
        response.read.return_value = raw
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        return response

    def opener(self, response=None, error=None):
        opener = Mock()
        opener.open.return_value = response or self.response()
        opener.open.side_effect = error
        return opener

    def test_cloud_and_server_auth_headers_and_204(self):
        for cfg in (CLOUD, SERVER):
            with self.subTest(deployment=cfg["deployment"]):
                response = self.response(b"")
                opener = self.opener(response)
                with patch.object(atl.urllib.request, "build_opener", return_value=opener) as build:
                    self.assertEqual(atl.jira_transition(cfg, "TEST-1", 31), {})
                request = opener.open.call_args.args[0]
                expected = ("Basic " + base64.b64encode(
                    f"{cfg['email']}:{cfg['api_token']}".encode()).decode()
                    if cfg["deployment"] == "cloud" else "Bearer " + cfg["api_token"])
                self.assertEqual(request.get_header("Authorization"), expected)
                self.assertEqual(request.get_method(), "POST")
                self.assertEqual(json.loads(request.data), {"transition": {"id": "31"}})
                self.assertEqual(opener.open.call_args.kwargs, {"timeout": atl.TIMEOUT})
                response.read.assert_called_once_with(atl.MAX_RESPONSE + 1)
                self.assertIsInstance(build.call_args.args[0], urllib.request.HTTPSHandler)
                self.assertIsInstance(build.call_args.args[1], atl._NoRedirect)

    def test_redirect_never_builds_another_credential_request(self):
        request = urllib.request.Request(CLOUD["base_url"], headers={"Authorization": "synthetic"})
        handler = atl._NoRedirect()
        for code in (301, 302, 303, 307, 308):
            self.assertIsNone(handler.redirect_request(request, None, code, "redirect", {},
                                                      "https://other.example.invalid"))

    def test_error_hints_keep_status_but_not_server_text(self):
        for code, hint in ((401, "api_token"), (403, "permissions"), (404, "base_url")):
            with self.subTest(code=code):
                content = io.BytesIO(CLOUD["api_token"].encode())
                error = urllib.error.HTTPError("https://private.invalid", code,
                                               CLOUD["api_token"], {}, content)
                with patch.object(atl.urllib.request, "build_opener", return_value=self.opener(error=error)):
                    with self.assertRaises(atl.AtlassianError) as caught:
                        atl.jira_comment(CLOUD, "TEST-1", "fixture")
                self.assertIn(str(code), str(caught.exception))
                self.assertIn(hint, str(caught.exception))
                self.assertNotIn(CLOUD["api_token"], str(caught.exception))
                self.assertFalse(isinstance(caught.exception, atl.OutcomeUnknown))
                self.assertTrue(content.closed)

    def test_lost_write_reply_is_unknown_and_never_retried(self):
        for error in (TimeoutError(CLOUD["api_token"]),
                      urllib.error.URLError(CLOUD["api_token"])):
            opener = self.opener(error=error)
            with patch.object(atl.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(atl.OutcomeUnknown) as caught:
                    atl.jira_create(CLOUD, "fixture")
            self.assertIn("Reconcile", str(caught.exception))
            self.assertNotIn(CLOUD["api_token"], str(caught.exception))
            opener.open.assert_called_once()

    def test_post_search_timeout_is_a_read_failure(self):
        with patch.object(atl.urllib.request, "build_opener",
                          return_value=self.opener(error=TimeoutError("private detail"))):
            with self.assertRaises(atl.AtlassianError) as caught:
                atl.jira_search(CLOUD, "project = TEST")
        self.assertNotIsInstance(caught.exception, atl.OutcomeUnknown)
        self.assertNotIn("private detail", str(caught.exception))

    def test_mutating_5xx_and_redirect_need_reconciliation(self):
        for code in (302, 408, 429, 500, 503):
            error = urllib.error.HTTPError("https://fixture.invalid", code, "private detail", {}, io.BytesIO(b"private"))
            opener = self.opener(error=error)
            with patch.object(atl.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(atl.OutcomeUnknown):
                    atl.jira_transition(CLOUD, "TEST-1", "31")
            opener.open.assert_called_once()

    def test_response_is_bounded_and_malformed_write_receipt_is_unknown(self):
        for raw in (b"x" * (atl.MAX_RESPONSE + 1), b"[]", b"\xff", b"not-json"):
            with self.subTest(length=len(raw)):
                response = self.response(raw)
                with patch.object(atl.urllib.request, "build_opener", return_value=self.opener(response)):
                    with self.assertRaises(atl.OutcomeUnknown):
                        atl.jira_comment(CLOUD, "TEST-1", "fixture")
                response.__exit__.assert_called_once()

    def test_target_validation_happens_before_transport(self):
        with patch.object(atl.urllib.request, "build_opener") as opener:
            for base in ("http://example.invalid", "https://user:secret@example.invalid",
                         "https://example.invalid?q=secret", "https://example.invalid/#secret",
                         "https://example.invalid/../other", "https://example.invalid/%0aheader",
                         "https://example.invalid:bad", "https://example.invalid\\other"):
                with self.subTest(base=base), self.assertRaises(atl.AtlassianError):
                    atl.whoami({**CLOUD, "base_url": base})
            for key in ("../TEST-1", "TEST-1/comment", "TEST-1?other", "test-1", None):
                with self.assertRaises(atl.AtlassianError):
                    atl.jira_comment(CLOUD, key, "fixture")
            for transition in (True, "31/other", "31\n", None):
                with self.assertRaises(atl.AtlassianError):
                    atl.jira_transition(CLOUD, "TEST-1", transition)
        opener.assert_not_called()

    def test_dry_run_preserves_payloads_without_auth_or_network(self):
        with patch.object(atl.urllib.request, "build_opener") as opener:
            cloud = atl.jira_create(CLOUD, "fixture", "line one\nline two", labels=["fixture"], dry_run=True)
            server = atl.jira_comment(SERVER, "TEST-1", "fixture text", dry_run=True)
            page = atl.confluence_upsert(CLOUD, "fixture", "<p>text</p>", parent_id=42, dry_run=True)
        opener.assert_not_called()
        self.assertEqual(cloud["body"]["fields"]["project"], {"key": "TEST"})
        self.assertEqual(cloud["body"]["fields"]["description"]["content"][1]["content"][0]["text"], "line two")
        self.assertEqual(server["body"], {"body": "fixture text"})
        self.assertIn("/jira/rest/api/2/", server["url"])
        self.assertEqual(page["body"]["ancestors"], [{"id": "42"}])
        self.assertNotIn(CLOUD["api_token"], json.dumps([cloud, server, page]))

    def test_confluence_uses_retained_id_and_next_version(self):
        receipt = {"id": "42", "title": "fixture", "type": "page",
                   "space": {"key": "DOCS"}, "version": {"number": 8}}
        with patch.object(atl, "confluence_find", return_value={"results": [{"id": "42", "title": "fixture", "version": {"number": 7}}]}), \
                patch.object(atl, "request", return_value=receipt) as request:
            self.assertEqual(atl.confluence_upsert(CLOUD, "fixture", "<p>new</p>"), receipt)
        self.assertEqual(request.call_args.args[1:3], ("PUT", "/wiki/rest/api/content/42"))
        self.assertEqual(request.call_args.args[3]["version"], {"number": 8})

    def test_ambiguous_page_or_missing_version_cannot_update(self):
        for results in (None, {}, [{"id": "42", "title": "fixture"}],
                        [{"id": "42", "title": "fixture", "version": "invalid"}],
                        [{"id": "42", "version": {"number": 1}}],
                        [{"id": "42"}, {"id": "43"}],
                        [{"id": "42/other", "title": "fixture", "version": {"number": 1}}]):
            with patch.object(atl, "confluence_find", return_value={"results": results}), \
                    patch.object(atl, "request") as request:
                with self.assertRaises(atl.AtlassianError):
                    atl.confluence_upsert(CLOUD, "fixture", "text")
                request.assert_not_called()

    def test_write_receipts_must_identify_the_selected_target(self):
        for receipt in ({}, {"key": "OTHER-1"}, {"key": CLOUD["api_token"]}):
            with patch.object(atl, "request", return_value=receipt) as request:
                with self.assertRaises(atl.OutcomeUnknown):
                    atl.jira_create(CLOUD, "fixture")
                request.assert_called_once()
        found = {"results": [{"id": "42", "title": "fixture", "version": {"number": 2}}]}
        for receipt in ({}, {"id": "43"}, {"id": CLOUD["api_token"]}):
            with patch.object(atl, "confluence_find", return_value=found), \
                    patch.object(atl, "request", return_value=receipt) as request:
                with self.assertRaises(atl.OutcomeUnknown):
                    atl.confluence_upsert(CLOUD, "fixture", "text")
                request.assert_called_once()

    def test_invalid_parent_is_rejected_before_lookup(self):
        with patch.object(atl, "confluence_find") as lookup:
            with self.assertRaises(atl.AtlassianError):
                atl.confluence_upsert(CLOUD, "fixture", "text", parent_id="42/other")
            lookup.assert_not_called()

    def test_paginated_lookup_cannot_create_a_page(self):
        with patch.object(atl, "confluence_find", return_value={"results": [], "_links": {"next": "unread"}}), \
                patch.object(atl, "request") as request:
            with self.assertRaises(atl.AtlassianError):
                atl.confluence_upsert(CLOUD, "fixture", "text")
            request.assert_not_called()

    def test_comment_without_receipt_stops_done_before_transition(self):
        with patch.object(atl, "request", return_value={}), \
                patch.object(task.atl, "load_config", return_value=CLOUD), \
                patch.object(task, "read_agent_log", return_value="fixture"), \
                patch.object(task, "pick_transition") as transition, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(task.main(["done", "TEST-1", "--from-log", "agent"]), 1)
        transition.assert_not_called()

    def test_confluence_receipt_must_match_title_space_type_and_version(self):
        receipt = {"id": "42", "title": "fixture", "type": "page",
                   "space": {"key": "DOCS"}, "version": {"number": 3}}
        changes = ({"title": "other"}, {"space": {"key": "OTHER"}},
                   {"type": "blogpost"}, {"version": {"number": 2}}, {"version": None})
        found = {"results": [{"id": "42", "title": "fixture", "version": {"number": 2}}]}
        for change in changes:
            with patch.object(atl, "confluence_find", return_value=found), \
                    patch.object(atl, "request", return_value={**receipt, **change}) as request:
                with self.assertRaises(atl.OutcomeUnknown):
                    atl.confluence_upsert(CLOUD, "fixture", "text")
                request.assert_called_once()


class LocalFileTests(unittest.TestCase):
    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix="agentmux-atlassian-offline-")
        self.addCleanup(fixture.cleanup)
        self.home = Path(fixture.name)

    def test_config_preserves_unknown_values_and_rejects_links_modes_and_size(self):
        path = self.home / "config.json"
        expected = {**CLOUD, "extension": {"retained": True}}
        path.write_text(json.dumps(expected))
        path.chmod(0o600)
        self.assertEqual(atl.load_config(path), expected)
        linked = self.home / "linked.json"
        linked.symlink_to(path)
        with self.assertRaises(atl.AtlassianError):
            atl.load_config(linked)
        linked.unlink()
        os.link(path, linked)
        with self.assertRaises(atl.AtlassianError):
            atl.load_config(path)
        linked.unlink()
        path.chmod(0o644)
        with self.assertRaises(atl.AtlassianError):
            atl.load_config(path)
        path.chmod(0o600)
        path.write_text("x" * (atl.MAX_CONFIG + 1))
        with self.assertRaises(atl.AtlassianError):
            atl.load_config(path)

    def test_log_tail_is_bounded_and_controls_are_removed(self):
        log = self.home / "agent.log"
        log.write_bytes(b"old" * 200 + b"\nkeep\x1b[31m color\x1b[0m\x1b]title\x1b\\\r\nlast\x00\x07\n")
        with patch.object(task, "LOG_DIR", self.home):
            result = task.read_agent_log("agent", 80)
        self.assertLessEqual(len(result.encode()), 80)
        self.assertIn("keep color\nlast", result)
        self.assertNotIn("title", result)
        self.assertFalse(any(ord(c) < 32 and c not in "\n\t" for c in result))

    def test_log_refuses_traversal_symlink_hardlink_and_fifo(self):
        target = self.home / "private"
        target.write_text(CLOUD["api_token"])
        log = self.home / "agent.log"
        with patch.object(task, "LOG_DIR", self.home):
            for name in ("../private", "agent\n", "/private"):
                with self.assertRaises(atl.AtlassianError):
                    task.read_agent_log(name)
            log.symlink_to(target)
            with self.assertRaises(atl.AtlassianError):
                task.read_agent_log("agent")
            log.unlink()
            os.link(target, log)
            with self.assertRaises(atl.AtlassianError):
                task.read_agent_log("agent")
            log.unlink()
            os.mkfifo(log)
            with self.assertRaises(atl.AtlassianError):
                task.read_agent_log("agent")

    def test_task_create_missing_receipt_never_prints_remote_body(self):
        output = io.StringIO()
        with patch.object(task.atl, "load_config", return_value=CLOUD), \
                patch.object(task.atl, "jira_create", return_value={"unexpected": CLOUD["api_token"]}), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = task.main(["create", "--summary", "fixture"])
        self.assertEqual(result, 1)
        self.assertIn("reconcile", output.getvalue())
        self.assertNotIn(CLOUD["api_token"], output.getvalue())

    def test_whoami_without_name_does_not_print_raw_response(self):
        output = io.StringIO()
        with patch.object(task.atl, "load_config", return_value=CLOUD), \
                patch.object(task.atl, "whoami", return_value={"unexpected": CLOUD["api_token"]}), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(task.main(["whoami"]), 1)
        self.assertNotIn(CLOUD["api_token"], output.getvalue())

    def test_report_builds_link_from_configured_site_and_receipt(self):
        for cfg, expected in ((CLOUD, "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=42"),
                              (SERVER, "https://jira.example.invalid/jira/pages/viewpage.action?pageId=42")):
            output = io.StringIO()
            with patch.object(task.atl, "load_config", return_value=cfg), \
                    patch.object(task, "read_agent_log", return_value="fixture"), \
                    patch.object(task.atl, "confluence_upsert", return_value={"id": "42", "_links": {"webui": CLOUD["api_token"]}}), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(task.main(["report", "agent"]), 0)
            self.assertEqual(output.getvalue().strip(), expected)

    def test_transition_display_redacts_credentials_and_terminal_controls(self):
        output = io.StringIO()
        name = "Done " + CLOUD["api_token"] + "\x1b]private-title\x07\x1b[31m"
        with patch.object(task.atl, "load_config", return_value=CLOUD), \
                patch.object(task.atl, "jira_transitions", return_value={"transitions": [{"id": "31", "name": name}]}), \
                contextlib.redirect_stdout(output):
            self.assertEqual(task.main(["transitions", "TEST-1"]), 0)
        self.assertIn("Done [redacted]", output.getvalue())
        self.assertNotIn(CLOUD["api_token"], output.getvalue())
        self.assertNotIn("private-title", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())

    def test_invalid_transition_entry_or_pattern_cannot_select_a_write(self):
        with patch.object(task.atl, "jira_transitions", return_value={"transitions": [{"id": "31/private", "name": "Done"}]}):
            with self.assertRaises(atl.AtlassianError):
                task.pick_transition(CLOUD, "TEST-1", "Done")
        with patch.object(task.atl, "jira_transitions", return_value={"transitions": [{"id": "31", "name": "Done"}]}):
            with self.assertRaises(atl.AtlassianError):
                task.pick_transition(CLOUD, "TEST-1", "[")


if __name__ == "__main__":
    unittest.main()
