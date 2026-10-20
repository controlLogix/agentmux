"""Offline checks for private, atomic Atlassian setup in a disposable home."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


class AtlassianSetupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="agentmux-atlassian-setup-")
        self.addCleanup(self.fixture.cleanup)
        self.home = Path(self.fixture.name)
        with patch.dict(os.environ, {"AGENTMUX_HOME": str(self.home)}):
            spec = importlib.util.spec_from_file_location(
                "fixture_setup_atlassian", Path(__file__).with_name("setup_atlassian.py"))
            self.setup = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.setup)
        self.secret = "fixture-secret-must-not-appear-in-output"
        self.output = io.StringIO()

    def configure(self, overwrite=False):
        answers = (["yes"] if overwrite else []) + [
            "cloud", "https://example.atlassian.net", "fixture@example.com",
            "AMUX", "DOCS", "done",
        ]
        with patch("builtins.input", side_effect=answers), patch.object(
            self.setup.getpass, "getpass", return_value=self.secret
        ), contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.output):
            return self.setup.main()

    def test_private_write_preserves_unrelated_files_and_hides_secret(self):
        unrelated = self.home / "user-config.json"
        unrelated.write_text('{"keep": "unchanged"}\n')
        self.assertEqual(self.configure(), 0)
        self.assertEqual(json.loads(self.setup.CONFIG.read_text())["api_token"], self.secret)
        self.assertEqual(stat.S_IMODE(self.setup.CONFIG.stat().st_mode), 0o600)
        self.assertEqual(unrelated.read_text(), '{"keep": "unchanged"}\n')
        self.assertNotIn(self.secret, self.output.getvalue())
        self.assertEqual(list(self.home.glob(".atlassian.json.*")), [])

    def test_predictable_temp_symlink_and_target_are_untouched(self):
        target = self.home / "keep.txt"
        target.write_text("unrelated content")
        old_temp = self.setup.CONFIG.with_name(f"atlassian.json.tmp.{os.getpid()}")
        old_temp.symlink_to(target)
        self.assertEqual(self.configure(), 0)
        self.assertTrue(old_temp.is_symlink())
        self.assertEqual(target.read_text(), "unrelated content")
        self.assertNotIn(self.secret, self.output.getvalue())

    def test_failed_replace_keeps_original_and_removes_private_temp(self):
        original = '{"existing": "preserve this configuration"}\n'
        self.setup.CONFIG.write_text(original)
        previous_umask = os.umask(0o027)
        try:
            with patch.object(self.setup.os, "replace", side_effect=OSError("fixture failure")):
                with self.assertRaisesRegex(OSError, "fixture failure"):
                    self.configure(overwrite=True)
            restored_umask = os.umask(0o027)
            self.assertEqual(restored_umask, 0o027)
        finally:
            os.umask(previous_umask)
        self.assertEqual(self.setup.CONFIG.read_text(), original)
        self.assertEqual(list(self.home.glob(".atlassian.json.*")), [])
        self.assertNotIn(self.secret, self.output.getvalue())

    def test_declining_overwrite_leaves_existing_config_unchanged(self):
        original = '{"existing": "keep"}\n'
        self.setup.CONFIG.write_text(original)
        with patch("builtins.input", return_value="no"), patch.object(
            self.setup.getpass, "getpass"
        ) as secret_prompt, contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.main(), 0)
        secret_prompt.assert_not_called()
        self.assertEqual(self.setup.CONFIG.read_text(), original)
        self.assertEqual(list(self.home.glob(".atlassian.json.*")), [])

    def test_overwrite_preserves_unrelated_keys(self):
        self.setup.CONFIG.write_text(json.dumps({"extension": {"keep": True}, "email": "old@example.com"}))
        self.assertEqual(self.configure(overwrite=True), 0)
        saved = json.loads(self.setup.CONFIG.read_text())
        self.assertEqual(saved["extension"], {"keep": True})
        self.assertEqual(saved["email"], "fixture@example.com")
        self.assertNotIn(self.secret, self.output.getvalue())

    def test_existing_symlinks_and_invalid_config_are_not_replaced(self):
        target = self.home / "missing-target"
        self.setup.CONFIG.symlink_to(target)
        with patch("builtins.input") as prompt, contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.main(), 1)
        prompt.assert_not_called()
        self.assertTrue(self.setup.CONFIG.is_symlink())
        self.assertFalse(target.exists())
        self.setup.CONFIG.unlink()
        self.setup.CONFIG.write_text("invalid private configuration")
        with patch("builtins.input") as prompt, contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.main(), 1)
        prompt.assert_not_called()
        self.assertEqual(self.setup.CONFIG.read_text(), "invalid private configuration")
        self.assertNotIn("invalid private configuration", self.output.getvalue())

    def test_existing_hardlinked_configuration_is_not_read_or_replaced(self):
        target = self.home / "other-owner-file"
        original = '{"existing": "preserve"}\n'
        target.write_text(original)
        os.link(target, self.setup.CONFIG)
        with patch("builtins.input") as prompt, contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.main(), 1)
        prompt.assert_not_called()
        self.assertEqual(target.read_text(), original)
        self.assertEqual(self.setup.CONFIG.stat().st_ino, target.stat().st_ino)

    def test_new_configuration_created_during_prompts_is_preserved(self):
        real_link = self.setup.os.link
        concurrent = '{"extension": "concurrent writer"}\n'
        def publish(source, destination):
            self.setup.CONFIG.write_text(concurrent)
            return real_link(source, destination)
        with patch.object(self.setup.os, "link", side_effect=publish):
            self.assertEqual(self.configure(), 1)
        self.assertEqual(self.setup.CONFIG.read_text(), concurrent)
        self.assertEqual(list(self.home.glob(".atlassian.json.*")), [])
        self.assertNotIn(self.secret, self.output.getvalue())

    def test_existing_configuration_changed_during_prompts_is_preserved(self):
        self.setup.CONFIG.write_text('{"extension": "original"}\n')
        concurrent = '{"extension": "new edit"}\n'
        real_mkstemp = self.setup.tempfile.mkstemp
        def create_temporary(**kwargs):
            self.setup.CONFIG.write_text(concurrent)
            return real_mkstemp(**kwargs)
        with patch.object(self.setup.tempfile, "mkstemp", side_effect=create_temporary):
            self.assertEqual(self.configure(overwrite=True), 1)
        self.assertEqual(self.setup.CONFIG.read_text(), concurrent)
        self.assertEqual(list(self.home.glob(".atlassian.json.*")), [])
        self.assertNotIn(self.secret, self.output.getvalue())

    def test_secret_prompt_without_echo_control_refuses_before_write(self):
        with patch("builtins.input", side_effect=["cloud", "https://example.atlassian.net", "fixture@example.com"]), \
                patch.object(self.setup.getpass, "getpass", side_effect=self.setup.getpass.GetPassWarning()), \
                contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.main(), 1)
        self.assertFalse(self.setup.CONFIG.exists())
        self.assertIn("disable echo", self.output.getvalue())

    def test_invalid_endpoint_is_reprompted_without_writing_credentials(self):
        answers = ["cloud", "https://user:private@example.invalid", "https://example.atlassian.net",
                   "fixture@example.com", "AMUX", "DOCS", "done"]
        with patch("builtins.input", side_effect=answers), \
                patch.object(self.setup.getpass, "getpass", return_value=self.secret), \
                contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.main(), 0)
        saved = json.loads(self.setup.CONFIG.read_text())
        self.assertEqual(saved["base_url"], "https://example.atlassian.net")
        self.assertNotIn("user:private", self.output.getvalue())

    def test_rotation_preserves_server_target_and_transition_defaults(self):
        original = {"deployment": "server", "base_url": "https://jira.example.invalid/context",
                    "api_token": "old-synthetic", "email": "retained@example.invalid",
                    "jira_project": "OLD", "confluence_space": "MixedCaseSpace",
                    "done_transition": "Ready for review", "extension": {"keep": True}}
        self.setup.CONFIG.write_text(json.dumps(original))
        with patch("builtins.input", side_effect=["yes", "", "", "", "", ""]), \
                patch.object(self.setup.getpass, "getpass", return_value=self.secret), \
                contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.main(), 0)
        self.assertEqual(json.loads(self.setup.CONFIG.read_text()), {**original, "api_token": self.secret})
        self.assertNotIn("old-synthetic", self.output.getvalue())

    def test_optional_selection_is_cleared_only_explicitly(self):
        original = {"deployment": "server", "base_url": "https://jira.example.invalid",
                    "api_token": "old-synthetic", "jira_project": "OLD",
                    "confluence_space": "DOCS", "done_transition": "Reviewed"}
        self.setup.CONFIG.write_text(json.dumps(original))
        with patch("builtins.input", side_effect=["yes", "", "", "-", "", ""]), \
                patch.object(self.setup.getpass, "getpass", return_value=self.secret), \
                contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.main(), 0)
        saved = json.loads(self.setup.CONFIG.read_text())
        self.assertNotIn("jira_project", saved)
        self.assertEqual(saved["confluence_space"], "DOCS")
        self.assertEqual(saved["done_transition"], "Reviewed")


if __name__ == "__main__":
    unittest.main()
