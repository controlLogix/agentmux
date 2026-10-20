"""Offline checks using temporary homes and synthetic credentials only."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
import warnings
from unittest.mock import patch

from taskmgmt import provider_setup as setup


REPO = Path(__file__).resolve().parent.parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProviderSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agentmux-provider-setup-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = self.root / "env"
        self.reference = setup.LocalSecretReference("xai", "XAI_API_KEY")
        self.secret = " fake-$HOME-$(not-a-command)-`not-a-command`-'quoted'-;*\\value "
        self.output = io.StringIO()

    def write_env(self, body):
        self.env.write_bytes(body)
        self.env.chmod(0o600)

    def test_literal_key_preserves_other_entries_comments_and_special_characters(self):
        before = b"# retained\r\nOTHER_KEY='unchanged ; $text'\r\nexport OPENAI_API_KEY=literal\nXAI_API_KEY=old\nexport XAI_API_KEY=duplicate\nTAIL=unchanged"
        self.write_env(before)
        with patch.object(subprocess, "run", side_effect=AssertionError("no process")):
            setup.store_secret(self.env, self.reference, self.secret)
        after = self.env.read_bytes()
        self.assertTrue(after.startswith(b"# retained\r\nOTHER_KEY='unchanged ; $text'\r\nexport OPENAI_API_KEY=literal\n"))
        self.assertTrue(after.endswith(b"TAIL=unchanged"))
        self.assertEqual(setup.env_values(after)["XAI_API_KEY"], self.secret)
        self.assertEqual(after.count(b"export XAI_API_KEY="), 1)
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o600)

    def test_unsupported_executable_env_content_is_preserved_and_not_evaluated(self):
        for body in (b"XAI_API_KEY=$(echo private)\n", b"export XAI_API_KEY=$OTHER\n", b"echo private\n", b"XAI_API_KEY=~user\n"):
            with self.subTest(body=body):
                self.write_env(body)
                with self.assertRaises(setup.SetupError):
                    setup.store_secret(self.env, self.reference, self.secret)
                self.assertEqual(self.env.read_bytes(), body)

    def test_unsafe_files_and_oversized_content_are_rejected_without_values(self):
        target = self.root / "other"
        target.write_text(self.secret)
        target.chmod(0o600)
        self.env.symlink_to(target)
        with self.assertRaises(setup.SetupError):
            setup.store_secret(self.env, self.reference, "new")
        self.assertEqual(target.read_text(), self.secret)
        self.env.unlink()
        for mode, body in ((0o644, b"XAI_API_KEY=synthetic"), (0o600, b"#" * 65537)):
            self.write_env(body)
            self.env.chmod(mode)
            with contextlib.redirect_stdout(self.output):
                self.assertEqual(setup.verify_grok(self.root), 1)
        self.assertNotIn("synthetic", self.output.getvalue())
        self.assertNotIn(self.secret, self.output.getvalue())

    def test_hidden_prompt_preserves_whitespace_and_no_value_reaches_output(self):
        with patch.dict(os.environ, {"AGENTMUX_HOME": str(self.root)}), patch.object(setup.getpass, "getpass", side_effect=[self.secret, self.secret]), contextlib.redirect_stdout(self.output):
            self.assertEqual(setup.main(["enter-key"]), 0)
        self.assertEqual(setup.env_values(self.env.read_bytes())["XAI_API_KEY"], self.secret)
        self.assertNotIn(self.secret, self.output.getvalue())
        self.assertNotIn("fake-", self.output.getvalue())

    def test_getpass_echo_fallback_is_refused(self):
        def unsafe_prompt(_):
            warnings.warn("echo unavailable", setup.getpass.GetPassWarning)
            return self.secret
        with patch.object(setup.getpass, "getpass", side_effect=unsafe_prompt):
            with self.assertRaises(setup.SetupError):
                setup.prompt_secret("XAI_API_KEY")
        self.assertFalse(self.env.exists())

    def test_empty_and_mismatched_terminal_entries_can_be_retried_without_echo(self):
        with patch.object(setup.getpass, "getpass", side_effect=["", "first", "second", self.secret, self.secret]), contextlib.redirect_stdout(self.output):
            self.assertEqual(setup.prompt_secret("XAI_API_KEY"), self.secret)
        self.assertNotIn(self.secret, self.output.getvalue())
        self.assertIn("entries differ", self.output.getvalue())

    def test_default_diagnostics_never_call_a_client_or_network(self):
        self.write_env(("export XAI_API_KEY=" + setup.shell_quote(self.secret) + "\n").encode())
        with patch.object(subprocess, "run", side_effect=AssertionError("no process")), patch.object(socket, "socket", side_effect=AssertionError("no network")), contextlib.redirect_stdout(self.output):
            self.assertEqual(setup.verify_grok(self.root), 2)
        self.assertIn("UNKNOWN", self.output.getvalue())
        self.assertNotIn(self.secret, self.output.getvalue())

    def test_typed_reference_and_literal_validation_do_not_include_values(self):
        for provider, name in (("unknown", "XAI_API_KEY"), ("xai", "OPENAI_API_KEY")):
            with self.assertRaises(setup.SetupError):
                setup.LocalSecretReference(provider, name)
        for secret in ("", " \t", "invalid\nvalue", "invalid\rvalue", "invalid\x00value"):
            with self.assertRaises(setup.SetupError):
                setup.store_secret(self.env, self.reference, secret)
        self.assertFalse(self.env.exists())

    def test_unicode_secret_characters_are_literal_and_round_trip(self):
        value = "synthetic-é-\u2028-\u2029-$()-'quote'"
        setup.store_secret(self.env, self.reference, value)
        self.assertEqual(setup.env_values(self.env.read_bytes())["XAI_API_KEY"], value)

    def test_exposure_check_never_opens_content_or_default_third_party_files(self):
        self.write_env(self.secret.encode())
        link = self.root / "auth.json"
        link.symlink_to(self.env)
        with patch.dict(os.environ, {"AGENTMUX_HOME": str(self.root)}), patch("builtins.open", side_effect=AssertionError("no content read")), patch.object(Path, "read_text", side_effect=AssertionError("no content read")), patch.object(os, "open", side_effect=AssertionError("no content read")), contextlib.redirect_stdout(self.output):
            self.assertEqual(setup.main(["check-exposure"]), 0)
        output = self.output.getvalue()
        self.assertNotIn(self.secret, output)
        self.assertNotIn(".claude", output)
        self.assertIn("private file permissions", output)
        self.assertIn("symlink; target not inspected", output)
        self.assertNotIn("sha256", output)


class PermissionSetupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="agentmux-permission-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "agentmux.sh").write_text("#!/bin/sh\n")
        self.path = self.root / "settings.json"
        self.original = b'{"permissions":{"allow":["Bash(git status)"],"deny":["Bash(rm *)"]},"other":{"nested":[1,"preserve"]}}\n'
        self.path.write_bytes(self.original)
        self.tool = load_module("fixture_permission_setup", REPO / "add-allow-rule.py")

    def test_preview_then_exact_apply_preserves_other_values_and_private_backup(self):
        preview = self.tool.update_permission(self.path, self.root)
        self.assertEqual(preview["state"], "preview")
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(list(self.root.glob("*.bak-*")), [])
        self.assertIn(str(self.root / "agentmux.sh"), preview["rule"])
        applied = self.tool.update_permission(self.path, self.root, preview["rule"])
        self.assertEqual(applied["state"], "applied")
        expected = json.loads(self.original)
        expected["permissions"]["allow"].append(preview["rule"])
        self.assertEqual(json.loads(self.path.read_bytes()), expected)
        backup = self.root / applied["backup"]
        self.assertEqual(backup.read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        again = self.tool.update_permission(self.path, self.root, preview["rule"])
        self.assertEqual(again["state"], "present")
        self.assertEqual(len(list(self.root.glob("*.bak-*"))), 1)

    def test_wrong_approval_and_malformed_settings_never_write(self):
        with self.assertRaises(setup.SetupError):
            self.tool.update_permission(self.path, self.root, "Bash(other:*)")
        self.assertEqual(self.path.read_bytes(), self.original)
        for raw in (b"[]", b'{"permissions":[]}', b'{"permissions":{"allow":"all"}}', b'{"key":1,"key":2}'):
            self.path.write_bytes(raw)
            rule = self.tool.permission_rule(self.root)
            with self.assertRaises(setup.SetupError):
                self.tool.update_permission(self.path, self.root, rule)
            self.assertEqual(self.path.read_bytes(), raw)
            self.assertEqual(list(self.root.glob("*.bak-*")), [])

    def test_existing_backups_survive_and_replacement_failure_retains_new_backup(self):
        prior = self.root / "settings.json.bak-existing"
        prior.write_text("older backup")
        rule = self.tool.permission_rule(self.root)
        with patch.object(setup.os, "replace", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError):
                self.tool.update_permission(self.path, self.root, rule)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(prior.read_text(), "older backup")
        fresh = [path for path in self.root.glob("*.bak-*") if path != prior]
        self.assertEqual(len(fresh), 1)
        self.assertEqual(fresh[0].read_bytes(), self.original)


class AuthDisplayTests(unittest.TestCase):
    def test_display_ignores_values_and_untrusted_server_text(self):
        tool = load_module("fixture_show_auth", REPO / "dashboard/show_auth.py")
        manifest = json.loads((REPO / "dashboard/auth.json").read_text())
        secret = "SYNTHETIC-DO-NOT-DISPLAY"
        snapshot = {"active": {"codex": secret}, "providers": [{"id": "custom", "configured": True,
            "settings": [{"key": "unexpected", "value": secret, "set": True}],
            "secrets": [{"name": "CODEX_CUSTOM_API_KEY", "value": secret, "set": True}],
            "methods": [{"id": "codex-custom", "configured": True, "settings": [{"key": "model", "value": secret}]}]}]}
        output = tool.render_auth(snapshot, manifest)
        self.assertNotIn(secret, output)
        self.assertIn("CODEX_CUSTOM_API_KEY: present", output)
        self.assertIn("unverified", output)


if __name__ == "__main__":
    unittest.main()
