"""Offline fixture checks for preserving native Codex configuration."""
import contextlib
import builtins
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import socket
import tempfile
import unittest
from unittest.mock import patch


class SetupAuthSafetyTests(unittest.TestCase):
    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix="agentmux-setup-auth-")
        self.addCleanup(fixture.cleanup)
        self.home = Path(fixture.name)
        env = patch.dict(os.environ, {"HOME": str(self.home),
            "AGENTMUX_HOME": str(self.home / ".agentmux"), "CODEX_HOME": str(self.home / ".codex")})
        env.start()
        self.addCleanup(env.stop)
        spec = importlib.util.spec_from_file_location("fixture_setup_auth", Path(__file__).with_name("setup_auth.py"))
        self.setup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.setup)
        self.manifest = self.setup.Manifest()
        self.method = self.manifest.methods["codex-custom"]
        self.values = {"model": "fixture-model", "gateway_base_url": "http://localhost:4000/v1"}
        self.path = self.setup.codex_home() / "codex-custom.config.toml"
        self.path.parent.mkdir()
        self.output = io.StringIO()
        self.secret = "SENTINEL-PRIVATE-CONTENT"

    def prepare_settings(self):
        self.setup.ROOT.mkdir()
        settings = {"version": 2, "active": {}, "providers": {}, "methods": {"codex-custom": self.values}}
        self.setup.SETTINGS.write_text(json.dumps(settings))
        self.setup.SETTINGS.chmod(0o600)
        self.setup.ENV_FILE.write_text(f"export CODEX_CUSTOM_API_KEY='{self.secret}'\n")
        self.setup.ENV_FILE.chmod(0o600)

    def test_existing_profile_conflict_precedes_prompts_and_settings_changes(self):
        self.prepare_settings()
        before = self.setup.SETTINGS.read_bytes()
        self.path.write_text(self.secret)
        with patch("builtins.input") as prompt, patch.object(self.setup, "configure_provider") as provider:
            with self.assertRaises(SystemExit) as raised:
                self.setup.configure_method("codex-custom", self.manifest)
        prompt.assert_not_called()
        provider.assert_not_called()
        self.assertIn("preserved", str(raised.exception))
        self.assertNotIn(self.secret, str(raised.exception))
        self.assertEqual(self.path.read_text(), self.secret)
        self.assertEqual(self.setup.SETTINGS.read_bytes(), before)

    def test_symlink_including_dangling_destination_is_preserved(self):
        for existing in (False, True):
            target = self.home / "target"
            if existing:
                target.write_text(self.secret)
            self.path.symlink_to(target)
            with self.assertRaises(SystemExit):
                self.setup.write_codex_profile(self.method, self.values)
            self.assertTrue(self.path.is_symlink())
            self.assertEqual(target.exists(), existing)
            if existing:
                self.assertEqual(target.read_text(), self.secret)
            self.path.unlink()

    def test_new_profile_is_private_and_unrelated_native_files_survive(self):
        unrelated = self.path.parent / "config.toml"
        unrelated.write_text(self.secret)
        with contextlib.redirect_stdout(self.output):
            self.setup.write_codex_profile(self.method, self.values)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(unrelated.read_text(), self.secret)
        self.assertNotIn(self.secret, self.output.getvalue())
        self.assertEqual(list(self.path.parent.glob(".codex-custom.config.toml.*")), [])

    def test_publish_race_preserves_new_destination_and_cleans_temp(self):
        original_link = os.link
        def race(source, destination):
            self.path.write_text(self.secret)
            return original_link(source, destination)
        with patch.object(self.setup.os, "link", side_effect=race):
            with self.assertRaises(SystemExit):
                self.setup.write_codex_profile(self.method, self.values)
        self.assertEqual(self.path.read_text(), self.secret)
        self.assertEqual(list(self.path.parent.glob(".codex-custom.config.toml.*")), [])

    def test_valid_syntax_is_unknown_and_does_not_start_client(self):
        self.prepare_settings()
        self.path.write_text(f'model = "{self.secret}"\n')
        with patch.object(subprocess, "run", side_effect=AssertionError("client must not run")), contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.verify("codex-custom", self.manifest), 2)
        self.assertIn("UNKNOWN", self.output.getvalue())
        self.assertNotIn(self.secret, self.output.getvalue())
        self.assertNotIn("codex-custom: configured", self.output.getvalue())

    def test_missing_invalid_oversized_and_symlink_profiles_fail_without_content(self):
        self.prepare_settings()
        for state in ("missing", "invalid", "oversized", "symlink"):
            with self.subTest(state=state):
                if state == "invalid":
                    self.path.write_text(self.secret + " = [")
                elif state == "oversized":
                    self.path.write_text("#" + self.secret * 5000)
                elif state == "symlink":
                    self.path.unlink()
                    self.path.symlink_to(self.setup.ENV_FILE)
                with contextlib.redirect_stdout(self.output):
                    self.assertEqual(self.setup.verify("codex-custom", self.manifest), 1)
                self.assertNotIn(self.secret, self.output.getvalue())

    def write_settings(self, value):
        self.setup.ROOT.mkdir(exist_ok=True)
        self.setup.SETTINGS.write_text(json.dumps(value))
        self.setup.SETTINGS.chmod(0o600)

    def test_v1_migration_keeps_active_v2_unknown_and_conflicting_legacy_values(self):
        for existing_legacy in (False, True):
            original = {"version": 1, "active": {"grok": "grok-api-key"},
                        "settings": {"model": "legacy-model"},
                        "providers": {"vertex": {"gcp_project": "example-project", "future": 7}},
                        "methods": {"codex-custom": self.values}, "future": {"nested": [1, 2]}}
            if existing_legacy:
                original["_v1_settings"] = {"model": "older-preserved-model"}
            self.write_settings(original)
            with contextlib.redirect_stdout(self.output):
                data = self.setup.load_settings()
                self.setup.save_settings(data)
            saved = json.loads(self.setup.SETTINGS.read_text())
            self.assertEqual(saved["active"], original["active"])
            self.assertEqual(saved["providers"], original["providers"])
            self.assertEqual(saved["methods"], original["methods"])
            self.assertEqual(saved["future"], original["future"])
            if existing_legacy:
                self.assertEqual(saved["_v1_settings"], original["_v1_settings"])
                self.assertEqual(saved["settings"], original["settings"])
            else:
                self.assertEqual(saved["_v1_settings"], original["settings"])

    def test_settings_changed_during_prompt_are_preserved(self):
        self.write_settings({"version": 2, "active": {}, "future": "original"})
        data = self.setup.load_settings()
        self.write_settings({"version": 2, "active": {}, "future": "concurrent"})
        current = self.setup.SETTINGS.read_bytes()
        with self.assertRaises(SystemExit):
            self.setup.save_settings(data)
        self.assertEqual(self.setup.SETTINGS.read_bytes(), current)

    def test_invalid_saved_fields_cannot_be_selected_and_are_not_echoed(self):
        self.prepare_settings()
        for bad in (self.secret + ";command", "https://user:secret@example.com", 12, ""):
            settings = json.loads(self.setup.SETTINGS.read_text())
            settings["methods"]["codex-custom"]["gateway_base_url"] = bad
            self.write_settings(settings)
            before = self.setup.SETTINGS.read_bytes()
            with contextlib.redirect_stdout(self.output), self.assertRaises(SystemExit) as error:
                self.setup.select("codex-custom", self.manifest)
            self.assertNotIn(self.secret, str(error.exception))
            self.assertEqual(before, self.setup.SETTINGS.read_bytes())

    def test_provider_updates_preserve_env_and_unrelated_settings(self):
        original = {"version": 2, "active": {"codex": "codex-chatgpt"},
                    "providers": {"vertex": {"gcp_project": "example-project", "gcp_region": "us-east5"}},
                    "methods": {"codex-custom": self.values}, "_v1_settings": {"old": "value"},
                    "future": {"keep": True}}
        self.write_settings(original)
        other = b"# retain this comment\r\nOTHER_KEY='unrelated ; $value'\r\n"
        self.setup.ENV_FILE.write_bytes(other)
        self.setup.ENV_FILE.chmod(0o600)
        secret = "  synthetic-quote'-$value-;\\key  "
        with patch.object(self.setup.provider_setup.getpass, "getpass", side_effect=[secret, secret]), contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.configure_provider("xai", self.manifest), 0)
        current = self.setup.ENV_FILE.read_bytes()
        self.assertTrue(current.startswith(other))
        self.assertEqual(self.setup.provider_setup.env_values(current)["XAI_API_KEY"], secret)
        saved = json.loads(self.setup.SETTINGS.read_text())
        self.assertEqual(saved["active"], original["active"])
        self.assertEqual(saved["methods"], original["methods"])
        self.assertEqual(saved["providers"]["vertex"], original["providers"]["vertex"])
        self.assertEqual(saved["_v1_settings"], original["_v1_settings"])
        self.assertEqual(saved["future"], original["future"])
        self.assertNotIn(secret, self.output.getvalue())
        self.assertNotIn(secret, self.setup.SETTINGS.read_text())

    def test_provider_prompt_does_not_overwrite_a_concurrent_unrelated_credential_change(self):
        self.prepare_settings()
        self.setup.ENV_FILE.write_bytes(b"export OPENAI_API_KEY='synthetic-old'\n")
        concurrent = b"# changed during the prompt\nexport OPENAI_API_KEY='synthetic-new'\nNEW_ENTRY='keep this too'\n"

        def enter_key(name):
            self.assertEqual(name, "XAI_API_KEY")
            self.setup.ENV_FILE.write_bytes(concurrent)
            return self.secret

        with patch.object(self.setup, "ask_secret", side_effect=enter_key), contextlib.redirect_stdout(self.output):
            self.assertEqual(self.setup.configure_provider("xai", self.manifest), 0)
        saved = self.setup.ENV_FILE.read_bytes()
        self.assertTrue(saved.startswith(concurrent))
        values = self.setup.provider_setup.env_values(saved)
        self.assertEqual(values["OPENAI_API_KEY"], "synthetic-new")
        self.assertEqual(values["NEW_ENTRY"], "keep this too")
        self.assertEqual(values["XAI_API_KEY"], self.secret)
        self.assertNotIn(self.secret, self.output.getvalue())

    def test_all_eight_methods_keep_scope_and_live_checks_unknown(self):
        expected = {"codex-chatgpt", "codex-api-key", "codex-custom", "claude-oauth",
                    "claude-api-key", "claude-vertex", "grok-device-code", "grok-api-key"}
        self.assertEqual(set(self.manifest.methods), expected)
        self.prepare_settings()
        settings = json.loads(self.setup.SETTINGS.read_text())
        settings["providers"]["vertex"] = {"gcp_project": "example-project", "gcp_region": "us-east5"}
        self.write_settings(settings)
        values = {name: self.secret for name in self.setup.provider_setup.PROVIDER_SECRETS.values()}
        with contextlib.redirect_stdout(self.output):
            self.setup.save_env(values)
            self.setup.write_codex_profile(self.method, self.values)
        with patch.object(subprocess, "run", side_effect=AssertionError("no process")), patch.object(socket, "socket", side_effect=AssertionError("no network")), contextlib.redirect_stdout(self.output):
            for method in expected:
                self.assertEqual(self.setup.verify(method, self.manifest), 2, method)
        self.assertNotIn(self.secret, self.output.getvalue())
        empty = {"providers": {}, "methods": {}}
        for method in expected:
            provider = self.manifest.provider_of(method)
            gaps = self.setup.missing_for(self.manifest, method, empty, set())
            for name in provider.get("secrets", []):
                self.assertIn(name, gaps)
            for spec in provider.get("settings", []):
                self.assertIn(provider["id"] + "." + spec["key"], gaps)
            for spec in self.manifest.methods[method].get("settings", []):
                self.assertIn(method + "." + spec["key"], gaps)

    def test_manifest_credential_references_are_exact_and_typed(self):
        for provider_id, provider in self.manifest.providers.items():
            for name in provider.get("secrets", []):
                reference = self.manifest.credential_reference(provider_id, name)
                self.assertIsInstance(reference, self.setup.provider_setup.LocalSecretReference)
                self.assertEqual((reference.kind, reference.provider, reference.name),
                                 ("local_env", provider_id, name))

    def test_provider_setup_consumes_the_manifest_credential_reference(self):
        self.setup.ROOT.mkdir()
        settings = {"version": 2, "active": {}, "providers": {}, "methods": {}}
        self.write_settings(settings)
        reference = self.manifest.credential_reference("xai", "XAI_API_KEY")
        with patch.object(self.manifest, "credential_reference", return_value=reference) as lookup, patch.object(
                self.setup, "ask_secret", return_value=self.secret), patch.object(
                self.setup, "save_credentials") as save:
            self.assertEqual(self.setup.configure_provider("xai", self.manifest), 0)
        lookup.assert_called_once_with("xai", "XAI_API_KEY")
        save.assert_called_once_with({reference: self.secret})

    def test_invalid_manifest_credential_reference_fails_before_prompt_or_write(self):
        invalid = {
            "version": 2,
            "providers": [{
                "id": "xai", "secrets": ["XAI_API_KEY"],
                "credential_references": [{
                    "kind": "local_env", "provider": "openai", "name": "OPENAI_API_KEY"}]}],
            "methods": [{"id": "grok-api-key", "cli": "grok", "provider": "xai"}],
        }
        path = self.home / "invalid-auth.json"
        path.write_text(json.dumps(invalid))
        with patch.object(self.setup, "MANIFEST", path), patch.object(
                self.setup, "ask_secret", side_effect=AssertionError("no prompt")):
            with self.assertRaises(SystemExit) as raised:
                self.setup.Manifest()
        self.assertIn("credential reference", str(raised.exception))
        self.assertFalse(self.setup.ENV_FILE.exists())

    def test_user_selection_preserves_other_cli_selections_and_unknown_values(self):
        self.prepare_settings()
        settings = json.loads(self.setup.SETTINGS.read_text())
        settings.update(active={"claude": "claude-oauth", "codex": "codex-chatgpt"}, future={"keep": 1})
        self.write_settings(settings)
        with contextlib.redirect_stdout(self.output):
            self.setup.select("codex-custom", self.manifest)
        saved = json.loads(self.setup.SETTINGS.read_text())
        self.assertEqual(saved["active"], {"claude": "claude-oauth", "codex": "codex-custom"})
        self.assertEqual(saved["future"], {"keep": 1})
        self.assertFalse(self.path.exists())

    def test_invalid_shapes_and_duplicate_keys_are_preserved(self):
        self.setup.ROOT.mkdir()
        for text in ('[]', '{"active":[]}', '{"providers":{"xai":7}}', '{"version":3}', '{"active":{},"active":{}}', '{"future":NaN}'):
            self.setup.SETTINGS.write_text(text)
            self.setup.SETTINGS.chmod(0o600)
            with self.assertRaises(SystemExit):
                self.setup.load_settings()
            self.assertEqual(self.setup.SETTINGS.read_text(), text)

    def test_endpoint_validation_rejects_invalid_hosts_ports_and_credentials(self):
        validator = self.setup.VALIDATORS["base_url"][0]
        for value in ("http://127.0.0.1:4000/v1", "http://[::1]:4000/v1", "https://api.example.com/v1"):
            self.assertTrue(validator.match(value), value)
        for value in ("http://[bad]/v1", "http://999.0.0.1/v1", "http://example..com/v1", "http://-bad.example/v1", "http://localhost:65536/v1", "http://localhost:0/v1", "http://user:token@localhost/v1", "http://localhost/v1?key=secret", "http://localhost/v1#secret"):
            self.assertIsNone(validator.match(value), value)

    def test_dashboard_path_import_keeps_the_shared_validators_available(self):
        original_import = builtins.__import__
        def dashboard_import(name, *args, **kwargs):
            if name == "taskmgmt":
                raise ModuleNotFoundError("not on this import path", name="taskmgmt")
            return original_import(name, *args, **kwargs)
        spec = importlib.util.spec_from_file_location("dashboard_fixture_setup", Path(__file__).with_name("setup_auth.py"))
        module = importlib.util.module_from_spec(spec)
        with patch.object(builtins, "__import__", side_effect=dashboard_import):
            spec.loader.exec_module(module)
        self.assertTrue(module.VALIDATORS["base_url"][0].match("http://localhost:4000/v1"))
        self.assertIsNone(module.VALIDATORS["base_url"][0].match("http://localhost:99999/v1"))


if __name__ == "__main__":
    unittest.main()
