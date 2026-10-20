"""The Hub forwards admitted display context without configuration defaults."""
from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hub import server
from hub.profile_context import ProfileContext


class HubProfileContext(unittest.TestCase):
    def make_hub(self, context):
        hub = server.Hub(profile_context=context)
        self.addCleanup(hub.io.shutdown, wait=True)
        self.addCleanup(hub.dbx.shutdown, wait=True)
        self.addCleanup(lambda: hub.dbx.submit(hub.store.db.close).result())
        return hub

    def test_actual_hub_passes_supplied_fields_to_all_adapters(self):
        for fields in ({"environment": "staging"}, {"project": "Display project"},
                       {"environment": "staging", "project": "Display project"}):
            with self.subTest(fields=fields), tempfile.TemporaryDirectory() as root, \
                    patch.object(server, "ROOT", root), patch.object(server, "HUBDIR", str(Path(root) / "hub")):
                context = ProfileContext(**fields)
                hub = self.make_hub(context)
                self.assertIs(hub.profile_context, context)
                self.assertIs(hub.fed.profile_context, context)
                for adapter in hub.fed.plugin_adapters.values():
                    self.assertEqual(adapter.contribution()["profileContext"], fields)
                    self.assertIs(adapter.context(hub.fed).profile_context, context)
                with self.assertRaises(AttributeError):
                    hub.profile_context = None
                with self.assertRaises(FrozenInstanceError):
                    hub.profile_context.project = "changed"
                self.doCleanups()

    def test_legacy_hub_omits_context_even_when_config_or_environment_has_labels(self):
        with tempfile.TemporaryDirectory() as root, patch.object(server, "ROOT", root), \
                patch.object(server, "HUBDIR", str(Path(root) / "hub")), \
                patch.dict(os.environ, {"AGENTMUX_ENVIRONMENT": "untrusted", "AGENTMUX_PROJECT": "untrusted"}):
            directory = Path(root) / "hub"
            directory.mkdir()
            (directory / "config.toml").write_text('environment = "untrusted"\nproject = "untrusted"\n')
            hub = self.make_hub(None)
            self.assertIsNone(hub.profile_context)
            self.assertIsNone(hub.fed.profile_context)
            for adapter in hub.fed.plugin_adapters.values():
                self.assertNotIn("profileContext", adapter.contribution())
                self.assertIsNone(adapter.context(hub.fed).profile_context)
            self.doCleanups()

    def test_invalid_context_refuses_before_any_storage(self):
        with patch.object(server.os, "makedirs") as mkdir:
            for context in ({"project": "untrusted"}, object()):
                with self.assertRaisesRegex(ValueError, "^invalid profile context$"):
                    server.Hub(profile_context=context)
            mkdir.assert_not_called()
