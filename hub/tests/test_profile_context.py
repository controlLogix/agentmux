"""Profile metadata remains explicit display context across adapter boundaries."""
from dataclasses import FrozenInstanceError, dataclass
import hashlib
import importlib
import unittest
from unittest.mock import MagicMock

from hub.profile_context import ProfileContext, RegisteredProfileContext
from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
from hub.fed.runtime import Federation
from hub.store import HubError


class ProfileContextTests(unittest.TestCase):
    def test_supplied_fields_only_and_immutable(self):
        for values in ({"environment": "staging"}, {"project": "Display project"},
                       {"environment": "staging", "project": "Display project"}):
            context = ProfileContext(**values)
            self.assertEqual(context.as_dict(), values)
            context.as_dict()["project"] = "changed"
            self.assertEqual(context.as_dict(), values)
            with self.assertRaises(FrozenInstanceError):
                context.project = "changed"
            self.assertNotIn("Display project", repr(context))
        for value in ("", " padded", "padded ", "a\nb", "a\x85b", "a\u2028b", "a\u2029b", "é" * 65, "\ud800", 7):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                ProfileContext(project=value)
        with self.assertRaises(ValueError):
            ProfileContext()
        self.assertEqual(ProfileContext(project="é" * 64).project, "é" * 64)

    def test_private_binding_checks_exact_bytes_and_identifiers(self):
        raw = b'{"selection":"original"}'
        profile_id, instance_id = "profile_" + "a" * 32, "instance_" + "b" * 32
        context = ProfileContext(project="Display project")
        binding = RegisteredProfileContext(selection_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
                    profile_id=profile_id, instance_id=instance_id, context=context)
        self.assertTrue(binding.matches_selection(raw, profile_id=profile_id, instance_id=instance_id))
        self.assertFalse(binding.matches_selection(raw + b" ", profile_id=profile_id, instance_id=instance_id))
        self.assertFalse(binding.matches_selection(raw, profile_id="profile_" + "c" * 32, instance_id=instance_id))
        self.assertNotIn(profile_id, repr(binding))
        self.assertEqual(binding.context.as_dict(), {"project": "Display project"})
        with self.assertRaises(FrozenInstanceError):
            binding.profile_id = "changed"

    def test_adapter_contribution_and_runtime_context_are_display_only(self):
        original = importlib.import_module("hub.fed.plugins.messages").PLUGIN
        context = ProfileContext(project="Display project")
        adapter = TrustedPluginAdapter(original, lambda _: SimpleContext(), profile_context=context)
        self.assertIs(adapter.context(None).profile_context, context)
        contribution = adapter.contribution()
        self.assertEqual(contribution["profileContext"], {"project": "Display project"})
        contribution["profileContext"]["project"] = "changed"
        self.assertEqual(adapter.contribution()["profileContext"], {"project": "Display project"})
        self.assertNotIn("profileContext", TrustedPluginAdapter(original).contribution())
        with self.assertRaises(HubError):
            TrustedPluginAdapter(original, profile_context={"projectId": "project_authority"})

    def test_every_builtin_receives_only_the_immutable_display_value(self):
        federation = MagicMock()
        federation.fcfg = {}
        federation.policy.shared.return_value = {}
        context = ProfileContext(environment="staging")
        for name in ("messages", "work", "board", "knowledge", "code"):
            with self.subTest(plugin=name):
                original = importlib.import_module("hub.fed.plugins." + name).PLUGIN
                adapter = TrustedPluginAdapter(original, builtin_context_factory(name), profile_context=context)
                supplied = adapter.context(federation)
                self.assertIs(supplied.profile_context, context)
                self.assertFalse(hasattr(supplied.profile_context, "profile_id"))
                self.assertIsNone(supplied.profile_context.project)
                with self.assertRaises(FrozenInstanceError):
                    supplied.profile_context = None

    def test_federation_explicit_context_reaches_builtin_and_extension_adapters(self):
        runtime = Federation.__new__(Federation)
        runtime._profile_context = ProfileContext(environment="staging")
        runtime.cfg = {"federation": {"plugins": ["messages"]}}
        runtime.plugins, runtime.plugin_adapters, runtime.routes = {}, {}, {}
        runtime._load_plugins()
        self.assertIs(runtime.plugin_adapters["messages"].profile_context, runtime.profile_context)
        self.assertEqual(runtime.plugin_adapters["messages"].contribution()["profileContext"], {"environment": "staging"})
        runtime._profile_context = None
        runtime._load_plugins()
        self.assertNotIn("profileContext", runtime.plugin_adapters["messages"].contribution())


@dataclass(frozen=True)
class SimpleContext:
    profile_context: ProfileContext | None = None
