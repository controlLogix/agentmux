"""The compatibility adapter preserves the existing trusted plugin contract."""
import asyncio
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from jsonschema import Draft202012Validator

from hub.fed.plugin_adapter import HOOKS, TrustedPluginAdapter
from hub.fed.plugin import Verb
from hub.fed.runtime import BUILTIN, Federation, _v_verbs
from hub.store import HubError


class Contribution(unittest.TestCase):
    def test_every_builtin_keeps_every_command_parameter_hook_and_sql(self):
        schema = json.loads((Path(__file__).resolve().parents[2] /
                             "contracts/v1/schemas/legacy-plugin-contribution.schema.json").read_text())
        validator = Draft202012Validator(schema)
        for name in BUILTIN:
            with self.subTest(plugin=name):
                original = importlib.import_module("hub.fed.plugins." + name).PLUGIN
                adapter = TrustedPluginAdapter(original)
                self.assertIs(adapter.original, original)
                self.assertIs(adapter.tables, original.tables)
                self.assertIs(adapter.handles, original.handles)
                contribution = adapter.contribution()
                validator.validate(contribution)
                self.assertEqual(contribution["tableStatements"], list(original.tables))
                self.assertEqual(contribution["envelopeTypes"], list(original.handles))
                self.assertEqual(contribution["hooks"], list(HOOKS))
                self.assertEqual(contribution["panelId"], name)
                expected = {f"fed_{name}_{key}": value for key, value in original.verbs().items()}
                actual = asyncio.run(_v_verbs(SimpleNamespace(verbs=expected), {}, "operator"))
                self.assertEqual(sorted(contribution["commands"], key=lambda row: row["verb"]), actual)
                self.assertEqual(list(adapter.verbs()), list(original.verbs()))
                for key, value in original.verbs().items():
                    self.assertEqual(adapter.verbs()[key].fn, value.fn)
                    self.assertEqual(list(adapter.verbs()[key].params), list(value.params))
                # Callers cannot rewrite plugin declarations by editing returned metadata.
                contribution["tableStatements"].append("not a plugin statement")
                self.assertEqual(adapter.contribution()["tableStatements"], list(original.tables))

    def test_runtime_keeps_original_helpers_and_routes_through_adapter(self):
        runtime = Federation.__new__(Federation)
        runtime.cfg = {"federation": {"plugins": list(BUILTIN)}}
        runtime.plugins, runtime.plugin_adapters, runtime.routes = {}, {}, {}
        runtime._load_plugins()
        for name in BUILTIN:
            original = importlib.import_module("hub.fed.plugins." + name).PLUGIN
            self.assertIs(runtime.plugins[name], original)
            self.assertIs(runtime.plugin_adapters[name].original, original)
            for kind in original.handles:
                self.assertIs(runtime.routes[kind], runtime.plugin_adapters[name])
        self.assertTrue(callable(runtime.plugins["messages"].send))
        self.assertTrue(callable(runtime.plugins["work"].add))
        self.assertEqual(runtime.plugin_adapters["board"].handles, ())

    def test_trusted_duck_typed_extension_is_kept(self):
        async def hook(*args):
            return args
        extension = SimpleNamespace(name="extension", handles=(), tables=[], verbs=lambda: {},
                                    panel=lambda ctx: {"title": "extension"},
                                    **{name: hook for name in HOOKS})
        module = SimpleNamespace(PLUGIN=extension)
        runtime = Federation.__new__(Federation)
        runtime.cfg = {"federation": {"plugins": ["customer.extension"]}}
        runtime.plugins, runtime.plugin_adapters, runtime.routes = {}, {}, {}
        with patch("hub.fed.runtime.importlib.import_module", return_value=module) as load:
            runtime._load_plugins()
        load.assert_called_once_with("customer.extension")
        self.assertIs(runtime.plugins["extension"], extension)
        with self.assertRaisesRegex(HubError, "unsupported federation plugin contract"):
            TrustedPluginAdapter(SimpleNamespace(name="incomplete"))

    def test_registration_waits_for_all_modules_and_keeps_original_bound_functions(self):
        loaded, registrations = [], []

        class Extension:
            name, handles, tables = "first", (), []

            async def hook(self, *args):
                return args

            start = on_connect = on_tick = on_envelope = on_local_event = on_revoke = hook

            def panel(self, ctx):
                return None

            def verbs(self):
                self_test.assertEqual(loaded, ["customer.first", "customer.second"])
                registry = {"run": Verb(self.hook, "Run the extension")}
                registrations.append(registry)
                return registry

        self_test = self
        first, second = Extension(), Extension()
        second.name = "second"

        def load(name):
            loaded.append(name)
            return SimpleNamespace(PLUGIN={"customer.first": first,
                                          "customer.second": second}[name])

        cfg = {"federation": {"plugins": ["customer.first", "customer.second"]}}
        hub = SimpleNamespace(cfg={}, dbx=Mock())
        with patch("hub.fed.runtime.config.load", return_value=cfg), \
                patch("hub.fed.runtime.importlib.import_module", side_effect=load):
            runtime = Federation(hub, Path("unused"), lambda *args: None)
        self.assertEqual(len(registrations), 2)
        for index, name in enumerate(("first", "second")):
            adapter = runtime.plugin_adapters[name]
            self.assertIs(adapter.verbs(), registrations[index])
            self.assertIs(runtime.verbs[f"fed_{name}_run"], registrations[index]["run"])
            adapter.contribution()
        self.assertEqual(len(registrations), 2)


class Delegation(unittest.IsolatedAsyncioTestCase):
    async def test_all_builtin_hooks_keep_exact_context_arguments_result_and_error(self):
        context, envelope, decision, event_data = (object() for _ in range(4))
        args = {"start": (context,), "on_connect": (context,), "on_tick": (context,),
                "on_envelope": (context, envelope, decision),
                "on_local_event": (context, "work_done", event_data), "on_revoke": (context, "peer")}
        for name in BUILTIN:
            original = importlib.import_module("hub.fed.plugins." + name).PLUGIN
            adapter = TrustedPluginAdapter(original)
            for hook, values in args.items():
                with self.subTest(plugin=name, hook=hook):
                    seen, result = [], object()
                    async def delegate(*received):
                        seen.append(received)
                        return result
                    with patch.object(original, hook, delegate):
                        self.assertIs(await getattr(adapter, hook)(*values), result)
                    self.assertEqual(len(seen), 1)
                    self.assertTrue(all(a is b for a, b in zip(seen[0], values)))
                    failure = RuntimeError("private failure")
                    async def fail(*received):
                        raise failure
                    with patch.object(original, hook, fail):
                        with self.assertRaises(RuntimeError) as raised:
                            await getattr(adapter, hook)(*values)
                    self.assertIs(raised.exception, failure)
            panel = {"title": name, "columns": ["name"], "rows": [["example"]], "actions": []}
            with patch.object(original, "panel", return_value=panel) as provider:
                self.assertIs(adapter.panel(context), panel)
                provider.assert_called_once_with(context)

    async def test_cancellation_is_not_reclassified(self):
        original = importlib.import_module("hub.fed.plugins.messages").PLUGIN
        adapter = TrustedPluginAdapter(original)
        failure = asyncio.CancelledError()
        async def cancel(ctx):
            raise failure
        with patch.object(original, "on_tick", cancel):
            with self.assertRaises(asyncio.CancelledError) as raised:
                await adapter.on_tick(object())
        self.assertIs(raised.exception, failure)
