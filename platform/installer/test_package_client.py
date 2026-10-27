"""Focused checks for the installed client package builder."""
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location("package_client", Path(__file__).with_name("package_client.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
bootstrap_spec = importlib.util.spec_from_file_location("client_bootstrap", Path(__file__).with_name("client_bootstrap.py"))
bootstrap = importlib.util.module_from_spec(bootstrap_spec)
bootstrap_spec.loader.exec_module(bootstrap)


class ClientPackageBuilder(unittest.TestCase):
    def test_native_callback_keeps_arguments_and_refuses_missing_route(self):
        from hub.native_core_callback import run_callback, MissingNativeCoreRoute
        arguments = ['native-core-callback', 'hub', 'post', '--to', 'agent:repo-worker-one', 'literal $text;']
        operation, selected = bootstrap._arguments('/selected/package', arguments)
        self.assertEqual(operation, 'native-core-callback')
        self.assertEqual(selected, arguments[1:])
        with self.assertRaises(MissingNativeCoreRoute):
            run_callback(selected)
        # This is only an argument/PID component control, not handler authorization.
        seen = []
        route = SimpleNamespace(invoke=lambda args: seen.append((os.getpid(), args)) or 0)
        self.assertEqual(run_callback(selected, route=route), 0)
        self.assertEqual(seen, [(os.getpid(), tuple(arguments[2:]))])
        for bad in (['native-core-callback'], ['native-core-callback', 'spawn', 'agent'],
                    ['native-core-callback', 'hub', 'bad\x00argument']):
            with self.subTest(arguments=bad), self.assertRaises(SystemExit):
                bootstrap._arguments('/selected/package', bad)

    def test_qualified_hub_imports_from_packaged_roster_without_starting_services(self):
        dependencies = next(Path(value) for value in sys.path
                            if value and (Path(value) / "nkeys").is_dir())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            app = root / "app"
            for name in (*package.MODULES, *package.ASSETS):
                package.copy_file(package.REPOSITORY / name, app / name)
            package.copy_tree(package.REPOSITORY / "sdk/python/agentmux_contracts",
                              app / "sdk/python/agentmux_contracts")
            for schema in (package.REPOSITORY / "contracts/v1/schemas").glob("*.schema.json"):
                package.copy_file(schema, app / "contracts/v1/schemas" / schema.name)
            project_modules = {Path(name).parts[0].removesuffix(".py")
                               for name in package.MODULES} | {"agentmux_contracts"}
            probe = """
import importlib
import json
from pathlib import Path
import sys
app, dependencies = (Path(value) for value in sys.argv[1:3])
project_modules = set(json.loads(sys.argv[3]))
sys.path[:0] = [str(app), str(app / 'sdk/python'), str(app / 'dashboard'),
                str(app / 'taskmgmt'), str(dependencies)]
def import_only(event, args):
    if event in ('socket.__new__', 'subprocess.Popen', 'os.posix_spawn',
                 'os.fork', 'sqlite3.connect', 'os.mkdir'):
        raise AssertionError('service effect during import: ' + event)
sys.addaudithook(import_only)
for name in ('identity.ordinary_secret', 'native_security.ordinary_secret_custody',
             'capability_owner.secret_consumer', 'capability_owner.secret_journal',
             'capability_owner.ordinary_secret', 'capability_owner.secret_journal_admission',
             'capability_owner.secret_resource', 'capability_owner.secret_host', 'identity.secret_selection',
             'hub.server', 'hub.enrolled_hub_bootstrap', 'hub.legacy_identity_client',
             'identity.message_client', 'identity.application_client',
             'identity.federation_policy_commands', 'identity.federation_policy_selection',
             'capability_owner.legacy_messages_client', 'capability_owner.knowledge',
             'capability_owner.knowledge_host', 'capability_owner.knowledge_control',
             'capability_owner.code', 'capability_owner.code_host',
             'capability_owner.code_legacy', 'capability_owner.code_bridge_service',
             'capability_owner.code_git', 'capability_owner.legacy_code_client',
             'capability_owner.code_completion',
             'identity.code_client', 'hub.fed.code_bridge',
             'capability_owner.work', 'capability_owner.work_host', 'capability_owner.work_legacy',
             'capability_owner.work_bridge_service', 'capability_owner.legacy_work_client', 'identity.work_client',
             'capability_owner.local_work_client', 'capability_owner.federated_work_client',
             'capability_owner.work_completion', 'capability_owner.work_rpc', 'capability_owner.work_control',
             'capability_owner.work_lifecycle', 'capability_owner.work_lifecycle_client',
             'capability_owner.work_source',
             'capability_owner.work_capture',
             'identity.core_work_transport', 'hub.core_work_transport',
             'capability_owner.core_work', 'capability_owner.core_work_client',
             'capability_owner.core_work_roles',
             'capability_owner.legacy_policy_client', 'capability_owner.policy_bootstrap',
             'capability_owner.federation_policy_transition'):
    importlib.import_module(name)
assert not (app / 'capability_owner/process_resource.py').exists()
from capability_owner import receiver
from identity.authority import AuthorityReader
from agentmux_contracts import ContractError
assert receiver._PROCESS_RESOURCE_TYPES == ()
class ProcessResource:
    pass
try:
    receiver.CapabilityReceiver(object.__new__(AuthorityReader), hub_id='hub-one',
                                resources=(ProcessResource(),))
except ContractError:
    pass
else:
    raise AssertionError('untyped Process registration accepted')
for name in ('messages', 'work', 'board', 'knowledge', 'code'):
    importlib.import_module('hub.fed.plugins.' + name)
for name, module in tuple(sys.modules.items()):
    if name.split('.')[0] in project_modules:
        source = getattr(module, '__file__', None)
        if source is not None:
            assert Path(source).resolve().is_relative_to(app), name
"""
            completed = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", probe, str(app),
                 str(dependencies), json.dumps(sorted(project_modules))],
                cwd=root, capture_output=True, text=True, timeout=10,
                env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8",
                     "HOME": str(root), "AGENTMUX_HOME": str(root / "unused-home")})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertFalse((root / "unused-home").exists())

    def test_builtin_contexts_construct_from_packaged_roster(self):
        dependencies = next(Path(value) for value in sys.path
                            if value and (Path(value) / "nkeys").is_dir())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            app = root / "app"
            for name in package.MODULES:
                package.copy_file(package.REPOSITORY / name, app / name)
            package.copy_tree(package.REPOSITORY / "sdk/python/agentmux_contracts",
                              app / "sdk/python/agentmux_contracts")
            project_modules = {Path(name).parts[0].removesuffix(".py")
                               for name in package.MODULES} | {"agentmux_contracts"}
            probe = """
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
from types import SimpleNamespace
app, dependencies = (Path(value) for value in sys.argv[1:3])
name, project_modules = sys.argv[3], set(json.loads(sys.argv[4]))
sys.path[:0] = [str(app), str(app / 'sdk/python'), str(dependencies)]
from hub.fed.plugin_adapter import builtin_context_factory
with ThreadPoolExecutor(max_workers=1) as io:
    federation = SimpleNamespace(fcfg={}, me='local', node='node',
        policy=SimpleNamespace(shared=lambda: {}), hub=SimpleNamespace(io=io))
    context = builtin_context_factory(name)(federation)
    assert type(context).__name__ == name.title() + 'Context'
    if name == 'code':
        # Exercise the production lazy import without changing a repository.
        version = asyncio.run(context.git._run(str(app.parent), '--version'))
        assert version.startswith('git version '), version
for module_name, module in tuple(sys.modules.items()):
    if module_name.split('.')[0] in project_modules:
        source = getattr(module, '__file__', None)
        if source is not None:
            assert Path(source).resolve().is_relative_to(app), module_name
"""
            for name in ("work", "knowledge", "code"):
                with self.subTest(context=name):
                    completed = subprocess.run(
                        [sys.executable, "-I", "-S", "-B", "-c", probe,
                         str(app), str(dependencies), name, json.dumps(sorted(project_modules))],
                        cwd=root, capture_output=True, text=True, timeout=10,
                        env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertEqual(completed.stdout, "")

    def test_private_operator_imports_from_installed_roots(self):
        dependencies = next(Path(value) for value in sys.path
                            if value and (Path(value) / "nkeys").is_dir())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            app = root / "app"
            for name in (*package.MODULES, *package.ASSETS):
                package.copy_file(package.REPOSITORY / name, app / name)
            package.copy_tree(package.REPOSITORY / "sdk/python/agentmux_contracts",
                              app / "sdk/python/agentmux_contracts")
            for schema in (package.REPOSITORY / "contracts/v1/schemas").glob("*.schema.json"):
                package.copy_file(schema, app / "contracts/v1/schemas" / schema.name)
            probe = """
from pathlib import Path
import sys
app, dependencies = (Path(value) for value in sys.argv[1:])
sys.path[:0] = [str(app), str(app / 'sdk/python'), str(dependencies)]
import integration_owner.operator_command as command
assert Path(command.__file__).resolve() == app / 'integration_owner/operator_command.py'
assert 'definition_commands' not in sys.modules
assert 'oidc_browser_login' not in sys.modules
assert 'identity.oidc_terminal_login' not in sys.modules
assert str(app / 'dashboard') not in sys.path
"""
            completed = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", probe, str(app), str(dependencies)],
                cwd=root, capture_output=True, text=True, timeout=10,
                env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")

    def test_selected_storage_imports_without_repository_access(self):
        dependencies = next(Path(value) for value in sys.path
                            if value and (Path(value) / "nkeys").is_dir())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            app = root / "app"
            for name in (*package.MODULES, *package.ASSETS):
                package.copy_file(package.REPOSITORY / name, app / name)
            package.copy_tree(package.REPOSITORY / "sdk/python/agentmux_contracts",
                              app / "sdk/python/agentmux_contracts")
            for schema in (package.REPOSITORY / "contracts/v1/schemas").glob("*.schema.json"):
                package.copy_file(schema, app / "contracts/v1/schemas" / schema.name)
            probe = """
from pathlib import Path
import sys
app, dependencies = (Path(value) for value in sys.argv[1:])
sys.path[:0] = [str(app), str(app / 'sdk/python'),
                str(app / 'dashboard'), str(app / 'taskmgmt'), str(dependencies)]
import capability_owner.selected_storage
import capability_owner.messages_host
import capability_owner.policy_host
import dashboard.application_service_host
import identity.native_activation
import identity.native_configuration
import identity.oidc_adapter
import identity.oidc_authorization_code
import identity.oidc_device_authorization
import identity.oidc_terminal_login
import oidc_browser_login
for name, module in tuple(sys.modules.items()):
    if name.split('.')[0] in ('capability_owner', 'dashboard', 'hub', 'identity',
                              'state_owner', 'native_security', 'agentmux_contracts'):
        source = getattr(module, '__file__', None)
        if source is not None:
            assert Path(source).resolve().is_relative_to(app), name
assert capability_owner.selected_storage.SelectedStorageHost
import asyncio
import hashlib
import os
from hub.store import Store, APP_ID, MIGRATIONS
source = app.parent / 'message-source'
source.mkdir(mode=0o700)
database, policy = source / 'messages.db', source / 'federation.toml'
store = Store(str(database))
store.db.close()
database.chmod(0o600)
policy_bytes = b'[federation]\\npeer="local"\\n'
policy.write_bytes(policy_bytes)
policy.chmod(0o600)
async def selected_source():
    host = capability_owner.messages_host.MessageStoreHost({
        'database': {'path': str(database), 'applicationId': APP_ID, 'userVersion': len(MIGRATIONS)},
        'policy': {'path': str(policy), 'sha256': 'sha256:' + hashlib.sha256(policy_bytes).hexdigest()}},
        repository=None, local_peer='local', owner_uid=os.getuid())
    try:
        await host.start()
        host.check_health()
    finally:
        await host.close()
asyncio.run(selected_source())
assert callable(identity.native_activation.activate_instance)
assert callable(identity.native_configuration.prepare_configuration_envelope)
assert Path(oidc_browser_login.__file__).resolve() == app / 'dashboard/oidc_browser_login.py'
"""
            completed = subprocess.run([sys.executable, "-I", "-B", "-c", probe,
                                        str(app), str(dependencies)],
                                       cwd=root, capture_output=True, text=True, timeout=10,
                                       env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")

    def test_roster_uses_wire_path_order_and_pins_empty_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a/file.py", "a.py", "z/__init__.py"):
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"")
                file.chmod(0o444)
            roster = package.file_roster(root)
            self.assertEqual([item["path"] for item in roster], ["a.py", "a/file.py", "z/__init__.py"])
            self.assertTrue(all(item["size"] == 0 and item["digest"] == package.digest(b"") for item in roster))

    def test_copy_materializes_hardlinks_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "source", root / "target"
            source.write_bytes(b"selected content")
            package.copy_file(source, target)
            self.assertNotEqual(source.stat().st_ino, target.stat().st_ino)
            alias = root / "alias"
            alias.symlink_to(source)
            with self.assertRaises(ValueError):
                package.copy_file(alias, root / "rejected")

    def test_repository_profile_reader_imports_only_its_packaged_namespace(self):
        required = ("hub/client_launch_repository.py", "dashboard/repository_profiles.py",
                    "taskmgmt/profile_owner.py")
        for name in required:
            self.assertEqual(package.MODULES.count(name), 1)
        self.assertEqual(package.MODULES.count("hub/client_launch_claude.py"), 1)
        for name in ("identity/oidc_adapter.py", "identity/oidc_authorization_code.py",
                     "identity/oidc_device_authorization.py", "identity/oidc_terminal_login.py",
                     "dashboard/oidc_browser_login.py"):
            self.assertEqual(package.MODULES.count(name), 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            app = root / "app"
            for name in required[1:]:
                package.copy_file(package.REPOSITORY / name, app / name)
            probe = """
import importlib
from pathlib import Path
import sys
app = Path(sys.argv[1])
sys.path.insert(0, str(app))
reader = importlib.import_module('dashboard.repository_profiles')
filesystem = importlib.import_module('taskmgmt.profile_owner')
assert reader.filesystem is filesystem
assert Path(reader.__file__).resolve() == app / 'dashboard/repository_profiles.py'
assert Path(filesystem.__file__).resolve() == app / 'taskmgmt/profile_owner.py'
for name in ('dashboard', 'taskmgmt'):
    assert list(sys.modules[name].__path__) == [str(app / name)]
assert not any(name.split('.')[0] in ('identity', 'integration_owner', 'state_owner',
    'application_service_process', 'server') for name in sys.modules)
assert str(app / 'dashboard') not in sys.path and str(app / 'taskmgmt') not in sys.path
assert reader.RepositoryProfileReference('profile_' + 'a' * 32).profile_id == 'profile_' + 'a' * 32
"""
            completed = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", probe, str(app)],
                                       cwd=root, capture_output=True, text=True, timeout=5,
                                       env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8",
                                            "PYTHONPATH": str(package.REPOSITORY)})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")

    def test_wrong_interpreter_version_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = subprocess.CompletedProcess([], 0, json.dumps(["3.14.8", "arm64", str(root / "python")]), "")
            with patch.object(package.subprocess, "run", return_value=probe):
                with self.assertRaisesRegex(ValueError, "3.14.4"):
                    package.build(python_root=root / "python", dependencies=root / "dependencies",
                                  frontend=root / "frontend", foundation_installation="a" * 64,
                                  output=root / "output", selection_output=root / "selection.json")
            self.assertFalse((root / "output").exists())

    def test_bootstrap_refuses_unisolated_invocation(self):
        completed = subprocess.run([sys.executable, str(Path(__file__).with_name("client_bootstrap.py")),
                                    "mcp", "/private/selection.json"],
                                   input="", capture_output=True, text=True, timeout=5)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertIn("Installed client invocation is invalid.", completed.stderr)

    def test_bootstrap_profile_operations_keep_selection_and_session_cleanup(self):
        root = "/protected/clients/" + "a" * 64
        selection = "/private/a 'literal' $(selection).json"
        expected = {
            "startup": ["startup"],
            "startup-json": ["startup", "--output", "json"],
            "startup-worker": ["startup", "--managed-worker"],
            "startup-worker-json": ["startup", "--managed-worker", "--output", "json"],
            "mcp": ["mcp", "--enrolled"],
            "mcp-worker": ["mcp", "--enrolled", "--managed-worker"],
            "dashboard": ["dashboard"],
        }
        class RetainedSession:
            def __init__(self):
                self.exit_code = Mock(return_value=7)

        for operation, client_arguments in expected.items():
            with self.subTest(operation=operation):
                self.assertEqual(bootstrap._arguments(root, [operation, selection]),
                                 (operation, [selection]))
                session = RetainedSession()
                client_main = Mock(return_value=session)
                selected_sys = SimpleNamespace(version_info=(3, 14, 4),
                    flags=SimpleNamespace(isolated=1, no_site=1), prefix=root + "/python",
                    path=[root + "/python/lib/python3.14"],
                    argv=[root + "/bootstrap.py", operation, selection])
                with patch.object(bootstrap, "sys", selected_sys), \
                        patch.object(bootstrap, "__file__", root + "/bootstrap.py"), \
                        patch.dict(sys.modules, {
                            "hub.cli": SimpleNamespace(Fail=RuntimeError, main=client_main),
                            "hub.client_launch_entrypoint": SimpleNamespace(EnrolledSession=RetainedSession)}), \
                        self.assertRaises(SystemExit) as completed:
                    bootstrap.main()
                self.assertEqual(completed.exception.code, 7)
                client_main.assert_called_once_with(client_arguments + ["--selection", selection])
                session.exit_code.assert_called_once_with()
                self.assertNotIn(root + "/app/dashboard", selected_sys.path)
                self.assertNotIn(root + "/app/taskmgmt", selected_sys.path)

    def test_bootstrap_profile_operations_refuse_extra_flags_and_unknown_values(self):
        root = "/protected/clients/" + "a" * 64
        selection = "/private/selection.json"
        for operation in ("startup", "startup-json", "startup-worker", "startup-worker-json", "mcp", "mcp-worker", "dashboard"):
            for arguments in ([operation], [operation, selection, "--managed-worker"],
                              [operation, selection, "--output", "json"],
                              [operation, "relative"], [operation, "/private/../selection.json"],
                              [operation, selection + "\n"]):
                with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                    bootstrap._arguments(root, arguments)
        for operation in ("", "mcp-json", "mcp-worker-json", "startup-json-worker",
                          "startup --managed-worker", "startup-worker --output json", "launch-app"):
            with self.subTest(operation=operation), self.assertRaises(SystemExit):
                bootstrap._arguments(root, [operation, selection])

    def test_bootstrap_repository_operations_preserve_root_and_cleanup(self):
        root = "/protected/clients/" + "a" * 64
        repository = "/private/a 'literal' $(répertoire)"
        expected = {
            "startup": ["startup"],
            "startup-json": ["startup", "--output", "json"],
            "startup-worker": ["startup", "--managed-worker"],
            "startup-worker-json": ["startup", "--managed-worker", "--output", "json"],
            "mcp": ["mcp", "--enrolled"],
            "mcp-worker": ["mcp", "--enrolled", "--managed-worker"],
        }

        class RetainedSession:
            def __init__(self):
                self.exit_code = Mock(return_value=7)

        for operation, client_arguments in expected.items():
            with self.subTest(operation=operation):
                arguments = ["repository-client", operation, repository]
                self.assertEqual(bootstrap._arguments(root, arguments),
                                 ("repository-client", [operation, repository]))
                session = RetainedSession()
                client_main = Mock(return_value=session)
                selected_sys = SimpleNamespace(version_info=(3, 14, 4),
                    flags=SimpleNamespace(isolated=1, no_site=1), prefix=root + "/python",
                    path=[root + "/python/lib/python3.14"], argv=[root + "/bootstrap.py", *arguments])
                with patch.object(bootstrap, "sys", selected_sys), \
                        patch.object(bootstrap, "__file__", root + "/bootstrap.py"), \
                        patch.dict(sys.modules, {
                            "hub.cli": SimpleNamespace(Fail=RuntimeError, main=client_main),
                            "hub.client_launch_entrypoint": SimpleNamespace(EnrolledSession=RetainedSession)}), \
                        self.assertRaises(SystemExit) as completed:
                    bootstrap.main()
                self.assertEqual(completed.exception.code, 7)
                client_main.assert_called_once_with(client_arguments + ["--repository-root", repository])
                session.exit_code.assert_called_once_with()
                self.assertNotIn(root + "/app/dashboard", selected_sys.path)
                self.assertNotIn(root + "/app/taskmgmt", selected_sys.path)

    def test_bootstrap_repository_operations_refuse_other_verbs_roots_and_flags(self):
        root = "/protected/clients/" + "a" * 64
        for operation in ("startup", "startup-json", "startup-worker", "startup-worker-json", "mcp", "mcp-worker"):
            accepted = ["repository-client", operation, "/r" * 127]
            self.assertEqual(bootstrap._arguments(root, accepted), ("repository-client", accepted[1:]))
            rejected = [accepted[:2], accepted + ["--selection", "/private/selection.json"],
                        accepted + ["--output", "json"]]
            rejected += [["repository-client", operation, value] for value in (
                "relative", "/", "//private/repository", "/private/../repository", "/private/repository\n",
                "/private/repository\t", "/private/repository\x7f", "/private/repository\u0085",
                "/private/repository\u009f", "/private/\udfff",
                "/" + "r" * 4096, "/" + "é" * 2048, "/r" * 128)]
            for arguments in rejected:
                with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                    bootstrap._arguments(root, arguments)
        for operation in ("", "mcp-json", "mcp-worker-json", "startup-json-worker",
                          "startup --managed-worker", "application-services", "client-setup",
                          "launch-claude-desktop", "repository-client", "claude-code-hook",
                          "claude-code-hook-worker", "dashboard"):
            with self.subTest(operation=operation), self.assertRaises(SystemExit):
                bootstrap._arguments(root, ["repository-client", operation, "/private/repository"])

    def test_bootstrap_desktop_selection_is_literal_and_closed(self):
        root = "/protected/clients/" + "a" * 64
        selection = "/private/a 'literal' $(selection).json"
        arguments = ["launch-claude-desktop", selection]
        self.assertEqual(bootstrap._arguments(root, arguments), (arguments[0], [selection]))
        for changed in (arguments[:1], arguments + ["--app", "/Applications/Other.app"],
                        [arguments[0], "relative"], [arguments[0], "/private/../selection"],
                        [arguments[0], "/private/selection\n"], ["launch-app", selection]):
            with self.subTest(arguments=changed), self.assertRaises(SystemExit):
                bootstrap._arguments(root, changed)

    def test_bootstrap_desktop_uses_named_launcher_without_changing_selection(self):
        root = "/protected/clients/" + "a" * 64
        selection = "/private/a 'literal' $(selection).json"
        desktop_main = Mock(return_value=0)
        selected_sys = SimpleNamespace(version_info=(3, 14, 4),
            flags=SimpleNamespace(isolated=1, no_site=1), prefix=root + "/python",
            path=[root + "/python/lib/python3.14"],
            argv=[root + "/bootstrap.py", "launch-claude-desktop", selection])
        with patch.object(bootstrap, "sys", selected_sys), \
                patch.object(bootstrap, "__file__", root + "/bootstrap.py"), \
                patch.dict(sys.modules, {"hub.client_launch_desktop": SimpleNamespace(main=desktop_main)}), \
                self.assertRaises(SystemExit) as completed:
            bootstrap.main()
        self.assertEqual(completed.exception.code, 0)
        desktop_main.assert_called_once_with(["--selection", selection])

    def test_bootstrap_claude_hook_uses_fixed_module_and_worker_context(self):
        root = "/protected/clients/" + "a" * 64
        selection = "/private/a 'literal' $(selection).json"
        for operation, managed_worker in (("claude-code-hook", False),
                                          ("claude-code-hook-worker", True)):
            with self.subTest(operation=operation):
                arguments = [operation, selection]
                self.assertEqual(bootstrap._arguments(root, arguments), (operation, [selection]))
                hook_main = Mock(return_value=0)
                selected_sys = SimpleNamespace(version_info=(3, 14, 4),
                    flags=SimpleNamespace(isolated=1, no_site=1), prefix=root + "/python",
                    path=[root + "/python/lib/python3.14"],
                    argv=[root + "/bootstrap.py", operation, selection])
                with patch.object(bootstrap, "sys", selected_sys), \
                        patch.object(bootstrap, "__file__", root + "/bootstrap.py"), \
                        patch.dict(sys.modules, {"hub.client_launch_claude": SimpleNamespace(main=hook_main)}), \
                        self.assertRaises(SystemExit) as completed:
                    bootstrap.main()
                self.assertEqual(completed.exception.code, 0)
                hook_main.assert_called_once_with(
                    ["--selection", selection], registered_context=None,
                    managed_worker=managed_worker)
        self.assertNotIn(root + "/app/dashboard", selected_sys.path)
        self.assertNotIn(root + "/app/taskmgmt", selected_sys.path)

    def test_bootstrap_private_services_accepts_no_command_line_selection(self):
        root = "/protected/clients/" + "a" * 64
        self.assertEqual(bootstrap._arguments(root, ["application-services"]),
                         ("application-services", []))
        for arguments in (["application-services", "/private/selection.json"],
                          ["application-services", "--selection", "/private/selection.json"],
                          ["application-services", "--lease-fd", "3"]):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                bootstrap._arguments(root, arguments)

    def test_bootstrap_private_services_uses_fixed_roots_and_receiver_status(self):
        root = "/protected/clients/" + "a" * 64
        service_main = Mock(return_value=1)
        selected_sys = SimpleNamespace(version_info=(3, 14, 4),
            flags=SimpleNamespace(isolated=1, no_site=1), prefix=root + "/python",
            path=[root + "/python/lib/python3.14"],
            argv=[root + "/bootstrap.py", "application-services"])
        with patch.object(bootstrap, "sys", selected_sys), \
                patch.object(bootstrap, "__file__", root + "/bootstrap.py"), \
                patch.dict(sys.modules, {"application_service_process": SimpleNamespace(main=service_main)}), \
                self.assertRaises(SystemExit) as completed:
            bootstrap.main()
        self.assertEqual(completed.exception.code, 1)
        service_main.assert_called_once_with()
        self.assertEqual(selected_sys.path, [root + "/app/dashboard", root + "/app/taskmgmt",
            root + "/app", root + "/app/sdk/python", root + "/site-packages",
            root + "/python/lib/python3.14"])

    def test_bootstrap_private_operator_accepts_no_command_arguments(self):
        root = "/protected/clients/" + "a" * 64
        self.assertEqual(bootstrap._arguments(root, ["integration-operator"]),
                         ("integration-operator", []))
        with self.assertRaises(SystemExit):
            bootstrap._arguments(root, ["integration-operator", "private"])
        operator_main = Mock(return_value=1)
        selected_sys = SimpleNamespace(version_info=(3, 14, 4),
            flags=SimpleNamespace(isolated=1, no_site=1), prefix=root + "/python",
            path=[root + "/python/lib/python3.14"],
            argv=[root + "/bootstrap.py", "integration-operator"])
        with patch.object(bootstrap, "sys", selected_sys), \
                patch.object(bootstrap, "__file__", root + "/bootstrap.py"), \
                patch.dict(sys.modules, {"integration_owner.operator_command":
                    SimpleNamespace(main=operator_main)}), \
                self.assertRaises(SystemExit) as completed:
            bootstrap.main()
        self.assertEqual(completed.exception.code, 1)
        operator_main.assert_called_once_with()

    def test_bootstrap_claude_setup_binds_internal_path_and_package(self):
        installation = "a" * 64
        root = "/protected/clients/" + installation
        configuration = "/private/Claude 'literal'/settings.json"
        arguments = ["claude-hook-setup", "--configuration", configuration,
                     "--client-installation", installation, "--selection", "/private/selection.json",
                     "--receipt", "/private/receipt.json", "--operation", "install"]
        for suffix in ([], ["--apply"]):
            self.assertEqual(bootstrap._arguments(root, arguments + suffix),
                             ("claude-hook-setup", [configuration, *arguments[3:], *suffix]))
            setup_main = Mock(return_value=0)
            selected_sys = SimpleNamespace(version_info=(3, 14, 4),
                flags=SimpleNamespace(isolated=1, no_site=1), prefix=root + "/python",
                path=[root + "/python/lib/python3.14"],
                argv=[root + "/bootstrap.py", *arguments, *suffix])
            with patch.object(bootstrap, "sys", selected_sys), \
                    patch.object(bootstrap, "__file__", root + "/bootstrap.py"), \
                    patch.dict(sys.modules, {"dashboard.claude_hook_setup": SimpleNamespace(main=setup_main)}), \
                    self.assertRaises(SystemExit) as completed:
                bootstrap.main()
            self.assertEqual(completed.exception.code, 0)
            setup_main.assert_called_once_with(arguments[3:] + suffix,
                                               configuration_path=configuration)
        for changed in (arguments + ["--apply=false"], arguments[:4] + ["b" * 64] + arguments[5:],
                        arguments[:2] + ["relative/settings.json"] + arguments[3:],
                        arguments[:2] + ["/private/other.json"] + arguments[3:]):
            with self.assertRaises(SystemExit):
                bootstrap._arguments(root, changed)

    def test_bootstrap_setup_binds_package_and_preserves_explicit_apply(self):
        installation = "a" * 64
        root = "/protected/clients/" + installation
        for operation in ("install", "remove", "restore", "recover"):
            arguments = ["client-setup", "--client-installation", installation,
                         "--selection", "/private/a 'literal' selection.json",
                         "--receipt", "/private/receipt.json", "--operation", operation]
            for suffix in ([], ["--apply"]):
                self.assertEqual(bootstrap._arguments(root, arguments + suffix),
                                 ("client-setup", arguments[1:] + suffix))
        for changed in (arguments + ["--apply=false"], arguments + ["--apply", "--apply"],
                        arguments[:2] + ["b" * 64] + arguments[3:],
                        arguments[:6] + ["relative"] + arguments[7:]):
            with self.assertRaises(SystemExit):
                bootstrap._arguments(root, changed)


@unittest.skipUnless(platform.system() == "Darwin" and platform.machine() == "arm64",
                     "Inherited registration admission targets native macOS ARM64.")
class RegisteredClientBootstrap(unittest.TestCase):
    def setUp(self):
        # Exercise the real immutable type and native descriptor checker.
        with patch.object(sys, "path", [str(package.REPOSITORY), *sys.path]):
            self.context_module = importlib.import_module("hub.profile_context")
            self.descriptors = importlib.import_module("native_security.descriptor_admission")
        self.root = "/protected/clients/" + "a" * 64

    def registration(self, change=None, raw=None, *, writable=False, mode=0o600, linked=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        record = {
            "schemaVersion": "1.0.0", "ownerUid": os.getuid(),
            "profileId": "profile_" + "b" * 32, "instanceId": "instance_" + "c" * 32,
            "clientInstallationId": "a" * 64, "profileSha256": "sha256:" + "d" * 64,
            "hostPolicySha256": "sha256:" + "e" * 64,
            "clientSelectionSha256": package.digest(b"selected bytes"),
            "environment": "development", "project": "Example project",
        }
        if change is not None:
            change(record)
        raw = json.dumps(record).encode() if raw is None else raw
        path = Path(directory.name) / "registration.json"
        path.write_bytes(raw)
        path.chmod(mode)
        if linked:
            os.link(path, path.with_suffix(".alias"))
        original = os.open(path, (os.O_RDWR if writable else os.O_RDONLY) | os.O_CLOEXEC)
        self.addCleanup(os.close, original)
        duplicate = os.dup(original)
        os.set_inheritable(duplicate, True)
        return original, duplicate, raw

    def assert_consumed(self, original, duplicate):
        with self.assertRaises(OSError):
            os.fstat(duplicate)
        os.fstat(original)

    def test_registered_arguments_are_closed(self):
        for operation in ("startup", "startup-json", "startup-worker", "startup-worker-json", "mcp", "mcp-worker", "dashboard", "claude-code-hook", "claude-code-hook-worker"):
            args = ["registered-client", operation, "/private/selection.json", "3", "sha256:" + "a" * 64]
            self.assertEqual(bootstrap._arguments(self.root, args), ("registered-client", args[1:]))
            refused = [args + ["--environment", "development"], args[:-1],
                       [*args[:2], "relative", *args[3:]]]
            refused += [[*args[:3], fd, args[4]] for fd in ("0", "1", "2", "03", "-3", "3 ", "2147483648")]
            refused += [[*args[:4], digest] for digest in ("sha256:bad", "sha256:" + "A" * 64)]
            for selected in refused:
                with self.subTest(selected=selected), self.assertRaises(SystemExit):
                    bootstrap._arguments(self.root, selected)
        for operation in ("repository-client", "registered-client", "application-services", "client-setup",
                          "launch-claude-desktop", "mcp-json"):
            with self.subTest(operation=operation), self.assertRaises(SystemExit):
                bootstrap._arguments(self.root, ["registered-client", operation, "/private/selection.json",
                                                 "3", "sha256:" + "a" * 64])

    def test_registered_claude_hook_retains_context_and_worker_operation(self):
        selection = "/private/literal selection.json"
        registered = Mock()
        for operation, managed_worker in (("claude-code-hook", False),
                                          ("claude-code-hook-worker", True)):
            with self.subTest(operation=operation):
                hook_main = Mock(return_value=0)
                selected_sys = SimpleNamespace(version_info=(3, 14, 4),
                    flags=SimpleNamespace(isolated=1, no_site=1), prefix=self.root + "/python",
                    path=[self.root + "/python/lib/python3.14"],
                    argv=[self.root + "/bootstrap.py", "registered-client", operation,
                          selection, "3", "sha256:" + "a" * 64])
                with patch.object(bootstrap, "sys", selected_sys), \
                        patch.object(bootstrap, "__file__", self.root + "/bootstrap.py"), \
                        patch.object(bootstrap, "_registered_context", return_value=registered) as context, \
                        patch.dict(sys.modules, {"hub.client_launch_claude": SimpleNamespace(main=hook_main)}), \
                        self.assertRaises(SystemExit) as completed:
                    bootstrap.main()
                self.assertEqual(completed.exception.code, 0)
                context.assert_called_once_with(self.root, "3", "sha256:" + "a" * 64)
                hook_main.assert_called_once_with(
                    ["--selection", selection], registered_context=registered,
                    managed_worker=managed_worker)

    def test_registration_read_closes_duplicate_and_returns_immutable_context(self):
        original, duplicate, raw = self.registration()
        os.lseek(original, 5, os.SEEK_SET)
        binding = bootstrap._registered_context(self.root, str(duplicate), package.digest(raw))
        self.assert_consumed(original, duplicate)
        self.assertEqual(os.lseek(original, 0, os.SEEK_CUR), 5)
        self.assertIs(type(binding), self.context_module.RegisteredProfileContext)
        self.assertIs(type(binding.context), self.context_module.ProfileContext)
        self.assertEqual(binding.context.as_dict(), {"environment": "development", "project": "Example project"})
        self.assertTrue(binding.matches_selection(b"selected bytes", profile_id="profile_" + "b" * 32,
                                                  instance_id="instance_" + "c" * 32))
        with self.assertRaises(AttributeError):
            binding.context.project = "changed"
        with self.assertRaises(AttributeError):
            binding.selection_sha256 = "sha256:" + "0" * 64
        rendered = binding.context.as_dict()
        rendered["project"] = "changed"
        self.assertEqual(binding.context.project, "Example project")
        self.assertNotIn("Example project", repr(binding.context))
        self.assertNotIn("profile_", repr(binding))

    def test_registration_refusal_consumes_only_duplicate(self):
        changes = {
            "owner": lambda value: value.update(ownerUid=os.getuid() + 1),
            "owner_type": lambda value: value.update(ownerUid=True),
            "client": lambda value: value.update(clientInstallationId="f" * 64),
            "profile": lambda value: value.update(profileId="profile"),
            "instance": lambda value: value.update(instanceId="instance"),
            "digest": lambda value: value.update(clientSelectionSha256="sha256:bad"),
            "unknown": lambda value: value.update(authority="administrator"),
            "null": lambda value: value.update(project=None),
            "control": lambda value: value.update(project="Example\u0085project"),
            "separator": lambda value: value.update(project="Example\u2028project"),
            "too_long": lambda value: value.update(project="é" * 65),
            "oversize": lambda value: value.update(project="x" * 16384),
            "missing": lambda value: value.pop("hostPolicySha256"),
            "absent_metadata": lambda value: (value.pop("environment"), value.pop("project")),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                original, duplicate, raw = self.registration(change)
                with self.assertRaises(bootstrap._RegistrationFailure) as rejected:
                    bootstrap._registered_context(self.root, str(duplicate), package.digest(raw))
                self.assertEqual(str(rejected.exception), "Installed client registration is invalid.")
                self.assert_consumed(original, duplicate)
        for raw in (b'{"schemaVersion":"1.0.0","schemaVersion":"1.0.0"}', b'{} trailing', b'{"x":NaN}'):
            original, duplicate, _ = self.registration(raw=raw)
            with self.assertRaises(bootstrap._RegistrationFailure):
                bootstrap._registered_context(self.root, str(duplicate), package.digest(raw))
            self.assert_consumed(original, duplicate)
        original, duplicate, raw = self.registration()
        with self.assertRaises(bootstrap._RegistrationFailure):
            bootstrap._registered_context(self.root, str(duplicate), "sha256:" + "0" * 64)
        self.assert_consumed(original, duplicate)

    def test_registration_cleanup_uncertainty_keeps_consumed_owner(self):
        original, duplicate, raw = self.registration()
        close = os.close
        def consumed(descriptor):
            close(descriptor)
            if descriptor == duplicate:
                raise OSError("private close failure")
        with patch.object(bootstrap.os, "close", side_effect=consumed) as close_call, \
                self.assertRaises(bootstrap._RegistrationFailure) as rejected:
            bootstrap._registered_context(self.root, str(duplicate), package.digest(raw))
        self.assertEqual([call for call in close_call.call_args_list if call.args == (duplicate,)],
                         [((duplicate,), {})])
        owner = rejected.exception.cleanup_owner
        self.assertIsNone(owner.descriptor)
        self.assertEqual(owner.uncertain, duplicate)
        owner.close()
        self.assertEqual(owner.uncertain, duplicate)
        self.assert_consumed(original, duplicate)

    def test_registration_refuses_writable_linked_public_and_pipe_descriptors(self):
        for options in ({"writable": True}, {"linked": True}, {"mode": 0o644}):
            with self.subTest(options=options):
                original, duplicate, raw = self.registration(**options)
                with self.assertRaises(bootstrap._RegistrationFailure):
                    bootstrap._registered_context(self.root, str(duplicate), package.digest(raw))
                self.assert_consumed(original, duplicate)
        original, writer = os.pipe()
        self.addCleanup(os.close, original)
        self.addCleanup(os.close, writer)
        duplicate = os.dup(original)
        os.set_inheritable(duplicate, True)
        with self.assertRaises(bootstrap._RegistrationFailure):
            bootstrap._registered_context(self.root, str(duplicate), "sha256:" + "a" * 64)
        self.assert_consumed(original, duplicate)

    def test_registered_dispatch_consumes_descriptor_before_cli_and_keeps_cleanup(self):
        expected = {
            "startup": ["startup"], "startup-json": ["startup", "--output", "json"],
            "startup-worker": ["startup", "--managed-worker"],
            "startup-worker-json": ["startup", "--managed-worker", "--output", "json"],
            "mcp": ["mcp", "--enrolled"], "mcp-worker": ["mcp", "--enrolled", "--managed-worker"],
        }
        class RetainedSession:
            def __init__(self):
                self.exit_code = Mock(return_value=7)
        for operation, cli_arguments in expected.items():
            with self.subTest(operation=operation):
                original, duplicate, raw = self.registration()
                session = RetainedSession()
                def client(arguments, *, registered_context):
                    self.assert_consumed(original, duplicate)
                    self.assertEqual(arguments, cli_arguments + ["--selection", "/private/literal selection.json"])
                    self.assertIs(type(registered_context), self.context_module.RegisteredProfileContext)
                    self.assertEqual(registered_context.context.project, "Example project")
                    return session
                client_main = Mock(side_effect=client)
                selected_sys = SimpleNamespace(version_info=(3, 14, 4),
                    flags=SimpleNamespace(isolated=1, no_site=1), prefix=self.root + "/python",
                    path=[self.root + "/python/lib/python3.14"],
                    argv=[self.root + "/bootstrap.py", "registered-client", operation,
                          "/private/literal selection.json", str(duplicate), package.digest(raw)])
                with patch.object(bootstrap, "sys", selected_sys), \
                        patch.object(bootstrap, "__file__", self.root + "/bootstrap.py"), \
                        patch.dict(sys.modules, {
                            "hub.cli": SimpleNamespace(Fail=RuntimeError, main=client_main),
                            "hub.client_launch_entrypoint": SimpleNamespace(EnrolledSession=RetainedSession)}), \
                        self.assertRaises(SystemExit) as completed:
                    bootstrap.main()
                self.assertEqual(completed.exception.code, 7)
                client_main.assert_called_once()
                session.exit_code.assert_called_once_with()
                self.assertNotIn(self.root + "/app/dashboard", selected_sys.path)
                self.assertNotIn(self.root + "/app/taskmgmt", selected_sys.path)


if __name__ == "__main__":
    unittest.main()


class LocalEnrollmentBootstrapRoute(unittest.TestCase):
    root = "/protected/clients/" + "a" * 64
    request = "/private/setup 'literal' request.json"
    digest = "sha256:" + "b" * 64

    def test_enrollment_route_keeps_literal_request_and_digest(self):
        arguments = ["application-enroll", "--client-installation", "a" * 64,
                     "--request", self.request, "--request-sha256", self.digest]
        self.assertEqual(bootstrap._arguments(self.root, arguments),
                         ("application-enroll", ["--request", self.request, "--request-sha256", self.digest]))

    def test_enrollment_route_refuses_other_installations_and_shapes(self):
        base = ["application-enroll", "--client-installation", "a" * 64,
                "--request", self.request, "--request-sha256", self.digest]
        for changed in (base[:5], base + ["--apply"],
                        [*base[:2], "b" * 64, *base[3:]],
                        [*base[:4], "relative.json", *base[5:]],
                        [*base[:4], "/private/../request.json", *base[5:]],
                        [*base[:6], "sha256:BAD"],
                        [*base[:3], "--selection", *base[4:]]):
            with self.subTest(arguments=changed), self.assertRaises(SystemExit):
                bootstrap._arguments(self.root, changed)

    def test_package_roster_includes_the_ceremony_and_bootstrap_owner(self):
        self.assertIn("identity/local_enrollment.py", package.MODULES)
        self.assertIn("identity/bootstrap.py", package.MODULES)


class DefinitionsRetirementBootstrapRoute(unittest.TestCase):
    root = "/protected/clients/" + "a" * 64
    repository = "/Users/owner/repo 'literal'"

    def test_retirement_route_keeps_literal_repository_hub_and_apply(self):
        base = ["retire-definitions-owner", "--client-installation", "a" * 64,
                "--repository-root", self.repository, "--hub-id", "hub_nick_c44c0018"]
        self.assertEqual(bootstrap._arguments(self.root, base),
                         ("retire-definitions-owner", ["--repository-root", self.repository,
                                                       "--hub-id", "hub_nick_c44c0018"]))
        self.assertEqual(bootstrap._arguments(self.root, base + ["--apply"])[1][-1], "--apply")

    def test_retirement_route_refuses_other_installations_and_shapes(self):
        base = ["retire-definitions-owner", "--client-installation", "a" * 64,
                "--repository-root", self.repository, "--hub-id", "hub_old"]
        for changed in (base[:5], base + ["--force"], base + ["--apply", "--apply"],
                        [*base[:2], "b" * 64, *base[3:]],
                        [*base[:4], "relative", *base[5:]],
                        [*base[:6], "Bad Hub"],
                        [*base[:5], "--hub", "hub_old"]):
            with self.subTest(arguments=changed), self.assertRaises(SystemExit):
                bootstrap._arguments(self.root, changed)

    def test_package_roster_includes_the_retirement_command(self):
        self.assertIn("dashboard/definition_retirement.py", package.MODULES)


class PackagedImportClosure(unittest.TestCase):
    # Imported only behind a guard that the supported installed routes never
    # take. Anything else a packaged module imports must be in the roster.
    INTENTIONALLY_UNPACKAGED = {
        "capability_owner/process_resource.py": "Process execution is outside the MVP; receiver uses find_spec",
        "capability_owner/process_admission.py": "only reached through process_resource",
        "capability_owner/process_host.py": "only when a service selection has a process section",
        "identity/process_selection.py": "only when a service selection has a process section",
        "capability_owner/legacy_board_service.py": "only when qualified_board=True, which no route passes",
        "dashboard/resource_probes.py": "dashboard resource checks; not the services host or core Hub",
        "dashboard/modbus_rtu.py": "dashboard Modbus RTU; not the services host or core Hub",
    }

    def test_every_in_repository_import_is_packaged_or_explicitly_optional(self):
        import ast
        repository = package.REPOSITORY
        listed = set(package.MODULES)

        def resolve(name):
            parts = name.split(".")
            for base in ((), ("dashboard",), ("taskmgmt",)):
                for candidate in (Path(*base, *parts).with_suffix(".py"), Path(*base, *parts, "__init__.py")):
                    if (repository / candidate).is_file():
                        return str(candidate)
            return None
        unexpected = {}
        for module in sorted(listed):
            parent = Path(module).parent.parts
            for node in ast.walk(ast.parse((repository / module).read_text())):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    target = node.module or ""
                    if node.level:
                        target = ".".join([*parent[:len(parent) - node.level + 1], *([target] if target else [])])
                    names = [target, *(target + "." + alias.name for alias in node.names)]
                for name in names:
                    path = resolve(name) if name else None
                    if (path and path not in listed and path not in self.INTENTIONALLY_UNPACKAGED
                            and not path.startswith("sdk/python/")):
                        unexpected.setdefault(path, set()).add(module)
        self.assertEqual(unexpected, {}, "packaged modules import unpackaged project modules")
