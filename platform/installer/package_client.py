"""Build the bounded ordinary client payload from explicitly prepared inputs.

This command never installs dependencies, writes protected paths, or enrolls a
profile. Its output still requires an independently approved selection digest.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


PYTHON_VERSION = "3.14.4"
REPOSITORY = Path(__file__).resolve().parents[2]
MODULES = (
    "agentmux_windows.py", "hub/__init__.py", "hub/cli.py",
    "hub/server.py", "hub/native_check_timing.py", "hub/enrolled_hub_bootstrap.py", "hub/legacy_identity_client.py",
    "hub/bridge.py", "hub/deliver.py", "hub/profiles.py", "hub/receipts.py", "hub/transport.py",
    "hub/client_startup.py", "hub/client_launch_selection.py",
    "hub/client_launch_coordinator.py", "hub/client_launch_entrypoint.py",
    "hub/client_launch_binding.py", "hub/client_launch_connection.py",
    "hub/client_launch_enrollment.py", "hub/client_launch_session.py",
    "hub/client_launch_imports.py", "hub/client_launch_desktop.py", "hub/client_launch_claude.py",
    "hub/nats_transport.py", "hub/authority_switch_recovery_client.py",
    "hub/client_launch_repository.py",
    "hub/profile_context.py", "hub/core_profile.py", "hub/core_endpoint.py",
    "hub/installed_client_admission.py", "hub/native_core_context.py", "hub/native_core_callback.py",
    "hub/native_descriptor_admission.py", "hub/fed/__init__.py", "hub/fed/mcp.py",
    "dashboard/client_setup.py", "dashboard/resource_registration.py", "dashboard/resource_settings.py",
    "dashboard/claude_hook_registration.py", "dashboard/claude_hook_setup.py",
    "dashboard/repository_profiles.py", "dashboard/oidc_browser_login.py",
    "taskmgmt/profile_owner.py",
    "native_security/__init__.py", "native_security/descriptor_admission.py", "native_security/core_caller.py", "native_security/nats_credentials.py",
    "native_security/secret_custody.py", "native_security/ordinary_secret_custody.py",
    "identity/__init__.py", "identity/application_binding.py", "identity/authority.py",
    "identity/ingress.py", "identity/capability_routes.py",
    "identity/application_client.py", "identity/application_enrollment.py", "identity/message_client.py",
    "identity/application_account.py", "identity/ordinary_secret.py",
    "identity/local_browser_session.py", "identity/oidc_adapter.py",
    "identity/oidc_authorization_code.py", "identity/oidc_device_authorization.py",
    "identity/oidc_terminal_login.py",
    # The local enrollment ceremony and the bootstrap owner it drives (AMUX-728).
    "identity/bootstrap.py", "identity/local_enrollment.py",
    # Imported by dashboard/application_service_host.py, which the installed
    # application-services process runs. Process execution stays excluded:
    # capability_owner/process_resource.py is optional by find_spec.
    "identity/execution_evidence.py", "execution_owner/__init__.py", "execution_owner/plans.py",
    "orchestration_owner/__init__.py", "orchestration_owner/commands.py", "orchestration_owner/domain_adapter.py",
    "orchestration_owner/journal.py", "orchestration_owner/owner.py", "orchestration_owner/phase_signer.py",
    "orchestration_owner/service.py", "orchestration_owner/worker.py",
    "integration_owner/__init__.py", "integration_owner/receipts.py", "integration_owner/intent.py",
    # Private service receiver and the selected identity, definition and
    # integration owners. Keep production dependencies explicit.
    "dashboard/application_service_host.py", "dashboard/application_service_process.py",
    "dashboard/local_browser_auth.py", "dashboard/dashboard_commands.py",
    "dashboard/dashboard_server_effects.py", "dashboard/server.py",
    "dashboard/boardagents.py", "dashboard/chatter_feed.py", "dashboard/codesys_panel.py",
    "dashboard/github_panel.py", "dashboard/fed_panel.py", "dashboard/hub_panel.py",
    "dashboard/boardteams.py", "dashboard/ccstore.py", "dashboard/github_auth.py",
    "dashboard/mqtt.py", "dashboard/mqtt_monitor.py", "dashboard/modbus_poll.py",
    "dashboard/netscan.py", "dashboard/profinet.py", "dashboard/runsview.py",
    "dashboard/suite_server.py",
    "dashboard/ccboard.py", "dashboard/definition_admission.py", "dashboard/definition_budget.py",
    "dashboard/definition_command_service.py", "dashboard/definition_commands.py",
    "dashboard/definition_completion.py", "dashboard/definition_effects.py",
    "dashboard/definition_owner_adapter.py", "dashboard/definition_service.py",
    # Owner-supported retirement of a stopped profile's definitions fence.
    "dashboard/definition_retirement.py",
    "hub/fed/owned_nats.py", "hub/fed/session.py", "hub/names.py", "hub/store.py",
    "hub/migration_recovery.py",
    "identity/application_host_selection.py", "identity/application_service_selection.py",
    "identity/capability_service.py", "identity/capacity.py", "identity/checkpoint.py",
    "identity/commands.py", "identity/downstream.py", "identity/legacy_identity.py", "identity/native_bridge.py",
    "identity/native_activation.py", "identity/native_configuration.py",
    "identity/native_records.py", "identity/observation_updates.py", "identity/service.py", "identity/transitions.py",
    "integration_owner/atlassian_requests.py", "integration_owner/commands.py",
    "integration_owner/credentials.py", "integration_owner/enrollment.py", "integration_owner/lifecycle.py",
    "integration_owner/observations.py", "integration_owner/receiver.py", "integration_owner/service.py",
    "integration_owner/operator_command.py", "integration_owner/operator_provisioning.py",
    "integration_owner/provisioning.py",
    "integration_owner/workers.py",
    "integration_owner/github_requests.py", "integration_owner/github_worker.py",
    "state_owner/__init__.py", "state_owner/_history_worker.py", "state_owner/artifacts.py",
    "state_owner/federation_policy.py",
    "state_owner/conversation_migration.py", "state_owner/task_migration.py",
    "state_owner/authority_switch.py", "state_owner/authority_switch_service.py",
    "state_owner/backup.py", "state_owner/backup_host.py", "state_owner/backup_lifecycle.py",
    "state_owner/checkpoint_host.py", "state_owner/checkpoints.py", "state_owner/history.py",
    "state_owner/ledger.py", "state_owner/recovery.py", "state_owner/retention.py",
    "taskmgmt/agentdefs.py", "taskmgmt/atlassian.py", "taskmgmt/definition_team.py",
    "taskmgmt/coordination.py", "taskmgmt/dispatch.py", "taskmgmt/run.py", "taskmgmt/notify.py",
    "taskmgmt/profile_packages.py",
    # Selected storage uses the existing board owners and their retained
    # federation helpers. Importing these modules does not start a federation.
    "capability_owner/__init__.py", "capability_owner/selected_storage.py",
    "capability_owner/secret_consumer.py", "capability_owner/secret_journal.py",
    "capability_owner/ordinary_secret.py", "capability_owner/secret_resource.py", "capability_owner/secret_host.py",
    "capability_owner/secret_journal_admission.py",
    "identity/secret_selection.py",
    "capability_owner/board_allocation.py", "capability_owner/board_allocation_journal.py",
    "capability_owner/board_allocation_owner.py", "capability_owner/board_journal.py",
    "capability_owner/board_owner.py", "capability_owner/board_phase_signer.py",
    "capability_owner/board_publisher.py", "capability_owner/board_target.py",
    "capability_owner/federation_board.py", "capability_owner/private_storage.py",
    "capability_owner/messages.py", "capability_owner/messages_host.py",
    "capability_owner/federated_storage.py", "capability_owner/knowledge.py",
    "capability_owner/knowledge_host.py",
    "capability_owner/code.py", "capability_owner/code_host.py", "capability_owner/code_legacy.py",
    "capability_owner/code_bridge_service.py", "capability_owner/code_git.py",
    "capability_owner/code_completion.py",
    "capability_owner/legacy_code_client.py", "identity/code_client.py",
    "capability_owner/work.py", "capability_owner/work_host.py", "capability_owner/work_legacy.py",
    "capability_owner/first_worker.py",
    "capability_owner/work_maintenance.py", "capability_owner/legacy_work_notifications.py",
    "capability_owner/work_bridge_service.py", "capability_owner/legacy_work_client.py", "identity/work_client.py",
    "capability_owner/local_work_client.py", "capability_owner/federated_work_client.py",
    "capability_owner/work_completion.py", "capability_owner/work_rpc.py", "capability_owner/work_control.py",
    "capability_owner/work_lifecycle.py", "capability_owner/work_lifecycle_client.py",
    "capability_owner/work_source.py",
    "capability_owner/work_capture.py",
    "identity/core_work_transport.py", "hub/core_work_transport.py",
    "capability_owner/core_work.py", "capability_owner/core_work_client.py",
    "capability_owner/core_work_roles.py",
    "capability_owner/knowledge_legacy.py", "capability_owner/knowledge_bridge_service.py",
    "capability_owner/legacy_knowledge_client.py", "identity/knowledge_client.py",
    "identity/peer_control.py",
    "identity/peer_control_commands.py", "capability_owner/peer_control_command.py",
    "capability_owner/peer_control_service.py", "capability_owner/peer_control_client.py",
    "identity/federation_policy_selection.py",
    "identity/federation_policy_commands.py", "identity/federation_policy_client.py",
    "capability_owner/federation_policy_transition.py", "capability_owner/legacy_policy_client.py",
    "capability_owner/knowledge_control.py", "capability_owner/policy_bootstrap.py",
    "capability_owner/message_bridge_service.py", "capability_owner/legacy_messages_client.py",
    "capability_owner/policy.py", "capability_owner/policy_host.py",
    "capability_owner/receiver.py", "capability_owner/reply_service.py",
    "capability_owner/resources.py", "capability_owner/workspace.py",
    "capability_owner/workspace_host.py", "identity/workspace_selection.py",
    "capability_owner/artifact_host.py", "capability_owner/artifact_resource.py", "identity/artifact_selection.py",
    "hub/fed/board_services.py", "hub/fed/code_services.py", "hub/fed/config.py",
    "hub/fed/work_services.py", "hub/fed/knowledge_services.py",
    "hub/fed/conn.py", "hub/fed/envelope.py", "hub/fed/guard.py", "hub/fed/ledger.py",
    "hub/fed/plugin.py", "hub/fed/plugin_adapter.py", "hub/fed/plugins/__init__.py",
    "hub/fed/plugins/messages.py", "hub/fed/plugins/code.py", "hub/fed/policy.py", "hub/fed/redact.py",
    "hub/fed/plugins/work.py", "hub/fed/plugins/board.py", "hub/fed/plugins/knowledge.py",
    "hub/fed/runtime.py", "hub/fed/message_services.py", "hub/fed/message_storage.py",
    "hub/fed/message_bridge.py",
    "hub/fed/knowledge_bridge.py",
    "hub/fed/code_bridge.py",
    "hub/fed/peer_control.py",
    "identity/configuration_events.py", "identity/configuration_subscription_control.py",
    "identity/native_subscriptions.py", "state_owner/configuration.py",
    "state_owner/configuration_events.py", "state_owner/configuration_host.py",
    "state_owner/configuration_subscriptions.py", "state_owner/configuration_watch_control.py",
    "state_owner/task.py", "state_owner/task_artifact_custody.py",
    "state_owner/task_host.py", "state_owner/task_service.py",
)
ASSETS = ("dashboard/auth.json", "dashboard/resources.json", "dashboard/index.html",
    "dashboard/agents.css", "dashboard/agents.js", "dashboard/app.js", "dashboard/chatter.js",
    "dashboard/codesys.js", "dashboard/fed.js", "dashboard/github.js", "dashboard/hub.js",
    "dashboard/iiot.js", "dashboard/kanban.css", "dashboard/kanban.js", "dashboard/mqtt.js",
    "dashboard/netscan.js", "dashboard/runs.js", "dashboard/style.css", "dashboard/teams.css",
    "dashboard/teams.js", "contracts/v1/registry.json", "contracts/v1/models/state-machines.json")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def copy_file(source, target, *, executable=False):
    target.parent.mkdir(parents=True, exist_ok=True)
    # uv may hardlink cached dependencies. Materialize new regular files; no
    # source link or external interpreter survives in the installed package.
    if not source.is_file() or source.is_symlink():
        raise ValueError("Package input must be a regular file.")
    with source.open("rb") as stream, target.open("xb") as output:
        shutil.copyfileobj(stream, output)
    target.chmod(0o555 if executable else 0o444)


def copy_tree(source, target, *, stdlib=False):
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        if ("__pycache__" in relative.parts or item.suffix == ".pyc"
                or (stdlib and ("site-packages" in relative.parts or "pkgconfig" in relative.parts))):
            continue
        if item.is_symlink():
            raise ValueError("Package input contains a symbolic link.")
        if item.is_dir():
            continue
        copy_file(item, target / relative, executable=item.suffix in (".so", ".dylib"))


def locked_dependencies(dependencies, lock):
    expected = {}
    for line in lock.read_text().splitlines():
        if line and not line.startswith("#"):
            name, version = line.split("==")
            expected[re.sub(r"[-_.]+", "-", name).lower()] = version
    found = {}
    for distribution in importlib.metadata.distributions(path=[str(dependencies)]):
        name = re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower()
        if name in found:
            raise ValueError("Duplicate installed dependency metadata.")
        found[name] = distribution.version
    if found != expected:
        raise ValueError("Prepared dependencies do not match the complete client lock.")


def file_roster(output):
    files = []
    for file in output.rglob("*"):
        if file.is_symlink():
            raise ValueError("Packaged files must not be symbolic links.")
        if file.is_dir():
            file.chmod(0o755)
            continue
        data = file.read_bytes()
        files.append({"path": file.relative_to(output).as_posix(), "digest": digest(data),
                      "size": len(data), "mode": file.stat().st_mode & 0o777})
    files.sort(key=lambda item: item["path"])
    if len(files) > 4096 or sum(item["size"] for item in files) > 256 * 1024 * 1024:
        raise ValueError("Prepared client exceeds the package bounds.")
    return files


def build(*, python_root, dependencies, frontend, foundation_installation, output, selection_output,
          native_core_tools=None):
    if not re.fullmatch(r"[0-9a-f]{64}", foundation_installation):
        raise ValueError("Foundation installation ID is invalid.")
    python = python_root / "bin/python3.14"
    probe = subprocess.run([str(python), "-I", "-S", "-c",
                            "import json,platform,sys; print(json.dumps([platform.python_version(),platform.machine(),sys.prefix]))"],
                           check=True, capture_output=True, text=True, timeout=10,
                           env={"PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"})
    if json.loads(probe.stdout) != [PYTHON_VERSION, "arm64", str(python_root)]:
        raise ValueError("Prepared Python must be a standalone native ARM64 3.14.4 runtime.")
    lock = Path(__file__).with_name("client-requirements.lock")
    locked_dependencies(dependencies, lock)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    copy_file(python, output / "python/bin/python3.14", executable=True)
    copy_tree(python_root / "lib", output / "python/lib", stdlib=True)
    copy_tree(dependencies, output / "site-packages")
    for name in (*MODULES, *ASSETS):
        copy_file(REPOSITORY / name, output / "app" / name)
    if native_core_tools is not None:
        # External tool bytes stay in their explicitly selected prepared locations.
        # The ordinary installed roster binds only this closed selection and code.
        raw = native_core_tools.read_bytes()
        if not 0 < len(raw) <= 65536:
            raise ValueError("Native core tool selection exceeds its bounds.")
        copy_file(native_core_tools, output / "app/native-core-tools.json")
        copy_file(REPOSITORY / "agentmux.sh", output / "app/agentmux.sh")
        for name in ('agentmux', 'python3', 'tmux', 'codex'):
            copy_file(Path(__file__).with_name('native_core_bin') / name,
                      output / 'app/native-bin' / name, executable=True)
    copy_tree(REPOSITORY / "sdk/python/agentmux_contracts", output / "app/sdk/python/agentmux_contracts")
    for source in sorted((REPOSITORY / "contracts/v1/schemas").glob("*.schema.json")):
        copy_file(source, output / "app/contracts/v1/schemas" / source.name)
    for directory in ("assets", "src", "vendor"):
        copy_tree(REPOSITORY / "dashboard" / directory,
                  output / "app/dashboard" / directory)
    copy_file(lock, output / "app/client-requirements.lock")
    copy_file(Path(__file__).with_name("client_bootstrap.py"), output / "bootstrap.py")
    files = file_roster(output)
    manifest = {"schemaVersion": "1.0.0", "kind": "ordinary-python-client",
                "foundationInstallationId": foundation_installation,
                "frontendDigest": digest(frontend.read_bytes()), "pythonVersion": PYTHON_VERSION,
                "interpreter": "python/bin/python3.14", "bootstrap": "bootstrap.py", "files": files}
    raw = (json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n").encode()
    (output / "client-manifest.json").write_bytes(raw)
    (output / "client-manifest.json").chmod(0o444)
    selection = {"schemaVersion": "1.0.0", "packageDirectory": str(output), "manifestDigest": digest(raw)}
    selected = (json.dumps(selection, separators=(",", ":"), sort_keys=True) + "\n").encode()
    with selection_output.open("xb") as stream:
        stream.write(selected)
    selection_output.chmod(0o600)
    return {"installationId": digest(raw)[7:], "selectionDigest": digest(selected),
            "pythonVersion": PYTHON_VERSION, "files": len(files)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("python-root", "dependencies", "frontend", "output", "selection-output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--foundation-installation", required=True)
    parser.add_argument("--native-core-tools", type=Path)
    args = parser.parse_args()
    for name in ("python_root", "dependencies", "frontend", "output", "selection_output"):
        value = getattr(args, name)
        if not value.is_absolute() or str(value) != os.path.normpath(value):
            parser.error("All input and output paths must be canonical absolute paths.")
    if args.native_core_tools is not None and (not args.native_core_tools.is_absolute()
            or str(args.native_core_tools) != os.path.normpath(args.native_core_tools)):
        parser.error("Native core tool selection must be a canonical absolute path.")
    print(json.dumps(build(**vars(args)), separators=(",", ":")))


if __name__ == "__main__":
    main()
