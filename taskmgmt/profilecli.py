"""Explicit foreground local-owner adoption of project profile examples."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dashboard"))
import profile_packages
from profile_owner import ProfileError, admit_project, read_private_input
from definition_service import DefinitionScope, DefinitionService


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ProfileError("profile_command_arguments_invalid")


def execute(args):
    parser = _Parser(description="Review and adopt bundled examples for one owned project.")
    parser.add_argument("command", choices=("catalog", "preview", "adopt"))
    parser.add_argument("--project", required=True)
    parser.add_argument("--request")
    parser.add_argument("--approval-checksum")
    parser.add_argument("--record-checksum")
    options = parser.parse_args(args)
    with admit_project(options.project) as owner:
        if options.command == "catalog":
            if options.request or options.approval_checksum or options.record_checksum:
                raise ProfileError("profile_command_arguments_invalid")
            return profile_packages.preview(owner.project, None, None, owner=owner)[0]
        if not options.request:
            raise ProfileError("profile_private_request_required")
        try:
            request = json.loads(read_private_input(options.request), object_pairs_hook=profile_packages._unique)
        except (ValueError, RecursionError):
            raise ProfileError("profile_request_invalid") from None
        if (not isinstance(request, dict) or set(request) != {"schemaVersion", "selections", "clients"}
                or request["schemaVersion"] != "1.0.0"):
            raise ProfileError("profile_request_invalid")
        if options.command == "preview":
            if options.approval_checksum or options.record_checksum:
                raise ProfileError("profile_command_arguments_invalid")
            return profile_packages.preview(owner.project, request["selections"], request["clients"], owner=owner)[0]
        if not options.approval_checksum or not options.record_checksum:
            raise ProfileError("profile_exact_approval_required")
        # Roots are explicit and used only for collision detection. No ambient
        # global or home definitions become project membership through this command.
        home = Path.home().resolve()
        global_root = Path.home() / ".agentmux"
        service = DefinitionService(DefinitionScope(owner.project, home, global_root, str(owner.project)))
        return service.adopt_profiles(owner, request["selections"], request["clients"],
                                      options.approval_checksum, options.record_checksum)


def main():
    try:
        result = execute(sys.argv[1:])
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        code = str(exc) if isinstance(exc, ProfileError) else "profile_command_failed"
        print(json.dumps({"status": "failed", "code": code}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
