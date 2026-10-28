"""Enter the packaged client with isolated, protected import paths."""
import os
import re
import sys


_CLIENT_OPERATIONS = {
    "startup": ("startup",),
    "startup-json": ("startup", "--output", "json"),
    "startup-worker": ("startup", "--managed-worker"),
    "startup-worker-json": ("startup", "--managed-worker", "--output", "json"),
    "mcp": ("mcp", "--enrolled"),
    "mcp-worker": ("mcp", "--enrolled", "--managed-worker"),
    "dashboard": ("dashboard",),
}
_CLAUDE_CODE_HOOKS = {"claude-code-hook": False, "claude-code-hook-worker": True}
_PROFILE_OPERATIONS = frozenset((*_CLIENT_OPERATIONS, *_CLAUDE_CODE_HOOKS))


def _absolute(path):
    return (isinstance(path, str) and os.path.isabs(path) and os.path.normpath(path) == path
            and len(path) <= 4096 and not any(character in path for character in "\x00\r\n"))


def _repository(path):
    if (not _absolute(path) or path == os.sep or path.startswith('//')
            or len(path.split(os.sep)) > 128
            or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in path)):
        return False
    try:
        return len(path.encode('utf-8')) <= 4096
    except UnicodeError:
        return False


def _registration_descriptor(value):
    return (isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,9}", value) is not None
            and 3 <= int(value) <= 2147483647)


def _arguments(root, arguments):
    if (3 <= len(arguments) <= 130 and arguments[0] == 'native-core-callback'
            and arguments[1] == 'hub'
            and all(type(value) is str and len(value) <= 65536 and '\x00' not in value for value in arguments)):
        return arguments[0], arguments[1:]
    if (len(arguments) in (11, 12) and arguments[0] == "claude-hook-setup"
            and arguments[1] == "--configuration" and _repository(arguments[2])
            and os.path.basename(arguments[2]) == "settings.json"):
        _, selected = _arguments(root, ["client-setup", *arguments[3:]])
        return arguments[0], [arguments[2], *selected]
    if arguments == ["application-services"]:
        return arguments[0], []
    if arguments == ["integration-operator"]:
        return arguments[0], []
    if (len(arguments) == 7 and arguments[0] == "application-enroll"
            and arguments[1] == "--client-installation" and re.fullmatch(r"[0-9a-f]{64}", arguments[2])
            and arguments[2] == os.path.basename(root)
            and arguments[3] == "--request" and _absolute(arguments[4])
            and arguments[5] == "--request-sha256" and re.fullmatch(r"sha256:[0-9a-f]{64}", arguments[6])):
        return arguments[0], ["--request", arguments[4], "--request-sha256", arguments[6]]
    if (len(arguments) == 19 and arguments[0] == "application-requests"
            and arguments[1::2] == ["--client-installation", "--foundation-selection", "--foundation-selection-sha256",
                                    "--repository-root", "--principal", "--local-node", "--message-peer",
                                    "--organization", "--output"]
            and re.fullmatch(r"[0-9a-f]{64}", arguments[2]) and arguments[2] == os.path.basename(root)
            and _absolute(arguments[4]) and re.fullmatch(r"sha256:[0-9a-f]{64}", arguments[6])
            and _absolute(arguments[8]) and all(re.fullmatch(r"[a-z0-9_]{1,32}", v) for v in arguments[10:15:2])
            and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", arguments[16]) and _absolute(arguments[18])):
        return arguments[0], arguments[1:]
    if (len(arguments) in (7, 8) and arguments[0] == "retire-definitions-owner"
            and arguments[1] == "--client-installation" and re.fullmatch(r"[0-9a-f]{64}", arguments[2])
            and arguments[2] == os.path.basename(root)
            and arguments[3] == "--repository-root" and _absolute(arguments[4])
            and arguments[5] == "--hub-id" and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", arguments[6])
            and arguments[7:] in ([], ["--apply"])):
        return arguments[0], ["--repository-root", arguments[4], "--hub-id", arguments[6], *arguments[7:]]
    if (7 <= len(arguments) <= 134 and arguments[0] == 'registered-core'
            and _absolute(arguments[1]) and _registration_descriptor(arguments[2])
            and re.fullmatch(r'sha256:[0-9a-f]{64}', arguments[3])
            and _repository(arguments[4]) and arguments[5] == '--'
            and all(type(value) is str and len(value) <= 65536 and '\x00' not in value for value in arguments[6:])):
        return arguments[0], arguments[1:]
    if (len(arguments) == 5 and arguments[0] == "registered-client"
            and arguments[1] in _PROFILE_OPERATIONS and _absolute(arguments[2])
            and _registration_descriptor(arguments[3])
            and re.fullmatch(r"sha256:[0-9a-f]{64}", arguments[4])):
        return arguments[0], arguments[1:]
    if (len(arguments) == 3 and arguments[0] == "repository-client"
            and arguments[1] in _CLIENT_OPERATIONS and arguments[1] != 'dashboard'
            and _repository(arguments[2])):
        return arguments[0], arguments[1:]
    if (len(arguments) == 2
            and (arguments[0] in _PROFILE_OPERATIONS or arguments[0] == "launch-claude-desktop")
            and _absolute(arguments[1])):
        return arguments[0], arguments[1:]
    if (len(arguments) in (9, 10) and arguments[0] == "client-setup"
            and arguments[1] == "--client-installation" and re.fullmatch(r"[0-9a-f]{64}", arguments[2])
            and arguments[2] == os.path.basename(root)
            and arguments[3] == "--selection" and _absolute(arguments[4])
            and arguments[5] == "--receipt" and _absolute(arguments[6])
            and arguments[7] == "--operation" and arguments[8] in ("install", "remove", "restore", "recover")
            and (len(arguments) == 9 or arguments[9] == "--apply")):
        return arguments[0], arguments[1:]
    raise SystemExit("Installed client invocation is invalid.")


class _RegistrationFailure(SystemExit):
    def __init__(self, owner, *causes):
        super().__init__("Installed client registration is invalid.")
        self.cleanup_owner = owner
        self._causes = causes


class _RegistrationDescriptor:
    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.uncertain = None

    def close(self):
        descriptor, self.descriptor = self.descriptor, None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException:
                self.uncertain = descriptor
                raise


def _registered_context(root, descriptor, digest):
    """Consume the inherited duplicate; never reopen the selection here."""
    owner = _RegistrationDescriptor(int(descriptor))
    failure = None
    try:
        fd = owner.descriptor
        os.set_inheritable(fd, False)
        import fcntl
        import hashlib
        import json
        import stat
        import time
        from hub.profile_context import ProfileContext, RegisteredProfileContext
        from native_security.descriptor_admission import DescriptorPurpose, check_descriptor

        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        def reject_constant(_value):
            raise ValueError

        deadline = time.monotonic() + 1
        before = os.fstat(fd)
        if (os.getuid() == 0 or os.getuid() != os.geteuid() or not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1 or not 0 < before.st_size <= 16384
                or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                or check_descriptor(fd, purpose=DescriptorPurpose.PRIVATE_FILE, deadline=deadline) is not True):
            raise ValueError
        raw = os.pread(fd, before.st_size, 0)
        if (check_descriptor(fd, purpose=DescriptorPurpose.PRIVATE_FILE, deadline=deadline) is not True
                or identity(os.fstat(fd)) != identity(before) or len(raw) != before.st_size
                or time.monotonic() >= deadline or "sha256:" + hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError
        record = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=reject_constant)
        required = {"schemaVersion", "ownerUid", "profileId", "instanceId", "clientInstallationId",
                    "profileSha256", "hostPolicySha256", "clientSelectionSha256"}
        if (type(record) is not dict or not required <= set(record) <= required | {"environment", "project"}
                or any(value is None for value in record.values()) or record['schemaVersion'] != "1.0.0"
                or type(record['ownerUid']) is not int or record['ownerUid'] != os.getuid()
                or type(record['clientInstallationId']) is not str
                or re.fullmatch(r"[0-9a-f]{64}", record['clientInstallationId']) is None
                or record['clientInstallationId'] != os.path.basename(root)):
            raise ValueError
        for field, pattern in (("profileId", r"profile_[0-9a-f]{32}"),
                               ("instanceId", r"instance_[0-9a-f]{32}"),
                               ("profileSha256", r"sha256:[0-9a-f]{64}"),
                               ("hostPolicySha256", r"sha256:[0-9a-f]{64}"),
                               ("clientSelectionSha256", r"sha256:[0-9a-f]{64}")):
            if type(record[field]) is not str or re.fullmatch(pattern, record[field]) is None:
                raise ValueError
        context = ProfileContext(environment=record.get('environment'), project=record.get('project'))
        return RegisteredProfileContext(selection_sha256=record['clientSelectionSha256'],
            profile_id=record['profileId'], instance_id=record['instanceId'], context=context)
    except BaseException as error:
        failure = error
        raise _RegistrationFailure(owner, error) from None
    finally:
        try:
            owner.close()
        except BaseException as cleanup:
            raise _RegistrationFailure(owner, failure, cleanup) from None


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    if (sys.version_info[:3] != (3, 14, 4) or not sys.flags.isolated
            or not sys.flags.no_site or sys.prefix != os.path.join(root, "python")):
        raise SystemExit("Installed client invocation is invalid.")
    operation, selected = _arguments(root, sys.argv[1:])
    # -I -S prevents cwd, user-site, PYTHONPATH and .pth import execution. Only
    # bundled standard-library paths and these explicit package paths remain.
    standard = os.path.join(root, "python", "lib") + os.sep
    if any(not item.startswith(standard) for item in sys.path):
        raise SystemExit("Installed Python import paths are invalid.")
    sys.dont_write_bytecode = True
    sys.path[:0] = [os.path.join(root, "app"), os.path.join(root, "app", "sdk", "python"),
                   os.path.join(root, "site-packages")]
    if operation == 'native-core-callback':
        from hub.native_core_callback import run_callback, MissingNativeCoreRoute
        try:
            from hub.client_launch_repository import RepositoryCoreCallback
            raise SystemExit(run_callback(selected, route=RepositoryCoreCallback()))
        except MissingNativeCoreRoute:
            raise SystemExit('Selected native callback routing is required.') from None
    if operation == "application-services":
        # The native host owns this private stdin/FD 3 protocol. Existing service
        # modules import each other from these fixed protected package roots.
        sys.path[:0] = [os.path.join(root, "app", "dashboard"),
                       os.path.join(root, "app", "taskmgmt")]
        from application_service_process import main as service_main
        raise SystemExit(service_main())
    if operation == "integration-operator":
        from integration_owner.operator_command import main as operator_main
        raise SystemExit(operator_main())
    if operation == "application-enroll":
        from identity.local_enrollment import main as enrollment_main
        raise SystemExit(enrollment_main(selected))
    if operation == "application-requests":
        from identity.application_requests import main as requests_main
        raise SystemExit(requests_main(selected))
    if operation == "retire-definitions-owner":
        # The definitions owner imports its siblings from these fixed roots.
        sys.path[:0] = [os.path.join(root, "app", "dashboard"),
                       os.path.join(root, "app", "taskmgmt")]
        from definition_retirement import main as retirement_main
        raise SystemExit(retirement_main(selected))
    if operation == "claude-hook-setup":
        from dashboard.claude_hook_setup import main as hook_setup_main
        raise SystemExit(hook_setup_main(selected[1:], configuration_path=selected[0]))
    if operation == "client-setup":
        from dashboard.client_setup import main as setup_main
        raise SystemExit(setup_main(selected))
    if operation == "launch-claude-desktop":
        from hub.client_launch_desktop import main as desktop_main
        raise SystemExit(desktop_main(["--selection", selected[0]]))
    if operation == 'registered-core':
        from hub.core_profile import run_registered_core
        raise SystemExit(run_registered_core(root, selected, registration_reader=_registered_context))
    registered_context = None
    if operation == "repository-client":
        arguments = [*_CLIENT_OPERATIONS[selected[0]], "--repository-root", selected[1]]
    elif operation == "registered-client":
        registered_context = _registered_context(root, selected[2], selected[3])
        if selected[0] in _CLAUDE_CODE_HOOKS:
            arguments = None
        else:
            arguments = [*_CLIENT_OPERATIONS[selected[0]], "--selection", selected[1]]
    else:
        arguments = (None if operation in _CLAUDE_CODE_HOOKS
                     else [*_CLIENT_OPERATIONS[operation], "--selection", selected[0]])
    if arguments is None:
        from hub.client_launch_claude import main as claude_hook_main
        selection = selected[1] if operation == "registered-client" else selected[0]
        hook_operation = selected[0] if operation == "registered-client" else operation
        raise SystemExit(claude_hook_main(
            ["--selection", selection], registered_context=registered_context,
            managed_worker=_CLAUDE_CODE_HOOKS[hook_operation]))
    from hub.cli import Fail, main as client_main
    from hub.client_launch_entrypoint import EnrolledSession
    try:
        session = (client_main(arguments, registered_context=registered_context)
                   if registered_context is not None else client_main(arguments))
        if not isinstance(session, EnrolledSession):
            raise SystemExit("Installed client did not retain its session.")
        raise SystemExit(session.exit_code())
    except Fail as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
