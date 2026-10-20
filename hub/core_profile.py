"""Retained central registration for explicit core Hub commands.

Profile display fields never authorize routing. Every use checks the original
registration, pinned route files and enrolled application selections.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import time

from agentmux_contracts import canonical_bytes, strict_loads
from hub.client_launch_selection import (_open_checked, DescriptorCleanup, DescriptorPurpose,
    load_selection)
from hub.native_descriptor_admission import check_descriptor


class CoreSetupRequired(ValueError):
    def __init__(self):
        super().__init__('selected_core_setup_required')


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


class PrivateFile:
    """Keep the original descriptor and refuse path or byte replacement."""
    def __init__(self, path, *, expected=None, limit=65536):
        self.path, self.fd, self.limit = path, None, limit
        try:
            self.fd = self._open()
            self.identity = self._identity()
            self.raw = os.pread(self.fd, limit + 1, 0)
            if not self.raw or len(self.raw) > limit or expected is not None and digest(self.raw) != expected:
                raise CoreSetupRequired()
            self.check()
        except BaseException:
            self.close()
            raise

    def _open(self):
        return _open_checked(self.path, purpose=DescriptorPurpose.PRIVATE_FILE,
            descriptor_admission=check_descriptor, deadline=time.monotonic() + 1)

    def _identity(self):
        value = os.fstat(self.fd)
        return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns

    def check(self):
        if self.fd is None:
            raise CoreSetupRequired()
        current = self._open()
        try:
            value = os.fstat(current)
            if ((value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns) != self.identity
                    or self._identity() != self.identity
                    or os.pread(current, self.limit + 1, 0) != self.raw):
                raise CoreSetupRequired()
        finally:
            DescriptorCleanup().close(current)

    def close(self):
        descriptor, self.fd = self.fd, None
        if descriptor is not None:
            DescriptorCleanup().close(descriptor)


class CoreRoute:
    def __init__(self, root, selection, registration_fd, registration_digest, repository, registration_reader):
        self.files, self.registration_fd = [], registration_fd
        try:
            self._initialize(root, selection, registration_fd, registration_digest, repository, registration_reader)
        except BaseException:
            self.close()
            raise

    def _initialize(self, root, selection, registration_fd, registration_digest, repository, registration_reader):
        self.reader, self.installation, self.registration_digest = registration_reader, root, registration_digest
        self.selection_path, self.repository = selection, repository
        self.context = self._registration()
        self.registration = self.hold(str(Path(selection).parent/'registration.json'), registration_digest)
        original = os.fstat(registration_fd)
        if (original.st_dev, original.st_ino) != self.registration.identity[:2]:
            raise CoreSetupRequired()
        self.selected_file = self.hold(selection, self.context.selection_sha256)
        self.selected = load_selection(selection, registered_context=self.context)
        if repository not in self.selected.invocation.workspaces or self.selected.core_hub is None:
            raise CoreSetupRequired()
        pin = self.selected.core_hub
        self.manifest = self.hold(pin['selection'], pin['sha256'])
        value = strict_loads(self.manifest.raw)
        if (type(value) is not dict or set(value) != {'schemaVersion', 'home', 'repositories', 'identity', 'messages', 'work'}
                or value['schemaVersion'] != '1.0.0' or type(value['repositories']) is not dict
                or set(value['repositories']) != set(self.selected.invocation.workspaces)
                or any(type(name) is not str or re.fullmatch(r'[a-z0-9_]{1,32}', name) is None
                    for name in value['repositories'].values())):
            raise CoreSetupRequired()
        self.local_repository = value['repositories'][repository]
        home = value['home']
        if (type(home) is not str or not os.path.isabs(home) or os.path.realpath(home) != home
                or any(os.path.commonpath((home, workspace)) == workspace for workspace in self.selected.invocation.workspaces)):
            raise CoreSetupRequired()
        self.home = home
        self.socket = str(Path(home)/'hub'/'hub.sock')
        if len(self.socket.encode()) > 103:
            raise CoreSetupRequired()
        self.paths, self.selections = {}, {}
        for family in ('identity', 'messages', 'work'):
            pins = value[family]
            if type(pins) is not list or not 1 <= len(pins) <= 16:
                raise CoreSetupRequired()
            self.paths[family] = []
            for entry in pins:
                if type(entry) is not dict or set(entry) != {'selection', 'sha256'}:
                    raise CoreSetupRequired()
                held = self.hold(entry['selection'], entry['sha256'])
                child = load_selection(held.path)
                if ((child.profile_id, child.instance_id, child.hub_id) !=
                        (self.selected.profile_id, self.selected.instance_id, self.selected.hub_id)
                        or child.invocation.workspaces != self.selected.invocation.workspaces
                        or child.application_client is None or child.application_connection is None):
                    raise CoreSetupRequired()
                # These private inputs remain pinned throughout session and endpoint use.
                self.hold(child.application_client)
                connection = self.hold(child.application_connection)
                self.hold(strict_loads(connection.raw)['credentialsFile'])
                self.paths[family].append(held.path)
                self.selections[held.path] = child
        identity_repositories = {name for path in self.paths['identity']
            for name in self.selections[path].application_repositories}
        if identity_repositories != set(value['repositories'].values()):
            raise CoreSetupRequired()
        self.binding = {'selection': self.context.selection_sha256, 'route': pin['sha256'],
            'profileId': self.selected.profile_id, 'instanceId': self.selected.instance_id,
            'hubId': self.selected.hub_id, 'repositories': value['repositories']}
        self.check()

    def _registration(self):
        # The installed reader consumes only this duplicate. This owner retains the original.
        duplicate = os.dup(self.registration_fd)
        return self.reader(self.installation, str(duplicate), self.registration_digest)

    def hold(self, path, expected=None):
        held = PrivateFile(path, expected=expected)
        self.files.append(held)
        return held

    def check(self):
        if self._registration() != self.context:
            raise CoreSetupRequired()
        for held in self.files:
            held.check()

    def load(self, path, *, deadline):
        self.check()
        if path not in self.selections or time.monotonic() >= deadline:
            raise CoreSetupRequired()
        return self.selections[path]

    def close(self):
        failures = []
        for held in reversed(self.files):
            try:
                held.close()
            except BaseException as error:
                failures.append(error)
        descriptor, self.registration_fd = self.registration_fd, None
        if descriptor is not None:
            try:
                DescriptorCleanup().close(descriptor)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise CoreSetupRequired() from failures[0]



def core_arguments(arguments):
    """Keep this entry point closed; nested launch and transport selection cannot escape it."""
    if (type(arguments) is not list or not 1 <= len(arguments) <= 128
            or any(type(value) is not str or len(value) > 65536 or '\x00' in value for value in arguments)):
        raise CoreSetupRequired()
    if arguments == ['start']:
        return arguments
    from hub import cli
    remaining = list(arguments)
    cli.opt(remaining, '--json', flag=True)
    cli.opt(remaining, '--as')
    if not remaining or remaining[0] not in {
            'stop', 'ping', 'status', 'whoami', 'agents', 'events', 'resolve', 'spawn', 'kill', 'adopt',
            'inbox', 'ack', 'post', 'claim', 'heartbeat', 'done', 'fail', 'return', 'block', 'work'}:
        raise CoreSetupRequired()
    if remaining[0] == 'work' and (len(remaining) < 2 or remaining[1] not in ('add', 'show', 'list', 'cancel')):
        raise CoreSetupRequired()
    return arguments

class _RetainedCoreStartup:
    """Keep outer custody while an unsuccessful Hub cleanup still has borrowers."""
    def __init__(self, failure, owners, route, startup_owners):
        self.failure, self.owners, self.route = failure, owners, route
        self.startup_owners = startup_owners
        self.close_failures = ()
        self.closed = False

    def close(self):
        if self.closed:
            return
        if self.close_failures:
            raise self.close_failures[0]
        if getattr(self.failure.owner, '_hub_borrowers_joined', False) is not True:
            raise self.failure
        failures = []
        try:
            self.owners.close()
        except BaseException as error:
            failures.append(error)
        try:
            self.route.close()
        except BaseException as error:
            failures.append(error)
        # ExitStack consumed its callbacks, even if one failed. Keep the owners
        # and original outcome; another close cannot establish successful cleanup.
        self.close_failures = tuple(failures)
        if self.close_failures:
            raise self.close_failures[0]
        self.closed = True


def run_registered_core(root, arguments, *, registration_reader):
    """Only the installed bootstrap calls this with its admitted registration FD."""
    route = object.__new__(CoreRoute)
    route.files, route.registration_fd = [], int(arguments[1])
    retained = False
    try:
        CoreRoute.__init__(route, root, arguments[0], int(arguments[1]), arguments[2], arguments[3], registration_reader)
        command = core_arguments(arguments[5:])
        from hub.core_endpoint import CoreEndpoint, CoreConnection
        if command == ['start']:
            # Explicit foreground ownership. Managed workers cannot start a second shared Hub.
            os.environ['AGENTMUX_HOME'] = route.home
            from hub import server
            from hub.enrolled_hub_bootstrap import _run_enrolled_hub
            if (server.ROOT, server.SOCK) != (route.home, route.socket):
                raise CoreSetupRequired()
            endpoint = CoreEndpoint(route)
            def run_server(**inputs):
                return server.main(profile_context=route.context.context, selected_endpoint=endpoint, **inputs)
            from contextlib import ExitStack
            import pwd
            from hub.installed_client_admission import admit_installed_client
            from hub.native_core_context import NativeCoreContext
            with ExitStack() as owners:
                installed = admit_installed_client(Path(root).name, route.selection_path,
                    deadline=time.monotonic()+30)
                owners.callback(installed.close)
                core = NativeCoreContext(installed, home=pwd.getpwuid(os.getuid()).pw_dir,
                    deadline=time.monotonic()+60)
                owners.callback(core.close)
                core.require_operator(deadline=time.monotonic()+10)
                try:
                    return _run_enrolled_hub(route.paths['identity'], loader=route.load,
                        message_paths=route.paths['messages'], work_paths=route.paths['work'],
                        server_main=run_server, native_core=core)
                except BaseException as failure:
                    if (type(failure) is server.HubCleanupFailure
                            and getattr(failure.owner, '_hub_borrowers_joined', False) is not True):
                        cleanup = _RetainedCoreStartup(failure, owners.pop_all(), route, (core, installed))
                        failure.cleanup_owners = (*failure.cleanup_owners, cleanup)
                        retained = True
                    raise
        from hub import cli
        connection = CoreConnection(route)
        token = cli.selected_connection.set(connection)
        try:
            cli.main(list(command))
            return 0
        finally:
            cli.selected_connection.reset(token)
            connection.close()
    except (Exception, SystemExit) as error:
        if retained:
            raise
        import sys
        from hub.cli import Fail
        if isinstance(error, Fail):
            sys.stderr.write(str(error) + '\n')
        else:
            sys.stderr.write('Selected core Hub setup or command failed. No default Hub was used.\n')
        return 1
    finally:
        if not retained:
            route.close()
