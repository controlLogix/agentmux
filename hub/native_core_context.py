"""Retained, explicit native tools for the installed core workflow.

This owner supplies executable bytes and arguments, never caller authority.
The installed package selects the closed roster; ambient paths select nothing.
"""
from dataclasses import dataclass
import errno
import socket
import mmap
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time

from agentmux_contracts import strict_loads
from hub.client_launch_selection import load_selection
from hub.installed_client_admission import (
    InstalledClientAdmission, PROTECTED_CLIENT_BASE, _RetainedPath, _read_file,
    _native_images, _native_text,
)
from native_security.descriptor_admission import DescriptorPurpose


class NativeCoreError(ValueError):
    def __init__(self, code='native_core_tools_unavailable', *, owner=None, causes=()):
        super().__init__(code)
        self.cleanup = owner
        self.causes = tuple(causes)


@dataclass(frozen=True)
class NativeCoreCommand:
    arguments: tuple[str, ...]
    environment: dict[str, str]


class _PreparedFile:
    def __init__(self, entry, deadline):
        if (type(entry) is not dict or set(entry) != {'path', 'sha256'}
                or type(entry['path']) is not str or type(entry['sha256']) is not str):
            raise NativeCoreError()
        self.path, self.digest = entry['path'], entry['sha256']
        if os.path.realpath(self.path) != self.path:
            raise NativeCoreError()
        self.held = _RetainedPath(self.path, purpose=DescriptorPurpose.PREPARED_CORE_FILE, deadline=deadline)
        try:
            self.check(deadline)
        except BaseException as failure:
            try:
                self.close()
            except BaseException as cleanup:
                raise NativeCoreError('native_core_cleanup_pending', owner=self,
                                      causes=(failure, cleanup)) from None
            raise

    def check(self, deadline):
        self.held.recheck(deadline=deadline)
        digest, _, _ = _read_file(self.held.fd, purpose=DescriptorPurpose.PREPARED_CORE_FILE,
            limit=512 * 1024 * 1024, deadline=deadline, owners=self.held._owners)
        if digest != self.digest:
            raise NativeCoreError()

    def image(self, deadline):
        # mmap avoids copying the large selected provider executable into Python.
        with mmap.mmap(self.held.fd, 0, access=mmap.ACCESS_READ) as raw:
            if raw[:4] != b'\xcf\xfa\xed\xfe':
                raise NativeCoreError()
            images = _native_images(self.path, raw, deadline=deadline)
        if len(images) != 1 or images[0][2] not in (2, 6):
            raise NativeCoreError()
        return images[0]

    def close(self):
        self.held.close()


class NativeCoreContext:
    """Borrow the installed owner; retain and close this owner's external inputs."""
    ROLES = frozenset(('tmux', 'bash', 'codexBinary', 'codexPackage',
                       'codexLayout', 'codexHost', 'codexRg', 'codexZsh'))
    EXECUTABLES = ('tmux', 'bash', 'codexBinary', 'codexHost', 'codexRg', 'codexZsh')

    def __init__(self, installed, *, home, deadline):
        self.files, self.aliases, self.pending = [], {}, []
        self.closed = False
        self.installed = installed
        try:
            if (type(installed) is not InstalledClientAdmission or type(home) is not str
                    or home != pwd.getpwuid(os.getuid()).pw_dir or os.path.realpath(home) != home):
                raise NativeCoreError()
            installed.recheck(deadline=deadline)
            self.home = home
            self.workspaces = load_selection(installed.declaration.enrollment_selection,
                                             deadline=deadline).invocation.workspaces
            self.root = PROTECTED_CLIENT_BASE + '/' + installed.declaration.installation_id
            selected = self.root + '/app/native-core-tools.json'
            # The retained installed owner checks this exact file against its roster.
            if 'app/native-core-tools.json' not in installed._roster:
                raise NativeCoreError()
            for name in ('app/agentmux.sh', 'app/native-bin/agentmux', 'app/native-bin/python3',
                         'app/native-bin/tmux', 'app/native-bin/codex'):
                if name not in installed._roster or (name != 'app/agentmux.sh'
                        and installed._roster[name]['mode'] != 0o555):
                    raise NativeCoreError()
            with open(selected, 'rb') as stream:
                raw = stream.read(65537)
            installed.recheck(deadline=deadline)
            if len(raw) > 65536:
                raise NativeCoreError()
            value = strict_loads(raw)
            if (type(value) is not dict or set(value) != {'schemaVersion', 'tools', 'libraries', 'callerImages'}
                    or value['schemaVersion'] != '1.0.0' or type(value['tools']) is not dict
                    or set(value['tools']) != self.ROLES or type(value['libraries']) is not list
                    or not 1 <= len(value['libraries']) <= 16
                    or type(value['callerImages']) is not list or not 1 <= len(value['callerImages']) <= 16):
                raise NativeCoreError()
            self.tools = {role: self._keep(entry, deadline) for role, entry in value['tools'].items()}
            libraries = [self._keep(entry, deadline) for entry in value['libraries']]
            self.caller_images = [self._keep(entry, deadline) for entry in value['callerImages']]
            self.by_path = {item.path: item for item in self.files}
            if len(self.by_path) != len(self.files) or sum(os.fstat(item.held.fd).st_size for item in self.files) > 1024**3:
                raise NativeCoreError()
            for role in self.EXECUTABLES:
                if not os.fstat(self.tools[role].held.fd).st_mode & stat.S_IXUSR:
                    raise NativeCoreError()
            self._codex_layout()
            self._libraries(libraries, deadline)
            self.recheck(deadline=deadline)
            self._verify_versions(deadline)
        except BaseException as failure:
            if getattr(failure, 'cleanup', None) is not None:
                self.pending.append(failure)
            try:
                self.close()
            except BaseException as cleanup:
                raise NativeCoreError('native_core_cleanup_pending', owner=self,
                                      causes=(failure, cleanup)) from None
            if isinstance(failure, NativeCoreError):
                raise
            raise NativeCoreError(causes=(failure,)) from None

    def _keep(self, entry, deadline):
        if (type(entry) is not dict or type(entry.get('path')) is not str
                or any(os.path.commonpath((entry['path'], root)) == root for root in self.workspaces)):
            raise NativeCoreError()
        for existing in self.files:
            if existing.path == entry['path']:
                if existing.digest != entry.get('sha256'):
                    raise NativeCoreError()
                return existing
        item = _PreparedFile(entry, deadline)
        self.files.append(item)
        return item

    def _codex_layout(self):
        vendor = Path(self.tools['codexBinary'].path).parent.parent
        root = vendor.parents[4]
        expected = {'codexPackage': root/'package.json', 'codexLayout': vendor/'codex-package.json',
            'codexBinary': vendor/'bin/codex', 'codexHost': vendor/'bin/codex-code-mode-host',
            'codexRg': vendor/'codex-path/rg', 'codexZsh': vendor/'codex-resources/zsh/bin/zsh'}
        if any(self.tools[key].path != str(path) for key, path in expected.items()):
            raise NativeCoreError()
        self.codex_package_root = str(root)
        raw = os.pread(self.tools['codexLayout'].held.fd, 65537, 0)
        value = strict_loads(raw)
        if (len(raw) > 65536 or type(value) is not dict or value != {
                'layoutVersion': 1, 'version': '0.162.1', 'target': 'aarch64-apple-darwin',
                'variant': 'codex', 'entrypoint': 'bin/codex', 'resourcesDir': 'codex-resources',
                'pathDir': 'codex-path'}):
            raise NativeCoreError()
        raw = os.pread(self.tools['codexPackage'].held.fd, 65537, 0)
        package = strict_loads(raw)
        if (len(raw) > 65536 or type(package) is not dict or package.get('name') != '@openai/codex'
                or package.get('version') != value['version']):
            raise NativeCoreError()

    def _verify_versions(self, deadline):
        for role, arguments in (('bash', ('--noprofile', '--norc', '--version')),
                                ('tmux', ('-V',)), ('codexBinary', ('--version',))):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeCoreError()
            result = subprocess.run([self.tools[role].path, *arguments], stdin=subprocess.DEVNULL,
                capture_output=True, timeout=min(remaining, 5),
                env={'HOME': self.home, 'PATH': '/usr/bin:/bin', 'LANG': 'en_US.UTF-8'})
            if result.returncode != 0 or len(result.stdout) > 65536 or result.stderr:
                raise NativeCoreError()
            if role == 'bash':
                match = re.match(rb'GNU bash, version ([0-9]+)\.([0-9]+)', result.stdout)
                if match is None or tuple(map(int, match.groups())) < (4, 1):
                    raise NativeCoreError()
            elif role == 'tmux' and result.stdout.strip() != b'tmux 3.8':
                raise NativeCoreError()
            elif role == 'codexBinary' and result.stdout.strip() != b'codex-cli 0.162.1':
                raise NativeCoreError()
            self.recheck(deadline=deadline)

    def _resolved(self, path):
        if not os.path.isabs(path) or os.path.normpath(path) != path:
            raise NativeCoreError()
        if any(os.path.commonpath((path, root)) == root for root in self.workspaces):
            raise NativeCoreError()
        actual = os.path.realpath(path)
        if actual not in self.by_path:
            raise NativeCoreError()
        # Retained canonical ancestors protect the actual file. Also bind loader
        # aliases so a Homebrew link change cannot redirect the next execution.
        self.aliases[path] = actual
        return actual

    def _libraries(self, libraries, deadline):
        images = {item.path: item.image(deadline) for item in libraries}
        for role in self.EXECUTABLES:
            item = self.tools[role]
            images[item.path] = item.image(deadline)
            if images[item.path][2] != 2:
                raise NativeCoreError()
        used = set()
        def expand(value, loader, executable):
            for prefix, base in (('@loader_path/', os.path.dirname(loader)),
                                 ('@executable_path/', os.path.dirname(executable))):
                if value.startswith(prefix):
                    return os.path.normpath(os.path.join(base, value[len(prefix):]))
            if value.startswith('/'):
                return value
            raise NativeCoreError()
        def visit(path, executable, inherited, seen):
            if path in seen:
                return
            seen.add(path)
            image = images[path]
            rpaths = []
            for command, raw, endian in image[3]:
                if command == 0x27:
                    raise NativeCoreError()
                if command == 0x8000001c:
                    rpaths.append(expand(_native_text(raw, endian), path, executable))
                if command == 0xe and _native_text(raw, endian) != '/usr/lib/dyld':
                    raise NativeCoreError()
            rpaths += list(inherited)
            for command, raw, endian in image[3]:
                if command not in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20):
                    continue
                value = _native_text(raw, endian, minimum=24, require_nul=True)
                if os.path.normpath(value) == value and value.startswith(('/usr/lib/', '/System/Library/')):
                    continue
                if value.startswith('@rpath/'):
                    candidates = [os.path.join(base, value[7:]) for base in rpaths]
                    existing = [candidate for candidate in candidates if os.path.exists(candidate)]
                    if not existing:
                        raise NativeCoreError()
                    # Bind every earlier missing candidate too: a newly created
                    # file there must not take precedence over the selected image.
                    for candidate in candidates[:candidates.index(existing[0])]:
                        self.aliases[candidate] = None
                    resolved = self._resolved(existing[0])
                else:
                    resolved = self._resolved(expand(value, path, executable))
                if resolved not in images or images[resolved][2] != 6:
                    raise NativeCoreError()
                used.add(resolved)
                visit(resolved, executable, rpaths, seen)
        for role in self.EXECUTABLES:
            path = self.tools[role].path
            visit(path, path, (), set())
        if used != {item.path for item in libraries}:
            raise NativeCoreError()

    def recheck(self, *, deadline):
        if self.closed or self.pending:
            raise NativeCoreError('native_core_cleanup_pending', owner=self)
        self.installed.recheck(deadline=deadline)
        for item in self.files:
            item.check(deadline)
        for path, expected in self.aliases.items():
            if (expected is None and os.path.lexists(path)
                    or expected is not None and os.path.realpath(path) != expected):
                raise NativeCoreError()
        if time.monotonic() >= deadline:
            raise NativeCoreError()

    def caller(self, pid, *, deadline):
        """Positive ancestry evidence, independent of transport availability."""
        from native_security.core_caller import NativeCallerProbe
        self.recheck(deadline=deadline)
        proof = NativeCallerProbe().observe(pid,
            tmux_image=self.tools['tmux'].path, deadline=deadline)
        self.recheck(deadline=deadline)
        return proof

    def require_operator(self, *, deadline):
        if self.caller(os.getpid(), deadline=deadline).in_pane:
            raise NativeCoreError('native_core_operator_required')

    def harness_command(self, verb, arguments, *, hub_home, socket_name):
        if (verb not in ('spawn', 'kill') or type(arguments) not in (tuple, list)
                or not 1 <= len(arguments) <= 128
                or any(type(value) is not str or '\x00' in value or len(value) > 65536 for value in arguments)
                or type(hub_home) is not str or not os.path.isabs(hub_home)
                or os.path.realpath(hub_home) != hub_home
                or any(os.path.commonpath((hub_home, root)) == root for root in self.workspaces)
                or type(socket_name) is not str
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', socket_name) is None):
            raise NativeCoreError()
        if verb == 'spawn':
            try:
                selected_cli = arguments[arguments.index('--cli')+1]
            except (ValueError, IndexError):
                raise NativeCoreError() from None
            if selected_cli != 'codex':
                raise NativeCoreError('native_core_provider_unavailable')
        self.recheck(deadline=time.monotonic()+10)
        environment = {'PATH': self.root + '/app/native-bin:/usr/bin:/bin',
            'HOME': self.home, 'LANG': 'en_US.UTF-8', 'LC_CTYPE': 'UTF-8',
            'AGENTMUX_HOME': hub_home, 'AGENTMUX_SOCKET': socket_name,
            'AGENTMUX_REPO': self.root + '/app', 'AGENTMUX_IDLE_MINUTES': '0',
            'AGENTMUX_NATIVE_CORE_ROOT': self.root,
            'AGENTMUX_NATIVE_CORE_TMUX': self.tools['tmux'].path,
            'AGENTMUX_NATIVE_CORE_CODEX': self.tools['codexBinary'].path,
            'CODEX_MANAGED_PACKAGE_ROOT': self.codex_package_root, 'CODEX_MANAGED_BY_NPM': '1'}
        # Preserve the existing machine restriction without importing ambient
        # executable paths or settings that could grant wider permissions.
        if os.environ.get('AGENTMUX_NO_BYPASS') == '1':
            environment['AGENTMUX_NO_BYPASS'] = '1'
        return NativeCoreCommand((self.tools['bash'].path, self.root + '/app/agentmux.sh', verb, *arguments), environment)

    def tmux(self, socket_name, arguments, *, timeout=10, input_=None):
        """Run only the selected transport, with the original bounded arguments."""
        if (type(socket_name) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', socket_name) is None
                or type(arguments) not in (tuple, list) or not 1 <= len(arguments) <= 128
                or any(type(value) is not str or '\x00' in value or len(value) > 65536 for value in arguments)
                or type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise NativeCoreError()
        self.recheck(deadline=time.monotonic()+10)
        result = subprocess.run([self.tools['tmux'].path, '-L', socket_name, *arguments],
            input=input_, stdin=None if input_ is not None else subprocess.DEVNULL,
            capture_output=True, timeout=timeout,
            env={'PATH': '/usr/bin:/bin', 'HOME': self.home, 'LANG': 'en_US.UTF-8'})
        self.recheck(deadline=time.monotonic()+10)
        return result

    def transport_not_connectable(self, socket_name):
        """Observe one endpoint, not server liveness, pane inventory or authority.

        ECONNREFUSED can also mean a live listener cannot queue a connection.
        This observation never permits deleting or replacing its socket.
        """
        if type(socket_name) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', socket_name) is None:
            raise NativeCoreError()
        parent = '/private/tmp'
        directory = parent + '/tmux-' + str(os.getuid())
        def binding(info):
            return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid
        def leaf(fd):
            try:
                return os.stat(socket_name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
        def identity(info):
            return None if info is None else (*binding(info), info.st_ctime_ns, info.st_mtime_ns)
        if os.path.realpath(parent) != parent:
            raise NativeCoreError()
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory_fd = None
        try:
            parent_info = os.fstat(parent_fd)
            if parent_info.st_uid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o1777:
                raise NativeCoreError()
            try:
                directory_fd = os.open('tmux-' + str(os.getuid()),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            except FileNotFoundError:
                # A missing namespace is distinct from a refused connection.
                if (os.path.lexists(directory)
                        or binding(os.stat(parent, follow_symlinks=False)) != binding(parent_info)):
                    raise NativeCoreError()
                return True
            directory_info = os.fstat(directory_fd)
            if directory_info.st_uid != os.getuid() or stat.S_IMODE(directory_info.st_mode) != 0o700:
                raise NativeCoreError()
            before = leaf(directory_fd)
            if before is not None and (not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid()):
                raise NativeCoreError()
            result = errno.ENOENT
            if before is not None:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(1)
                    result = probe.connect_ex(directory + '/' + socket_name)
            if (binding(os.stat(parent, follow_symlinks=False)) != binding(parent_info)
                    or binding(os.stat(directory, follow_symlinks=False)) != binding(directory_info)
                    or identity(leaf(directory_fd)) != identity(before)):
                raise NativeCoreError()
            if before is None:
                return True
            if result == 0:
                return False
            if result == errno.ECONNREFUSED:
                return True
            raise NativeCoreError()
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
            os.close(parent_fd)

    def close(self):
        if self.closed:
            if self.pending:
                raise NativeCoreError('native_core_cleanup_pending', owner=self, causes=self.pending)
            return
        self.closed = True
        for item in reversed(self.files):
            try:
                item.close()
            except BaseException as failure:
                self.pending.append(failure)
        if self.pending:
            raise NativeCoreError('native_core_cleanup_pending', owner=self, causes=self.pending)
