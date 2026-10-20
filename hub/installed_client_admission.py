"""Retain native admission for the explicitly selected installed MCP client.

Only the fixed protected package root and stable frontend are eligible. Native
checks come from native_security; a declaration is output, not proof of admission.
No command is executed and no user settings are written by this module.
"""
from dataclasses import dataclass, field
from contextlib import contextmanager
import hashlib
import os
import re
import time
import threading

from native_security import descriptor_admission as native

PROTECTED_CLIENT_BASE = '/Library/Application Support/Agentmux/Protected/clients'
STABLE_FRONTEND = '/Library/Application Support/Agentmux/Protected/agentmux-runtime'
_ID = re.compile(r'[0-9a-f]{64}')


class InstalledClientError(ValueError):
    """Closed diagnostic with retained cleanup state; private paths stay hidden."""
    def __init__(self, code, *, cleanup=None):
        super().__init__(code)
        self.cleanup = cleanup


@dataclass(frozen=True)
class InstalledClientDeclaration:
    schema_version: str
    installation_id: str
    client_id: str
    command: str = field(repr=False)
    arguments: tuple[str, ...] = field(repr=False)
    enrollment_selection: str = field(repr=False)
    transport: str


def _deadline(deadline):
    now = time.monotonic()
    if type(deadline) not in (int, float) or not now < deadline < float('inf'):
        raise InstalledClientError('installed_client_deadline')


def _canonical(path):
    return (type(path) is str and 0 < len(path) <= 4096 and os.path.isabs(path)
            and os.path.normpath(path) == path and not path.startswith('//')
            and not any(c in '\x00\r\n' or '\ud800' <= c <= '\udfff' for c in path))


def _identity(fd, *, directory=False):
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            None if directory else (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns))


class _Descriptors:
    """Consume each owned close once and retain any uncertainty without retry."""
    def __init__(self):
        self.live = set()
        self.uncertain = []
        self.native_uncertain = False

    def add(self, fd):
        self.live.add(fd)
        return fd

    def close(self, fd):
        self.live.remove(fd)
        try:
            os.close(fd)
        except BaseException:
            self.uncertain.append(fd)
            raise InstalledClientError('installed_client_cleanup_pending', cleanup=self) from None

    def close_all(self):
        for fd in tuple(self.live):
            try:
                self.close(fd)
            except InstalledClientError:
                pass
        if self.uncertain or self.native_uncertain:
            raise InstalledClientError('installed_client_cleanup_pending', cleanup=self)

    @property
    def closed(self):
        return not self.live and not self.uncertain and not self.native_uncertain


def _admit(fd, purpose, deadline, *, owners=None):
    _deadline(deadline)
    try:
        accepted = native.check_descriptor(fd, purpose=purpose, deadline=deadline)
    except native.AdmissionError as exc:
        if str(exc) == 'native_admission_cleanup' and owners is not None:
            owners.native_uncertain = True
        code = ('installed_client_cleanup_pending' if str(exc) == 'native_admission_cleanup'
                else 'installed_client_native_admission_failed')
        raise InstalledClientError(code, cleanup=owners if code == 'installed_client_cleanup_pending' else None) from None
    if accepted is not True:
        raise InstalledClientError('installed_client_native_admission_failed')
    _deadline(deadline)


def _open_absolute(path, *, purpose, owners, deadline):
    """Retain each no-follow ancestor and the final descriptor for rechecking."""
    if not _canonical(path):
        raise InstalledClientError('installed_client_path_invalid')
    components = path.split('/')[1:]
    if len(components) > 128 or any(not name for name in components):
        raise InstalledClientError('installed_client_path_invalid')
    rows = []
    parent = owners.add(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
    protected = purpose not in (native.DescriptorPurpose.PRIVATE_FILE, native.DescriptorPurpose.PRIVATE_DIRECTORY,
                                native.DescriptorPurpose.PREPARED_CORE_FILE)
    ancestor = (native.DescriptorPurpose.PROTECTED_ANCESTOR if protected
                else native.DescriptorPurpose.PRIVATE_ANCESTOR)
    _admit(parent, ancestor, deadline, owners=owners)
    rows.append(('/', parent, ancestor, _identity(parent, directory=True)))
    current_path = ''
    for index, name in enumerate(components):
        last = index == len(components) - 1
        role = purpose if last else ancestor
        if purpose is native.DescriptorPurpose.PRIVATE_FILE and index == len(components) - 2:
            role = native.DescriptorPurpose.PRIVATE_DIRECTORY
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        final_directory = purpose in (native.DescriptorPurpose.PROTECTED_ANCESTOR,
                                       native.DescriptorPurpose.PRIVATE_DIRECTORY)
        if not last or final_directory:
            flags |= os.O_DIRECTORY
        current = owners.add(os.open(name, flags, dir_fd=parent))
        _admit(current, role, deadline, owners=owners)
        current_path += '/' + name
        rows.append((current_path, current, role, _identity(current, directory=not last
                      or final_directory)))
        parent = current
    return rows


def _read_file(fd, *, purpose, limit, deadline, capture=False, owners=None):
    try:
        return _read_held(fd, purpose=purpose, limit=limit, deadline=deadline,
                          capture=capture, owners=owners)
    except OSError:
        raise InstalledClientError('installed_client_file_unavailable') from None


def _read_held(fd, *, purpose, limit, deadline, capture, owners):
    """Hash bounded held bytes and reject metadata changes across the read."""
    _admit(fd, purpose, deadline, owners=owners)
    before = _identity(fd)
    if not 0 <= os.fstat(fd).st_size <= limit:
        raise InstalledClientError('installed_client_file_invalid')
    os.lseek(fd, 0, os.SEEK_SET)
    digest, chunks, size = hashlib.sha256(), [], 0
    while True:
        _deadline(deadline)
        block = os.read(fd, min(65536, limit + 1 - size))
        if not block:
            break
        size += len(block)
        if size > limit:
            raise InstalledClientError('installed_client_file_invalid')
        digest.update(block)
        if capture:
            chunks.append(block)
    _admit(fd, purpose, deadline, owners=owners)
    if _identity(fd) != before or os.fstat(fd).st_size != size:
        raise InstalledClientError('installed_client_file_changed')
    return 'sha256:' + digest.hexdigest(), before, b''.join(chunks) if capture else None


class _RetainedPath:
    """Keep original descriptors and reject path substitution on every recheck."""
    def __init__(self, path, *, purpose, deadline):
        self._path, self._purpose = path, purpose
        self._owners = _Descriptors()
        self._walk_cleanup = []
        try:
            self._rows = _open_absolute(path, purpose=purpose, owners=self._owners, deadline=deadline)
        except BaseException as exc:
            self._owners.close_all()
            if isinstance(exc, OSError):
                raise InstalledClientError('installed_client_path_unavailable') from None
            raise

    @property
    def fd(self):
        if self.closed or self._owners.uncertain or self._owners.native_uncertain or self._walk_cleanup:
            raise InstalledClientError('installed_client_unavailable')
        return self._rows[-1][1]

    @property
    def closed(self):
        return self._owners.closed and all(owner.closed for owner in self._walk_cleanup)

    def recheck(self, *, deadline):
        if (not self._owners.live or self._owners.uncertain or self._owners.native_uncertain
                or self._walk_cleanup):
            raise InstalledClientError('installed_client_unavailable')
        temporary = _Descriptors()
        try:
            fresh = _open_absolute(self._path, purpose=self._purpose, owners=temporary, deadline=deadline)
            if len(fresh) != len(self._rows):
                raise InstalledClientError('installed_client_path_changed')
            for expected, actual in zip(self._rows, fresh):
                name, original, purpose, identity = expected
                _admit(original, purpose, deadline, owners=self._owners)
                directory = purpose in (native.DescriptorPurpose.PROTECTED_ANCESTOR,
                    native.DescriptorPurpose.PRIVATE_ANCESTOR, native.DescriptorPurpose.PRIVATE_DIRECTORY)
                if (name != actual[0] or purpose is not actual[2]
                        or _identity(original, directory=directory) != identity or actual[3] != identity):
                    raise InstalledClientError('installed_client_path_changed')
        except OSError:
            raise InstalledClientError('installed_client_path_changed') from None
        finally:
            try:
                temporary.close_all()
            except InstalledClientError:
                self._walk_cleanup.append(temporary)
                raise
        _deadline(deadline)

    def close(self):
        self._owners.close_all()
        if any(not owner.closed for owner in self._walk_cleanup):
            raise InstalledClientError('installed_client_cleanup_pending', cleanup=self)


_MANIFEST_LIMIT = 2 * 1024 * 1024
_FILE_LIMIT = 64 * 1024 * 1024
_TOTAL_LIMIT = 256 * 1024 * 1024
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}')
_REQUIRED = frozenset(('bootstrap.py', 'python/bin/python3.14', 'python/lib/libpython3.14.dylib',
    'python/lib/python3.14/os.py', 'app/hub/cli.py', 'app/hub/client_launch_entrypoint.py',
    'app/hub/client_launch_coordinator.py', 'app/sdk/python/agentmux_contracts/validation.py',
    'app/contracts/v1/schemas/startup-status-observation.schema.json', 'app/client-requirements.lock'))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _invalid_constant(_):
    raise ValueError


def _decode_manifest(raw):
    """Match runtime.DecodeClientManifest; its selected bytes identify the package."""
    import json
    import posixpath
    bad = 'installed_client_manifest_invalid'
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _MANIFEST_LIMIT:
            raise ValueError
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_invalid_constant)
        if (type(value) is not dict or set(value) != {'schemaVersion', 'kind', 'foundationInstallationId',
                'frontendDigest', 'pythonVersion', 'interpreter', 'bootstrap', 'files'}
                or value['schemaVersion'] != '1.0.0' or value['kind'] != 'ordinary-python-client'
                or type(value['foundationInstallationId']) is not str
                or not _ID.fullmatch(value['foundationInstallationId'])
                or type(value['frontendDigest']) is not str or not _DIGEST.fullmatch(value['frontendDigest'])
                or value['pythonVersion'] != '3.14.4' or value['interpreter'] != 'python/bin/python3.14'
                or value['bootstrap'] != 'bootstrap.py' or type(value['files']) is not list
                or not 4 <= len(value['files']) <= 4096):
            raise ValueError
        previous, total, roster, directories = '', 0, {}, {''}
        for item in value['files']:
            if type(item) is not dict or set(item) != {'path', 'digest', 'size', 'mode'}:
                raise ValueError
            name = item['path']
            if (type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_.+/-]+', name)
                    or len(name) > 512 or len(name.split('/')) > 24 or posixpath.normpath(name) != name
                    or name == '.' or name.startswith(('/', '../')) or name <= previous
                    or type(item['digest']) is not str or not _DIGEST.fullmatch(item['digest'])
                    or type(item['size']) is not int or not 0 <= item['size'] <= _FILE_LIMIT
                    or type(item['mode']) is not int or item['mode'] not in (0o444, 0o555)
                    or not (name in ('bootstrap.py', 'python/bin/python3.14')
                            or name.startswith(('python/lib/', 'site-packages/', 'app/')))
                    or '/__pycache__/' in name or name.endswith(('.pyc', '/pyvenv.cfg'))):
                raise ValueError
            total += item['size']
            if total > _TOTAL_LIMIT:
                raise ValueError
            roster[name], previous = item, name
            parent = posixpath.dirname(name)
            while parent:
                directories.add(parent)
                parent = posixpath.dirname(parent)
        if (not _REQUIRED <= roster.keys() or roster['python/bin/python3.14']['mode'] != 0o555
                or len(directories) - 1 > 1024 or any(name in roster for name in directories)):
            raise ValueError
        return value, roster, directories
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise InstalledClientError(bad) from None


def _file_purpose(mode):
    if mode == 0o555:
        return native.DescriptorPurpose.PROTECTED_EXECUTABLE
    purpose = getattr(native.DescriptorPurpose, 'PROTECTED_FILE', None)
    if purpose is None:
        raise InstalledClientError('installed_client_native_admission_required')
    return purpose


def _snapshot_tree(root, roster, directories, *, deadline, expected=None):
    """Check every derived directory and roster file, rejecting unlisted entries.

    Only the bounded directory depth is held open at once. All files are hashed
    again on recheck and compared with their admitted identities. Root-owned
    directories and native ACL admission exclude ordinary-user mutation; a trusted
    administrator remains responsible for writes during the operation.
    """
    owners, snapshot = _Descriptors(), {}
    expected_files = dict(roster)
    native_roster = {name: item for name, item in roster.items() if name != 'client-manifest.json'}
    native_files = {}
    def walk(fd, prefix):
        _admit(fd, native.DescriptorPurpose.PROTECTED_ANCESTOR, deadline, owners=owners)
        if os.fstat(fd).st_mode & 0o7777 != 0o755:
            raise InstalledClientError('installed_client_permissions')
        snapshot[prefix] = _identity(fd, directory=True)
        # scandir permits early refusal instead of materializing an unbounded list.
        scan_fd = owners.add(os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=fd))
        try:
            with os.scandir(scan_fd) as entries:
                count = 0
                for entry in entries:
                    _deadline(deadline)
                    count += 1
                    if count > 4096 + 1024:
                        raise InstalledClientError('installed_client_tree_changed')
                    name = entry.name if not prefix else prefix + '/' + entry.name
                    directory = name in directories
                    if not directory and name not in expected_files:
                        raise InstalledClientError('installed_client_tree_changed')
                    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                    if directory:
                        flags |= os.O_DIRECTORY
                    child = owners.add(os.open(entry.name, flags, dir_fd=fd))
                    try:
                        if directory:
                            walk(child, name)
                        else:
                            item = expected_files[name]
                            role = _file_purpose(item['mode'])
                            digest, identity, data = _read_file(child, purpose=role, limit=item['size'],
                                                           deadline=deadline, owners=owners, capture=True)
                            if (digest != item['digest'] or os.fstat(child).st_size != item['size']
                                    or os.fstat(child).st_mode & 0o7777 != item['mode']):
                                raise InstalledClientError('installed_client_file_changed')
                            if name != 'client-manifest.json' and _native_candidate(name, data):
                                native_files[name] = data
                            snapshot[name] = identity
                    finally:
                        owners.close(child)
        finally:
            owners.close(scan_fd)
    try:
        walk(root, '')
        if set(snapshot) != set(roster) | directories:
            raise InstalledClientError('installed_client_tree_changed')
        if expected is not None and snapshot != expected:
            raise InstalledClientError('installed_client_tree_changed')
        _native_payload(native_files, native_roster, deadline=deadline)
    except OSError:
        raise InstalledClientError('installed_client_tree_changed') from None
    finally:
        owners.close_all()
    _deadline(deadline)
    return snapshot


class InstalledClientAdmission:
    """An owner issued by native admission, never by a JSON declaration alone."""
    def __init__(self, token, *, declaration, package, manifest, frontend, selection, roster, directories, snapshot):
        if token is not _ISSUER:
            raise InstalledClientError('installed_client_admission_required')
        self._lock = threading.RLock()
        self._declaration = declaration
        self._package, self._manifest, self._frontend, self._selection = package, manifest, frontend, selection
        self._roster, self._directories, self._snapshot = roster, directories, snapshot
        self._cleanup = []

    @property
    def declaration(self):
        return self._declaration

    @property
    def closed(self):
        return all(item.closed for item in (self._package, self._manifest, self._frontend, self._selection)) and not self._cleanup

    def recheck(self, *, deadline):
        with self._lock:
            self._recheck(deadline=deadline)

    @contextmanager
    def hold(self, *, deadline):
        """Keep close and recheck serialized through the caller's publication."""
        with self._lock:
            self._recheck(deadline=deadline)
            yield self._declaration

    def _recheck(self, *, deadline):
        if self._cleanup:
            raise InstalledClientError('installed_client_cleanup_pending', cleanup=self)
        try:
            for item in (self._package, self._manifest, self._frontend, self._selection):
                item.recheck(deadline=deadline)
            _snapshot_tree(self._package.fd, self._roster, self._directories,
                           deadline=deadline, expected=self._snapshot)
        except InstalledClientError as exc:
            if exc.cleanup is not None:
                self._cleanup.append(exc.cleanup)
            raise
        _deadline(deadline)

    def close(self):
        with self._lock:
            self._close()

    def _close(self):
        failures = []
        for item in (self._selection, self._frontend, self._manifest, self._package):
            try:
                item.close()
            except InstalledClientError as exc:
                failures.append(exc.cleanup)
        self._cleanup.extend(item for item in failures if item is not None)
        if self._cleanup:
            raise InstalledClientError('installed_client_cleanup_pending', cleanup=self)


_ISSUER = object()


def admit_installed_client(installation_id, enrollment_selection, *, deadline=None):
    """Admit only the fixed native installed package selected by its manifest ID.

    The installer selection file is a different artifact, independently admitted
    by the Go installer. This function consumes the installed manifest identity and
    the private enrollment selection used by the ordinary MCP client. The installer
    and stable frontend also verify native images before installation and execution.
    """
    from hub.client_launch_selection import load_selection, SelectionError
    if type(installation_id) is not str or not _ID.fullmatch(installation_id) or not _canonical(enrollment_selection):
        raise InstalledClientError('installed_client_selection_invalid')
    if deadline is None:
        deadline = time.monotonic() + 10
    _deadline(deadline)
    retained = []
    def keep(path, purpose):
        value = _RetainedPath(path, purpose=purpose, deadline=deadline)
        retained.append(value)
        return value
    try:
        package_path = PROTECTED_CLIENT_BASE + '/' + installation_id
        package = keep(package_path, native.DescriptorPurpose.PROTECTED_ANCESTOR)
        manifest = keep(package_path + '/client-manifest.json', _file_purpose(0o444))
        digest, _, raw = _read_file(manifest.fd, purpose=_file_purpose(0o444), limit=_MANIFEST_LIMIT,
                                   deadline=deadline, capture=True, owners=manifest._owners)
        if digest != 'sha256:' + installation_id:
            raise InstalledClientError('installed_client_manifest_changed')
        metadata, roster, directories = _decode_manifest(raw)
        frontend = keep(STABLE_FRONTEND, native.DescriptorPurpose.PROTECTED_EXECUTABLE)
        digest, _, _ = _read_file(frontend.fd, purpose=native.DescriptorPurpose.PROTECTED_EXECUTABLE,
                                  limit=128 * 1024 * 1024, deadline=deadline, owners=frontend._owners)
        if digest != metadata['frontendDigest']:
            raise InstalledClientError('installed_client_frontend_changed')
        selection = keep(enrollment_selection, native.DescriptorPurpose.PRIVATE_FILE)
        load_selection(enrollment_selection, deadline=deadline)
        selection.recheck(deadline=deadline)
        full_roster = dict(roster)
        full_roster['client-manifest.json'] = {'digest': 'sha256:' + installation_id,
                                             'mode': 0o444, 'size': len(raw)}
        snapshot = _snapshot_tree(package.fd, full_roster, directories, deadline=deadline)
        declaration = InstalledClientDeclaration('1.0.0', installation_id, 'claude-desktop', STABLE_FRONTEND,
            ('mcp', '--client-installation', installation_id, '--selection', enrollment_selection),
            enrollment_selection, 'stdio')
        result = InstalledClientAdmission(_ISSUER, declaration=declaration, package=package, manifest=manifest,
            frontend=frontend, selection=selection, roster=full_roster, directories=directories, snapshot=snapshot)
        result.recheck(deadline=deadline)
        return result
    except BaseException as exc:
        pending = []
        for item in reversed(retained):
            try:
                item.close()
            except InstalledClientError as cleanup:
                pending.append(cleanup.cleanup)
        if isinstance(exc, (InstalledClientError, SelectionError)) and exc.cleanup is not None:
            pending.append(exc.cleanup)
        if pending:
            raise InstalledClientError('installed_client_cleanup_pending', cleanup=pending) from None
        if isinstance(exc, InstalledClientError):
            raise
        if isinstance(exc, SelectionError):
            raise InstalledClientError('installed_client_enrollment_invalid', cleanup=exc.cleanup) from None
        if isinstance(exc, (OSError, ValueError, TypeError)):
            raise InstalledClientError('installed_client_unavailable') from None
        raise


def _native_candidate(name, data):
    return (name == 'python/bin/python3.14' or name.endswith(('.dylib', '.so'))
            or data[:4] in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
                b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe'))


def _native_structure(data, commands, *, endian, wide, deadline):
    """Check the structural command forms read by Go's debug/macho.NewFile.

    Validate ranges directly rather than allocating segment, symbol or relocation
    objects. Zero-length table reads need no file bytes, as in Go's saferio reader.
    """
    import struct
    symbols = None
    def file_range(offset, length):
        if length and (offset > len(data) or length > len(data) - offset):
            raise ValueError
    for command, raw, _ in commands:
        _deadline(deadline)
        if command in (0x8000001c, 0xc):
            minimum = 12 if command == 0x8000001c else 24
            if len(raw) < minimum or struct.unpack_from(endian + 'I', raw, 8)[0] >= len(raw):
                raise ValueError
        elif command == 2:  # LC_SYMTAB
            if len(raw) < 24:
                raise ValueError
            _, _, offset, count, strings, string_size = struct.unpack_from(endian + '6I', raw)
            stride = 16 if wide else 12
            file_range(offset, count * stride)
            file_range(strings, string_size)
            for index in range(count):
                _deadline(deadline)
                if struct.unpack_from(endian + 'I', data, offset + index * stride)[0] >= string_size:
                    raise ValueError
            symbols = count
        elif command == 0xb:  # LC_DYSYMTAB
            if len(raw) < 80:
                raise ValueError
            fields = struct.unpack_from(endian + '20I', raw)
            if symbols is None or fields[6] > symbols or fields[6] + fields[7] > symbols:
                raise ValueError
            file_range(fields[14], fields[15] * 4)
        elif command in (1, 0x19):  # LC_SEGMENT / LC_SEGMENT_64
            large = command == 0x19
            header, section = (72, 80) if large else (56, 68)
            if len(raw) < header:
                raise ValueError
            count = struct.unpack_from(endian + 'I', raw, 64 if large else 48)[0]
            if count > (len(raw) - header) // section:
                raise ValueError
            if large:
                offset, size = struct.unpack_from(endian + '2Q', raw, 40)
                if offset >= 1 << 63 or size >= 1 << 63:
                    raise ValueError
            for index in range(count):
                _deadline(deadline)
                location, relocations = struct.unpack_from(endian + '2I', raw,
                    header + index * section + (56 if large else 48))
                if relocations:
                    file_range(location, relocations * 8)


def _native_images(name, data, *, deadline):
    """Match Go's generic ARM64 policy and every fat-table/header binding."""
    import struct
    _deadline(deadline)
    def thin(raw):
        endian = {b'\xcf\xfa\xed\xfe': '<', b'\xfe\xed\xfa\xcf': '>',
                  b'\xce\xfa\xed\xfe': '<', b'\xfe\xed\xfa\xce': '>'}.get(raw[:4])
        if endian is None or len(raw) < 28:
            raise ValueError
        _, cpu, subtype, kind, count, size, flags = struct.unpack_from(endian + '7I', raw)
        start = 32 if raw[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf') else 28
        if start + size > len(raw) or count > size // 8 or count > 4096:
            raise ValueError
        commands, offset = [], start
        for _ in range(count):
            _deadline(deadline)
            command, length = struct.unpack_from(endian + '2I', raw, offset)
            if length < 8 or offset + length > start + size:
                raise ValueError
            commands.append((command, raw[offset:offset + length], endian))
            offset += length
        _native_structure(raw, commands, endian=endian, wide=start == 32, deadline=deadline)
        return cpu, subtype, kind, commands
    try:
        images = []
        if data[:4] == b'\xca\xfe\xba\xbe':
            count = struct.unpack_from('>I', data, 4)[0]
            if not count or count > (len(data) - 8) // 20 or count > 64:
                raise ValueError
            seen, image_kind = set(), None
            for index in range(count):
                _deadline(deadline)
                cpu, subtype, offset, length, align = struct.unpack_from('>5I', data, 8 + index * 20)
                if (cpu, subtype) in seen or offset + length > len(data):
                    raise ValueError
                seen.add((cpu, subtype))
                candidate = thin(data[offset:offset + length])
                if candidate[:2] != (cpu, subtype):
                    raise InstalledClientError('installed_client_native_architecture_invalid')
                if image_kind is not None and candidate[2] != image_kind:
                    raise ValueError
                image_kind = candidate[2]
                if cpu == 0x100000c:
                    images.append(candidate)
        else:
            images.append(thin(data))
        if not images or any(image[0] != 0x100000c or image[1] != 0
                or name == 'python/bin/python3.14' and image[2] != 2 for image in images):
            raise InstalledClientError('installed_client_native_architecture_invalid')
        return images
    except InstalledClientError:
        raise
    except (ValueError, struct.error):
        raise InstalledClientError('installed_client_native_image_invalid') from None


def _native_text(raw, endian, *, minimum=12, require_nul=False):
    import struct
    if len(raw) < minimum:
        raise InstalledClientError('installed_client_native_image_invalid')
    offset = struct.unpack_from(endian + 'I', raw, 8)[0]
    if offset < minimum or offset >= len(raw) or require_nul and b'\x00' not in raw[offset:]:
        raise InstalledClientError('installed_client_native_image_invalid')
    try:
        return raw[offset:].split(b'\x00', 1)[0].decode('ascii')
    except UnicodeError:
        raise InstalledClientError('installed_client_native_image_invalid') from None


def _resolve_library(name, value):
    import posixpath
    if value.startswith('@loader_path/'):
        value = posixpath.join(posixpath.dirname(name), value[len('@loader_path/'):])
    elif value.startswith('@executable_path/'):
        value = posixpath.join('python/bin', value[len('@executable_path/'):])
    else:
        return None
    value = posixpath.normpath(value)
    if (value == '.' or value.startswith(('/', '../')) or len(value) > 512
            or len(value.split('/')) > 24 or not re.fullmatch(r'[A-Za-z0-9_.+/-]+', value)):
        return None
    return value


def _native_rpaths(name, image, *, deadline):
    paths = []
    for command, raw, endian in image[3]:
        _deadline(deadline)
        if command == 0x8000001c:
            value = _resolve_library(name, _native_text(raw, endian))
            if value is None:
                raise InstalledClientError('installed_client_library_path_invalid')
            paths.append(value)
    return tuple(paths)


def _native_libraries(name, data, roster, *, deadline=None, inherited_rpaths=()):
    """Match Go file checks; inherited paths come only from admitted interpreter bytes."""
    import posixpath
    import struct
    if deadline is None:
        deadline = time.monotonic() + 10
    _deadline(deadline)
    if not _native_candidate(name, data):
        return
    for image in _native_images(name, data, deadline=deadline):
        rpaths = _native_rpaths(name, image, deadline=deadline) + tuple(inherited_rpaths)
        for command, raw, endian in image[3]:
            _deadline(deadline)
            if command == 0x27:
                raise InstalledClientError('installed_client_loader_environment_denied')
            if command == 0xe:
                if len(raw) < 12:
                    raise InstalledClientError('installed_client_native_image_invalid')
                offset = struct.unpack_from(endian + 'I', raw, 8)[0]
                if offset < 12 or offset >= len(raw) or raw[offset:].rstrip(b'\x00') != b'/usr/lib/dyld':
                    raise InstalledClientError('installed_client_loader_invalid')
            if command not in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20):
                continue
            library = _native_text(raw, endian, minimum=24, require_nul=True)
            if posixpath.normpath(library) == library and library.startswith(('/usr/lib/', '/System/Library/')):
                continue
            if library.startswith('@rpath/'):
                found = any(posixpath.normpath(posixpath.join(path, library[len('@rpath/'):])) in roster for path in rpaths)
            else:
                found = _resolve_library(name, library) in roster
            if not found:
                raise InstalledClientError('installed_client_library_outside_package')
    _deadline(deadline)


def _native_payload(files, roster, *, deadline):
    """Derive one generic ARM64 interpreter's actual paths before extension checks."""
    interpreter = files.get('python/bin/python3.14')
    if interpreter is None:
        raise InstalledClientError('installed_client_interpreter_missing')
    images = _native_images('python/bin/python3.14', interpreter, deadline=deadline)
    if len(images) != 1:
        raise InstalledClientError('installed_client_interpreter_invalid')
    paths = _native_rpaths('python/bin/python3.14', images[0], deadline=deadline)
    for name, data in files.items():
        _native_libraries(name, data, roster, deadline=deadline, inherited_rpaths=paths)
    _deadline(deadline)
