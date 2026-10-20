"""Native local-owner admission for the private project profile record.

This proves an operating-system owner, not an enrolled human or organization.
The SDK 26.5 ACL and mount checks match platform/privatefs's descriptor policy.
"""
from contextlib import contextmanager
import ctypes as C
from dataclasses import dataclass
import errno
import fcntl
import os
from pathlib import Path
import platform
import stat
import unicodedata


class ProfileError(ValueError):
    """A fixed diagnostic; never include private record or persona contents."""


class NativeCleanupFailure(ProfileError):
    def __init__(self, acl, security, operation):
        super().__init__("profile_acl_close_failed")
        self._consumed_acl, self._consumed_security = acl, security
        self.operation_error = operation


class _Mount(C.Structure):
    _fields_ = [("bsize", C.c_uint32), ("iosize", C.c_int32),
                ("blocks", C.c_uint64), ("bfree", C.c_uint64), ("bavail", C.c_uint64),
                ("files", C.c_uint64), ("ffree", C.c_uint64), ("fsid", C.c_int32 * 2),
                ("owner", C.c_uint32), ("kind", C.c_uint32), ("flags", C.c_uint32),
                ("subtype", C.c_uint32), ("name", C.c_char * 16),
                ("mount", C.c_char * 1024), ("source", C.c_char * 1024),
                ("extended", C.c_uint32), ("reserved", C.c_uint32 * 7)]


def _native(fd, private):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ProfileError("profile_native_platform_unsupported")
    lib = C.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    for name, args, result in (
        ("fstatfs", [C.c_int, C.c_void_p], C.c_int),
        ("filesec_init", [], C.c_void_p), ("filesec_free", [C.c_void_p], None),
        ("fstatx_np", [C.c_int, C.c_void_p, C.c_void_p], C.c_int),
        ("filesec_query_property", [C.c_void_p, C.c_int, C.c_void_p], C.c_int),
        ("filesec_get_property", [C.c_void_p, C.c_int, C.c_void_p], C.c_int),
        ("acl_valid", [C.c_void_p], C.c_int),
        ("acl_get_entry", [C.c_void_p, C.c_int, C.c_void_p], C.c_int),
        ("acl_get_tag_type", [C.c_void_p, C.c_void_p], C.c_int),
        ("acl_get_permset", [C.c_void_p, C.c_void_p], C.c_int),
        ("acl_get_perm_np", [C.c_void_p, C.c_int], C.c_int),
        ("acl_free", [C.c_void_p], C.c_int),
    ):
        function = getattr(lib, name)
        function.argtypes, function.restype = args, result
    mount = _Mount()
    if lib.fstatfs(fd, C.byref(mount)) or not mount.flags & 0x1000 or mount.flags & 0x200000:
        raise ProfileError("profile_local_mount_required")
    security = lib.filesec_init()
    acl = C.c_void_p()
    failure = None
    try:
        if not security:
            raise ProfileError("profile_acl_unavailable")
        # fstatx_np writes struct stat here; the oversized aligned buffer is not
        # interpreted. Identity is separately checked with Python's native fstat.
        metadata = (C.c_uint64 * 64)()
        present = C.c_int()
        if (lib.fstatx_np(fd, metadata, security)
                or lib.filesec_query_property(security, 5, C.byref(present))):
            raise ProfileError("profile_acl_unavailable")
        if not present.value:
            return
        if (lib.filesec_get_property(security, 5, C.byref(acl)) or not acl.value
                or acl.value == C.c_void_p(-1).value or lib.acl_valid(acl)):
            raise ProfileError("profile_acl_invalid")
        for index in range(129):
            entry = C.c_void_p()
            C.set_errno(0)
            if lib.acl_get_entry(acl, index, C.byref(entry)):
                if C.get_errno() == errno.EINVAL:
                    return
                raise ProfileError("profile_acl_invalid")
            tag, permissions = C.c_int(), C.c_void_p()
            if index == 128 or lib.acl_get_tag_type(entry, C.byref(tag)):
                raise ProfileError("profile_acl_invalid")
            if tag.value == 2:
                continue
            if tag.value != 1 or private:
                raise ProfileError("profile_acl_access_denied")
            if lib.acl_get_permset(entry, C.byref(permissions)):
                raise ProfileError("profile_acl_invalid")
            for bit in (2, 4, 5, 6, 8, 10, 12, 13):
                if lib.acl_get_perm_np(permissions, 1 << bit) != 0:
                    raise ProfileError("profile_acl_access_denied")
        raise ProfileError("profile_acl_invalid")
    except BaseException as exc:
        failure = exc
        raise
    finally:
        close_failed = bool(acl.value and acl.value != C.c_void_p(-1).value and lib.acl_free(acl))
        if security:
            lib.filesec_free(security)
        if close_failed:
            raise NativeCleanupFailure(acl.value, security, failure) from failure


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(fd, *, private=False, owner=False):
    info = os.fstat(fd)
    uid = os.geteuid()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid)
            or (owner and info.st_uid != uid)
            or (info.st_mode & 0o22 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))
            or (private and stat.S_IMODE(info.st_mode) != 0o700)):
        raise ProfileError("profile_owner_directory_required")
    _native(fd, private)
    return info


_TOKEN = object()


@dataclass(frozen=True, repr=False)
class LocalOwner:
    project: Path
    uid: int
    project_identity: tuple
    _token: object
    _fd: int
    _live: list
    _ancestors: tuple

    def __repr__(self):
        return "LocalOwner(operating-system owner only)"


@contextmanager
def admit_project(project):
    """Establish local ownership internally for an explicit foreground command."""
    if os.getuid() != os.geteuid():
        raise ProfileError("profile_owner_mismatch")
    supplied = os.fspath(project)
    path = Path(supplied)
    if (not isinstance(supplied, str) or len(supplied) > 4096
            or any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in supplied)
            or not path.is_absolute() or supplied != os.path.normpath(supplied)
            or path == Path("/") or path.resolve() != path or len(path.parts) > 128):
        raise ProfileError("profile_canonical_project_required")
    held = []
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        held.append(fd)
        _directory(fd)
        for part in path.parts[1:]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=fd)
            held.append(fd)
            _directory(fd, owner=len(held) == len(path.parts))
        owner = LocalOwner(path, os.geteuid(), identity(os.fstat(fd)), _TOKEN, fd, [True], tuple(held))
        try:
            yield owner
            check_owner(owner)
        finally:
            owner._live[0] = False
    finally:
        _close_all(held)


def _close_all(held):
    failures = []
    for fd in reversed(held):
        try:
            os.close(fd)
        except OSError as exc:
            failures.append(exc)
    if failures:
        # Every descriptor has been consumed once; retrying a numeric fd is unsafe.
        raise ProfileError("profile_descriptor_close_failed") from ExceptionGroup(
            "profile descriptor close failures", failures)


def check_owner(owner):
    if (not isinstance(owner, LocalOwner) or owner._token is not _TOKEN
            or not owner._live[0]
            or owner.uid != os.getuid() or owner.uid != os.geteuid()
            or identity(os.fstat(owner._fd))[:5] != owner.project_identity[:5]
            or identity(owner.project.stat(follow_symlinks=False))[:5] != owner.project_identity[:5]
            or owner.project.resolve() != owner.project):
        raise ProfileError("profile_owner_changed")
    for index, fd in enumerate(owner._ancestors):
        held = _directory(fd, owner=index == len(owner._ancestors) - 1)
        if index:
            slot = os.stat(owner.project.parts[index], dir_fd=owner._ancestors[index - 1],
                           follow_symlinks=False)
            if (held.st_dev, held.st_ino) != (slot.st_dev, slot.st_ino):
                raise ProfileError("profile_owner_ancestor_changed")


@contextmanager
def record_directory(owner, *, create=False, exclusive=False):
    check_owner(owner)
    held = []
    try:
        fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=owner._fd)
        held.append(fd)
        _directory(fd, owner=True)
        if identity(os.fstat(fd))[:5] != owner.project_identity[:5]:
            raise ProfileError("profile_owner_changed")
        for name, private in ((".agentmux", False), ("profile-adoptions", True)):
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=fd)
            held.append(fd)
            _directory(fd, private=private, owner=True)
        if exclusive:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProfileError("profile_adoption_busy") from None
        yield fd
        check_owner(owner)
        for index, ancestor in enumerate(held):
            _directory(ancestor, private=index == 2, owner=True)
        assert_directory(owner, fd)
    finally:
        _close_all(held)


def assert_directory(owner, fd):
    check_owner(owner)
    leaf = owner.project / ".agentmux/profile-adoptions"
    actual, held = leaf.stat(follow_symlinks=False), os.fstat(fd)
    if (leaf.resolve() != leaf or (actual.st_dev, actual.st_ino) != (held.st_dev, held.st_ino)):
        raise ProfileError("profile_record_directory_changed")
    _directory(fd, private=True, owner=True)


def read_record(fd, limit=1 << 20, name="record.json"):
    """Read the exact private leaf while holding its revision descriptor."""
    try:
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None, None
    try:
        before = os.fstat(child)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 <= before.st_size <= limit):
            raise ProfileError("profile_private_record_required")
        _native(child, True)
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(child, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        raw = b"".join(chunks)
        if size > limit or identity(before) != identity(os.fstat(child)):
            raise ProfileError("profile_record_changed")
        assert_record(fd, identity(before), name=name)
        return raw, identity(before)
    finally:
        _close_all([child])


def assert_record(fd, expected, name="record.json"):
    try:
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        current = None
    if (current is not None and identity(current) != expected) or (current is None and expected is not None):
        raise ProfileError("profile_record_changed")


def read_private_input(path):
    supplied = os.fspath(path)
    path = Path(supplied)
    if (not isinstance(supplied, str) or len(supplied) > 4096
            or any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in supplied)
            or not path.is_absolute() or str(path) != supplied or path.resolve() != path):
        raise ProfileError("profile_private_input_invalid")
    with admit_project(path.parent) as owner:
        _directory(owner._fd, owner=True, private=True)
        raw, _ = read_record(owner._fd, name=path.name)
        if raw is None:
            raise ProfileError("profile_private_input_invalid")
        return raw
