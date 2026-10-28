"""Darwin ARM64 descriptor admission for installed client adapters.

This checks held descriptors, not path selection, executable content or application
access. The path owner must retain ancestor handles, rewalk without symlinks and
compare identities before launch. No library path or policy comes from settings.
"""
from __future__ import annotations

import ctypes as C
from enum import Enum
import errno
import os
import platform
import stat
import sys
import time


class AdmissionError(ValueError):
    """A fixed diagnostic that does not expose private filesystem details."""


class DescriptorPurpose(str, Enum):
    PRIVATE_ANCESTOR = "private_ancestor"
    PRIVATE_DIRECTORY = "private_directory"
    PRIVATE_FILE = "private_file"
    PROTECTED_ANCESTOR = "protected_ancestor"
    PROTECTED_EXECUTABLE = "protected_executable"
    PROTECTED_FILE = "protected_file"
    PREPARED_CORE_FILE = "prepared_core_file"


class _Timespec(C.Structure):
    _fields_ = [("seconds", C.c_int64), ("nanoseconds", C.c_int64)]


# Darwin ARM64 SDK layouts. An SDK compilation test checks size and offsets.
class _Stat(C.Structure):
    _fields_ = [("dev", C.c_int32), ("mode", C.c_uint16), ("nlink", C.c_uint16),
                ("ino", C.c_uint64), ("uid", C.c_uint32), ("gid", C.c_uint32),
                ("rdev", C.c_int32), ("atime", _Timespec), ("mtime", _Timespec),
                ("ctime", _Timespec), ("birthtime", _Timespec),
                ("size", C.c_int64), ("blocks", C.c_int64), ("blksize", C.c_int32),
                ("flags", C.c_uint32), ("gen", C.c_uint32), ("lspare", C.c_int32),
                ("qspare", C.c_int64 * 2)]


class _Statfs(C.Structure):
    _fields_ = [("bsize", C.c_uint32), ("iosize", C.c_int32),
                ("blocks", C.c_uint64), ("bfree", C.c_uint64), ("bavail", C.c_uint64),
                ("files", C.c_uint64), ("ffree", C.c_uint64), ("fsid", C.c_int32 * 2),
                ("owner", C.c_uint32), ("type", C.c_uint32), ("flags", C.c_uint32),
                ("subtype", C.c_uint32), ("fstypename", C.c_char * 16),
                ("mntonname", C.c_char * 1024), ("mntfromname", C.c_char * 1024),
                ("flags_ext", C.c_uint32), ("reserved", C.c_uint32 * 7)]


def _deadline(deadline):
    now = time.monotonic()
    if (type(deadline) not in (int, float) or not now < deadline <= now + 1):
        raise AdmissionError("native_admission_deadline")


def _supported():
    if sys.platform != "darwin" or platform.machine() != "arm64" or os.geteuid() == 0:
        raise AdmissionError("native_admission_unqualified")


class _Darwin:
    def __init__(self):
        _supported()
        self.lib = C.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        signatures = {
            "fstatfs": ([C.c_int, C.POINTER(_Statfs)], C.c_int),
            "filesec_init": ([], C.c_void_p),
            "filesec_free": ([C.c_void_p], None),
            "fstatx_np": ([C.c_int, C.POINTER(_Stat), C.c_void_p], C.c_int),
            "filesec_query_property": ([C.c_void_p, C.c_int, C.POINTER(C.c_int)], C.c_int),
            "filesec_get_property": ([C.c_void_p, C.c_int, C.c_void_p], C.c_int),
            "acl_valid": ([C.c_void_p], C.c_int),
            "acl_get_entry": ([C.c_void_p, C.c_int, C.POINTER(C.c_void_p)], C.c_int),
            "acl_get_tag_type": ([C.c_void_p, C.POINTER(C.c_int)], C.c_int),
            "acl_get_permset": ([C.c_void_p, C.POINTER(C.c_void_p)], C.c_int),
            "acl_get_perm_np": ([C.c_void_p, C.c_int], C.c_int),
            "acl_free": ([C.c_void_p], C.c_int),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = args, result

    def check(self, fd, purpose, deadline):
        def call(name, *args):
            _deadline(deadline)
            result = getattr(self.lib, name)(*args)
            _deadline(deadline)
            return result

        mount = _Statfs()
        if (call("fstatfs", fd, C.byref(mount)) != 0 or not mount.flags & 0x1000
                or mount.flags & 0x200000):
            raise AdmissionError("native_admission_mount")
        if purpose in (DescriptorPurpose.PROTECTED_ANCESTOR, DescriptorPurpose.PROTECTED_EXECUTABLE,
                       DescriptorPurpose.PROTECTED_FILE):
            if mount.owner != 0 or mount.fstypename != b"apfs":
                raise AdmissionError("native_admission_mount")
        # Register returned native allocations before checking the deadline again.
        _deadline(deadline)
        security = self.lib.filesec_init()
        if not security:
            raise AdmissionError("native_admission_acl")
        acl = C.c_void_p()
        try:
            metadata, present = _Stat(), C.c_int()
            if (call("fstatx_np", fd, C.byref(metadata), security) != 0
                    or call("filesec_query_property", security, 5, C.byref(present)) != 0):
                raise AdmissionError("native_admission_acl")
            # The ACL below and this identity and policy come from one atomic call.
            snapshot = (metadata.ino, metadata.mode, metadata.uid, metadata.gid, metadata.nlink)
            if present.value == 0:
                return snapshot
            # Darwin returns a validity bitmask (ACL is 1 << 5), not Boolean 1.
            _deadline(deadline)
            status = self.lib.filesec_get_property(security, 5, C.byref(acl))
            _deadline(deadline)
            if status != 0 or acl.value in (None, 1) or call("acl_valid", acl) != 0:
                raise AdmissionError("native_admission_acl")
            for index in range(129):
                entry = C.c_void_p()
                C.set_errno(0)
                status = call("acl_get_entry", acl, index, C.byref(entry))
                if status != 0:
                    if C.get_errno() == errno.EINVAL:
                        return snapshot
                    raise AdmissionError("native_admission_acl")
                if index == 128 or not entry.value:
                    raise AdmissionError("native_admission_acl")
                tag = C.c_int()
                if call("acl_get_tag_type", entry, C.byref(tag)) != 0:
                    raise AdmissionError("native_admission_acl")
                if tag.value == 2:
                    continue
                if tag.value != 1 or purpose in (DescriptorPurpose.PRIVATE_DIRECTORY, DescriptorPurpose.PRIVATE_FILE,
                                               DescriptorPurpose.PROTECTED_EXECUTABLE, DescriptorPurpose.PROTECTED_FILE,
                                               DescriptorPurpose.PREPARED_CORE_FILE):
                    raise AdmissionError("native_admission_acl")
                permissions = C.c_void_p()
                if call("acl_get_permset", entry, C.byref(permissions)) != 0 or not permissions.value:
                    raise AdmissionError("native_admission_acl")
                for bit in (2, 4, 5, 6, 8, 10, 12, 13):
                    if call("acl_get_perm_np", permissions, 1 << bit) != 0:
                        raise AdmissionError("native_admission_acl")
        finally:
            # Cleanup runs even after expiry; native allocations are never abandoned.
            try:
                if acl.value not in (None, 1) and self.lib.acl_free(acl) != 0:
                    raise AdmissionError("native_admission_cleanup")
            finally:
                self.lib.filesec_free(security)


def _metadata(fd, purpose):
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o6022:
        raise AdmissionError("native_admission_permissions")
    directory = stat.S_ISDIR(info.st_mode)
    regular = stat.S_ISREG(info.st_mode)
    if purpose in (DescriptorPurpose.PRIVATE_DIRECTORY, DescriptorPurpose.PRIVATE_FILE):
        if info.st_uid != os.geteuid() or not (purpose is DescriptorPurpose.PRIVATE_DIRECTORY and directory and mode == 0o700
                or purpose is DescriptorPurpose.PRIVATE_FILE and regular and mode == 0o600):
            raise AdmissionError("native_admission_permissions")
    elif purpose is DescriptorPurpose.PRIVATE_ANCESTOR:
        if not directory or info.st_uid not in (0, os.geteuid()):
            raise AdmissionError("native_admission_permissions")
    elif purpose is DescriptorPurpose.PROTECTED_ANCESTOR:
        if not directory or info.st_uid != 0:
            raise AdmissionError("native_admission_permissions")
    elif purpose is DescriptorPurpose.PROTECTED_EXECUTABLE:
        if not regular or info.st_uid != 0 or mode != 0o555 or not 1 <= info.st_size <= 128 * 1024 * 1024:
            raise AdmissionError("native_admission_permissions")
    elif purpose is DescriptorPurpose.PROTECTED_FILE:
        if not regular or info.st_uid != 0 or mode != 0o444 or not 0 <= info.st_size <= 128 * 1024 * 1024:
            raise AdmissionError("native_admission_permissions")
    elif purpose is DescriptorPurpose.PREPARED_CORE_FILE:
        # Selected native core tools are ordinary user programs, never protected
        # runtime roles. Their separate owner pins bytes and the full load closure.
        if (not regular or info.st_uid not in (0, os.geteuid())
                or mode not in (0o444, 0o644, 0o555, 0o755)
                or not 0 < info.st_size <= 512 * 1024 * 1024):
            raise AdmissionError("native_admission_permissions")
    if regular and info.st_nlink != 1:
        raise AdmissionError("native_admission_permissions")
    # Directory content may change independently; retain its identity and policy.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            None if directory else (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns))


# A held ancestor's ctime moves whenever any entry in it changes, so one pass can
# overlap unrelated activity. Only a complete pass that saw no change is accepted.
_STABLE_PASSES = 4


def _identity(metadata):
    """Identity and policy only: device, inode, mode, owner, group, links."""
    return metadata[:5] + ((metadata[5][0],) if metadata[5] is not None else ())


def _stable_check(backend, fd, purpose, deadline, *, live=False):
    for _ in range(_STABLE_PASSES):
        before = _metadata(fd, purpose)
        revision = os.fstat(fd).st_ctime_ns
        _deadline(deadline)
        snapshot = backend.check(fd, purpose, deadline)
        after = _metadata(fd, purpose)
        if live:
            # A live database file's size and times move with each of its owner's
            # commits; its identity and policy, and the ACL snapshot taken with
            # them, must not.
            if _identity(before) == _identity(after) and snapshot == _identity(after)[1:]:
                return
        elif before == after and os.fstat(fd).st_ctime_ns == revision:
            return
        if time.monotonic() >= deadline:
            break
    raise AdmissionError('native_admission_changed')


def check_retained_descriptor(fd, *, purpose, deadline):
    """Apply native policy without duplicating or closing a borrowed descriptor.

    The caller must retain this exact descriptor throughout the call and until
    its dependent resource closes. SQLite custody needs this form because closing
    any descriptor for an inode can release that process's POSIX locks.

    A retained private file is a live database file its caller writes, so only
    its identity and policy are compared across a pass, not its size or times.
    That custody fences observed replacement; it does not isolate a hostile
    same-UID host, which could change and restore a mode within one pass.
    """
    now = time.monotonic()
    if type(deadline) not in (int, float) or not now < deadline < float('inf'):
        raise AdmissionError('native_admission_deadline')
    deadline = min(deadline, now + 1)
    _deadline(deadline)
    _supported()
    if type(fd) is not int or fd < 0 or type(purpose) is not DescriptorPurpose:
        raise AdmissionError('native_admission_invalid')
    try:
        backend = _Darwin()
        _stable_check(backend, fd, purpose, deadline, live=purpose is DescriptorPurpose.PRIVATE_FILE)
        _deadline(deadline)
    except (OSError, AttributeError):
        raise AdmissionError('native_admission_unavailable') from None
    return True


def check_descriptor(fd, *, purpose, deadline):
    """Fixed installed-adapter check; return True or raise AdmissionError.

    The coordinator retains its original descriptors and rewalks the path before
    launch. This check owns only a temporary duplicate, closed before returning.
    Purpose must be a DescriptorPurpose member, never a configuration value.
    Native calls cannot be preempted safely; expiry refuses admission after the
    call completes, and cleanup always consumes the owned duplicate once.
    """
    now = time.monotonic()
    if type(deadline) not in (int, float) or not now < deadline < float("inf"):
        raise AdmissionError("native_admission_deadline")
    deadline = min(deadline, now + 1)
    _deadline(deadline)
    _supported()
    if type(fd) is not int or fd < 0 or type(purpose) is not DescriptorPurpose:
        raise AdmissionError("native_admission_invalid")
    owned = None
    try:
        backend = _Darwin()
        _deadline(deadline)
        owned = os.dup(fd)
        _stable_check(backend, owned, purpose, deadline)
        _deadline(deadline)
    except (OSError, AttributeError):
        raise AdmissionError("native_admission_unavailable") from None
    finally:
        if owned is not None:
            try:
                os.close(owned)
            except OSError:
                raise AdmissionError("native_admission_cleanup") from None
    _deadline(deadline)
    return True
