"""Fixed cooperative identity-fixture setup; not installed-CLI qualification.

Reviewed invocation uses a trusted system Python with -I -S -c and the literal
reviewed source bytes. Never invoke this through a user-writable script path as
root. --validate-only and --self-test are unprivileged controls. --install needs
root, an independently reviewed manifest digest, and a bounded stdin envelope.
No installed artifact is executed, removed, overwritten, or discovered by glob.

Native constants/layouts below come from the local MacOSX26.5.sdk sys/{stat,
mount,fcntl,acl}.h and mirror privatefs/access_darwin.go and runtime/acl_darwin.go.
They do not enroll SDK27 or qualify runtime process identity on a new SDK.
"""

import base64
import ctypes as C
import errno
import hashlib
import json
import os
import re
import select
import signal
import stat
import struct
import sys
import time


BASE = "/Library/Application Support/Agentmux/Protected/releases"
ROOTS = ["/", "/Library", "/Library/Application Support",
         "/Library/Application Support/Agentmux",
         "/Library/Application Support/Agentmux/Protected", BASE]
ROSTER = ["fixture", "bin/boot", "bin/kernel-lifecycle",
          "bin/internal-communication", "bin/exported-status"]
PROTOCOL = "bounded_stdin_sha256_verified_before_exclusive_descriptor_creation"
MAX_PAYLOAD = 32 * 1024 * 1024
MAX_MANIFEST = 64 * 1024
MAX_INPUT = 4 * ((MAX_PAYLOAD + 2) // 3) + 4 * ((MAX_MANIFEST + 2) // 3) + 128
FIELDS = {"purpose", "releaseDirectory", "ancestors", "directoryMode", "ownerUID",
          "group", "members", "inputDigest", "inputBytes", "copyProtocol",
          "readyForExecution", "sourceDescriptorClosed"}


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def closed_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode_json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=closed_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused("json_constant")))


def decode64(value, maximum):
    require(type(value) is str and len(value) <= 4 * ((maximum + 2) // 3), "base64_bounds")
    result = base64.b64decode(value, validate=True)
    require(len(result) <= maximum and base64.b64encode(result).decode("ascii") == value,
            "base64_noncanonical")
    return result


def validate(raw, expected_digest):
    """Pure validation: completes before native admission or filesystem writes."""
    require(type(raw) is bytes and len(raw) <= MAX_INPUT, "input_bounds")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest) is not None, "plan_hash_shape")
    envelope = decode_json(raw)
    require(type(envelope) is dict and set(envelope) == {"manifestBase64", "payloadBase64"},
            "envelope_fields")
    manifest_bytes = decode64(envelope["manifestBase64"], MAX_MANIFEST)
    require(sha(manifest_bytes) == expected_digest, "plan_hash_mismatch")
    plan = decode_json(manifest_bytes)
    require(type(plan) is dict and set(plan) == FIELDS, "manifest_fields")
    require(plan["purpose"] == "cooperative_native_identity_fixture_only" and
            plan["copyProtocol"] == PROTOCOL and plan["readyForExecution"] is True and
            plan["sourceDescriptorClosed"] is True, "plan_not_reviewable")
    directory = plan["releaseDirectory"]
    require(type(directory) is str and re.fullmatch(re.escape(BASE) + r"/[0-9a-f]{64}", directory)
            is not None, "release_path")
    require(plan["ancestors"] == ROOTS + [directory, directory + "/bin"], "ancestor_roster")
    require(plan["directoryMode"] == "0755" and type(plan["ownerUID"]) is int and
            plan["ownerUID"] == 0 and plan["group"] == "wheel", "ownership_policy")
    require(type(plan["inputBytes"]) is int and 32 <= plan["inputBytes"] <= MAX_PAYLOAD,
            "payload_size")
    payload = decode64(envelope["payloadBase64"], MAX_PAYLOAD)
    require(len(payload) == plan["inputBytes"] and sha(payload) == plan["inputDigest"],
            "payload_hash_mismatch")
    magic, cpu, _, kind = struct.unpack_from("<IIII", payload)
    require(magic == 0xFEEDFACF and cpu == 0x0100000C and kind == 2, "native_arm64_macho_required")
    require(type(plan["members"]) is list and len(plan["members"]) == len(ROSTER), "member_count")
    for member, name in zip(plan["members"], ROSTER):
        require(type(member) is dict and set(member) == {"relativePath", "digest", "bytes", "mode"},
                "member_fields")
        require(member["relativePath"] == name and member["digest"] == plan["inputDigest"] and
                type(member["bytes"]) is int and member["bytes"] == len(payload) and
                member["mode"] == "0555", "fixed_member_roster")
    return plan, payload


class Timespec(C.Structure):
    _fields_ = [("seconds", C.c_int64), ("nanoseconds", C.c_int64)]


class NativeStat(C.Structure):
    _fields_ = [("dev", C.c_int32), ("mode", C.c_uint16), ("nlink", C.c_uint16),
                ("ino", C.c_uint64), ("uid", C.c_uint32), ("gid", C.c_uint32),
                ("rdev", C.c_int32), ("atime", Timespec), ("mtime", Timespec),
                ("ctime", Timespec), ("birthtime", Timespec), ("size", C.c_int64),
                ("blocks", C.c_int64), ("blksize", C.c_int32), ("flags", C.c_uint32),
                ("gen", C.c_uint32), ("lspare", C.c_int32), ("qspare", C.c_int64 * 2)]


class NativeMount(C.Structure):
    _fields_ = [("bsize", C.c_uint32), ("iosize", C.c_int32),
                ("blocks", C.c_uint64), ("bfree", C.c_uint64), ("bavail", C.c_uint64),
                ("files", C.c_uint64), ("ffree", C.c_uint64), ("fsid", C.c_int32 * 2),
                ("owner", C.c_uint32), ("type", C.c_uint32), ("flags", C.c_uint32),
                ("subtype", C.c_uint32), ("typename", C.c_char * 16),
                ("mountpoint", C.c_char * 1024), ("source", C.c_char * 1024),
                ("flags_ext", C.c_uint32), ("reserved", C.c_uint32 * 7)]


class NativePolicy:
    def __init__(self, ledger, deadline):
        require(not any(key.startswith("DYLD_") for key in os.environ), "loader_environment_refused")
        require(sys.platform == "darwin" and os.uname().machine == "arm64" and
                C.sizeof(C.c_void_p) == 8 and C.sizeof(NativeStat) == 144 and
                C.sizeof(NativeMount) == 2168, "native_layout_unqualified")
        self.ledger = ledger
        self.deadline = deadline
        self.lib = C.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        pointer = C.c_void_p
        signatures = {
            "filesec_init": (pointer, []), "filesec_free": (None, [pointer]),
            "filesec_query_property": (C.c_int, [pointer, C.c_int, C.POINTER(C.c_int)]),
            "filesec_get_property": (C.c_int, [pointer, C.c_int, pointer]),
            "fstatx_np": (C.c_int, [C.c_int, C.POINTER(NativeStat), pointer]),
            "fstatfs": (C.c_int, [C.c_int, C.POINTER(NativeMount)]),
            "acl_valid": (C.c_int, [pointer]), "acl_free": (C.c_int, [pointer]),
            "acl_get_entry": (C.c_int, [pointer, C.c_int, C.POINTER(pointer)]),
            "acl_get_tag_type": (C.c_int, [pointer, C.POINTER(C.c_int)]),
            "acl_get_permset": (C.c_int, [pointer, C.POINTER(pointer)]),
            "acl_get_perm_np": (C.c_int, [pointer, C.c_int]),
        }
        for name, (restype, argtypes) in signatures.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = restype, argtypes

    def check(self, fd):
        mount = NativeMount()
        require(self.lib.fstatfs(fd, C.byref(mount)) == 0 and mount.flags & 0x00001000 and
                not mount.flags & 0x00200000 and mount.owner == 0 and mount.typename == b"apfs",
                "native_mount_refused")
        security = None
        allocation = {"kind": "filesec", "allocated": False, "freeAttempted": False, "freeSucceeded": False}
        self.ledger["nativeAllocations"].append(allocation)
        acl = C.c_void_p()
        acl_record = None
        original_failure = False
        try:
            with SignalWindow(self.deadline):
                security = self.lib.filesec_init()
                allocation["allocated"] = bool(security)
            require(bool(security), "filesec_allocation_failed")
            metadata, present = NativeStat(), C.c_int()
            require(self.lib.fstatx_np(fd, C.byref(metadata), security) == 0 and
                    self.lib.filesec_query_property(security, 5, C.byref(present)) == 0,
                    "descriptor_acl_query_failed")
            actual = os.fstat(fd)
            require((metadata.dev, metadata.ino, metadata.uid, metadata.mode) ==
                    (actual.st_dev, actual.st_ino, actual.st_uid, actual.st_mode), "native_stat_disagrees")
            if present.value == 0:
                return
            require(present.value == 1, "descriptor_acl_unknown")
            acl_record = {"kind": "acl", "retrievalAttempted": True, "allocated": False,
                          "freeAttempted": False, "freeSucceeded": False}
            self.ledger["nativeAllocations"].append(acl_record)
            require(self.lib.filesec_get_property(security, 5, C.byref(acl)) == 0 and
                    acl.value not in (None, 1), "descriptor_acl_unknown")
            require(self.lib.acl_valid(acl) == 0, "descriptor_acl_invalid")
            for index in range(129):
                entry = C.c_void_p()
                C.set_errno(0)
                found = self.lib.acl_get_entry(acl, index, C.byref(entry))
                if found != 0:
                    require(C.get_errno() == errno.EINVAL, "descriptor_acl_iteration_failed")
                    return
                require(index < 128, "descriptor_acl_too_large")
                tag = C.c_int()
                require(self.lib.acl_get_tag_type(entry, C.byref(tag)) == 0, "descriptor_acl_tag_failed")
                if tag.value == 2:
                    continue
                require(tag.value == 1, "descriptor_acl_tag_unknown")
                permissions = C.c_void_p()
                require(self.lib.acl_get_permset(entry, C.byref(permissions)) == 0,
                        "descriptor_acl_permissions_failed")
                for bit in (2, 5, 4, 6, 8, 10, 12, 13):
                    require(self.lib.acl_get_perm_np(permissions, 1 << bit) == 0,
                            "descriptor_acl_grants_mutation")
            raise Refused("descriptor_acl_incomplete")
        except Refused as error:
            original_failure = True
            allocation["operationErrorCode"] = str(error)
            self.ledger["causes"].append({"stage": "native_acl_admission", "code": str(error)})
            raise
        except Exception:
            original_failure = True
            allocation["operationErrorCode"] = "descriptor_acl_operation_failed"
            self.ledger["causes"].append({"stage": "native_acl_admission", "code": "descriptor_acl_operation_failed"})
            raise
        finally:
            free_failed = False
            try:
                if acl.value not in (None, 1):
                    acl_record["allocated"] = True
                    with SignalWindow(self.deadline, closing=True):
                        pointer, acl.value = acl.value, None
                        acl_record["freeAttempted"] = True
                        acl_record["freeSucceeded"] = self.lib.acl_free(pointer) == 0
                        free_failed = not acl_record["freeSucceeded"]
                        if free_failed:
                            acl_record["errorCode"] = "descriptor_acl_free_failed"
                            self.ledger["causes"].append({"stage": "native_acl_cleanup", "code": "descriptor_acl_free_failed"})
                            self.ledger["cleanupFailed"] = True
            finally:
                if security is not None:
                    with SignalWindow(self.deadline, closing=True):
                        pointer, security = security, None
                        allocation["freeAttempted"] = True
                        self.lib.filesec_free(pointer)  # void API: completion, not a native success result.
                        allocation["freeSucceeded"] = True
            if free_failed:
                self.ledger["cleanupFailed"] = True
                if not original_failure:
                    raise Refused("descriptor_acl_free_failed")


class Installer:
    def __init__(self, policy, ledger, deadline):
        self.policy, self.ledger = policy, ledger
        self.deadline = deadline
        self.handles = []
        self.chain = []

    def open_held(self, path, flags, parent=None, name=None, mode=0o600, created=None):
        record = {"path": path, "openAttempted": False, "openConfirmed": False,
                  "closeAttempted": False, "closeSucceeded": False}
        self.ledger["descriptors"].append(record)
        handle = {"fd": None, "record": record, "parent": parent, "name": name, "created": created}
        self.handles.append(handle)  # Register the slot before the syscall, not after its return.
        with SignalWindow(self.deadline):
            record["openAttempted"] = True
            try:
                if parent is None:
                    handle["fd"] = os.open(path, flags, mode)
                else:
                    handle["fd"] = os.open(name, flags, mode, dir_fd=parent["fd"])
            except OSError as error:
                record["errorCode"] = "descriptor_open_failed"
                if created is not None:
                    if flags & os.O_CREAT:
                        created["creationState"] = "not_created_exists" if error.errno == errno.EEXIST else "uncertain"
                        created["errorCode"] = "exclusive_creation_failed"
                    else:
                        created["acquisitionState"] = "uncertain"
                        created["errorCode"] = "created_directory_open_failed"
                    self.ledger["causes"].append({"stage": "descriptor_acquisition", "code": created["errorCode"], "path": path})
                raise
            record["openConfirmed"] = True
            if created is not None:
                created.update(creationState="confirmed", creationSucceeded=True)
        self.refresh(handle)
        handle["identity"] = (record["device"], record["inode"])
        return handle

    def creation_intent(self, path, kind):
        intent = {"path": path, "kind": kind, "creationState": "attempted", "creationAttempted": False,
                  "creationSucceeded": False, "admitted": False, "closeAttempted": False,
                  "closeSucceeded": False}
        self.ledger["created"].append(intent)
        return intent

    def refresh(self, handle):
        info = os.fstat(handle["fd"])
        metadata = {"device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
                    "gid": info.st_gid, "mode": format(stat.S_IMODE(info.st_mode), "04o"),
                    "bytes": info.st_size, "links": info.st_nlink}
        handle["record"].update(metadata)
        if handle["created"] is not None:
            handle["created"].update(metadata)
        return info

    def admit(self, handle, directory):
        info = self.refresh(handle)
        require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o6022 and
                (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)),
                "protected_metadata_refused")
        if not directory:
            require(info.st_nlink == 1 and info.st_size <= MAX_PAYLOAD, "protected_file_links_or_size")
        self.policy.check(handle["fd"])

    def admit_interpreter(self):
        path = os.path.realpath(sys.executable)
        require(path in ("/usr/bin/python3", "/Library/Developer/CommandLineTools/usr/bin/python3",
                         "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9"),
                "trusted_system_interpreter_required")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        parent = self.open_held("/", flags | os.O_DIRECTORY)
        self.admit(parent, True)
        parts = path.lstrip("/").split("/")
        current = ""
        for index, name in enumerate(parts):
            current += "/" + name
            directory = index < len(parts) - 1
            child = self.open_held(current, flags | (os.O_DIRECTORY if directory else 0), parent, name)
            # System executables can have more than one link. Interpreter
            # admission uses the same ancestor ACL/mount and ownership policy,
            # while fixture artifacts themselves must have exactly one link.
            info = self.refresh(child)
            require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o6022 and
                    (stat.S_ISDIR(info.st_mode) if directory else
                     stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111)),
                    "system_interpreter_metadata_refused")
            self.policy.check(child["fd"])
            parent = child

    def fence(self):
        for handle in self.chain:
            self.admit(handle, True)
            if handle["parent"] is not None:
                current = os.stat(handle["name"], dir_fd=handle["parent"]["fd"], follow_symlinks=False)
                require((current.st_dev, current.st_ino) == handle["identity"], "held_ancestor_replaced")

    def directory(self, parent, name, path, create=False, fresh=False):
        self.fence()
        created = None
        if create:
            intent = self.creation_intent(path, "directory")
            with SignalWindow(self.deadline):
                intent["creationAttempted"] = True
                try:
                    os.mkdir(name, 0o700, dir_fd=parent["fd"])
                except FileExistsError:
                    intent["creationState"] = "not_created_exists"
                    require(not fresh, "fresh_destination_collision")
                except OSError:
                    intent.update(creationState="uncertain", errorCode="directory_creation_failed")
                    raise
                else:
                    intent.update(creationState="confirmed", creationSucceeded=True)
                    created = intent
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        handle = self.open_held(path, flags, parent, name, created=created)
        self.admit(handle, True)
        if created is not None:
            os.fchown(handle["fd"], 0, 0)
            os.fchmod(handle["fd"], 0o755)
            self.admit(handle, True)
            created["admitted"] = True
        self.chain.append(handle)
        return handle

    def file(self, parent, name, path, payload, digest):
        self.fence()
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        created = self.creation_intent(path, "file")
        created.update(expectedDigest=digest, creationAttempted=True)
        handle = self.open_held(path, flags, parent, name, created=created)
        fd = handle["fd"]
        self.admit(handle, False)
        os.fchown(fd, 0, 0)
        view = memoryview(payload)
        while view:
            count = os.write(fd, view[:65536])
            require(count > 0, "artifact_write_incomplete")
            view = view[count:]
        os.fsync(fd)
        self.hash_file(handle)
        require(created["actualDigest"] == digest and created["bytes"] == len(payload),
                "installed_artifact_hash_mismatch")
        os.fchmod(fd, 0o555)
        self.admit(handle, False)
        info = self.refresh(handle)
        require(info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o555 and info.st_nlink == 1,
                "installed_artifact_metadata_mismatch")
        created["admitted"] = True

    def hash_file(self, handle):
        info = self.refresh(handle)
        require(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= MAX_PAYLOAD, "ledger_file_bounds")
        os.lseek(handle["fd"], 0, os.SEEK_SET)
        digest, count = hashlib.sha256(), 0
        while True:
            block = os.read(handle["fd"], 65536)
            if not block:
                break
            count += len(block)
            require(count <= MAX_PAYLOAD, "ledger_file_bounds")
            digest.update(block)
        handle["created"].update(actualDigest="sha256:" + digest.hexdigest(), bytes=count)

    def install(self, plan, payload):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        root = self.open_held("/", flags)
        self.admit(root, True)
        self.chain.append(root)
        parent = root
        for index, path in enumerate(ROOTS[1:], 1):
            parent = self.directory(parent, path.rsplit("/", 1)[1], path, create=index >= 3)
        release = self.directory(parent, plan["releaseDirectory"].rsplit("/", 1)[1],
                                 plan["releaseDirectory"], create=True, fresh=True)
        binary_dir = self.directory(release, "bin", plan["releaseDirectory"] + "/bin", create=True, fresh=True)
        for member in plan["members"]:
            name = member["relativePath"]
            destination = release if name == "fixture" else binary_dir
            self.file(destination, name.rsplit("/", 1)[-1], plan["releaseDirectory"] + "/" + name,
                      payload, member["digest"])
        self.fence()
        for handle in self.handles:
            if handle["created"] is not None:
                os.fsync(handle["fd"])

    def close(self):
        # Cancellation is deferred across the entire closeout traversal, not
        # merely each close syscall. Bookkeeping between handles must not
        # strand the rest of the already registered descriptor roster.
        with CloseoutSignals(self.ledger, self.deadline):
            self.close_registered()

    def close_registered(self):
        for handle in reversed(self.handles):
            if handle["fd"] is None:
                continue  # No descriptor was returned; never invent or retry one.
            fd = handle["fd"]
            record = handle["record"]
            try:
                handle["fd"] = fd
                if handle["created"] is not None and handle["created"]["kind"] == "file":
                    self.hash_file(handle)
                else:
                    self.refresh(handle)
            except Exception:
                record["finalObservationFailed"] = True
                record["observationErrorCode"] = "descriptor_final_observation_failed"
                self.ledger["causes"].append({"stage": "descriptor_closeout", "code": "descriptor_final_observation_failed", "path": record["path"]})
                self.ledger["cleanupFailed"] = True
            try:
                with SignalWindow(self.deadline, closing=True):
                    handle["fd"] = None  # Consume once before close, including uncertain close failures.
                    record["closeAttempted"] = True
                    try:
                        os.close(fd)
                        record["closeSucceeded"] = True
                    except OSError:
                        record["closeErrorCode"] = "descriptor_close_failed"
                        self.ledger["causes"].append({"stage": "descriptor_closeout", "code": "descriptor_close_failed", "path": record["path"]})
                        self.ledger["cleanupFailed"] = True
                    if handle["created"] is not None:
                        handle["created"].update(closeAttempted=True, closeSucceeded=record["closeSucceeded"])
            except Refused:
                # Restoring the mask can deliver an already pending cancel.
                # This descriptor is consumed; continue with every remaining
                # registered handle without retrying its numeric descriptor.
                record["closeoutErrorCode"] = "descriptor_closeout_cancelled"
                self.ledger["causes"].append({"stage": "descriptor_closeout", "code": "descriptor_closeout_cancelled", "path": record["path"]})
                self.ledger["cleanupFailed"] = True
            except Exception:
                record["closeoutErrorCode"] = "descriptor_closeout_operation_failed"
                self.ledger["causes"].append({"stage": "descriptor_closeout", "code": "descriptor_closeout_operation_failed", "path": record["path"]})
                self.ledger["cleanupFailed"] = True


class SignalWindow:
    """Delay only reviewed cancellation signals across syscall ownership transfer.

    The existing alarm stays armed. Pending signals are delivered on restoring
    the original mask; the monotonic check also refuses an expired setup budget.
    Closing may consume already-owned descriptors after expiry, never mutate a
    destination or reset the alarm to obtain more setup time.
    """
    def __init__(self, deadline, closing=False):
        self.deadline, self.closing = deadline, closing

    def __enter__(self):
        if not self.closing:
            require(time.monotonic() < self.deadline, "setup_absolute_deadline")
        self.previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM, signal.SIGTERM, signal.SIGINT})

    def __exit__(self, kind, value, traceback):
        signal.pthread_sigmask(signal.SIG_SETMASK, self.previous)
        if kind is None and not self.closing:
            require(time.monotonic() < self.deadline, "setup_absolute_deadline")


class CloseoutSignals:
    """Record cancellation until every owned close has been attempted once."""
    def __init__(self, ledger, deadline):
        self.ledger, self.deadline = ledger, deadline
        self.previous = {}

    def cancelled(self, _signum, _frame):
        self.ledger["cleanupFailed"] = True
        self.ledger["closeoutCancellationObserved"] = True
        # Bound diagnostics even if a caller sends repeated cancellation.
        if not any(item.get("code") == "closeout_cancellation_deferred" for item in self.ledger["causes"]):
            self.ledger["causes"].append({"stage": "descriptor_closeout", "code": "closeout_cancellation_deferred"})

    def __enter__(self):
        with SignalWindow(self.deadline, closing=True):
            for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
                self.previous[number] = signal.signal(number, self.cancelled)

    def __exit__(self, kind, value, traceback):
        # Pending cancellation after handlers are restored may still raise,
        # but the complete roster has already been consumed by this point.
        with SignalWindow(self.deadline, closing=True):
            for number, previous in self.previous.items():
                signal.signal(number, previous)


class FinalizationSignals:
    """Terminal process handlers stay non-raising through result selection.

    They deliberately remain installed until this one-shot setup process exits;
    restoring raising handlers between receipt output and return is unsafe.
    """
    def __init__(self, ledger):
        self.ledger = ledger

    def cancelled(self, _signum, _frame):
        self.ledger["finalizationCancellationObserved"] = True
        self.ledger["success"] = False
        self.ledger.setdefault("errorCode", "finalization_cancelled")
        if not any(item.get("code") == "finalization_cancelled" for item in self.ledger["causes"]):
            self.ledger["causes"].append({"stage": "ledger_finalization", "code": "finalization_cancelled"})

    def install(self):
        with SignalWindow(time.monotonic(), closing=True):
            for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
                signal.signal(number, self.cancelled)


def timeout(_signum, _frame):
    raise Refused("setup_absolute_deadline")


def emit_ledger(ledger):
    # A stalled diagnostic consumer cannot retain a root setup process forever.
    deadline = time.monotonic() + 2
    ledger["receiptRequiresZeroExit"] = True
    raw = (json.dumps(ledger, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    cancelled_before_write = bool(ledger.get("finalizationCancellationObserved"))
    if cancelled_before_write:
        # No byte has been emitted. One replacement serialization can describe
        # the cancellation honestly; this is not a second output attempt.
        ledger["success"] = False
        raw = (json.dumps(ledger, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > 1024 * 1024:
        return False
    try:
        os.set_blocking(1, False)
        view = memoryview(raw)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [1], [], remaining)[1]:
                return False
            if ledger.get("finalizationCancellationObserved") and not cancelled_before_write:
                ledger["receiptEmissionConfirmed"] = False
                return False
            try:
                count = os.write(1, view[:65536])
            except BlockingIOError:
                continue
            if count <= 0:
                return False
            view = view[count:]
            if ledger.get("finalizationCancellationObserved") and not cancelled_before_write:
                # Even complete-looking bytes are unconfirmed when cancellation
                # raced their write. Return nonzero; never emit a replacement.
                ledger["receiptEmissionConfirmed"] = False
                return False
        return True
    except OSError:
        return False


def finish_ledger(ledger, result):
    FinalizationSignals(ledger).install()
    if ledger["cleanupFailed"]:
        ledger["success"], result = False, 1
        ledger.setdefault("errorCode", "setup_cleanup_failed")
    if not emit_ledger(ledger):
        result = 1
    if ledger.get("finalizationCancellationObserved"):
        result = 1
    return result


def validation_controls():
    """Pure schema/byte controls; synthetic headers do not prove a native image."""
    payload = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
    directory = BASE + "/" + "a" * 64
    good = {"purpose": "cooperative_native_identity_fixture_only", "releaseDirectory": directory,
            "ancestors": ROOTS + [directory, directory + "/bin"], "directoryMode": "0755",
            "ownerUID": 0, "group": "wheel", "inputDigest": sha(payload), "inputBytes": len(payload),
            "copyProtocol": PROTOCOL, "readyForExecution": True, "sourceDescriptorClosed": True,
            "members": [{"relativePath": name, "digest": sha(payload), "bytes": len(payload),
                         "mode": "0555"} for name in ROSTER]}

    def envelope(plan, content=payload):
        manifest = json.dumps(plan, separators=(",", ":")).encode("utf-8")
        raw = json.dumps({"manifestBase64": base64.b64encode(manifest).decode("ascii"),
                          "payloadBase64": base64.b64encode(content).decode("ascii")}).encode("utf-8")
        return raw, sha(manifest)

    raw, digest = envelope(good)
    require(validate(raw, digest)[1] == payload, "control_valid_plan_failed")
    controls = [
        ("manifest_hash", raw, "sha256:" + "0" * 64),
        ("payload_hash", *envelope(good, payload[:-1] + b"x")),
        ("duplicate_envelope_key", b'{"manifestBase64":"","manifestBase64":"","payloadBase64":""}', digest),
    ]
    changes = [
        ("unknown_field", lambda p: p.update(unreviewed=True)),
        ("wrong_purpose", lambda p: p.update(purpose="installed_cli_qualification")),
        ("unreviewed", lambda p: p.update(readyForExecution=False)),
        ("unclosed_source", lambda p: p.update(sourceDescriptorClosed=False)),
        ("path_escape", lambda p: p.update(releaseDirectory=directory + "/../escape")),
        ("ancestor_omission", lambda p: p.update(ancestors=p["ancestors"][1:])),
        ("boolean_size", lambda p: p.update(inputBytes=True)),
        ("wrong_owner", lambda p: p.update(ownerUID=True)),
        ("extra_member", lambda p: p["members"].append(dict(p["members"][0]))),
        ("duplicate_role", lambda p: p["members"][1].update(relativePath="fixture")),
        ("writable_mode", lambda p: p["members"][0].update(mode="0755")),
    ]
    for name, change in changes:
        modified = json.loads(json.dumps(good))
        change(modified)
        controls.append((name, *envelope(modified)))
    for name, raw, digest in controls:
        try:
            validate(raw, digest)
        except (Refused, ValueError, TypeError):
            continue
        raise Refused("control_invalid_plan_accepted_" + name)
    return {"controls": len(controls) + 1, "nativeExecutionEvidence": False}


def closeout_fault_controls():
    """Unprivileged OS descriptors plus explicit syscall-failure substitutes.

    No policy or installer admission is substituted to claim a protected pass.
    These controls exercise cancellation/close bookkeeping only.
    """
    from unittest import mock

    require(os.getuid() != 0 and os.geteuid() != 0, "fault_controls_must_be_unprivileged")
    original_close, original_stat = os.close, os.fstat
    original_mask = signal.pthread_sigmask
    completed = []
    for scenario in ("before_iterations", "during_observation", "mask_restoration",
                     "observation_failure", "close_failure", "primary_and_cleanup_failure"):
        ledger = {"created": [], "descriptors": [], "nativeAllocations": [],
                  "causes": [], "cleanupFailed": False}
        installer = Installer(None, ledger, time.monotonic() + 5)
        for _ in range(3):
            installer.open_held("/dev/null", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors = [handle["fd"] for handle in installer.handles]
        calls = {fd: 0 for fd in descriptors}
        injected = [False]
        first = descriptors[-1]
        if scenario == "primary_and_cleanup_failure":
            ledger["causes"].append({"stage": "setup", "code": "control_primary_operation_failed"})

        def close_fd(fd):
            if fd in calls:
                calls[fd] += 1
            original_close(fd)
            if fd == first and scenario in ("close_failure", "primary_and_cleanup_failure"):
                raise OSError(errno.EIO, "controlled close result")

        def observe_fd(fd):
            if fd == first and not injected[0]:
                if scenario == "during_observation":
                    injected[0] = True
                    os.kill(os.getpid(), signal.SIGINT)
                elif scenario in ("observation_failure", "primary_and_cleanup_failure"):
                    injected[0] = True
                    raise OSError(errno.EIO, "controlled observation result")
            return original_stat(fd)

        def restore_mask(how, mask):
            if scenario == "mask_restoration" and how == signal.SIG_SETMASK and not injected[0] and any(
                    item["closeAttempted"] for item in ledger["descriptors"]):
                injected[0] = True
                os.kill(os.getpid(), signal.SIGTERM)
            return original_mask(how, mask)

        traverse = installer.close_registered

        def before_iterations():
            if scenario == "before_iterations":
                injected[0] = True
                os.kill(os.getpid(), signal.SIGALRM)
            traverse()

        with mock.patch.object(installer, "close_registered", before_iterations), \
                mock.patch.object(os, "close", close_fd), \
                mock.patch.object(os, "fstat", observe_fd), \
                mock.patch.object(signal, "pthread_sigmask", restore_mask):
            installer.close()
            installer.close()  # Consumption is shared; this must not retry an FD.
        require(all(count == 1 for count in calls.values()) and all(
            item["closeAttempted"] for item in ledger["descriptors"]), "control_close_roster_incomplete")
        for fd in descriptors:
            try:
                original_stat(fd)
            except OSError as error:
                require(error.errno == errno.EBADF, "control_descriptor_state_unknown")
            else:
                raise Refused("control_descriptor_remained_open")
        require(ledger["cleanupFailed"] is True, "control_cleanup_failure_not_recorded")
        codes = {item["code"] for item in ledger["causes"]}
        if scenario in ("before_iterations", "during_observation", "mask_restoration"):
            require("closeout_cancellation_deferred" in codes and injected[0], "control_cancellation_not_recorded")
        if scenario == "primary_and_cleanup_failure":
            require({"control_primary_operation_failed", "descriptor_final_observation_failed",
                     "descriptor_close_failed"} <= codes, "control_original_cause_lost")
            with mock.patch.dict(globals(), {"emit_ledger": lambda _: True}):
                require(finish_ledger(ledger, 0) != 0, "control_primary_cleanup_failure_false_green")
        completed.append(scenario)

    ledger = {"created": [], "descriptors": [], "nativeAllocations": [], "causes": [], "cleanupFailed": False}
    expired = Installer(None, ledger, time.monotonic() - 1)
    with mock.patch.object(os, "mkdir", side_effect=AssertionError("unexpected mutation")) as mkdir_call, \
            mock.patch.object(signal, "alarm", side_effect=AssertionError("unexpected alarm reset")) as alarm_call:
        try:
            expired.directory({"fd": -1}, "unused", "/unused-control-intent", create=True, fresh=True)
        except Refused as error:
            require(str(error) == "setup_absolute_deadline", "control_expiry_stage_changed")
        else:
            raise Refused("control_expired_deadline_accepted")
        require(mkdir_call.call_count == 0 and alarm_call.call_count == 0, "control_expiry_mutated_or_reset_alarm")
    completed.append("expired_deadline_no_mutation_or_alarm_reset")

    # Exercise main's actual common return, including its self-test branch.
    # The substitute drops only diagnostic output; validation still runs.
    captured = []

    def failed_emission(record):
        captured.append(record)
        return False

    with mock.patch.object(sys, "argv", ["installer-control", "--self-test"]), \
            mock.patch.dict(globals(), {"emit_ledger": failed_emission}):
        result = main()
    require(result != 0 and len(captured) == 1 and captured[0].get("controls") == 15,
            "control_selftest_emission_failure_false_green")
    completed.append("selftest_ledger_emission_failure_nonzero")

    original_dumps = json.dumps
    for stage in ("serialization", "partial_write", "complete_write"):
        ledger = {"success": True, "cleanupFailed": False, "causes": []}
        written, dumps_count, injected = [], [0], [False]
        previous_handlers = {number: signal.getsignal(number) for number in
                             (signal.SIGALRM, signal.SIGTERM, signal.SIGINT)}

        def serialize(record, *args, **kwargs):
            dumps_count[0] += 1
            raw = original_dumps(record, *args, **kwargs)
            if stage == "serialization" and not injected[0]:
                injected[0] = True
                os.kill(os.getpid(), signal.SIGTERM)
            return raw

        def write_receipt(fd, raw):
            require(fd == 1, "control_unexpected_output_descriptor")
            count = min(17, len(raw)) if stage == "partial_write" else len(raw)
            written.append(bytes(raw[:count]))
            if stage != "serialization" and not injected[0]:
                injected[0] = True
                os.kill(os.getpid(), signal.SIGINT)
            return count

        try:
            with mock.patch.object(json, "dumps", serialize), \
                    mock.patch.object(os, "write", write_receipt), \
                    mock.patch.object(os, "set_blocking"), \
                    mock.patch.object(select, "select", return_value=([], [1], [])):
                result = finish_ledger(ledger, 0)
        finally:
            for number, previous in previous_handlers.items():
                signal.signal(number, previous)
        require(result != 0 and injected[0] and ledger.get("finalizationCancellationObserved") is True,
                "control_finalization_cancel_false_green")
        require(len(written) == 1 and any(item["code"] == "finalization_cancelled" for item in ledger["causes"]),
                "control_finalization_repeated_or_missing_cause")
        if stage == "serialization":
            receipt = decode_json(written[0])
            require(receipt["success"] is False and dumps_count[0] == 2,
                    "control_serialization_cancel_success_overclaimed")
        else:
            require(ledger.get("receiptEmissionConfirmed") is False and dumps_count[0] == 1,
                    "control_racing_write_receipt_confirmed")
        completed.append("finalization_cancel_during_" + stage)
    return {"closeoutFaultControls": completed, "controls": len(completed),
            "syscallSubstitutes": True, "nativeExecutionEvidence": False}


def main():
    ledger = {"schemaVersion": "1.0.0", "purpose": "cooperative_native_identity_fixture_only",
              "success": False, "mutationStarted": False, "created": [], "descriptors": [],
              "nativeAllocations": [], "causes": [], "cleanupFailed": False, "retainedForReview": True,
              "protectedLoaderQualified": False, "nativeProcessIdentityQualified": False}
    installer = None
    result = 1
    try:
        require(sys.flags.isolated == 1 and sys.flags.no_site == 1, "isolated_interpreter_required")
        signal.signal(signal.SIGALRM, timeout)
        signal.signal(signal.SIGTERM, timeout)
        signal.signal(signal.SIGINT, timeout)
        setup_deadline = time.monotonic() + 120
        signal.alarm(120)  # Bounds validation, setup and normal closeout together.
        if sys.argv[1:] == ["--self-test"]:
            require(os.getuid() != 0 and os.geteuid() != 0, "unprivileged_isolated_controls_required")
            ledger.update(validation_controls())
        elif sys.argv[1:] == ["--fault-controls"]:
            ledger.update(closeout_fault_controls())
        elif sys.argv[1:] == ["--native-admission-control"]:
            require(os.getuid() != 0 and os.geteuid() != 0, "native_control_must_be_unprivileged")
            policy = NativePolicy(ledger, setup_deadline)
            installer = Installer(policy, ledger, setup_deadline)
            installer.admit_interpreter()
            ledger["nativeMetadataControlCompleted"] = True
        else:
            require(len(sys.argv) == 3 and sys.argv[1] in ("--validate-only", "--install"), "arguments")
            raw = sys.stdin.buffer.read(MAX_INPUT + 1)
            plan, payload = validate(raw, sys.argv[2])
            ledger.update(planDigest=sys.argv[2], payloadDigest=sha(payload), payloadBytes=len(payload),
                          releaseDirectory=plan["releaseDirectory"], allInputVerified=True)
            if sys.argv[1] == "--install":
                require(os.getuid() == 0 and os.geteuid() == 0, "root_setup_required")
                policy = NativePolicy(ledger, setup_deadline)
                installer = Installer(policy, ledger, setup_deadline)
                installer.admit_interpreter()
                os.umask(0o077)
                ledger["mutationStarted"] = True
                installer.install(plan, payload)
            else:
                require(os.getuid() != 0 and os.geteuid() != 0, "validation_must_be_unprivileged")
        ledger["success"] = True
        result = 0
    except Refused as error:
        ledger["errorCode"] = str(error)
        ledger["causes"].append({"stage": "setup", "code": str(error)})
    except Exception:
        ledger["errorCode"] = "setup_operation_failed"
        ledger["causes"].append({"stage": "setup", "code": "setup_operation_failed"})
    finally:
        FinalizationSignals(ledger).install()
        if installer is not None:
            try:
                installer.close()
            except Exception:
                ledger["cleanupFailed"] = True
                ledger.setdefault("errorCode", "setup_closeout_interrupted")
        signal.alarm(0)
        result = finish_ledger(ledger, result)
    return result


if __name__ == "__main__":
    sys.exit(main())
