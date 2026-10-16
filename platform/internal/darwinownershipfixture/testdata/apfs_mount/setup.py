import ctypes as C
import contextlib, hashlib, json, os, plistlib, re, select, selectors, signal, stat, subprocess, sys, threading, time

ROOT = "/private/tmp/agentmux-c05-apfs-20261015-7c4e92b1"
NONCE = "20261015-7c4e92b1"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/root", "TMPDIR": "/private/tmp", "LC_ALL": "C"}
# Proposed policy, not execution approval: one original 120s operation budget,
# then TERM on only the created hdiutil object, 2s grace, then KILL that object.
# Even after KILL, ownership/captures remain held until the sole wait terminates.
BUDGET_SECONDS = 120
TERM_GRACE_SECONDS = 2
owned = []
cancelled = False
deadline = 0.0

class FixtureFailure(RuntimeError):
    def __init__(self, message, causes):
        super().__init__(message + "; retain all fixture resources")
        self.causes = tuple(causes)

def require(value, message):
    if not value:
        raise FixtureFailure(message, ())

def cancel(signum, frame):
    global cancelled
    cancelled = True  # Sticky and non-raising through creation, wait and closeout.

def gate():
    require(not cancelled, "fixture_cancelled")
    require(time.monotonic() < deadline, "fixture_original_deadline_expired")

def require_unmasked():
    current = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    require(not current.intersection({signal.SIGINT, signal.SIGTERM}),
            "fixture_inherited_cancellation_mask_refused")

@contextlib.contextmanager
def mutation_window(after=True):
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        gate()
        require(not signal.sigpending().intersection({signal.SIGINT, signal.SIGTERM}),
                "fixture_cancellation_pending")
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    if after:
        gate()

def mutate(operation, *args, **kwargs):
    with mutation_window():
        return operation(*args, **kwargs)

def hold(path, flags, mode=0o600, *, dir_fd=None):
    with mutation_window():
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dir_fd)
        owned.append(fd)  # Transfer ownership before pending cancellation delivery.
    return fd

def close_all():
    failures = []
    while owned:
        fd = owned.pop()
        try:
            os.close(fd)
        except BaseException as error:
            failures.append(error)  # Preserve actual causes; consumed once.
    if failures:
        raise FixtureFailure("owned_descriptor_cleanup_failed", failures)

def identity(fd):
    s = os.fstat(fd)
    return {"dev": s.st_dev, "ino": s.st_ino, "uid": s.st_uid,
            "mode": stat.S_IMODE(s.st_mode), "nlink": s.st_nlink}

def private_bytes(rootfd, name, data):
    fd = hold(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=rootfd)
    require(mutate(os.write, fd, data) == len(data), "short private record write")
    mutate(os.fsync, fd)

# Proposed bounds require independent policy review before any execution.
CAPTURE_LIMIT = 1024 * 1024
PIPE_DRAIN_SECONDS = 1
KILL_JOIN_SECONDS = 2

def wait_confirmed(terminal, wait_result):
    # Thread termination alone and a failed wait never prove child completion.
    return terminal.is_set() and "status" in wait_result and "error" not in wait_result

def retain_unconfirmed(child, waiter, terminal, wait_result, causes, shutdown_at=None, killed=False):
    causes.append(FixtureFailure("owned_terminal_historically_unconfirmed", ()))
    try:
        print("owned_hdiutil_terminal_unconfirmed_resources_retained", file=sys.stderr, flush=True)
    except BaseException as error:
        causes.append(error)
    while True:
        if wait_confirmed(terminal, wait_result):
            waiter.join(timeout=KILL_JOIN_SECONDS)
            if not waiter.is_alive():
                return  # Same original successful wait; historical failure stays.
        now = time.monotonic()
        if shutdown_at is None and (cancelled or now >= deadline):
            shutdown_at = now
            try:
                child.terminate()
            except BaseException as error:
                causes.append(error)
        if shutdown_at is not None and not killed and now >= shutdown_at + TERM_GRACE_SECONDS:
            killed = True
            try:
                child.kill()
            except BaseException as error:
                causes.append(error)
        # Avoid a busy loop when a failed original wait set terminal.
        time.sleep(0.02)

def prepare_owned(out, err):
    state = {"child": None, "terminal": threading.Event(), "wait_result": {}, "causes": [],
             "streams": [{"pipe": None, "destination": out, "bytes": 0, "eof": False, "overflow": False},
                         {"pipe": None, "destination": err, "bytes": 0, "eof": False, "overflow": False}]}
    def wait_once():
        try:
            state["wait_result"]["status"] = state["child"].wait()
        except BaseException as error:
            state["wait_result"]["error"] = error
        finally:
            state["terminal"].set()
    state["waiter"] = threading.Thread(target=wait_once, name="sole-owned-hdiutil-wait", daemon=True)
    return state

def run_owned(state):
    child, terminal, wait_result = state["child"], state["terminal"], state["wait_result"]
    causes, streams, waiter = state["causes"], state["streams"], state["waiter"]
    streams[0]["pipe"], streams[1]["pipe"] = child.stdout, child.stderr
    selector = None
    shutdown_at = None
    killed_at = None
    terminal_at = None
    selector_failed = False
    try:
        waiter.start()
    except BaseException as error:
        causes.append(error)
        # The object already exists. Never unwind into descriptor closeout.
        retain_unconfirmed(child, waiter, terminal, wait_result, causes, shutdown_at, killed_at is not None)
    try:
        selector = selectors.DefaultSelector()
    except BaseException as error:
        causes.append(error)
        retain_unconfirmed(child, waiter, terminal, wait_result, causes, shutdown_at, killed_at is not None)
    try:
        for stream in streams:
            try:
                os.set_blocking(stream["pipe"].fileno(), False)
                selector.register(stream["pipe"], selectors.EVENT_READ, stream)
            except BaseException as error:
                causes.append(error)
                stream["eof"] = True
        while True:
            now = time.monotonic()
            if (cancelled or now >= deadline or causes) and shutdown_at is None and not terminal.is_set():
                shutdown_at = now
                # Only the original Popen object's synchronized signaling API.
                try:
                    child.terminate()
                except BaseException as error:
                    causes.append(error)
            if shutdown_at is not None and not terminal.is_set() and killed_at is None and now >= shutdown_at + TERM_GRACE_SECONDS:
                killed_at = now
                try:
                    child.kill()
                except BaseException as error:
                    causes.append(error)
            if killed_at is not None and not terminal.is_set() and now >= killed_at + KILL_JOIN_SECONDS:
                retain_unconfirmed(child, waiter, terminal, wait_result, causes, shutdown_at, killed_at is not None)
            if terminal.is_set():
                if "error" in wait_result:
                    causes.append(wait_result["error"])
                    retain_unconfirmed(child, waiter, terminal, wait_result, causes, shutdown_at, killed_at is not None)
                if terminal_at is None:
                    terminal_at = now
                if all(stream["eof"] for stream in streams):
                    break
                if now >= terminal_at + PIPE_DRAIN_SECONDS:
                    causes.append(FixtureFailure("owned_pipe_drain_deadline", ()))
                    break
            if selector_failed:
                terminal.wait(0.02)
                continue
            try:
                events = selector.select(0.02)
            except BaseException as error:
                causes.append(error)
                selector_failed = True
                # Stop reading but retain capture files until original wait.
                for stream in streams:
                    stream["eof"] = True
                continue
            for key, _ in events:
                stream = key.data
                try:
                    data = os.read(stream["pipe"].fileno(), 65536)
                except BlockingIOError:
                    continue
                except BaseException as error:
                    causes.append(error)
                    data = b""
                if not data:
                    stream["eof"] = True
                    try:
                        selector.unregister(stream["pipe"])
                    except BaseException as error:
                        causes.append(error)
                    continue
                remaining = CAPTURE_LIMIT - stream["bytes"]
                kept = data[:remaining]
                if len(data) > remaining and not stream["overflow"]:
                    stream["overflow"] = True
                    causes.append(FixtureFailure("owned_capture_overflow", ()))
                if kept:
                    try:
                        written = os.write(stream["destination"], kept)
                        require(written == len(kept), "owned_capture_short_write")
                        stream["bytes"] += written
                    except BaseException as error:
                        causes.append(error)
                        # No failed-write retry. Remaining stream bytes are discarded.
                        stream["bytes"] = CAPTURE_LIMIT
        waiter.join(timeout=KILL_JOIN_SECONDS)
        if waiter.is_alive():
            retain_unconfirmed(child, waiter, terminal, wait_result, causes, shutdown_at, killed_at is not None)
    finally:
        # This finally is reachable only with confirmed terminal wait, or before
        # a child-specific operation failed. Unknown terminal paths retain above.
        if not terminal.is_set() or "error" in wait_result or waiter.is_alive():
            retain_unconfirmed(child, waiter, terminal, wait_result, causes, shutdown_at, killed_at is not None)
        try:
            if selector is not None:
                selector.close()
        except BaseException as error:
            causes.append(error)
        for stream in streams:
            try:
                stream["pipe"].close()
            except BaseException as error:
                causes.append(error)
    if wait_result.get("status") != 0:
        causes.append(FixtureFailure("fixed_hdiutil_command_failed", ()))
    try:
        gate()  # A late zero cannot clear cancel, overflow or original expiry.
    except BaseException as error:
        causes.append(error)
    if causes:
        raise FixtureFailure("owned_command_failed", causes)

def command(rootfd, name, args):
    gate()
    out = hold(name + ".stdout", os.O_RDWR | os.O_CREAT | os.O_EXCL, dir_fd=rootfd)
    err = hold(name + ".stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL, dir_fd=rootfd)
    # Non-raising sticky handlers protect ownership transfer without masking
    # the child. A racing cancellation may create this exact owned child;
    # run_owned must stop/join it before any post-creation gate can raise.
    state = prepare_owned(out, err)  # All Event/Thread constructors precede Popen.
    require_unmasked()
    gate()
    state["child"] = subprocess.Popen(["/usr/bin/hdiutil"] + args, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                                     env=ENV, close_fds=True)
    try:
        run_owned(state)
    except BaseException as error:
        if (not wait_confirmed(state["terminal"], state["wait_result"])
                or state["waiter"].is_alive()):
            state["causes"].append(error)
            retain_unconfirmed(state["child"], state["waiter"], state["terminal"],
                               state["wait_result"], state["causes"])
        raise
    size = os.fstat(out).st_size
    require(size <= CAPTURE_LIMIT, "hdiutil result exceeds private capture bound")
    data = os.pread(out, size, 0)
    require(len(data) == size, "short held hdiutil result read")
    gate()
    return data

def entities(value):
    require(isinstance(value, list) and value, "missing attachment entities")
    result = {}
    for entry in value:
        device = entry.get("dev-entry")
        require(isinstance(device, str) and re.fullmatch(r"/dev/disk[0-9]+(?:s[0-9]+)*", device), "invalid attached device")
        require(device not in result, "duplicate attached device")
        hint = entry.get("content-hint", "")
        apfs_uuid = "7C3457EF-0000-11AA-AA11-00306543ECAC"
        if hint == "Apple_APFS":
            require(entry.get("unmapped-content-hint") == apfs_uuid,
                    "apfs_alias_canonical_uuid_missing_or_different")
            hint = apfs_uuid
        elif hint == apfs_uuid:
            require(entry.get("unmapped-content-hint", apfs_uuid) == apfs_uuid,
                    "apfs_canonical_uuid_conflict")
        result[device] = {"mountpoint": entry.get("mount-point", ""), "hint": hint}
    return result

def verify_info(rootfd, label, image, expected):
    data = command(rootfd, label, ["info", "-plist"])
    matches = [item for item in plistlib.loads(data).get("images", [])
               if item.get("image-path") == image]
    require(len(matches) == 1, "image attachment not uniquely identified")
    require(entities(matches[0].get("system-entities")) == expected, "image attachment entity mapping changed")
    return hashlib.sha256(data).hexdigest()

def confirmation():
    data = b""
    while not data.endswith(b"\n") and len(data) < 128:
        gate()
        if select.select([sys.stdin.fileno()], [], [], 0.02)[0]:
            part = os.read(sys.stdin.fileno(), 128-len(data))
            require(part, "joined attestation missing")
            data += part
    require(data == b"JOINED 20261015-7c4e92b1\n", "joined tests and inspector attestation required")

def finalize(action):
    causes = []
    result = None
    try:
        gate()
        result = action()
    except BaseException as error:
        causes.append(error)
    try:
        close_all()
    except BaseException as error:
        causes.append(error)
    try:
        gate()
    except BaseException as error:
        causes.append(error)
    if causes:
        raise FixtureFailure("fixture_operation_failed", causes)
    # No Complete output exists until all owned closes and command waits succeed.
    print(json.dumps(result), flush=True)
    gate()  # A cancellation during final output still forces a nonzero exit.

def entrypoint(action):
    global cancelled, deadline
    require(sys.argv == ["-c"] and sys.flags.isolated and sys.flags.no_site and os.getuid() == 0 and os.geteuid() == 0,
            "execute only reviewed literal bytes using isolated system Python as root")
    cancelled = False
    deadline = time.monotonic() + BUDGET_SECONDS
    # Install before any descriptor acquisition or Popen. Keep until process exit.
    signal.signal(signal.SIGINT, cancel)
    signal.signal(signal.SIGTERM, cancel)
    require_unmasked()
    os.umask(0o077)
    finalize(action)

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


def partial_v2_native_library():
    require(sys.platform == "darwin" and os.uname().machine == "arm64" and
            C.sizeof(C.c_void_p) == 8 and C.sizeof(NativeMount) == 2168 and
            C.sizeof(NativeStat) == 144, "partial_v2_native_layout")
    require(not any(k.startswith("DYLD_") for k in os.environ),
            "partial_v2_loader_environment")
    lib = C.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    for name, restype, args in (
        ("fstatfs", C.c_int, [C.c_int, C.POINTER(NativeMount)]),
        ("filesec_init", C.c_void_p, []),
        ("filesec_free", None, [C.c_void_p]),
        ("fstatx_np", C.c_int, [C.c_int, C.POINTER(NativeStat), C.c_void_p]),
        ("filesec_query_property", C.c_int, [C.c_void_p, C.c_int, C.POINTER(C.c_int)])):
        function = getattr(lib, name)
        function.restype, function.argtypes = restype, args
    return lib

def partial_v2_acl_absent(lib, fd):
    # Same FILESEC_ACL absence predicate as the native ownership inspector.
    security = lib.filesec_init()
    require(bool(security), "partial_v2_filesec_allocation")
    causes = []
    try:
        native, present = NativeStat(), C.c_int(-1)
        C.set_errno(0)
        if lib.fstatx_np(fd, C.byref(native), security) != 0:
            raise OSError(C.get_errno(), "partial_v2_fstatx")
        actual = os.fstat(fd)
        require((native.dev, native.ino, native.uid, native.mode) ==
                (actual.st_dev, actual.st_ino, actual.st_uid, actual.st_mode),
                "partial_v2_native_stat_disagrees")
        C.set_errno(0)
        if lib.filesec_query_property(security, 5, C.byref(present)) != 0:
            raise OSError(C.get_errno(), "partial_v2_acl_query")
        require(present.value == 0, "partial_v2_explicit_acl_present_or_unknown")
    except BaseException as error:
        causes.append(error)
    try:
        lib.filesec_free(security)  # Consume once; no retry on any exception.
    except BaseException as error:
        causes.append(error)
    if causes:
        raise FixtureFailure("partial_v2_acl_admission_failed", causes)


def metadata_native_mount(lib, fd):
    value = NativeMount()
    C.set_errno(0)
    if lib.fstatfs(fd, C.byref(value)) != 0:
        raise OSError(C.get_errno(), "metadata_fstatfs")
    return {"fsid": list(value.fsid), "owner": value.owner, "flags": value.flags,
            "type": value.typename.decode("ascii"), "mountpoint": value.mountpoint.decode("ascii"),
            "source": value.source.decode("ascii")}

def metadata_devfs(lib, devfd):
    held_info = os.fstat(devfd)
    path_info = os.stat("/dev", follow_symlinks=False)
    require(stat.S_ISDIR(held_info.st_mode) and stat.S_ISDIR(path_info.st_mode) and
            held_info.st_uid == held_info.st_gid == 0 and
            not stat.S_IMODE(held_info.st_mode) & 0o022 and
            (held_info.st_dev, held_info.st_ino, held_info.st_mode, held_info.st_uid, held_info.st_gid) ==
            (path_info.st_dev, path_info.st_ino, path_info.st_mode, path_info.st_uid, path_info.st_gid),
            "metadata_dev_directory_changed")
    partial_v2_acl_absent(lib, devfd)
    policy = metadata_native_mount(lib, devfd)
    require(policy["type"] == "devfs" and policy["mountpoint"] == "/dev" and
            policy["source"] == "devfs" and policy["owner"] == 0 and
            policy["fsid"] != [0, 0] and policy["flags"] & 0x1000,
            "metadata_devfs_policy")
    return {"directory": identity(devfd), "mountPolicy": policy}

def metadata_map(label, attached):
    require(label in ("owners", "noowners") and type(attached) is dict and
            1 <= len(attached) <= 16, "metadata_entity_roster")
    for device, entry in attached.items():
        require(type(device) is str and re.fullmatch(r"/dev/disk[0-9]+(?:s[0-9]+)*", device) and
                type(entry) is dict and set(entry) == {"mountpoint", "hint"} and
                type(entry["mountpoint"]) is str and type(entry["hint"]) is str,
                "metadata_entity_schema")
    mountpoint = ROOT + "/" + label
    mounted = [dev for dev, entry in attached.items() if entry["mountpoint"] == mountpoint]
    whole = [dev for dev, entry in attached.items() if entry["hint"] == "GUID_partition_scheme"
             and re.fullmatch(r"/dev/disk[0-9]+", dev)]
    require(len(mounted) == len(whole) == 1 and
            all(not v["mountpoint"] or v["mountpoint"] == mountpoint for v in attached.values()),
            "metadata_entity_binding")
    return mounted[0], whole[0]

def metadata_mount(lib, fd, label, attached):
    mounted, whole = metadata_map(label, attached)
    value = metadata_native_mount(lib, fd)
    require(value["type"] == "apfs" and value["owner"] == 0 and
            value["flags"] & 0x1000 and
            bool(value["flags"] & 0x200000) == (label == "noowners") and
            value["fsid"] != [0, 0] and value["source"] == mounted and
            value["mountpoint"] == ROOT + "/" + label,
            "metadata_mount_policy")
    partial_v2_acl_absent(lib, fd)
    return value

def metadata_nodes(devfd, attached, mounted, mountedfd):
    # Every basename comes from this exact freshly verified image map.
    result = {}
    for path in sorted(attached):
        require(re.fullmatch(r"/dev/disk[0-9]+(?:s[0-9]+)*", path) is not None,
                "metadata_device_basename")
        info = os.stat(path[5:], dir_fd=devfd, follow_symlinks=False)
        require(stat.S_ISBLK(info.st_mode) and info.st_uid == 0 and
                not stat.S_IMODE(info.st_mode) & 0o022 and info.st_nlink == 1,
                "metadata_device_node_policy")
        if path == mounted:
            require(info.st_rdev == os.fstat(mountedfd).st_dev, "metadata_mount_rdev")
        result[path] = {"dev": info.st_dev, "ino": info.st_ino, "mode": info.st_mode,
                        "uid": info.st_uid, "gid": info.st_gid, "nlink": info.st_nlink,
                        "rdev": info.st_rdev}
    return result

def metadata_observe(lib, rootfd, imagefd, mountedfd, devfd, label, attached):
    mounted, whole = metadata_map(label, attached)
    for fd in (rootfd, imagefd):
        partial_v2_acl_absent(lib, fd)
    root_path = os.stat(ROOT, follow_symlinks=False)
    require(stat.S_ISDIR(root_path.st_mode) and root_path.st_uid == 0 and
            (root_path.st_dev, root_path.st_ino) ==
            (os.fstat(rootfd).st_dev, os.fstat(rootfd).st_ino),
            "metadata_root_path_changed")
    mount_path = os.stat(label, dir_fd=rootfd, follow_symlinks=False)
    mount_stat = os.fstat(mountedfd)
    image_path = os.stat(label + ".dmg", dir_fd=rootfd, follow_symlinks=False)
    image_stat = os.fstat(imagefd)
    require(stat.S_ISDIR(mount_path.st_mode) and stat.S_ISREG(image_path.st_mode) and
            (mount_path.st_dev, mount_path.st_ino) == (mount_stat.st_dev, mount_stat.st_ino) and
            (image_path.st_dev, image_path.st_ino) == (image_stat.st_dev, image_stat.st_ino) and
            mount_stat.st_dev != root_path.st_dev, "metadata_image_or_mount_path_changed")
    before_devfs = metadata_devfs(lib, devfd)
    before_mount = metadata_mount(lib, mountedfd, label, attached)
    first = metadata_nodes(devfd, attached, mounted, mountedfd)
    second = metadata_nodes(devfd, attached, mounted, mountedfd)
    require(first == second and metadata_devfs(lib, devfd) == before_devfs and
            metadata_mount(lib, mountedfd, label, attached) == before_mount,
            "metadata_observation_changed")
    return {"mountPolicy": before_mount, "devfs": before_devfs, "deviceNodeMetadata": first}

def metadata_close_selected(fds):
    failures = []
    for fd in fds:
        require(fd in owned, "metadata_close_not_owned")
        owned.remove(fd)
        try:
            os.close(fd)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise FixtureFailure("metadata_close_failed", failures)

def metadata_control(lib, mountedfd, label, expected=None):
    require(os.getuid() == os.geteuid() == 0, "metadata_control_root_context")
    require(label in ("owners", "noowners"), "metadata_control_label")
    policy = metadata_native_mount(lib, mountedfd)
    require(policy["type"] == "apfs" and policy["owner"] == 0 and
            policy["flags"] & 0x1000 and
            bool(policy["flags"] & 0x200000) == (label == "noowners") and
            policy["mountpoint"] == ROOT + "/" + label,
            "metadata_control_mount_policy")
    # Fixed fixture policy from independent root observations: noowners has
    # parent UID0 and control UID99. The UID501 inspector remains separate.
    ignored = bool(policy["flags"] & 0x200000)
    expected_parent_uid = 0 if ignored else 501
    expected_control_uid = 99 if ignored else 501
    parent = os.fstat(mountedfd)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == expected_parent_uid and
            stat.S_IMODE(parent.st_mode) == 0o700 and parent.st_flags == 0,
            "metadata_mount_directory_policy")
    fd = hold("control", os.O_RDONLY | os.O_NONBLOCK, dir_fd=mountedfd)
    value = identity(fd)
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0 and
            info.st_uid == expected_control_uid and stat.S_IMODE(info.st_mode) == 0o600 and
            info.st_dev == os.fstat(mountedfd).st_dev and info.st_flags == 0,
            "metadata_control_policy")
    partial_v2_acl_absent(lib, fd)
    require(metadata_native_mount(lib, fd) == policy and metadata_native_mount(lib, mountedfd) == policy,
            "metadata_control_filesystem_changed")
    if expected is not None:
        require(value == expected, "metadata_control_identity_changed")
    return fd

def metadata_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "metadata_receipt_duplicate_key")
        result[key] = value
    return result

def metadata_equal(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == \
           json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)


PRIOR_PARTIAL_ROOT = "/private/tmp/agentmux-c05-apfs-20261015-4d927ca8"
PRIOR_PARTIAL_IMAGE = PRIOR_PARTIAL_ROOT + "/owners.dmg"

def prior_partial_identity(oldfd):
    parent = os.fstat(oldfd)
    path = os.stat(PRIOR_PARTIAL_ROOT, follow_symlinks=False)
    expected_root = (16777234, 2395883, 0, 0, 0o711)
    for value in (parent, path):
        require(stat.S_ISDIR(value.st_mode) and
                (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                 stat.S_IMODE(value.st_mode)) == expected_root,
                "prior_partial_root_changed")
    # Metadata only. Never open or read bytes from the retained image.
    image = os.stat("owners.dmg", dir_fd=oldfd, follow_symlinks=False)
    expected_image = (16777234, 2395887, 0, 0, 0o600, 1, 134217728)
    require(stat.S_ISREG(image.st_mode) and
            (image.st_dev, image.st_ino, image.st_uid, image.st_gid,
             stat.S_IMODE(image.st_mode), image.st_nlink, image.st_size) == expected_image,
            "prior_partial_image_changed")
    return expected_image

def prior_partial_absent(lib, rootfd, label):
    require(label in ("owners", "noowners"), "prior_partial_label_refused")
    oldfd = hold(PRIOR_PARTIAL_ROOT, os.O_RDONLY | os.O_DIRECTORY)
    partial_v2_acl_absent(lib, oldfd)
    before = prior_partial_identity(oldfd)
    # command returns only after its original child wait and capture work join.
    raw = command(rootfd, label + "-prior-partial-absence", ["info", "-plist"])
    parsed = plistlib.loads(raw)
    require(type(parsed) is dict and type(parsed.get("images")) is list and
            all(type(item) is dict and type(item.get("image-path")) is str
                for item in parsed["images"]), "prior_partial_info_schema")
    require(not any(item["image-path"] == PRIOR_PARTIAL_IMAGE for item in parsed["images"]),
            "prior_partial_image_still_attached")
    require(prior_partial_identity(oldfd) == before, "prior_partial_identity_changed")
    metadata_close_selected((oldfd,))
    return {"image": PRIOR_PARTIAL_IMAGE, "imageAbsent": True,
            "imageIdentity": list(before), "infoSHA256": hashlib.sha256(raw).hexdigest()}

def setup():
    lib = partial_v2_native_library()
    # Exclusive creation: never reuse or repair an existing path.
    mutate(os.mkdir, ROOT, 0o711)
    rootfd = hold(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    mutate(os.fchmod, rootfd, 0o711)
    root_identity = identity(rootfd)
    require(root_identity["uid"] == 0 and root_identity["mode"] == 0o711, "unsafe fixture parent")
    records = []
    prior_partial_proofs = []
    for label, owners in [("owners", "on"), ("noowners", "off")]:
        image = ROOT + "/" + label + ".dmg"
        mountpoint = ROOT + "/" + label
        mutate(os.mkdir, label, 0o700, dir_fd=rootfd)
        prior_partial_proofs.append(prior_partial_absent(lib, rootfd, label))
        command(rootfd, label + "-create", ["create", "-size", "128m", "-fs", "APFS",
                "-layout", "GPTSPUD", "-type", "UDIF", "-volname", "AgentmuxC05",
                image])
        imagefd = hold(label + ".dmg", os.O_RDONLY, dir_fd=rootfd)
        mutate(os.fchmod, imagefd, 0o600)
        image_identity = identity(imagefd)
        require(image_identity["uid"] == 0 and image_identity["mode"] == 0o600 and
                image_identity["nlink"] == 1 and stat.S_ISREG(os.fstat(imagefd).st_mode),
                "unsafe backing image")
        data = command(rootfd, label + "-attach", ["attach", "-plist", "-nobrowse",
                       "-noautoopen", "-owners", owners, "-mountpoint", mountpoint, image])
        attached = entities(plistlib.loads(data).get("system-entities"))
        mounted = [dev for dev, entry in attached.items() if entry["mountpoint"] == mountpoint]
        require(len(mounted) == 1 and all(not e["mountpoint"] or e["mountpoint"] == mountpoint
                for e in attached.values()), "unexpected mounted entity")
        whole = [dev for dev, entry in attached.items()
                 if entry["hint"] == "GUID_partition_scheme" and re.fullmatch(r"/dev/disk[0-9]+", dev)]
        require(len(whole) == 1, "ambiguous exact image detach device")
        info_hash = verify_info(rootfd, label + "-info", image, attached)
        mountedfd = hold(label, os.O_RDONLY | os.O_DIRECTORY, dir_fd=rootfd)
        devfd = hold("/dev", os.O_RDONLY | os.O_DIRECTORY)
        admitted = metadata_observe(lib, rootfd, imagefd, mountedfd, devfd, label, attached)
        require(os.stat(label, dir_fd=rootfd, follow_symlinks=False).st_ino == os.fstat(mountedfd).st_ino,
                "mountpoint identity changed")
        controlfd = hold("control", os.O_RDWR | os.O_CREAT | os.O_EXCL, dir_fd=mountedfd)
        require(os.fstat(controlfd).st_dev == os.fstat(mountedfd).st_dev and
                os.fstat(controlfd).st_nlink == 1 and os.fstat(controlfd).st_size == 0,
                "fresh control identity differs")
        # Only these two held, freshly created/mounted objects change owner.
        mutate(os.fchown, mountedfd, 501, -1)
        mutate(os.fchmod, mountedfd, 0o700)
        mutate(os.fchown, controlfd, 501, -1)
        mutate(os.fchmod, controlfd, 0o600)
        require(identity(imagefd) == image_identity, "backing image path identity changed")
        checkfd = metadata_control(lib, mountedfd, label, identity(controlfd))
        metadata_close_selected((checkfd,))
        partial_v2_acl_absent(lib, controlfd)
        require(metadata_observe(lib, rootfd, imagefd, mountedfd, devfd, label, attached) == admitted,
                "metadata_setup_policy_changed")
        records.append({"label": label, "image": image, "imageIdentity": image_identity,
                        "mountpoint": mountpoint, "mountIdentity": identity(mountedfd),
                        "controlIdentity": identity(controlfd), "entities": attached,
                        "detachDevice": whole[0], "attachSHA256": hashlib.sha256(data).hexdigest(),
                        "infoSHA256": info_hash, **admitted})
    require(records[0]["mountPolicy"]["fsid"] != records[1]["mountPolicy"]["fsid"] and
            records[0]["mountIdentity"]["dev"] != records[1]["mountIdentity"]["dev"] and
            records[0]["mountPolicy"]["source"] != records[1]["mountPolicy"]["source"],
            "metadata_pair_not_distinct")
    receipt = {"version": 2, "nonce": NONCE, "rootIdentity": root_identity, "attachments": records}
    encoded = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    private_bytes(rootfd, "root-receipt.json", encoded)
    return {"setupComplete": True, "rootReceipt": receipt,
            "priorPartialImageAbsence": prior_partial_proofs,
            "rootReceiptSHA256": hashlib.sha256(encoded).hexdigest(),
            "requiresUnprivilegedFstatfsAndACLVerification": True}

import errno

MAX_NODES = 24
MAX_DEPTH = 5
SAFE_CODES = frozenset({
    'fixture_operation_failed', 'owned_descriptor_cleanup_failed',
    'owned_command_failed', 'fixed_hdiutil_command_failed',
    'fixture_cancelled', 'fixture_original_deadline_expired',
    'partial_live_map_changed', 'partial_held_identity_changed',
    'partial_image_path_replaced', 'partial_volume_device_changed',
    'partial_guid_device_type_changed', 'partial_saved_maps_differ',
    'partial_image_not_unique_in_info', 'partial_scope_no_longer_exact',
    'partial_saved_capture_changed', 'partial_object_type_changed',
    'diagnostic_admission_refused', 'diagnostic_capture_refused',
    'diagnostic_short_read', 'diagnostic_capture_changed',
    'diagnostic_map_refused', 'diagnostic_identity_refused',
    'diagnostic_capture_operation_failed',
    'diagnostic_maps_differ',
    'diagnostic_cancelled', 'diagnostic_deadline_expired',
})
SAFE_CODES = SAFE_CODES | frozenset(["partial_v2_acl_admission_failed","partial_v2_acl_query","partial_v2_dev_directory_identity","partial_v2_dev_directory_type","partial_v2_devfs_fstatfs","partial_v2_devfs_policy","partial_v2_device_guid_map","partial_v2_device_metadata","partial_v2_device_mount_map","partial_v2_device_path_replaced","partial_v2_device_rdev","partial_v2_device_target","partial_v2_device_type","partial_v2_explicit_acl_present_or_unknown","partial_v2_filesec_allocation","partial_v2_fstatfs","partial_v2_fstatx","partial_v2_loader_environment","partial_v2_mount_changed","partial_v2_mount_device_rdev","partial_v2_mount_policy","partial_v2_native_layout","partial_v2_native_stat_disagrees","partial_v2_predetach_device_changed","partial_v2_predetach_mount_changed","partial_v2_review_unbound","partial_v2_root_path_replaced","partial_v2_selected_close_failed","partial_v2_unowned_close"])

# Exact source-literal message mappings. No runtime message enrollment.
SAFE_MESSAGE_CODES = {'ambiguous exact image detach device': 'stage_ambiguous_exact_image_detach_device', 'apfs_alias_canonical_uuid_missing_or_different': 'apfs_alias_canonical_uuid_missing_or_different', 'apfs_canonical_uuid_conflict': 'apfs_canonical_uuid_conflict', 'backing image changed before detach': 'stage_backing_image_changed_before_detach', 'backing image path identity changed': 'stage_backing_image_path_identity_changed', 'detach device not bound to exact image': 'stage_detach_device_not_bound_to_exact_image', 'duplicate attached device': 'stage_duplicate_attached_device', 'execute only reviewed literal bytes using isolated system Python as root': 'stage_execute_only_reviewed_literal_bytes_using_isolated_system_python_as_root', 'fixed_hdiutil_command_failed': 'fixed_hdiutil_command_failed', 'fixture image remains attached': 'stage_fixture_image_remains_attached', 'fixture parent changed before detach': 'stage_fixture_parent_changed_before_detach', 'fixture_cancellation_pending': 'fixture_cancellation_pending', 'fixture_cancelled': 'fixture_cancelled', 'fixture_failure_report_failed': 'fixture_failure_report_failed', 'fixture_inherited_cancellation_mask_refused': 'fixture_inherited_cancellation_mask_refused', 'fixture_operation_failed': 'fixture_operation_failed', 'fixture_original_deadline_expired': 'fixture_original_deadline_expired', 'fresh control identity differs': 'stage_fresh_control_identity_differs', 'hdiutil result exceeds private capture bound': 'stage_hdiutil_result_exceeds_private_capture_bound', 'held backing image identity differs': 'stage_held_backing_image_identity_differs', 'held mountpoint identity differs': 'stage_held_mountpoint_identity_differs', 'image attachment entity mapping changed': 'stage_image_attachment_entity_mapping_changed', 'image attachment not uniquely identified': 'stage_image_attachment_not_uniquely_identified', 'invalid attached device': 'stage_invalid_attached_device', 'joined attestation missing': 'stage_joined_attestation_missing', 'joined tests and inspector attestation required': 'stage_joined_tests_and_inspector_attestation_required', 'literal fixture path binding differs': 'stage_literal_fixture_path_binding_differs', 'metadata_attachment_schema': 'metadata_attachment_schema', 'metadata_close_failed': 'metadata_close_failed', 'metadata_close_not_owned': 'metadata_close_not_owned', 'metadata_control_filesystem_changed': 'metadata_control_filesystem_changed', 'metadata_control_identity_changed': 'metadata_control_identity_changed', 'metadata_control_label': 'metadata_control_label', 'metadata_control_mount_policy': 'metadata_control_mount_policy', 'metadata_control_policy': 'metadata_control_policy', 'metadata_control_root_context': 'metadata_control_root_context', 'metadata_dev_directory_changed': 'metadata_dev_directory_changed', 'metadata_devfs_policy': 'metadata_devfs_policy', 'metadata_device_basename': 'metadata_device_basename', 'metadata_device_node_policy': 'metadata_device_node_policy', 'metadata_entity_binding': 'metadata_entity_binding', 'metadata_entity_roster': 'metadata_entity_roster', 'metadata_entity_schema': 'metadata_entity_schema', 'metadata_image_or_mount_path_changed': 'metadata_image_or_mount_path_changed', 'metadata_mount_directory_policy': 'metadata_mount_directory_policy', 'metadata_mount_policy': 'metadata_mount_policy', 'metadata_mount_rdev': 'metadata_mount_rdev', 'metadata_observation_changed': 'metadata_observation_changed', 'metadata_pair_not_distinct': 'metadata_pair_not_distinct', 'metadata_predetach_image_changed': 'metadata_predetach_image_changed', 'metadata_predetach_mount_identity': 'metadata_predetach_mount_identity', 'metadata_predetach_policy_changed': 'metadata_predetach_policy_changed', 'metadata_receipt_duplicate_key': 'metadata_receipt_duplicate_key', 'metadata_receipt_policy_changed': 'metadata_receipt_policy_changed', 'metadata_receipt_schema': 'metadata_receipt_schema', 'metadata_root_path_changed': 'metadata_root_path_changed', 'metadata_setup_policy_changed': 'metadata_setup_policy_changed', 'missing attachment entities': 'stage_missing_attachment_entities', 'mounted device not unique': 'stage_mounted_device_not_unique', 'mountpoint identity changed': 'stage_mountpoint_identity_changed', 'owned_capture_overflow': 'owned_capture_overflow', 'owned_capture_short_write': 'owned_capture_short_write', 'owned_command_failed': 'owned_command_failed', 'owned_descriptor_cleanup_failed': 'owned_descriptor_cleanup_failed', 'owned_pipe_drain_deadline': 'owned_pipe_drain_deadline', 'owned_terminal_historically_unconfirmed': 'owned_terminal_historically_unconfirmed', 'partial_v2_acl_admission_failed': 'partial_v2_acl_admission_failed', 'partial_v2_explicit_acl_present_or_unknown': 'partial_v2_explicit_acl_present_or_unknown', 'partial_v2_filesec_allocation': 'partial_v2_filesec_allocation', 'partial_v2_loader_environment': 'partial_v2_loader_environment', 'partial_v2_native_layout': 'partial_v2_native_layout', 'partial_v2_native_stat_disagrees': 'partial_v2_native_stat_disagrees', 'prior_partial_identity_changed': 'prior_partial_identity_changed', 'prior_partial_image_changed': 'prior_partial_image_changed', 'prior_partial_image_still_attached': 'prior_partial_image_still_attached', 'prior_partial_info_schema': 'prior_partial_info_schema', 'prior_partial_label_refused': 'prior_partial_label_refused', 'prior_partial_root_changed': 'prior_partial_root_changed', 'root receipt binding differs': 'stage_root_receipt_binding_differs', 'root receipt changed': 'stage_root_receipt_changed', 'short held hdiutil result read': 'stage_short_held_hdiutil_result_read', 'short private record write': 'stage_short_private_record_write', 'unexpected mounted entity': 'stage_unexpected_mounted_entity', 'unsafe backing image': 'stage_unsafe_backing_image', 'unsafe fixture parent': 'stage_unsafe_fixture_parent', 'unsafe root receipt': 'stage_unsafe_root_receipt'}
SAFE_CODES = SAFE_CODES | frozenset(SAFE_MESSAGE_CODES.values())

def safe_causes(error):
    """Never stringify exceptions, filenames, arbitrary values, or class names."""
    seen = set()
    budget = [MAX_NODES]

    messages = {code: code for code in SAFE_CODES}
    messages.update(SAFE_MESSAGE_CODES)
    messages.update({message + "; retain all fixture resources": code for message, code in tuple(messages.items())})

    def visit(item, depth):
        if budget[0] == 0:
            return {'kind': 'node_limit'}
        budget[0] -= 1
        if id(item) in seen:
            return {'kind': 'cycle'}
        seen.add(id(item))
        if depth >= MAX_DEPTH:
            return {'kind': 'depth_limit'}
        result = {'kind': 'exception', 'code': 'unclassified'}
        # Use base descriptors to avoid overridden __str__/attribute access.
        if issubclass(type(item), BaseException):
            args = BaseException.args.__get__(item)
            if type(args) is tuple and args and type(args[0]) is str and len(args[0]) <= 160:
                code = messages.get(args[0])
                if code is not None:
                    result['code'] = code
        if issubclass(type(item), OSError):
            number = OSError.errno.__get__(item)
            if type(number) is int and number in errno.errorcode:
                result.update(kind='os_error', errno=number, errnoName=errno.errorcode[number])
        # FixtureFailure stores causes in its own dictionary. Do not traverse
        # arbitrary iterables, exception contexts, properties, or descriptors.
        try:
            attributes = BaseException.__dict__['__dict__'].__get__(item)
        except (TypeError, AttributeError, KeyError):
            attributes = {}
        children = attributes.get('causes') if type(attributes) is dict else None
        if type(children) is tuple:
            result['causes'] = []
            for child in children:
                if budget[0] == 0:
                    result['truncated'] = True
                    break
                result['causes'].append(visit(child, depth + 1))
        return result

    return visit(error, 0)


def entrypoint_with_failure_report(action):
    try:
        entrypoint(action)
    except FixtureFailure as error:
        # finalize already attempted all owned closes; preserve their causes.
        try:
            print(json.dumps({"complete": False, "causes": safe_causes(error)},
                             separators=(",", ":")), file=sys.stderr, flush=True)
        except BaseException as report_error:
            failure = FixtureFailure("fixture_failure_report_failed", (error, report_error))
            raise SystemExit(1) from failure
        raise SystemExit(1) from error

if __name__ == "__main__":
    entrypoint_with_failure_report(setup)

